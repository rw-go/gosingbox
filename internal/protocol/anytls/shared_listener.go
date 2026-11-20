package anytls

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"

	anytls "github.com/anytls/sing-anytls"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/sniff"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
)

const (
	clientHelloTimeout  = 5 * time.Second
	maxClientHelloBytes = 128 << 10
)

var listenerName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

type listenerGroups struct{ groups map[string]*sharedListener }

// Configuration construction is serial. Once started, targets are immutable;
// user updates operate on the member's existing AnyTLS service instead.
type sharedListener struct {
	options  option.ListenOptions
	listener *listener.Listener
	targets  map[string]*Inbound
	mu       sync.Mutex
	ready    int
	closed   bool
	pending  map[net.Conn]struct{}
}

func canonicalServerName(value string) (string, error) {
	name := strings.ToLower(strings.TrimSuffix(value, "."))
	if len(name) == 0 || len(name) > 253 || net.ParseIP(name) != nil {
		return "", fmt.Errorf("shared AnyTLS listener requires a DNS tls.server_name")
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid shared AnyTLS server name")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", fmt.Errorf("invalid shared AnyTLS server name")
			}
		}
	}
	return name, nil
}

func (m *listenerGroups) join(name, sni string, target *Inbound, options listener.Options) (*sharedListener, error) {
	if !listenerName.MatchString(name) || options.Listen.ListenPort == 0 {
		return nil, fmt.Errorf("shared AnyTLS listener requires a valid name and nonzero port")
	}
	serverName, err := canonicalServerName(sni)
	if err != nil {
		return nil, err
	}
	g := m.groups[name]
	if g == nil {
		g = &sharedListener{options: options.Listen, targets: make(map[string]*Inbound), pending: make(map[net.Conn]struct{})}
		options.ConnectionHandler = g
		g.listener = listener.New(options)
		m.groups[name] = g
	} else if !reflect.DeepEqual(g.options, options.Listen) {
		return nil, fmt.Errorf("shared AnyTLS listener %q has inconsistent listen options", name)
	}
	if _, exists := g.targets[serverName]; exists {
		return nil, fmt.Errorf("shared AnyTLS listener %q has duplicate server name %q", name, serverName)
	}
	g.targets[serverName] = target
	return g, nil
}

func (g *sharedListener) startMember() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return net.ErrClosed
	}
	g.ready++
	// All member TLS providers and services must be ready before accepting.
	if g.ready == len(g.targets) {
		return g.listener.Start()
	}
	return nil
}

func (g *sharedListener) Close() error {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return nil
	}
	g.closed = true
	connections := make([]net.Conn, 0, len(g.pending))
	for conn := range g.pending {
		connections = append(connections, conn)
	}
	g.mu.Unlock()
	err := g.listener.Close()
	// Also close connections still awaiting a ClientHello or TLS/authentication.
	for _, conn := range connections {
		_ = conn.Close()
	}
	return err
}

func (g *sharedListener) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	release, err := anytls.BeginHandshake()
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}
	defer release()
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		N.CloseOnHandshakeFailure(conn, onClose, net.ErrClosed)
		return
	}
	g.pending[conn] = struct{}{}
	g.mu.Unlock()
	defer func() { g.mu.Lock(); delete(g.pending, conn); g.mu.Unlock() }()

	var hello adapter.InboundContext
	var captured bytes.Buffer
	if err := conn.SetReadDeadline(time.Now().Add(clientHelloTimeout)); err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}
	// Reuse sing-box's TLS parser; it handles ClientHello fragmentation. Bound
	// both bytes and time, and replay every consumed byte to the selected TLS
	// server. This never dials a loopback proxy or replaces the real source IP.
	err = sniff.TLSClientHello(ctx, &hello, io.TeeReader(io.LimitReader(conn, maxClientHelloBytes), &captured))
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, fmt.Errorf("invalid shared AnyTLS ClientHello"))
		return
	}
	name, err := canonicalServerName(hello.Domain)
	target := g.targets[name]
	if err != nil || target == nil {
		N.CloseOnHandshakeFailure(conn, onClose, fmt.Errorf("unrecognized shared AnyTLS server name"))
		return
	}
	metadata.Inbound = target.Tag()
	metadata.InboundType = C.TypeAnyTLS
	// Keep the outer SNI out of metadata.Domain: later domain-based routing
	// must still inspect the user's destination, not the selected entry name.
	target.acceptConnection(ctx, bufio.NewCachedConn(conn, buf.As(captured.Bytes())), metadata, onClose, release)
}
