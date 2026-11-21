package anytls

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anytls/sing-anytls/padding"
	"github.com/anytls/sing-anytls/session"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const probePassword = "11111111-1111-4111-8111-111111111111"

type echoHandler struct{ users chan string }

func (h echoHandler) NewConnectionEx(ctx context.Context, conn net.Conn, _, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	name, _ := auth.UserFromContext[string](ctx)
	h.users <- name
	go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
}

func newService(t *testing.T) (*Service, chan string) {
	t.Helper()
	users := make(chan string, 16)
	s, err := NewService(ServiceConfig{
		Users:         []User{{Name: "1001", Password: probePassword}},
		PaddingScheme: padding.DefaultPaddingScheme,
		Handler:       echoHandler{users}, Logger: logger.NOP(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, users
}

func newClient(t *testing.T, s *Service, password string, dials *atomic.Int32) *Client {
	t.Helper()
	c, err := NewClient(context.Background(), ClientConfig{
		Password: password, Logger: logger.NOP(),
		IdleSessionCheckInterval: time.Hour, IdleSessionTimeout: time.Hour, MinIdleSession: 1,
		DialOut: func(context.Context) (net.Conn, error) {
			dials.Add(1)
			client, server := net.Pipe()
			go func() {
				defer server.Close()
				_ = s.NewConnection(context.Background(), server, M.ParseSocksaddr("127.0.0.1:12345"), nil)
			}()
			return client, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func roundTrip(c *Client) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := c.CreateProxy(ctx, M.ParseSocksaddr("example.invalid:443"))
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err = conn.Write([]byte("ping")); err != nil {
		return err
	}
	b := make([]byte, 4)
	_, err = io.ReadFull(conn, b)
	if err == nil && string(b) != "ping" {
		return io.ErrUnexpectedEOF
	}
	return err
}

// The local patch must revoke both existing sessions and fresh authentication.
func TestExistingSessionRevokedOnUserRemoval(t *testing.T) {
	s, users := newService(t)
	var dials atomic.Int32
	c := newClient(t, s, probePassword, &dials)
	if err := roundTrip(c); err != nil {
		t.Fatal(err)
	}
	if name := <-users; name != "1001" {
		t.Fatalf("unexpected user %q", name)
	}
	s.UpdateUsers(nil)
	if err := roundTrip(c); err == nil {
		t.Fatal("removed user reused an authenticated session")
	}
	var freshDials atomic.Int32
	fresh := newClient(t, s, probePassword, &freshDials)
	if err := roundTrip(fresh); err == nil {
		t.Fatal("fresh authentication unexpectedly accepted removed user")
	}
	t.Log("CONFIRMED: fresh connection with the removed password is rejected")
}

func TestUserReplacementAndIdentity(t *testing.T) {
	s, users := newService(t)
	const replacement = "22222222-2222-4222-8222-222222222222"
	s.UpdateUsers([]User{{Name: "1001", Password: replacement}})
	var dials atomic.Int32
	c := newClient(t, s, replacement, &dials)
	if err := roundTrip(c); err != nil {
		t.Fatal(err)
	}
	if name := <-users; name != "1001" {
		t.Fatalf("identity changed: %q", name)
	}
	var oldDials atomic.Int32
	old := newClient(t, s, probePassword, &oldDials)
	if err := roundTrip(old); err == nil {
		t.Fatal("old password unexpectedly accepted")
	}
}

// Race validation uses the same actual dependency graph as gosingbox.
func TestConcurrentUpdateAndHandshake(t *testing.T) {
	s, _ := newService(t)
	hash := sha256.Sum256([]byte(probePassword))
	payload := append(hash[:], 0, 0)
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 20000; i++ {
			s.UpdateUsers([]User{{Name: "1001", Password: probePassword}})
		}
	}()
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 300; i++ {
			client, server := net.Pipe()
			go func() { _, _ = client.Write(payload); _ = client.Close() }()
			_ = s.NewConnection(context.Background(), server, M.ParseSocksaddr("127.0.0.1:12345"), nil)
			_ = server.Close()
		}
	}()
	close(start)
	wg.Wait()
}

func TestLateRegistrationRejectsRemovedGeneration(t *testing.T) {
	s, _ := newService(t)
	hash := sha256.Sum256([]byte(probePassword))
	old := s.users[hash]
	s.UpdateUsers(nil)
	s.UpdateUsers([]User{{Name: "1001", Password: probePassword}})
	if s.registerSession(nil, old, nil) {
		t.Fatal("stale handshake resurrected after remove/re-add")
	}
	s.Close()
	if s.registerSession(nil, s.users[hash], nil) {
		t.Fatal("late session registered after shutdown")
	}
}

func TestServiceCloseRejectsPendingHandshake(t *testing.T) {
	s, _ := newService(t)
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan error, 1)
	started := make(chan struct{})
	go func() {
		done <- s.NewConnection(context.Background(), &readSignalConn{Conn: server, started: started}, M.Socksaddr{}, nil)
	}()
	<-started
	s.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("pending handshake did not stop")
	}
}

type readSignalConn struct {
	net.Conn
	started chan struct{}
}

func (c *readSignalConn) Read(p []byte) (int, error) { close(c.started); return c.Conn.Read(p) }

func TestAuthenticationAdmission(t *testing.T) {
	var pending []func()
	defer func() {
		for _, h := range pending {
			h()
		}
	}()
	for range maxPendingHandshakes {
		h, err := BeginHandshake()
		if err != nil {
			t.Fatal(err)
		}
		pending = append(pending, h)
	}
	if h, err := BeginHandshake(); err == nil {
		h()
		t.Fatal("handshake admitted above the limit")
	}
	pending[0]()
	pending[0]()
	h, err := BeginHandshake()
	if err != nil {
		t.Fatal("failed to reclaim exactly one slot", err)
	}
	h()
}

// Observe deadline installation and clearing without waiting on a real timer.
type authDeadlineConn struct {
	net.Conn
	deadlines []time.Time
}

func (c *authDeadlineConn) SetReadDeadline(d time.Time) error {
	c.deadlines = append(c.deadlines, d)
	return c.Conn.SetReadDeadline(d)
}

func TestAuthenticationReadDeadline(t *testing.T) {
	s, _ := newService(t)
	client, server := net.Pipe()
	defer server.Close()
	c := &authDeadlineConn{Conn: server}
	go func() {
		_, _ = client.Write([]byte{0})
		client.Close()
	}()
	start := time.Now()
	_ = s.NewConnection(context.Background(), c, M.Socksaddr{}, nil)
	if len(c.deadlines) != 2 || c.deadlines[0].Before(start.Add(authenticationTimeout)) || !c.deadlines[1].IsZero() {
		t.Fatal("authentication read did not set then clear its own deadline")
	}
}

func TestActiveSessionReleasesAdmission(t *testing.T) {
	s, _ := newService(t)
	var dials atomic.Int32
	client := newClient(t, s, probePassword, &dials)
	if err := roundTrip(client); err != nil {
		t.Fatal(err)
	}
	if len(handshakeSlots) != 0 {
		t.Fatal("authenticated session is still using a pending slot")
	}
}

func TestFragmentedAndLargePaddingAuthentication(t *testing.T) {
	s, users := newService(t)
	hash := sha256.Sum256([]byte(probePassword))
	// 24 KiB padding exceeds buf.NewPacket() (16 KiB) and arrives in small chunks.
	const padLen = 24 * 1024
	var authHeader bytes.Buffer
	authHeader.Write(hash[:])
	var lenBytes [2]byte
	binary.BigEndian.PutUint16(lenBytes[:], padLen)
	authHeader.Write(lenBytes[:])
	authHeader.Write(make([]byte, padLen))

	c, err := NewClient(context.Background(), ClientConfig{
		Password: probePassword, Logger: logger.NOP(),
		IdleSessionCheckInterval: time.Hour, IdleSessionTimeout: time.Hour,
		DialOut: func(context.Context) (net.Conn, error) {
			client, server := net.Pipe()
			go func() {
				defer server.Close()
				_ = s.NewConnection(context.Background(), server, M.ParseSocksaddr("127.0.0.1:12345"), nil)
			}()
			return &chunkedAuthConn{Conn: client, customAuth: authHeader.Bytes()}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := roundTrip(c); err != nil {
		t.Fatalf("fragmented large-padding handshake failed: %v", err)
	}
	if got := <-users; got != "1001" {
		t.Fatalf("unexpected user %q", got)
	}
}

type chunkedAuthConn struct {
	net.Conn
	mu         sync.Mutex
	sentAuth   bool
	customAuth []byte
}

func (c *chunkedAuthConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	first := !c.sentAuth
	c.sentAuth = true
	c.mu.Unlock()
	if !first {
		return c.Conn.Write(p)
	}
	// Replace client's default first auth packet with fragmented writes of customAuth.
	raw := c.customAuth
	steps := []int{1, 7, 24, 1, 1, 513, 4096}
	offset := 0
	for _, step := range steps {
		if offset >= len(raw) {
			break
		}
		end := min(offset+step, len(raw))
		if _, err := c.Conn.Write(raw[offset:end]); err != nil {
			return 0, err
		}
		offset = end
	}
	if offset < len(raw) {
		if _, err := c.Conn.Write(raw[offset:]); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func TestAuthenticatedSessionStreamLimitAndDestinationTimeout(t *testing.T) {
	prevTimeout := streamDestinationTimeout
	prevMax := maxSessionStreams
	streamDestinationTimeout = 40 * time.Millisecond
	maxSessionStreams = 3
	defer func() {
		streamDestinationTimeout = prevTimeout
		maxSessionStreams = prevMax
	}()

	s, _ := newService(t)

	// 1) Normal sequential session reuse via Client uses a single underlying session.
	var dials atomic.Int32
	pooled := newClient(t, s, probePassword, &dials)
	for i := 0; i < 3; i++ {
		if err := roundTrip(pooled); err != nil {
			t.Fatalf("pooled roundTrip %d: %v", i, err)
		}
	}
	if dials.Load() != 1 {
		t.Fatalf("expected 1 pooled session dial, got %d", dials.Load())
	}
	_ = pooled.Close()

	// 2) Single multiplexed session: enforce maxSessionStreams (3), reject 4th, reclaim on close & timeout.
	clientPipe, serverPipe := net.Pipe()
	defer clientPipe.Close()
	defer serverPipe.Close()
	go func() {
		defer serverPipe.Close()
		_ = s.NewConnection(context.Background(), serverPipe, M.ParseSocksaddr("127.0.0.1:23456"), nil)
	}()

	hash := sha256.Sum256([]byte(probePassword))
	if _, err := clientPipe.Write(append(hash[:], 0, 0)); err != nil {
		t.Fatal(err)
	}
	cliSess := session.NewClientSession(clientPipe, &s.padding, logger.NOP())
	defer cliSess.Close()
	cliSess.Run()

	openPingStream := func() (net.Conn, error) {
		st, err := cliSess.OpenStream()
		if err != nil {
			return nil, err
		}
		if err = M.SocksaddrSerializer.WriteAddrPort(st, M.ParseSocksaddr("example.invalid:443")); err != nil {
			_ = st.Close()
			return nil, err
		}
		_ = st.SetDeadline(time.Now().Add(500 * time.Millisecond))
		if _, err = st.Write([]byte("ping")); err != nil {
			_ = st.Close()
			return nil, err
		}
		reply := make([]byte, 4)
		if _, err = io.ReadFull(st, reply); err != nil {
			_ = st.Close()
			return nil, err
		}
		_ = st.SetDeadline(time.Time{})
		return st, nil
	}

	var openConns []net.Conn
	defer func() {
		for _, conn := range openConns {
			_ = conn.Close()
		}
	}()
	for i := 0; i < 3; i++ {
		st, err := openPingStream()
		if err != nil {
			t.Fatalf("open stream %d: %v", i, err)
		}
		openConns = append(openConns, st)
	}

	var srvSession *session.Session
	s.mu.RLock()
	for sess := range s.sessions {
		srvSession = sess
	}
	s.mu.RUnlock()
	if srvSession == nil || srvSession.ActiveStreams() != 3 {
		t.Fatalf("expected 3 active server streams, got %v", srvSession)
	}

	// 4th concurrent stream on the same session must be rejected without breaking existing 3 streams.
	if extra, err := openPingStream(); err == nil {
		_ = extra.Close()
		t.Fatal("4th stream above maxSessionStreams unexpectedly succeeded")
	}
	if srvSession.ActiveStreams() != 3 {
		t.Fatalf("server stream count exceeded cap: %d", srvSession.ActiveStreams())
	}

	// Closing 1 stream reclaims its slot; now test stalled destination-address timeout reclamation!
	_ = openConns[0].Close()
	openConns = openConns[1:]
	deadline := time.Now().Add(500 * time.Millisecond)
	for srvSession.ActiveStreams() != 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if srvSession.ActiveStreams() != 2 {
		t.Fatalf("expected 2 active streams after close, got %d", srvSession.ActiveStreams())
	}

	// Open a stalled stream that sends cmdSYN only and never writes destination address.
	stalled, err := cliSess.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	defer stalled.Close()
	// Wait for streamDestinationTimeout (40ms) to self-close and reclaim the 3rd slot.
	deadline = time.Now().Add(500 * time.Millisecond)
	for srvSession.ActiveStreams() != 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if srvSession.ActiveStreams() != 2 {
		t.Fatalf("stalled stream slot was not reclaimed after timeout: %d", srvSession.ActiveStreams())
	}

	// Now opening a valid 3rd stream succeeds!
	recovered, err := openPingStream()
	if err != nil {
		t.Fatalf("expected reclaimed slot to admit new valid stream: %v", err)
	}
	openConns = append(openConns, recovered)
}
