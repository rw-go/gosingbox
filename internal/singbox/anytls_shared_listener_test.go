//go:build with_v2ray_api && with_clash_api

package singbox

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	anytls "github.com/anytls/sing-anytls"
	"github.com/rwnode/rwnode-gosingbox/internal/state"
	"github.com/rwnode/rwnode-gosingbox/internal/testutil"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/experimental/v2rayapi"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

// Fragment the first plaintext TLS handshake record across multiple records,
// exercising both ClientHello reassembly and byte-for-byte replay.
type fragmentedHelloConn struct {
	net.Conn
	first bool
}

func (c *fragmentedHelloConn) Write(p []byte) (int, error) {
	if c.first || len(p) < 5 || p[0] != 22 {
		return c.Conn.Write(p)
	}
	c.first = true
	n := int(p[3])<<8 | int(p[4])
	if len(p) < n+5 {
		return c.Conn.Write(p)
	}
	for offset := 0; offset < n; {
		size := min(23, n-offset)
		record := append([]byte{22, p[1], p[2], byte(size >> 8), byte(size)}, p[5+offset:5+offset+size]...)
		if _, err := c.Conn.Write(record); err != nil {
			return 0, err
		}
		offset += size
	}
	if len(p) > n+5 {
		if _, err := c.Conn.Write(p[n+5:]); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func sniClient(t *testing.T, port int, sni, password string, fragmented bool) *anytls.Client {
	t.Helper()
	c, err := anytls.NewClient(context.Background(), anytls.ClientConfig{
		Password: password, Logger: logger.NOP(), IdleSessionCheckInterval: time.Hour, IdleSessionTimeout: time.Hour, MinIdleSession: 1,
		DialOut: func(ctx context.Context) (net.Conn, error) {
			d := net.Dialer{Timeout: time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}}
			raw, err := d.DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", port))
			if err != nil {
				return nil, err
			}
			if fragmented {
				raw = &fragmentedHelloConn{Conn: raw}
			}
			conn := tls.Client(raw, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
			if err = conn.HandshakeContext(ctx); err != nil {
				raw.Close()
				return nil, err
			}
			return conn, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func markerServer(t *testing.T, marker string) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				b := make([]byte, 4)
				for {
					if _, err := io.ReadFull(c, b); err != nil {
						return
					}
					if _, err := c.Write(append([]byte(marker), b...)); err != nil {
						return
					}
				}
			}()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}
func markerPing(conn net.Conn, marker string) error {
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		return err
	}
	b := make([]byte, len(marker)+4)
	if _, err := io.ReadFull(conn, b); err != nil {
		return err
	}
	if string(b) != marker+"ping" {
		return fmt.Errorf("unexpected destination %q", b)
	}
	return nil
}
func openSNI(c *anytls.Client) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return c.CreateProxy(ctx, M.ParseSocksaddr("destination.example:80"))
}

func sharedConfig(t *testing.T, port int) map[string]any {
	t.Helper()
	certificate := testutil.TLS(t)
	inbounds := []any{}
	for i, sni := range []string{"wyx.cloud", "goouzi.top"} {
		tlsOptions := map[string]any{}
		for k, v := range certificate {
			tlsOptions[k] = v
		}
		tlsOptions["server_name"] = sni
		users := []any{map[string]any{"name": "1", "password": testutil.UUID1}}
		if i == 0 {
			users = append(users, map[string]any{"name": "2", "password": testutil.UUID2})
		}
		inbounds = append(inbounds, map[string]any{"type": "anytls", "tag": fmt.Sprint("route-", i), "listen": "127.0.0.1", "listen_port": port, "shared_listener": "test-443", "tls": tlsOptions, "users": users})
	}
	return map[string]any{"log": map[string]any{"disabled": true}, "inbounds": inbounds, "outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}}, "route": map[string]any{"rules": []any{
		map[string]any{"inbound": []string{"route-0"}, "action": "route", "outbound": "direct", "override_address": "127.0.0.1", "override_port": markerServer(t, "A:")},
		map[string]any{"inbound": []string{"route-1"}, "action": "route", "outbound": "direct", "override_address": "127.0.0.1", "override_port": markerServer(t, "B:")},
	}}}
}

func TestAnyTLSSharedListenerRoutesPermissionsAndLifecycle(t *testing.T) {
	port := testutil.Port(t)
	cfg := sharedConfig(t, port)
	clash := fmt.Sprintf("127.0.0.1:%d", testutil.Port(t))
	cfg["experimental"] = map[string]any{"clash_api": map[string]any{"external_controller": clash}, "v2ray_api": map[string]any{"listen": "127.0.0.1:0", "stats": map[string]any{"enabled": true, "users": []string{"1", "2"}}}}
	e := NewEngine(Options{ClashAddr: clash})
	defer e.Shutdown()
	if err := e.ApplyConfig(cfg); err != nil {
		t.Fatal(err)
	}
	instance := e.box
	a := sniClient(t, port, "wyx.cloud", testutil.UUID1, true)
	b := sniClient(t, port, "GOOUZI.TOP", testutil.UUID1, false)
	ca, err := openSNI(a)
	if err != nil {
		t.Fatal(err)
	}
	defer ca.Close()
	if err = markerPing(ca, "A:"); err != nil {
		t.Fatal(err)
	}
	cb, err := openSNI(b)
	if err != nil {
		t.Fatal(err)
	}
	defer cb.Close()
	if err = markerPing(cb, "B:"); err != nil {
		t.Fatal(err)
	}
	for _, sni := range []string{"unknown.example", ""} {
		c := sniClient(t, port, sni, testutil.UUID1, false)
		conn, err := openSNI(c)
		if err == nil {
			defer conn.Close()
			if markerPing(conn, "A:") == nil {
				t.Fatal("unknown or missing SNI accepted")
			}
		}
	}
	unauthorized := sniClient(t, port, "goouzi.top", testutil.UUID2, false)
	if conn, err := openSNI(unauthorized); err == nil {
		defer conn.Close()
		if markerPing(conn, "B:") == nil {
			t.Fatal("SNI bypassed independent user authorization")
		}
	}
	entries, err := FetchOnlineConnections(context.Background(), clash)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, entry := range entries {
		if entry.Metadata.User == "1" && entry.Metadata.SourceIP == "127.0.0.2" {
			seen++
		}
	}
	if seen < 2 {
		t.Fatalf("source address or authenticated user lost: %d", seen)
	}
	stats := service.FromContext[adapter.V2RayServer](e.ctx).StatsService().(*v2rayapi.StatsService)
	counters, err := stats.QueryStats(e.ctx, &v2rayapi.QueryStatsRequest{Patterns: []string{"user>>>1>>>traffic>>>"}})
	if err != nil {
		t.Fatal(err)
	}
	var transferred int64
	for _, counter := range counters.Stat {
		transferred += counter.Value
	}
	if transferred < 20 {
		t.Fatalf("shared listener did not account for both authenticated streams: %d", transferred)
	}
	users, err := state.FromConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	delete(users["route-0"].Users, "1")
	if err = e.ApplyUsers(users); err != nil {
		t.Fatal(err)
	}
	if markerPing(ca, "A:") == nil {
		t.Fatal("revoked active stream survived")
	}
	if err = markerPing(cb, "B:"); err != nil {
		t.Fatalf("other SNI disconnected: %v", err)
	}
	if e.box != instance {
		t.Fatal("user update restarted shared listener")
	}
	// Multiple streams on the same AnyTLS session retain the chosen route.
	cb2, err := openSNI(b)
	if err != nil {
		t.Fatal(err)
	}
	defer cb2.Close()
	if err = markerPing(cb2, "B:"); err != nil {
		t.Fatal(err)
	}
	users["route-0"].Users["1"] = state.User{ID: "1", Credential: testutil.UUID1}
	if err = e.ApplyUsers(users); err != nil {
		t.Fatal(err)
	}
	fresh := sniClient(t, port, "wyx.cloud", testutil.UUID1, false)
	restored, err := openSNI(fresh)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if err = markerPing(restored, "A:"); err != nil {
		t.Fatal(err)
	}
	// Shutdown also closes clients that have sent no ClientHello yet.
	pending, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer pending.Close()
	_ = pending.SetDeadline(time.Now().Add(time.Second))
	e.Shutdown()
	one := make([]byte, 1)
	if _, err = pending.Read(one); err == nil {
		t.Fatal("pending TLS connection survived shutdown")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("pending TLS connection was left open until the deadline")
	}
	if err = e.ApplyConfig(cfg); err != nil {
		t.Fatalf("shared port not released: %v", err)
	}
}

func TestAnyTLSSharedListenerRejectsInvalidGroups(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		mutate     func(map[string]any)
	}{
		{"duplicate", "duplicate server name", func(i map[string]any) { i["tls"].(map[string]any)["server_name"] = "WYX.CLOUD." }},
		{"missing-sni", "requires a DNS", func(i map[string]any) { delete(i["tls"].(map[string]any), "server_name") }},
		{"wildcard", "invalid shared AnyTLS", func(i map[string]any) { i["tls"].(map[string]any)["server_name"] = "*.example.com" }},
		{"listen-options", "inconsistent listen options", func(i map[string]any) { i["tcp_fast_open"] = true }},
		{"zero-port", "nonzero port", func(i map[string]any) { i["listen_port"] = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := sharedConfig(t, testutil.Port(t))
			tc.mutate(cfg["inbounds"].([]any)[1].(map[string]any))
			e := NewEngine(Options{})
			defer e.Shutdown()
			err := e.ApplyConfig(cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q, got %v", tc.want, err)
			}
		})
	}
}
