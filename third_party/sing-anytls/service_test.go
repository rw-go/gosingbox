package anytls

import (
	"context"
	"crypto/sha256"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anytls/sing-anytls/padding"
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
