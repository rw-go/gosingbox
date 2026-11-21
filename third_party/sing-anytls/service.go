package anytls

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/anytls/sing-anytls/padding"
	"github.com/anytls/sing-anytls/session"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Bound pending authentication across all listeners, including shared SNI groups.
const maxPendingHandshakes = 128
const authenticationTimeout = 10 * time.Second

var (
	streamDestinationTimeout = 10 * time.Second
	maxSessionStreams        = session.MaxStreamsPerSession
)

var handshakeSlots = make(chan struct{}, maxPendingHandshakes)

// BeginHandshake reserves a slot before transport negotiation. The returned
// release function is idempotent across early errors and successful admission.
func BeginHandshake() (func(), error) {
	select {
	case handshakeSlots <- struct{}{}:
		return sync.OnceFunc(func() { <-handshakeSlots }), nil
	default:
		return nil, errors.New("AnyTLS pending handshake limit reached")
	}
}

type Service struct {
	mu              sync.RWMutex
	users           map[[32]byte]*account
	sessions        map[*session.Session]*account
	pending         map[net.Conn]struct{}
	closed          bool
	padding         atomic.TypedValue[*padding.PaddingFactory]
	handler         N.TCPConnectionHandlerEx
	fallbackHandler N.TCPConnectionHandlerEx
	logger          logger.ContextLogger
}

type account struct {
	name string
	hash [32]byte
}

type ServiceConfig struct {
	PaddingScheme   []byte
	Users           []User
	Handler         N.TCPConnectionHandlerEx
	FallbackHandler N.TCPConnectionHandlerEx
	Logger          logger.ContextLogger
}

type User struct {
	Name     string
	Password string
}

func NewService(config ServiceConfig) (*Service, error) {
	service := &Service{
		handler:         config.Handler,
		fallbackHandler: config.FallbackHandler,
		logger:          config.Logger,
		users:           make(map[[32]byte]*account),
		sessions:        make(map[*session.Session]*account),
		pending:         make(map[net.Conn]struct{}),
	}

	if service.handler == nil || service.logger == nil {
		return nil, os.ErrInvalid
	}

	for _, user := range config.Users {
		hash := sha256.Sum256([]byte(user.Password))
		service.users[hash] = &account{name: user.Name, hash: hash}
	}

	if !padding.UpdatePaddingScheme(config.PaddingScheme, &service.padding) {
		return nil, errors.New("incorrect padding scheme format")
	}

	return service, nil
}

// UpdateUsers replaces authentication and synchronously revokes sessions whose
// credential or identity changed. Identical updates preserve existing sessions.
func (s *Service) UpdateUsers(users []User) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	next := make(map[[32]byte]*account, len(users))
	for _, user := range users {
		hash := sha256.Sum256([]byte(user.Password))
		a := s.users[hash]
		if a == nil || a.name != user.Name {
			a = &account{name: user.Name, hash: hash}
		}
		next[hash] = a
	}
	s.users = next
	for sess, a := range s.sessions {
		if next[a.hash] != a {
			_ = sess.Close()
			delete(s.sessions, sess)
		}
	}
}

// Close rejects late handshakes and closes idle, active and unauthenticated connections.
func (s *Service) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for sess := range s.sessions {
		_ = sess.Close()
	}
	for conn := range s.pending {
		_ = conn.Close()
	}
	return nil
}

// NewConnection `conn` should be plaintext
func (s *Service) NewConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose N.CloseHandlerFunc) error {
	release, err := BeginHandshake()
	if err != nil {
		return err
	}
	return s.AuthenticateConnection(ctx, conn, source, onClose, release)
}

// AuthenticateConnection accepts a slot reserved before the transport handshake.
func (s *Service) AuthenticateConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose N.CloseHandlerFunc, release func()) error {
	if release == nil {
		return os.ErrInvalid
	}
	defer release()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return net.ErrClosed
	}
	original := conn
	s.pending[original] = struct{}{}
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.pending, original); s.mu.Unlock() }()
	if err := conn.SetReadDeadline(time.Now().Add(authenticationTimeout)); err != nil {
		return err
	}
	clearAuthDeadline := sync.OnceValue(func() error {
		return original.SetReadDeadline(time.Time{})
	})
	defer func() { _ = clearAuthDeadline() }()

	var header [34]byte
	nHash, err := io.ReadFull(conn, header[:32])
	if err != nil {
		_ = clearAuthDeadline()
		return s.fallbackWithPrefix(ctx, conn, header[:nHash], source, err, onClose)
	}
	var passwordSha256 [32]byte
	copy(passwordSha256[:], header[:32])
	s.mu.RLock()
	account := s.users[passwordSha256]
	s.mu.RUnlock()
	if account == nil {
		_ = clearAuthDeadline()
		return s.fallbackWithPrefix(ctx, conn, header[:32], source, E.New("unknown user password"), onClose)
	}
	ctx = auth.ContextWithUser(ctx, account.name)

	nLen, err := io.ReadFull(conn, header[32:34])
	if err != nil {
		_ = clearAuthDeadline()
		return s.fallbackWithPrefix(ctx, conn, header[:32+nLen], source, E.Extend(err, "read padding length"), onClose)
	}
	paddingLen := int(binary.BigEndian.Uint16(header[32:34]))
	if paddingLen > 0 {
		if s.fallbackHandler == nil {
			if _, err = io.CopyN(io.Discard, conn, int64(paddingLen)); err != nil {
				_ = clearAuthDeadline()
				return s.fallback(ctx, conn, source, E.Extend(err, "read padding"), onClose)
			}
		} else {
			paddingBytes := make([]byte, paddingLen)
			nPad, readErr := io.ReadFull(conn, paddingBytes)
			if readErr != nil {
				_ = clearAuthDeadline()
				prefix := make([]byte, 34+nPad)
				copy(prefix, header[:])
				copy(prefix[34:], paddingBytes[:nPad])
				return s.fallbackWithPrefix(ctx, conn, prefix, source, E.Extend(readErr, "read padding"), onClose)
			}
		}
	}
	if err := clearAuthDeadline(); err != nil {
		return err
	}

	session := session.NewServerSession(conn, func(stream *session.Stream) {
		if err := stream.SetReadDeadline(time.Now().Add(streamDestinationTimeout)); err != nil {
			_ = stream.HandshakeFailure(err)
			_ = stream.Close()
			return
		}
		destination, err := M.SocksaddrSerializer.ReadAddrPort(stream)
		if err == nil {
			err = stream.SetReadDeadline(time.Time{})
		}
		if err != nil {
			s.logger.ErrorContext(ctx, "ReadAddrPort:", err)
			_ = stream.HandshakeFailure(err)
			_ = stream.Close()
			return
		}

		s.mu.RLock()
		valid := !s.closed && s.users[passwordSha256] == account
		s.mu.RUnlock()
		if !valid {
			_ = stream.HandshakeFailure(E.New("unauthorized stream"))
			_ = stream.Close()
			return
		}
		s.handler.NewConnectionEx(ctx, stream, source, destination, onClose)
	}, &s.padding, s.logger)
	session.SetMaxStreams(maxSessionStreams)
	// Recheck the immutable account generation after parsing. A removal/re-add
	// between authentication and registration cannot resurrect the old session.
	if !s.registerSession(session, account, original) {
		_ = session.Close()
		return E.New("user revoked during handshake")
	}

	release()
	defer func() { s.mu.Lock(); delete(s.sessions, session); s.mu.Unlock() }()
	session.Run()
	session.Close()
	return nil
}

func (s *Service) fallbackWithPrefix(ctx context.Context, conn net.Conn, prefix []byte, source M.Socksaddr, err error, onClose N.CloseHandlerFunc) error {
	if s.fallbackHandler == nil {
		return E.Extend(err, "fallback disabled")
	}
	if len(prefix) > 0 {
		conn = bufio.NewCachedConn(conn, buf.As(prefix))
	}
	s.fallbackHandler.NewConnectionEx(ctx, conn, source, M.Socksaddr{}, onClose)
	return nil
}

func (s *Service) fallback(ctx context.Context, conn net.Conn, source M.Socksaddr, err error, onClose N.CloseHandlerFunc) error {
	if s.fallbackHandler == nil {
		return E.Extend(err, "fallback disabled")
	}
	s.fallbackHandler.NewConnectionEx(ctx, conn, source, M.Socksaddr{}, onClose)
	return nil
}

func (s *Service) registerSession(sess *session.Session, a *account, conn net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.users[a.hash] != a {
		return false
	}
	delete(s.pending, conn)
	s.sessions[sess] = a
	return true
}
