package session

import (
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/anytls/sing-anytls/pipe"
)

// Stream implements net.Conn
type Stream struct {
	id uint32

	sess *Session

	pipeR         *pipe.PipeReader
	pipeW         *pipe.PipeWriter
	writeDeadline pipe.PipeDeadline

	dieOnce    sync.Once
	hookMu     sync.Mutex
	hookClosed bool
	dieHook    func()
	dieErr     atomic.Pointer[error]

	reportOnce sync.Once
}

// newStream initiates a Stream struct
func newStream(id uint32, sess *Session) *Stream {
	s := new(Stream)
	s.id = id
	s.sess = sess
	s.pipeR, s.pipeW = pipe.Pipe()
	s.writeDeadline = pipe.MakePipeDeadline()
	return s
}

// Read implements net.Conn
func (s *Stream) Read(b []byte) (n int, err error) {
	n, err = s.pipeR.Read(b)
	if closed := s.dieErr.Load(); n == 0 && closed != nil {
		err = *closed
	}
	return
}

// Write implements net.Conn
func (s *Stream) Write(b []byte) (n int, err error) {
	select {
	case <-s.writeDeadline.Wait():
		return 0, os.ErrDeadlineExceeded
	default:
	}
	if closed := s.dieErr.Load(); closed != nil {
		return 0, *closed
	}
	n, err = s.sess.writeDataFrame(s.id, b)
	return
}

// Close implements net.Conn
func (s *Stream) Close() error {
	return s.closeWithError(io.ErrClosedPipe)
}

// closeLocally only closes Stream and don't notify remote peer
func (s *Stream) closeLocally() {
	var once bool
	s.dieOnce.Do(func() {
		err := net.ErrClosed
		s.dieErr.Store(&err)
		s.pipeR.Close()
		once = true
	})
	if once {
		s.runCloseHook()
	}
}

func (s *Stream) closeWithError(err error) error {
	var once bool
	s.dieOnce.Do(func() {
		s.dieErr.Store(&err)
		s.pipeR.Close()
		once = true
	})
	if once {
		s.runCloseHook()
		return s.sess.streamClosed(s.id)
	} else {
		return *s.dieErr.Load()
	}
}

func (s *Stream) SetReadDeadline(t time.Time) error {
	return s.pipeR.SetReadDeadline(t)
}

func (s *Stream) SetWriteDeadline(t time.Time) error {
	s.writeDeadline.Set(t)
	return nil
}

func (s *Stream) SetDeadline(t time.Time) error {
	s.SetWriteDeadline(t)
	return s.SetReadDeadline(t)
}

// LocalAddr satisfies net.Conn interface
func (s *Stream) LocalAddr() net.Addr {
	if ts, ok := s.sess.conn.(interface {
		LocalAddr() net.Addr
	}); ok {
		return ts.LocalAddr()
	}
	return nil
}

// RemoteAddr satisfies net.Conn interface
func (s *Stream) RemoteAddr() net.Addr {
	if ts, ok := s.sess.conn.(interface {
		RemoteAddr() net.Addr
	}); ok {
		return ts.RemoteAddr()
	}
	return nil
}

// HandshakeFailure should be called when Server fail to create outbound proxy
func (s *Stream) HandshakeFailure(err error) error {
	var once bool
	s.reportOnce.Do(func() {
		once = true
	})
	if once && err != nil && s.sess.peerVersion.Load() >= 2 {
		f := newFrame(cmdSYNACK, s.id)
		f.data = []byte(err.Error())
		if _, err := s.sess.writeControlFrame(f); err != nil {
			return err
		}
	}
	return nil
}

// HandshakeSuccess should be called when Server success to create outbound proxy
func (s *Stream) HandshakeSuccess() error {
	var once bool
	s.reportOnce.Do(func() {
		once = true
	})
	if once && s.sess.peerVersion.Load() >= 2 {
		if _, err := s.sess.writeControlFrame(newFrame(cmdSYNACK, s.id)); err != nil {
			return err
		}
	}
	return nil
}

// The client may attach its pool hook while the peer closes the stream.
func (s *Stream) setCloseHook(hook func()) {
	s.hookMu.Lock()
	if s.hookClosed {
		s.hookMu.Unlock()
		hook()
		return
	}
	s.dieHook = hook
	s.hookMu.Unlock()
}
func (s *Stream) runCloseHook() {
	s.hookMu.Lock()
	s.hookClosed = true
	hook := s.dieHook
	s.dieHook = nil
	s.hookMu.Unlock()
	if hook != nil {
		hook()
	}
}
