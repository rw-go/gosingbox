// Package server provides the panel-facing HTTPS server with mutual TLS and
// JWT authentication, mirroring the official node's HTTPS REST + JWT surface.
package server

import (
	"compress/gzip"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/klauspost/compress/zstd"

	"github.com/rwnode/rwnode-gosingbox/internal/payload"
)

const maxRequestBodyBytes int64 = 64 << 20

// ServerFactory wraps a net/http.ServeMux and panel payload, adding mTLS +
// JWT middleware automatically.
type ServerFactory struct {
	Mux               *http.ServeMux
	Payload           *payload.Payload
	Logger            *slog.Logger
	InternalRESTToken string
	InternalOnly      bool
	// VerifySNI enables private-SNI checks on the mTLS handshake (the client
	// SNI must match the value derived from the SECRET_KEY material).
	VerifySNI bool
}

// ListenAndServe builds the full mTLS + JWT handler and starts listening.
// If Payload is nil, the server runs without HTTPS (plain HTTP, not recommended).
func (f *ServerFactory) ListenAndServe(addr string) error {
	return f.serve(f.Mux, addr, func(server *http.Server) error {
		if f.Payload != nil {
			cert, err := tls.X509KeyPair([]byte(f.Payload.NodeCertPEM), []byte(f.Payload.NodeKeyPEM))
			if err != nil {
				return err
			}
			caPool := x509.NewCertPool()
			if !caPool.AppendCertsFromPEM([]byte(f.Payload.CACertPEM)) {
				return errMsg("failed to parse CA cert")
			}
			tlsCfg := &tls.Config{
				Certificates: []tls.Certificate{cert},
				ClientCAs:    caPool,
				ClientAuth:   tls.RequireAndVerifyClientCert,
				MinVersion:   tls.VersionTLS13,
			}
			if f.VerifySNI {
				expected, err := payload.DeriveSNI(f.Payload.CACertPEM, f.Payload.JWTPublicKeyPEM)
				if err != nil {
					return err
				}
				tlsCfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
					// A client that sends no SNI is still subject to mTLS,
					// matching the official SNICallback semantics.
					if hello.ServerName == "" {
						return nil, nil
					}
					if subtle.ConstantTimeCompare([]byte(hello.ServerName), []byte(expected)) != 1 {
						return nil, fmt.Errorf("unknown sni")
					}
					return nil, nil
				}
			}
			server.TLSConfig = tlsCfg
			return server.ListenAndServeTLS("", "")
		}
		return server.ListenAndServe()
	})
}

// ListenAndServeUnix serves internal endpoints on an abstract Unix socket.
// The token is passed as ?token=..., matching the official Node internal API.
func (f *ServerFactory) ListenAndServeUnix(path string) error {
	listener, err := net.Listen("unix", "\x00"+strings.TrimPrefix(path, "@"))
	if err != nil {
		return err
	}
	return f.serve(f.Mux, "unix:"+path, func(server *http.Server) error { return server.Serve(listener) })
}

func (f *ServerFactory) serve(mux *http.ServeMux, addr string, start func(*http.Server) error) error {
	var next http.Handler = mux
	if f.Logger != nil {
		next = f.logWrap(mux)
	}
	next = f.limitBody(next)
	next = f.decompress(next)
	handler := next
	if f.InternalOnly {
		handler = f.internalTokenWrap(next)
	} else {
		handler = f.jwtWrap(next)
	}

	server := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		// WriteTimeout must exceed the geocheck timeout (45s) so a long
		// geo report is not cut off mid-stream.
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	return start(server)
}

// logWrap logs every request at debug level (method, path, remote).
func (f *ServerFactory) logWrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.Logger.Debug("http request", "method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr)
		next.ServeHTTP(w, r)
	})
}

// decompress transparently decodes compressed request bodies based on the
// Content-Encoding header. The Remnawave panel sends bodies zstd-compressed
// (Node.js side uses body-parser-with-zstd), and without this the JSON decode
// sees raw zstd bytes (first byte 0x28 = '(').
func (f *ServerFactory) decompress(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Bound the compressed input before handing it to a decompressor, then
		// bound the expanded body below to prevent compression bombs.
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		enc := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding")))
		if enc == "" || enc == "identity" {
			next.ServeHTTP(w, r)
			return
		}

		var reader io.ReadCloser
		var err error
		switch enc {
		case "zstd":
			zr, e := zstd.NewReader(r.Body)
			if e == nil {
				reader = zr.IOReadCloser()
			} else {
				err = e
			}
		case "gzip":
			reader, err = gzip.NewReader(r.Body)
		default:
			// deflate/br etc.: unsupported; pass through (let handler fail loudly
			// rather than silently pretending identity).
			next.ServeHTTP(w, r)
			return
		}
		if err != nil {
			writeJSON(w, http.StatusUnsupportedMediaType, map[string]any{"error": "unsupported content-encoding: " + enc})
			return
		}
		r.Body = reader
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		next.ServeHTTP(w, r)
		_ = reader.Close()
	})
}

func (f *ServerFactory) limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		next.ServeHTTP(w, r)
	})
}

func (f *ServerFactory) jwtWrap(next http.Handler) http.Handler {
	if f.Payload == nil || f.Payload.JWTPublicKey == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "jwt public key not available"})
		})
	}

	keyFunc := func(t *jwt.Token) (any, error) { return f.Payload.JWTPublicKey, nil }

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := bearerToken(r)
		if tok == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "missing bearer token"})
			return
		}
		claims := jwt.MapClaims{}
		// Restrict to RS256: the panel signs node tokens with its RSA private
		// key. Without this whitelist the parser would also accept RS384/RS512
		// (and, if keyFunc ever changed to bytes, would open up alg-confusion).
		if _, err := jwt.ParseWithClaims(tok, claims, keyFunc, jwt.WithValidMethods([]string{"RS256"})); err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid jwt"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (f *ServerFactory) internalTokenWrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f.InternalRESTToken == "" || r.URL.Query().Get("token") != f.InternalRESTToken {
			if hijacker, ok := w.(http.Hijacker); ok {
				if conn, _, err := hijacker.Hijack(); err == nil {
					_ = conn.Close()
					return
				}
			}
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid internal token"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		return h[7:]
	}
	return ""
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

type errMsg string

func (e errMsg) Error() string { return string(e) }
