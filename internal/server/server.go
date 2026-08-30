// Package server provides the panel-facing HTTPS server with mutual TLS and
// JWT authentication, mirroring the official node's HTTPS REST + JWT surface.
package server

import (
	"compress/gzip"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/klauspost/compress/zstd"

	"github.com/rwsbnode/gosingbox/internal/payload"
)

// ServerFactory wraps a net/http.ServeMux and panel payload, adding mTLS +
// JWT middleware automatically.
type ServerFactory struct {
	Mux     *http.ServeMux
	Payload *payload.Payload
	Logger  *slog.Logger
}

// ListenAndServe builds the full mTLS + JWT handler and starts listening.
// If Payload is nil, the server runs without HTTPS (plain HTTP, not recommended).
func (f *ServerFactory) ListenAndServe(addr string) error {
	var next http.Handler = f.Mux
	if f.Logger != nil {
		next = f.logWrap(f.Mux)
	}
	next = f.decompress(next)
	handler := f.jwtWrap(next)

	server := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	if f.Payload != nil {
		cert, err := tls.X509KeyPair([]byte(f.Payload.NodeCertPEM), []byte(f.Payload.NodeKeyPEM))
		if err != nil {
			return err
		}
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM([]byte(f.Payload.CACertPEM)) {
			return errMsg("failed to parse CA cert")
		}
		server.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientCAs:    caPool,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			MinVersion:   tls.VersionTLS13,
		}
		return server.ListenAndServeTLS("", "")
	}
	return server.ListenAndServe()
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
		next.ServeHTTP(w, r)
		_ = reader.Close()
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
		// Skip JWT for internal endpoints (used by sing-box to fetch config).
		if strings.HasPrefix(r.URL.Path, "/internal/") {
			next.ServeHTTP(w, r)
			return
		}
		tok := bearerToken(r)
		if tok == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "missing bearer token"})
			return
		}
		claims := jwt.MapClaims{}
		if _, err := jwt.ParseWithClaims(tok, claims, keyFunc); err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid jwt"})
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
