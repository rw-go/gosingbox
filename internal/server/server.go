// Package server provides the panel-facing HTTPS server with mutual TLS and
// JWT authentication, mirroring the official node's HTTPS REST + JWT surface.
package server

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"rwnode-singbox/internal/payload"
)

// ServerFactory wraps a net/http.ServeMux and panel payload, adding mTLS +
// JWT middleware automatically.
type ServerFactory struct {
	Mux     *http.ServeMux
	Payload *payload.Payload
}

// ListenAndServe builds the full mTLS + JWT handler and starts listening.
// If Payload is nil, the server runs without HTTPS (plain HTTP, not recommended).
func (f *ServerFactory) ListenAndServe(addr string) error {
	handler := f.jwtWrap(f.Mux)

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
