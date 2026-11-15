package server

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/klauspost/compress/zstd"
	"github.com/rwnode/rwnode-gosingbox/internal/controller"
	"github.com/rwnode/rwnode-gosingbox/internal/payload"
)

func TestDecompressZstd(t *testing.T) {
	payload := `{"internals":{},"xrayConfig":{"inbounds":[{"protocol":"vless"}]}}`

	var buf bytes.Buffer
	zw, _ := zstd.NewWriter(&buf)
	_, _ = zw.Write([]byte(payload))
	_ = zw.Close()

	var got []byte
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = b
	})
	f := &ServerFactory{Logger: nil}
	wrapped := f.decompress(handler)

	req := httptest.NewRequest("POST", "/node/xray/start", bytes.NewReader(buf.Bytes()))
	req.Header.Set("Content-Encoding", "zstd")
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
	if string(got) != payload {
		t.Fatalf("decompressed mismatch:\n got=%s\nwant=%s", got, payload)
	}
	var obj map[string]any
	if err := json.Unmarshal(got, &obj); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if _, ok := obj["xrayConfig"]; !ok {
		t.Fatalf("missing xrayConfig field")
	}
}

func TestCapabilitiesRequirePanelJWT(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &ServerFactory{Payload: &payload.Payload{JWTPublicKey: &key.PublicKey}}
	mux := http.NewServeMux()
	controller.NewXray(nil, nil).Router(mux)
	handler := f.jwtWrap(mux)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"exp": time.Now().Add(time.Minute).Unix()})
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, bearer string
		status       int
	}{
		{"missing", "", http.StatusUnauthorized},
		{"invalid", "Bearer invalid", http.StatusUnauthorized},
		{"authenticated", "Bearer " + signed, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/node/capabilities", nil)
			req.Header.Set("Authorization", tc.bearer)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			if rec.Code == http.StatusOK && !strings.Contains(rec.Body.String(), `"contractVersion":1`) {
				t.Fatal("missing capability response")
			}
		})
	}
}

func TestDecompressIdentity(t *testing.T) {
	var got []byte
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = b
	})
	f := &ServerFactory{}
	wrapped := f.decompress(handler)
	req := httptest.NewRequest("POST", "/x", strings.NewReader("hello"))
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)
	if string(got) != "hello" {
		t.Fatalf("identity passthrough broken: %q", got)
	}
}

func TestInternalAuthorizationRequiresLoopbackOrToken(t *testing.T) {
	f := &ServerFactory{InternalRESTToken: "secret"}
	for name, tc := range map[string]struct {
		query string
		want  int
	}{
		"missing": {query: "", want: http.StatusUnauthorized},
		"wrong":   {query: "wrong", want: http.StatusUnauthorized},
		"valid":   {query: "secret", want: http.StatusOK},
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/internal/get-config?token="+tc.query, nil)
			rec := httptest.NewRecorder()
			f.internalTokenWrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })).ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
		})
	}
}
