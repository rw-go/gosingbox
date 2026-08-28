package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
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
