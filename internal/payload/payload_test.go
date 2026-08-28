package payload

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

// buildOfficial builds a panel-style SECRET_KEY envelope (camelCase fields).
func buildOfficial() string {
	key := "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----"
	cert := "-----BEGIN CERTIFICATE-----\nMIIDXzCCAkcC\n-----END CERTIFICATE-----"
	fields := map[string]string{
		"caCertPem":   cert,
		"nodeCertPem": cert,
		"nodeKeyPem":  key,
	}
	b, _ := json.Marshal(fields)
	return base64.StdEncoding.EncodeToString(b)
}

func TestParseOfficialBase64(t *testing.T) {
	secret := buildOfficial()
	raw, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"caCertPem", "nodeCertPem", "nodeKeyPem"} {
		if _, ok := obj[k]; !ok {
			t.Fatalf("missing field %s", k)
		}
	}
}

func TestParseBase64Envelope(t *testing.T) {
	p, err := Parse(buildOfficial())
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if p.NodeKeyPEM == "" || p.NodeCertPEM == "" || p.CACertPEM == "" {
		t.Fatal("empty PEM fields")
	}
	if !hasPrefix(p.CACertPEM, "-----BEGIN CERTIFICATE-----") {
		t.Fatalf("caCert not normalized: %q", p.CACertPEM[:30])
	}
}

func hasPrefix(s, p string) bool { return len(s) >= len(p) && s[:len(p)] == p }

// TestNormalizePemLiteralNewlines ensures literal \n escapes become real
// newlines and the header/footer are on their own lines.
func TestNormalizePemLiteralNewlines(t *testing.T) {
	in := `-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END PUBLIC KEY-----`
	got := normalizePem(in)
	want := "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END PUBLIC KEY-----"
	if got != want {
		t.Fatalf("normalizePem mismatch:\n got=%q\nwant=%q", got, want)
	}
}