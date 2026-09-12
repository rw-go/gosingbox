// Package payload parses the panel-issued SECRET_KEY payload (node identity
// material: CA cert, node cert, node private key, JWT public key) required for
// mTLS and JWT verification.
//
// The official node (decode-node-payload util) expects SECRET_KEY to be a
// base64-encoded JSON object with camelCase fields:
//
//	{
//	  "caCertPem":    "-----BEGIN CERTIFICATE-----\n...",
//	  "jwtPublicKey": "-----BEGIN PUBLIC KEY-----\n...",
//	  "nodeCertPem":  "-----BEGIN CERTIFICATE-----\n...",
//	  "nodeKeyPem":   "-----BEGIN PRIVATE KEY-----\n..."
//	}
//
// where PEM bodies contain literal `\n` escape sequences that must be turned
// back into real newlines. Plain-JSON (non-base64) payloads and the legacy
// snake_case field names are also tolerated for backwards compatibility.
package payload

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
)

// Payload holds the decoded node identity material from SECRET_KEY.
type Payload struct {
	NodeKeyPEM   string // PEM RSA private key (node key)
	NodeCertPEM  string // PEM node certificate
	CACertPEM    string // PEM CA certificate
	JWTPublicKey *rsa.PublicKey
	// JWTPublicKeyPEM is the normalized PEM of the JWT public key. It is kept
	// alongside the parsed key so the private TLS SNI can be derived (>= 3.3.0).
	JWTPublicKeyPEM string
	RawJSON         map[string]any
}

// Parse decodes SECRET_KEY into node identity material.
//
//  1. Trims surrounding whitespace and quotes (single, double, or backticks).
//  2. Strips internal whitespace/newlines so multiline YAML/env values decode cleanly.
//  3. Tries base64-decode (StdEncoding, RawStdEncoding, URLEncoding, RawURLEncoding)
//     then JSON-parse (official panel format).
//  4. Falls back to plain JSON (already-decoded payload).
func Parse(secretKey string) (*Payload, error) {
	trimmed := strings.TrimSpace(secretKey)

	// Strip surrounding quotes if present (e.g. SECRET_KEY="..." or '...')
	if len(trimmed) >= 2 {
		if (trimmed[0] == '"' && trimmed[len(trimmed)-1] == '"') ||
			(trimmed[0] == '\'' && trimmed[len(trimmed)-1] == '\'') ||
			(trimmed[0] == '`' && trimmed[len(trimmed)-1] == '`') {
			trimmed = strings.TrimSpace(trimmed[1 : len(trimmed)-1])
		}
	}

	// Try decoding base64 after stripping whitespace/newlines (matching Node.js Buffer.from(x, 'base64'))
	cleaned := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, trimmed)

	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}

	for _, enc := range encodings {
		if raw, err := enc.DecodeString(cleaned); err == nil {
			var obj map[string]any
			if json.Unmarshal(raw, &obj) == nil && len(obj) > 0 {
				return parseObject(obj)
			}
		}
	}

	// Fallback: plain JSON.
	var obj map[string]any
	if json.Unmarshal([]byte(trimmed), &obj) == nil && len(obj) > 0 {
		return parseObject(obj)
	}

	return nil, fmt.Errorf("unable to parse SECRET_KEY payload (expected base64-encoded JSON)")
}

func parseObject(obj map[string]any) (*Payload, error) {
	p := &Payload{RawJSON: obj}

	get := func(keys ...string) string {
		for _, k := range keys {
			if s, ok := obj[k].(string); ok && s != "" {
				return s
			}
		}
		return ""
	}

	nodeKey := get("nodeKeyPem", "node_key", "nodeKey", "key")
	nodeCert := get("nodeCertPem", "node_cert", "nodeCert", "cert")
	caCert := get("caCertPem", "ca_cert", "caCert", "ca")
	jwtPub := get("jwtPublicKey", "jwt_public_key", "jwtPublicKey")

	if nodeKey == "" || nodeCert == "" || caCert == "" {
		return nil, fmt.Errorf("SECRET_KEY payload missing nodeKeyPem/nodeCertPem/caCertPem")
	}

	p.NodeKeyPEM = normalizePem(nodeKey)
	p.NodeCertPEM = normalizePem(nodeCert)
	p.CACertPEM = normalizePem(caCert)

	if jwtPub != "" {
		p.JWTPublicKeyPEM = normalizePem(jwtPub)
		key, err := parseRSAPublicKeyPEM([]byte(p.JWTPublicKeyPEM))
		if err != nil {
			return nil, fmt.Errorf("parse jwt public key: %w", err)
		}
		p.JWTPublicKey = key
	}
	return p, nil
}

// normalizePem turns literal `\n` escape sequences into real newlines and
// normalizes the PEM header/footer line breaks (mirrors the Node.js
// decode-node-payload normalizePem).
func normalizePem(pemStr string) string {
	s := strings.ReplaceAll(pemStr, `\n`, "\n")
	s = strings.ReplaceAll(s, "\r\n", "\n")

	var out []string
	for _, line := range strings.Split(s, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "-----BEGIN ") {
			out = append(out, trimmed)
			continue
		}
		if strings.HasPrefix(trimmed, "-----END ") {
			out = append(out, trimmed)
			continue
		}
		out = append(out, trimmed)
	}
	return strings.Join(out, "\n")
}

func parseRSAPublicKeyPEM(block []byte) (*rsa.PublicKey, error) {
	der, _ := pem.Decode(block)
	if der == nil {
		return nil, fmt.Errorf("no PEM block in key")
	}
	var key any
	var err error
	if der.Type == "PUBLIC KEY" {
		key, err = x509.ParsePKIXPublicKey(der.Bytes)
	} else if der.Type == "RSA PUBLIC KEY" {
		key, err = x509.ParsePKCS1PublicKey(der.Bytes)
	} else {
		return nil, fmt.Errorf("unexpected key type %q", der.Type)
	}
	if err != nil {
		return nil, err
	}
	pub, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("JWT key is not RSA")
	}
	return pub, nil
}

// ParseRSAPublicKey is an exported convenience for JWT middleware.
func ParseRSAPublicKey(pemBytes []byte) (*rsa.PublicKey, error) {
	return parseRSAPublicKeyPEM(pemBytes)
}
