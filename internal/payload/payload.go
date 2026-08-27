// Package payload parses the panel-issued SECRET_KEY payload (node certs +
// JWT public key) required for mTLS and JWT verification.
package payload

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
)

// Payload holds the decoded node identity material from SECRET_KEY.
type Payload struct {
	NodeKeyPEM   string // PEM RSA private key
	NodeCertPEM  string // PEM node certificate
	CACertPEM    string // PEM CA certificate
	JWTPublicKey *rsa.PublicKey
	RawJSON      map[string]any
}

// Parse decodes the SECRET_KEY JSON payload and extracts the crypto material.
// Expected envelope mirrors the official node (decode-node-payload util).
func Parse(secretKey string) (*Payload, error) {
	raw := []byte(secretKey)

	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		// Older panels wrap in a base64 string field; try our known shapes.
		return parseLegacy(secretKey)
	}
	return parseObject(obj)
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

	nodeKey := get("node_key", "nodeKey", "key")
	nodeCert := get("node_cert", "nodeCert", "cert")
	caCert := get("ca_cert", "caCert", "ca")
	jwtPub := get("jwt_public_key", "jwtPublicKey", "public_key")

	if nodeKey == "" || nodeCert == "" || caCert == "" {
		return nil, fmt.Errorf("SECRET_KEY payload missing node_key/node_cert/ca_cert")
	}

	p.NodeKeyPEM = nodeKey
	p.NodeCertPEM = nodeCert
	p.CACertPEM = caCert

	if jwtPub != "" {
		key, err := parseRSAPublicKeyPEM([]byte(jwtPub))
		if err != nil {
			return nil, fmt.Errorf("parse jwt public key: %w", err)
		}
		p.JWTPublicKey = key
	}
	return p, nil
}

// parseLegacy handles the "secretKey" (single string) or base64-wrapped shapes
// used by some panels. If decodable as JSON with cert fields, reuse parseObject.
func parseLegacy(secretKey string) (*Payload, error) {
	// Try base64 decode then JSON parse.
	if raw, err := base64.StdEncoding.DecodeString(secretKey); err == nil {
		var obj map[string]any
		if json.Unmarshal(raw, &obj) == nil {
			return parseObject(obj)
		}
	}
	return nil, fmt.Errorf("unable to parse SECRET_KEY payload")
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
