// Package testutil provides isolated loopback protocol fixtures for integration tests.
package testutil

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	anytls "github.com/anytls/sing-anytls"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

const UUID1 = "11111111-1111-4111-8111-111111111111"
const UUID2 = "22222222-2222-4222-8222-222222222222"
const UUID3 = "33333333-3333-4333-8333-333333333333"

func Port(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return p
}
func TLS(t *testing.T) map[string]any {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"enabled": true, "certificate": []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}, "key": []string{string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))}}
}
func Echo(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return l.Addr().String()
}

type Client struct {
	Core  *anytls.Client
	Dials atomic.Int32
}

func NewClient(t *testing.T, port int, password string) *Client {
	t.Helper()
	result := &Client{}
	core, err := anytls.NewClient(context.Background(), anytls.ClientConfig{
		Password: password, Logger: logger.NOP(), IdleSessionCheckInterval: time.Hour, IdleSessionTimeout: time.Hour, MinIdleSession: 1,
		DialOut: func(ctx context.Context) (net.Conn, error) {
			result.Dials.Add(1)
			d := tls.Dialer{NetDialer: &net.Dialer{Timeout: time.Second}, Config: &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"}}
			return d.DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", port))
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	result.Core = core
	t.Cleanup(func() { _ = core.Close() })
	return result
}
func (c *Client) Open(destination string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := c.Core.CreateProxy(ctx, M.ParseSocksaddr(destination))
	if err == nil {
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	}
	return conn, err
}
func Ping(conn net.Conn) error {
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		return err
	}
	b := make([]byte, 4)
	if _, err := io.ReadFull(conn, b); err != nil {
		return err
	}
	if string(b) != "ping" {
		return fmt.Errorf("bad echo")
	}
	return nil
}
func (c *Client) RoundTrip(destination string) error {
	conn, err := c.Open(destination)
	if err != nil {
		return err
	}
	defer conn.Close()
	return Ping(conn)
}
