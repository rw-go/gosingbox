//go:build with_v2ray_api && with_clash_api

package singbox

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/experimental/v2rayapi"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	"github.com/sagernet/sing-vmess/vless"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"

	"github.com/rwnode/rwnode-gosingbox/internal/transpiler"
)

func availablePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

// Exercise the real 1.14 engine, not just a mock: both inbounds must retain
// their listener while users and the live v2ray stats whitelist are updated.
func TestApplyConfigAndHotSwapUsers(t *testing.T) {
	serverKey := base64.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012"))
	userKey := base64.StdEncoding.EncodeToString([]byte("abcdefghijklmnopqrstuvwxyz123456"))
	vlessPort, ssPort := availablePort(t), availablePort(t)
	if vlessPort == ssPort {
		ssPort = availablePort(t)
	}
	destination, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	go func() {
		for {
			conn, err := destination.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				request := make([]byte, 4)
				if _, err := io.ReadFull(conn, request); err == nil {
					_, _ = conn.Write([]byte("pong"))
				}
			}()
		}
	}()
	e := NewEngine(Options{StatsAddr: "127.0.0.1:0", ClashAddr: "127.0.0.1:0"})
	defer e.Shutdown()
	config := map[string]any{
		"log": map[string]any{"level": "error"},
		"inbounds": []any{
			map[string]any{
				"type": "vless", "tag": "vless-in", "listen": "127.0.0.1", "listen_port": vlessPort,
				"users": []any{map[string]any{"name": "first@example.com", "uuid": "55e49069-576e-4fc5-ad35-9d8f651999b9"}},
			},
			map[string]any{
				"type": "shadowsocks", "tag": "ss-in", "listen": "127.0.0.1", "listen_port": ssPort,
				"method": "2022-blake3-aes-256-gcm", "password": serverKey,
				"users": []any{map[string]any{"name": "first-ss@example.com", "password": userKey}},
			},
		},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
		"experimental": map[string]any{
			"v2ray_api": map[string]any{
				"listen": "127.0.0.1:0",
				"stats":  map[string]any{"enabled": true, "users": []string{"first@example.com", "first-ss@example.com"}},
			},
			"clash_api": map[string]any{"external_controller": "127.0.0.1:0"},
		},
	}
	if err := e.ApplyConfig(config); err != nil {
		t.Fatal(err)
	}
	if got, err := e.UpdateVLESSUsers([]string{"vless-in"}, []option.VLESSUser{{
		Name: "second@example.com", UUID: "ad40887c-40f9-4911-8ff7-5254d513fb88",
	}}); err != nil || got != 1 {
		t.Fatalf("VLESS hot swap: got %d, err %v", got, err)
	}
	if got, err := e.UpdateSSUsers([]string{"ss-in"}, []option.ShadowsocksUser{{
		Name: "second-ss@example.com", Password: userKey,
	}}); err != nil || got != 1 {
		t.Fatalf("SS2022 hot swap: got %d, err %v", got, err)
	}
	e.UpdateStatsUsers([]string{"second@example.com", "second-ss@example.com"})
	// Connect through both updated protocols to a loopback echo server. This
	// checks that the new users really authenticate and route without a restart.
	checkProxy := func(port int, wrap func(net.Conn) (net.Conn, error)) {
		t.Helper()
		raw, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)), 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Close()
		_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
		conn, err := wrap(raw)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		response := make([]byte, 4)
		if _, err := io.ReadFull(conn, response); err != nil || string(response) != "pong" {
			t.Fatalf("routed response = %q, err %v", response, err)
		}
	}
	serverDest := M.ParseSocksaddr(destination.Addr().String())
	vlessClient, err := vless.NewClient("ad40887c-40f9-4911-8ff7-5254d513fb88", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	checkProxy(vlessPort, func(conn net.Conn) (net.Conn, error) { return vlessClient.DialConn(conn, serverDest) })
	ssClient, err := shadowaead_2022.NewWithPassword("2022-blake3-aes-256-gcm", serverKey+":"+userKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	checkProxy(ssPort, func(conn net.Conn) (net.Conn, error) { return ssClient.DialConn(conn, serverDest) })
	server := service.FromContext[adapter.V2RayServer](e.ctx)
	if server == nil {
		t.Fatal("v2ray server unavailable after hot swap")
	}
	stats := server.StatsService().(*v2rayapi.StatsService)
	results, err := stats.QueryStats(e.ctx, &v2rayapi.QueryStatsRequest{Patterns: []string{"user>>>"}})
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, entry := range results.Stat {
		if entry.Value >= 4 {
			found[entry.Name] = true
		}
	}
	for _, name := range []string{"second@example.com", "second-ss@example.com"} {
		if !found["user>>>"+name+">>>traffic>>>uplink"] {
			t.Fatalf("new user %s traffic was not counted: %v", name, results.Stat)
		}
	}
	if !e.IsRunning() {
		t.Fatal("engine stopped during user hot swap")
	}
	if service.FromContext[adapter.InboundManager](e.ctx) == nil {
		t.Fatal("inbound manager unavailable after hot swap")
	}
	if e.ctx.Err() != nil {
		t.Fatalf("running context canceled: %v", e.ctx.Err())
	}
}

func TestTranspiledPanelConfigStartsOnV114(t *testing.T) {
	serverKey := base64.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012"))
	userKey := base64.StdEncoding.EncodeToString([]byte("abcdefghijklmnopqrstuvwxyz123456"))
	panel := map[string]any{
		"inbounds": []any{map[string]any{
			"protocol": "shadowsocks", "tag": "ss-in", "listen": "127.0.0.1", "port": 0,
			"settings": map[string]any{
				"method": "2022-blake3-aes-256-gcm", "password": serverKey,
				"clients": []any{map[string]any{"email": "user@example.com", "password": userKey}},
			},
			"sniffing": map[string]any{"enabled": true},
		}},
		"outbounds": []any{
			map[string]any{"protocol": "freedom", "tag": "direct", "settings": map[string]any{"domainStrategy": "UseIPv4v6"}},
			map[string]any{"protocol": "blackhole", "tag": "block"},
		},
		"routing": map[string]any{"rules": []any{map[string]any{"domain": []any{"domain:example.com"}, "outboundTag": "block"}}},
	}
	raw, err := json.Marshal(panel)
	if err != nil {
		t.Fatal(err)
	}
	result, err := transpiler.Transpile(raw, "127.0.0.1:0", "127.0.0.1:0", "error", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(Options{StatsAddr: "127.0.0.1:0", ClashAddr: "127.0.0.1:0"})
	defer e.Shutdown()
	if err := e.ApplyConfig(result.Config); err != nil {
		t.Fatalf("sing-box 1.14 rejected transpiled config: %v", err)
	}
}

func TestTranspiledRealityConfigStartsOnV114(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	panel := map[string]any{
		"inbounds": []any{map[string]any{
			"protocol": "vless", "tag": "vless-in", "listen": "127.0.0.1", "port": availablePort(t),
			"settings": map[string]any{"clients": []any{map[string]any{
				"id": "55e49069-576e-4fc5-ad35-9d8f651999b9", "email": "user@example.com", "flow": "xtls-rprx-vision",
			}}},
			"streamSettings": map[string]any{
				"security": "reality",
				"realitySettings": map[string]any{
					"privateKey":  base64.RawURLEncoding.EncodeToString(key.Bytes()),
					"serverNames": []any{"example.com"}, "dest": "example.com:443", "shortIds": []any{""},
				},
			},
		}},
		"outbounds": []any{map[string]any{"protocol": "freedom", "tag": "direct"}},
	}
	raw, err := json.Marshal(panel)
	if err != nil {
		t.Fatal(err)
	}
	result, err := transpiler.Transpile(raw, "127.0.0.1:0", "127.0.0.1:0", "error", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(Options{StatsAddr: "127.0.0.1:0", ClashAddr: "127.0.0.1:0"})
	defer e.Shutdown()
	if err := e.ApplyConfig(result.Config); err != nil {
		t.Fatalf("sing-box 1.14 rejected VLESS Reality config: %v", err)
	}
}
