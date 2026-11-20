//go:build with_v2ray_api && with_clash_api

package singbox

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rwnode/rwnode-gosingbox/internal/state"
	"github.com/rwnode/rwnode-gosingbox/internal/testutil"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/experimental/v2rayapi"
	"github.com/sagernet/sing/service"
)

func TestAnyTLSHotUpdateStatisticsAndOnlineIdentity(t *testing.T) {
	port := testutil.Port(t)
	clash := fmt.Sprintf("127.0.0.1:%d", testutil.Port(t))
	cfg := map[string]any{
		"log":          map[string]any{"disabled": true},
		"inbounds":     []any{map[string]any{"type": "anytls", "tag": "any-in", "listen": "127.0.0.1", "listen_port": port, "tls": testutil.TLS(t), "users": []any{map[string]any{"name": "1", "password": testutil.UUID1}}}},
		"outbounds":    []any{map[string]any{"type": "direct", "tag": "direct"}},
		"experimental": map[string]any{"v2ray_api": map[string]any{"listen": "127.0.0.1:0", "stats": map[string]any{"enabled": true, "users": []string{"1"}}}, "clash_api": map[string]any{"external_controller": clash}},
	}
	e := NewEngine(Options{ClashAddr: clash})
	if err := e.ApplyConfig(cfg); err != nil {
		t.Fatal(err)
	}
	defer e.Shutdown()
	instance := e.box
	users, err := state.FromConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	users["any-in"].Users["2"] = state.User{ID: "2", Credential: testutil.UUID2}
	if err = e.ApplyUsers(users); err != nil {
		t.Fatal(err)
	}
	client := testutil.NewClient(t, port, testutil.UUID2)
	dest := testutil.Echo(t)
	conn, err := client.Open(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err = testutil.Ping(conn); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	seen := false
	for time.Now().Before(deadline) {
		entries, err := FetchOnlineConnections(context.Background(), clash)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.Metadata.User == "2" && entry.Metadata.SourceIP == "127.0.0.1" {
				seen = true
			}
		}
		if seen {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !seen {
		t.Fatal("AnyTLS user/IP metadata missing")
	}
	stats := service.FromContext[adapter.V2RayServer](e.ctx).StatsService().(*v2rayapi.StatsService)
	readCounter := func() int64 {
		t.Helper()
		reply, err := stats.QueryStats(e.ctx, &v2rayapi.QueryStatsRequest{Patterns: []string{"user>>>2>>>traffic>>>uplink"}})
		if err != nil {
			t.Fatal(err)
		}
		var count int64
		for _, item := range reply.Stat {
			count += item.Value
		}
		return count
	}
	if count := readCounter(); count < 4 {
		t.Fatalf("new user missing stats: %d", count)
	}
	delete(users["any-in"].Users, "2")
	if err = e.ApplyUsers(users); err != nil {
		t.Fatal(err)
	}
	if err = testutil.Ping(conn); err == nil {
		t.Fatal("removed active stream survived")
	}
	if count := readCounter(); count < 4 {
		t.Fatal("unreported removed user counters discarded")
	}
	if e.box != instance {
		t.Fatal("listener/core restarted during hot updates")
	}
	// Rollback configuration must preserve deletion, including an empty user list.
	delete(users["any-in"].Users, "1")
	if err = e.ApplyUsers(users); err != nil {
		t.Fatal(err)
	}
	current, err := state.FromConfig(e.currentConfig)
	if err != nil || len(current["any-in"].Users) != 0 {
		t.Fatal("stale rollback credentials")
	}
	if _, _, err = e.parseOptions(e.currentConfig, e.currentFormat); err != nil {
		t.Fatal(err)
	}
}
func TestAnyTLSRejectsMissingTLS(t *testing.T) {
	e := NewEngine(Options{})
	defer e.Shutdown()
	err := e.ApplyConfig(map[string]any{"inbounds": []any{map[string]any{"type": "anytls", "tag": "a", "listen": "127.0.0.1", "listen_port": 0}}, "outbounds": []any{map[string]any{"type": "direct"}}})
	if err == nil || !strings.Contains(err.Error(), "requires TLS") {
		t.Fatalf("plaintext AnyTLS accepted: %v", err)
	}
}

func TestAnyTLSRejectsReality(t *testing.T) {
	e := NewEngine(Options{})
	defer e.Shutdown()
	err := e.ApplyConfig(map[string]any{"inbounds": []any{map[string]any{"type": "anytls", "tag": "a", "listen": "127.0.0.1", "listen_port": 0, "tls": map[string]any{"enabled": true, "reality": map[string]any{"enabled": true}}}}})
	if err == nil || !strings.Contains(err.Error(), "ordinary TLS") {
		t.Fatalf("unvalidated AnyTLS Reality accepted: %v", err)
	}
}
