//go:build with_v2ray_api && with_clash_api

package app

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rwnode/rwnode-gosingbox/internal/singbox"
	"github.com/rwnode/rwnode-gosingbox/internal/state"
	"github.com/rwnode/rwnode-gosingbox/internal/testutil"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	M "github.com/sagernet/sing/common/metadata"
)

func TestXrayInputPerInboundHotUpdateAndEmptySSRecovery(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	stats := fmt.Sprintf("127.0.0.1:%d", testutil.Port(t))
	clash := fmt.Sprintf("127.0.0.1:%d", testutil.Port(t))
	engine := singbox.NewEngine(singbox.Options{StatsAddr: stats, ClashAddr: clash, Logger: logger})
	st := state.New()
	a := New(logger, engine, st, 5000, false)
	defer a.Stop()
	p1, p2 := testutil.Port(t), testutil.Port(t)
	key := base64.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012"))
	user1 := base64.StdEncoding.EncodeToString([]byte("abcdefghijklmnopqrstuvwxyz123456"))
	user2 := base64.StdEncoding.EncodeToString([]byte("123456abcdefghijklmnopqrstuvwxyz"))
	panel := map[string]any{"inbounds": []any{}}
	inbound := func(tag string, port int, name, password string) map[string]any {
		return map[string]any{"protocol": "shadowsocks", "tag": tag, "listen": "127.0.0.1", "port": port, "settings": map[string]any{"method": "2022-blake3-aes-256-gcm", "password": key, "clients": []any{map[string]any{"email": name, "password": password}}}}
	}
	panel["inbounds"] = []any{inbound("a", p1, "1", user1), inbound("b", p2, "2", user2)}
	raw, err := json.Marshal(panel)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.StartWithForce(raw, false); err != nil {
		t.Fatal(err)
	}
	snapshot, _ := st.Snapshot()
	if len(snapshot["a"].Users) != 1 || snapshot["a"].Users["1"].Credential != user1 || snapshot["b"].Users["2"].Credential != user2 {
		t.Fatal("initial users leaked between inbounds")
	}
	dest := testutil.Echo(t)
	open := func(port int, credential string) (net.Conn, error) {
		r, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		if err != nil {
			return nil, err
		}
		client, err := shadowaead_2022.NewWithPassword("2022-blake3-aes-256-gcm", key+":"+credential, nil)
		if err != nil {
			r.Close()
			return nil, err
		}
		_ = r.SetDeadline(time.Now().Add(300 * time.Millisecond))
		conn, err := client.DialConn(r, M.ParseSocksaddr(dest))
		if err != nil {
			r.Close()
		}
		return conn, err
	}
	active, err := open(p2, user2)
	if err != nil {
		t.Fatal(err)
	}
	defer active.Close()
	if err = testutil.Ping(active); err != nil {
		t.Fatal(err)
	}
	if err = a.UpdateUsers([]state.Update{{ID: "1"}}); err != nil {
		t.Fatal(err)
	}
	// Only authorization was changed: another user's existing stream remains.
	if err = testutil.Ping(active); err != nil {
		t.Fatal("unaffected SS stream interrupted")
	}
	// An identical saved full push must restore its users even after incremental removal.
	if err = a.StartWithForce(raw, false); err != nil {
		t.Fatal(err)
	}
	snapshot, _ = st.Snapshot()
	if len(snapshot["a"].Users) != 1 {
		t.Fatal("identical full push ignored current user differences")
	}
	if err = testutil.Ping(active); err != nil {
		t.Fatal("full user-only push restarted listeners")
	}
	// Concurrent retries are serialized; unrelated users remain present.
	var wg sync.WaitGroup
	errors := make(chan error, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errors <- a.UpdateUsers([]state.Update{{ID: "1", Memberships: []state.Membership{{Tag: "a", Protocol: "shadowsocks22", User: state.User{ID: "1", Credential: user1}}}}})
		}()
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	if err = a.UpdateUsers([]state.Update{{ID: "1"}}); err != nil {
		t.Fatal(err)
	}
	// Force a subsequent engine config failure to exercise rollback with zero SS users.
	invalid := map[string]any{"inbounds": []any{map[string]any{"type": "anytls", "tag": "bad", "listen": "127.0.0.1", "listen_port": 0}}}
	if err = engine.ApplyConfig(invalid); err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("expected actual instance rollback: %v", err)
	}
	if !engine.IsRunning() {
		t.Fatal("failed apply did not restore previous core")
	}
	snapshot, _ = st.Snapshot()
	if len(snapshot["a"].Users) != 0 || len(snapshot["b"].Users) != 1 {
		t.Fatal("empty managed SS state lost")
	}
	rawConn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", p1), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = rawConn.SetDeadline(time.Now().Add(time.Second))
	single, err := shadowaead_2022.NewWithPassword("2022-blake3-aes-256-gcm", key, nil)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := single.DialConn(rawConn, M.ParseSocksaddr(dest))
	if err == nil {
		err = testutil.Ping(shared)
	}
	_ = rawConn.Close()
	if err == nil {
		t.Fatal("empty managed SS became a shared-password server after rollback")
	}
	// Rebuild with an empty managed list via the public full configuration path.
	panel["inbounds"].([]any)[0].(map[string]any)["settings"].(map[string]any)["clients"] = []any{}
	emptyConfig, _ := json.Marshal(panel)
	if err = a.StartWithForce(emptyConfig, true); err != nil {
		t.Fatal(err)
	}
	if err = a.UpdateUsers([]state.Update{{ID: "1", Memberships: []state.Membership{{Tag: "a", Protocol: "shadowsocks22", User: state.User{ID: "1", Credential: user1}}}}}); err != nil {
		t.Fatal("empty SS inbound not updatable", err)
	}
	restored, err := open(p1, user1)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if err = testutil.Ping(restored); err != nil {
		t.Fatal(err)
	}
}
