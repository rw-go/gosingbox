//go:build with_v2ray_api && with_clash_api

package controller

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rwnode/rwnode-gosingbox/internal/state"
	"github.com/rwnode/rwnode-gosingbox/internal/testutil"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	M "github.com/sagernet/sing/common/metadata"
)

func fixedSSPing(port int, password, destination string) error {
	method, err := shadowaead_2022.NewWithPassword("2022-blake3-aes-256-gcm", password, nil)
	if err != nil {
		return err
	}
	raw, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		return err
	}
	defer raw.Close()
	conn, err := method.DialConn(raw, M.ParseSocksaddr(destination))
	if err != nil {
		return err
	}
	defer conn.Close()
	return testutil.Ping(conn)
}

func fixedSSPacketPing(port int, password string, destination net.Addr) error {
	method, err := shadowaead_2022.NewWithPassword("2022-blake3-aes-256-gcm", password, nil)
	if err != nil {
		return err
	}
	raw, err := net.DialTimeout("udp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		return err
	}
	defer raw.Close()
	conn := method.DialPacketConn(raw)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = conn.WriteTo([]byte("ping"), destination); err != nil {
		return err
	}
	data := make([]byte, 64)
	n, _, err := conn.ReadFrom(data)
	if err != nil {
		return err
	}
	if string(data[:n]) != "ping" {
		return fmt.Errorf("bad UDP echo")
	}
	return nil
}

func TestNativeFixedSSRelaysSurviveUserRevocationAndRestart(t *testing.T) {
	h := newNativeHarness(t)
	direct, relay, peer, managed := testutil.Port(t), testutil.Port(t), testutil.Port(t), testutil.Port(t)
	key := func(value byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32)) }
	fixed := func(tag string, port int, password string) map[string]any {
		return map[string]any{"type": "shadowsocks", "tag": tag, "listen": "127.0.0.1", "listen_port": port, "method": "2022-blake3-aes-256-gcm", "password": password}
	}
	h.config["inbounds"] = append(h.config["inbounds"].([]any), fixed("ss-direct", direct, key(1)), fixed("ss-relay", relay, key(2)), fixed("ss-peer", peer, key(3)))
	closed := fixed("ss-managed", managed, key(4))
	closed["users"] = []any{}
	h.config["inbounds"] = append(h.config["inbounds"].([]any), closed)
	h.config["outbounds"] = append(h.config["outbounds"].([]any), map[string]any{"type": "shadowsocks", "tag": "to-peer", "server": "127.0.0.1", "server_port": peer, "method": "2022-blake3-aes-256-gcm", "password": key(3)})
	h.config["route"].(map[string]any)["rules"] = []any{map[string]any{"inbound": []any{"ss-relay"}, "action": "route", "outbound": "to-peer"}}
	h.start(h.config, "singbox", false, "")
	echo := testutil.Echo(t)
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udp.Close() })
	go func() {
		data := make([]byte, 2048)
		for {
			n, addr, e := udp.ReadFrom(data)
			if e != nil {
				return
			}
			_, _ = udp.WriteTo(data[:n], addr)
		}
	}()
	checkFixed := func() {
		t.Helper()
		for _, entry := range []struct {
			port     int
			password string
		}{{direct, key(1)}, {relay, key(2)}} {
			if e := fixedSSPing(entry.port, entry.password, echo); e != nil {
				t.Fatal("fixed TCP relay", e)
			}
			if e := fixedSSPacketPing(entry.port, entry.password, udp.LocalAddr()); e != nil {
				t.Fatal("fixed UDP relay", e)
			}
		}
	}
	checkFixed()
	if fixedSSPing(direct, key(9), echo) == nil {
		t.Fatal("wrong fixed PSK was accepted")
	}
	if fixedSSPing(managed, key(4), echo) == nil {
		t.Fatal("empty managed server accepted its master password")
	}
	counters, err := h.app.QueryUserCounters(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range counters {
		if c.Value != 0 {
			t.Fatal("fixed relay traffic charged to a panel user")
		}
	}
	if err = h.app.UpdateUsers([]state.Update{{ID: "1", Memberships: []state.Membership{
		{Tag: "any", Protocol: "anytls", User: state.User{ID: "1", Credential: testutil.UUID1}},
		{Tag: "ss-managed", Protocol: "shadowsocks22", User: state.User{ID: "1", Credential: key(5)}},
	}}}); err != nil {
		t.Fatal(err)
	}
	if err = fixedSSPing(managed, key(4)+":"+key(5), echo); err != nil {
		t.Fatal("managed user authentication", err)
	}
	if err = h.app.UpdateUsers([]state.Update{{ID: "1"}, {ID: "2"}}); err != nil {
		t.Fatal(err)
	}
	checkFixed()
	if fixedSSPing(managed, key(4), echo) == nil {
		t.Fatal("revoking users enabled fixed-password fallback")
	}
	counts, err := h.app.Query(context.Background(), []string{"inbound>>>ss-relay>>>", "inbound>>>ss-peer>>>"}, false)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, c := range counts {
		if c.Value > 0 {
			for _, tag := range []string{"ss-relay", "ss-peer"} {
				if strings.HasPrefix(c.Name, "inbound>>>"+tag+">>>") {
					seen[tag] = true
				}
			}
		}
	}
	if len(seen) != 2 {
		t.Fatal("relay route or node traffic counters missing")
	}
	view := h.call("GET", "/internal/get-config", nil)
	var current map[string]any
	if err = json.Unmarshal(view.Body.Bytes(), &current); err != nil {
		t.Fatal(err)
	}
	for _, v := range current["inbounds"].([]any) {
		ib := v.(map[string]any)
		if strings.HasPrefix(ib["tag"].(string), "ss-") && ib["tag"] != "ss-managed" {
			if _, present := ib["users"]; present {
				t.Fatal("user mutation changed fixed relay mode")
			}
		}
	}
	h.start(current, "singbox", true, "")
	checkFixed()
	if fixedSSPing(managed, key(4), echo) == nil {
		t.Fatal("restart enabled master-password fallback")
	}
}
