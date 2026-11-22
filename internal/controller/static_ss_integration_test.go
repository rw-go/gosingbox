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
	direct, relay, peer, emptyUsers, panelManaged := testutil.Port(t), testutil.Port(t), testutil.Port(t), testutil.Port(t), testutil.Port(t)
	key := func(value byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32)) }
	fixed := func(tag string, port int, password string) map[string]any {
		return map[string]any{"type": "shadowsocks", "tag": tag, "listen": "127.0.0.1", "listen_port": port, "method": "2022-blake3-aes-256-gcm", "password": password}
	}
	h.config["inbounds"] = append(h.config["inbounds"].([]any), fixed("ss-direct", direct, key(1)), fixed("ss-relay", relay, key(2)), fixed("ss-peer", peer, key(3)))
	withEmptyUsers := fixed("ss-empty", emptyUsers, key(4))
	withEmptyUsers["users"] = []any{}
	withPanelManaged := fixed("ss-panel-zero", panelManaged, key(6))
	withPanelManaged["users"] = []any{}
	withPanelManaged["managed"] = true
	h.config["inbounds"] = append(h.config["inbounds"].([]any), withEmptyUsers, withPanelManaged)
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
	checkPSK := func(port int, password string) {
		t.Helper()
		if e := fixedSSPing(port, password, echo); e != nil {
			t.Fatalf("PSK TCP relay on port %d failed: %v", port, e)
		}
		if e := fixedSSPacketPing(port, password, udp.LocalAddr()); e != nil {
			t.Fatalf("PSK UDP relay on port %d failed: %v", port, e)
		}
	}
	checkAllZeroUserPSK := func() {
		t.Helper()
		checkPSK(direct, key(1))
		checkPSK(relay, key(2))
		checkPSK(emptyUsers, key(4))
		checkPSK(panelManaged, key(6))
	}
	// 1. All 0-user SS2022 shapes (users omitted, users=[], users=[]+managed=true) accept PSK over TCP & UDP.
	checkAllZeroUserPSK()
	if fixedSSPing(direct, key(9), echo) == nil {
		t.Fatal("wrong fixed PSK was accepted")
	}
	counters, err := h.app.QueryUserCounters(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range counters {
		if c.Value != 0 {
			t.Fatal("0-user PSK relay traffic charged to a panel user")
		}
	}

	// 2. Incremental 0 -> >0 promotion switches ss-empty & ss-panel-zero to multi-user EIH (bare PSK rejected).
	if err = h.app.UpdateUsers([]state.Update{{ID: "1", Memberships: []state.Membership{
		{Tag: "any", Protocol: "anytls", User: state.User{ID: "1", Credential: testutil.UUID1}},
		{Tag: "ss-empty", Protocol: "shadowsocks22", User: state.User{ID: "1", Credential: key(5)}},
		{Tag: "ss-panel-zero", Protocol: "shadowsocks22", User: state.User{ID: "1", Credential: key(7)}},
	}}}); err != nil {
		t.Fatal(err)
	}
	checkPSK(emptyUsers, key(4)+":"+key(5))
	checkPSK(panelManaged, key(6)+":"+key(7))
	if fixedSSPing(emptyUsers, key(4), echo) == nil || fixedSSPing(panelManaged, key(6), echo) == nil {
		t.Fatal("multi-user EIH inbound accepted bare server PSK")
	}
	checkPSK(direct, key(1))
	checkPSK(relay, key(2))

	// 3. Incremental >0 -> 0 demotion revokes EIH and immediately restores single-user PSK relay mode.
	if err = h.app.UpdateUsers([]state.Update{{ID: "1"}, {ID: "2"}}); err != nil {
		t.Fatal(err)
	}
	if fixedSSPing(emptyUsers, key(4)+":"+key(5), echo) == nil || fixedSSPing(panelManaged, key(6)+":"+key(7), echo) == nil {
		t.Fatal("revoked EIH user still accepted after >0 -> 0 demotion")
	}
	checkAllZeroUserPSK()

	counts, err := h.app.Query(context.Background(), []string{
		"inbound>>>ss-relay>>>", "inbound>>>ss-peer>>>", "inbound>>>ss-empty>>>", "inbound>>>ss-panel-zero>>>",
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, c := range counts {
		if c.Value > 0 {
			for _, tag := range []string{"ss-relay", "ss-peer", "ss-empty", "ss-panel-zero"} {
				if strings.HasPrefix(c.Name, "inbound>>>"+tag+">>>") {
					seen[tag] = true
				}
			}
		}
	}
	if len(seen) != 4 {
		t.Fatalf("relay route or node traffic counters missing: seen=%v", seen)
	}

	view := h.call("GET", "/internal/get-config", nil)
	var current map[string]any
	if err = json.Unmarshal(view.Body.Bytes(), &current); err != nil {
		t.Fatal(err)
	}
	for _, v := range current["inbounds"].([]any) {
		ib := v.(map[string]any)
		tag := ib["tag"].(string)
		if _, hasManaged := ib["managed"]; hasManaged {
			t.Fatalf("0-user SS inbound %q leaked managed flag in get-config", tag)
		}
		switch tag {
		case "ss-direct", "ss-relay", "ss-peer":
			if _, present := ib["users"]; present {
				t.Fatalf("user mutation added users to omitted-users SS inbound %q", tag)
			}
		case "ss-empty", "ss-panel-zero":
			uList, ok := ib["users"].([]any)
			if !ok || len(uList) != 0 {
				t.Fatalf("demoted SS inbound %q did not normalize users to []: %#v", tag, ib["users"])
			}
		}
	}
	h.start(current, "singbox", true, "")
	checkAllZeroUserPSK()
}
