package transpiler

import (
	"encoding/base64"
	"encoding/json"
	"slices"
	"testing"
)

func TestFullVLESSConfigKeepsPerInboundUsers(t *testing.T) {
	inbound := func(tag, id string) map[string]any {
		return map[string]any{
			"protocol": "vless", "tag": tag, "port": 443,
			"settings":       map[string]any{"clients": []any{map[string]any{"email": id, "id": id}}},
			"streamSettings": map[string]any{"security": "reality", "realitySettings": map[string]any{"privateKey": "test-key", "serverNames": []string{"example.invalid"}}},
		}
	}
	raw, _ := json.Marshal(map[string]any{"inbounds": []any{inbound("a", "1"), inbound("b", "2")}})
	result, err := Transpile(raw, "127.0.0.1:0", "127.0.0.1:0", "error", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i, item := range result.Config["inbounds"].([]any) {
		ib := item.(map[string]any)
		users := ib["users"].([]VlessUser)
		want := []string{"1", "2"}[i]
		if len(users) != 1 || users[0].UUID != want {
			t.Fatalf("users leaked on %s: %+v", ib["tag"], users)
		}
	}
}

func TestShadowsocksInboundSingleUserVsMultiUserModes(t *testing.T) {
	serverPSK := base64.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012"))
	userKey := base64.StdEncoding.EncodeToString([]byte("abcdefghijklmnopqrstuvwxyz123456"))

	// Panel-dispatched jp4 shape: VLESS Reality with 1 user + SS2022 with
	// settings.clients=[] (0 authorized users) + a second SS2022 with 1 user.
	panel := map[string]any{
		"inbounds": []any{
			map[string]any{
				"tag":      "SS_IN_JP4",
				"port":     8999,
				"protocol": "shadowsocks",
				"settings": map[string]any{
					"method":   "2022-blake3-aes-256-gcm",
					"clients":  []any{},
					"network":  "tcp,udp",
					"password": serverPSK,
				},
			},
			map[string]any{
				"tag":      "VLESS_PUBLIC_INBOUND_JP4",
				"port":     443,
				"protocol": "vless",
				"settings": map[string]any{
					"clients": []any{map[string]any{"id": "11111111-1111-4111-8111-111111111111", "email": "u1", "flow": "xtls-rprx-vision"}},
				},
				"streamSettings": map[string]any{
					"security":        "reality",
					"realitySettings": map[string]any{"privateKey": "test-key", "serverNames": []any{"next.tama.ac.jp"}},
				},
			},
			map[string]any{
				"tag":      "SS_MULTI",
				"port":     9000,
				"protocol": "shadowsocks",
				"settings": map[string]any{
					"method":   "2022-blake3-aes-256-gcm",
					"clients":  []any{map[string]any{"email": "u2", "password": userKey}},
					"password": serverPSK,
				},
			},
		},
	}
	raw, err := json.Marshal(panel)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Default transpile (!useDesired): 0-client SS_IN_JP4 omits "users" and "managed"
	// (single-user PSK mode), while >0-client SS_MULTI emits "password" + "users".
	res, err := Transpile(raw, "127.0.0.1:0", "127.0.0.1:0", "error", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	inbounds := res.Config["inbounds"].([]any)
	if len(inbounds) != 3 {
		t.Fatalf("expected 3 inbounds, got %d", len(inbounds))
	}
	ssSingle := inbounds[0].(map[string]any)
	if ssSingle["password"] != serverPSK {
		t.Fatalf("SS_IN_JP4 password = %v, want %s", ssSingle["password"], serverPSK)
	}
	if _, hasUsers := ssSingle["users"]; hasUsers {
		t.Fatalf("0-client SS_IN_JP4 must omit users for single-user PSK mode, got %#v", ssSingle["users"])
	}
	if _, hasManaged := ssSingle["managed"]; hasManaged {
		t.Fatalf("0-client SS_IN_JP4 must omit managed for single-user PSK mode, got %#v", ssSingle["managed"])
	}

	ssMulti := inbounds[2].(map[string]any)
	if ssMulti["password"] != serverPSK {
		t.Fatalf("SS_MULTI password = %v", ssMulti["password"])
	}
	multiUsers, ok := ssMulti["users"].([]any)
	if !ok || len(multiUsers) != 1 {
		t.Fatalf("SS_MULTI users = %#v, want 1 user", ssMulti["users"])
	}
	if _, hasManaged := ssMulti["managed"]; hasManaged {
		t.Fatalf("non-empty SS_MULTI must not set managed, got %#v", ssMulti["managed"])
	}

	stats := res.Config["experimental"].(map[string]any)["v2ray_api"].(map[string]any)["stats"].(map[string]any)
	statInbounds := stats["inbounds"].([]string)
	if !slices.Contains(statInbounds, "SS_IN_JP4") || !slices.Contains(statInbounds, "VLESS_PUBLIC_INBOUND_JP4") || !slices.Contains(statInbounds, "SS_MULTI") {
		t.Fatalf("stats.inbounds missing expected tags: %v", statInbounds)
	}
	statUsers := stats["users"].([]string)
	if !slices.Equal(statUsers, []string{"u1", "u2"}) {
		t.Fatalf("stats.users = %v, want [u1 u2]", statUsers)
	}

	// 2. Explicit empty desiredSsUsers (useDesired == true && len == 0): emits "users": [] and "managed": true.
	resDesiredEmpty, err := Transpile(raw, "127.0.0.1:0", "127.0.0.1:0", "error", nil, []SsUser{})
	if err != nil {
		t.Fatal(err)
	}
	ssDesiredEmpty := resDesiredEmpty.Config["inbounds"].([]any)[0].(map[string]any)
	emptyUsers, hasUsers := ssDesiredEmpty["users"].([]any)
	if !hasUsers || len(emptyUsers) != 0 || ssDesiredEmpty["managed"] != true {
		t.Fatalf("useDesired=true with 0 users must emit users=[] and managed=true, got %#v", ssDesiredEmpty)
	}
}
