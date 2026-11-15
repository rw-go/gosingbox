package nativeconfig

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/rwnode/rwnode-gosingbox/internal/testutil"
)

var management = Management{StatsAddress: "127.0.0.1:6450", ClashAddress: "[::1]:9090", ClashSecret: "node-owned-secret"}

func config(t *testing.T) map[string]any {
	t.Helper()
	return map[string]any{"inbounds": []any{map[string]any{"type": "anytls", "tag": "any", "tls": testutil.TLS(t), "users": []any{map[string]any{"name": "1", "password": testutil.UUID1}}}}}
}
func prepare(t *testing.T, cfg map[string]any, m Management) (*Prepared, error) {
	t.Helper()
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return Prepare(raw, m)
}
func first(cfg map[string]any) map[string]any { return cfg["inbounds"].([]any)[0].(map[string]any) }

func TestPreservesNativeFieldsAndOwnsManagement(t *testing.T) {
	cfg := config(t)
	cfg["dns"] = map[string]any{"servers": []any{map[string]any{"type": "local", "tag": "local"}}}
	cfg["route"] = map[string]any{"final": "out", "rules": []any{map[string]any{"domain_suffix": []any{"example.test"}, "action": "reject"}}}
	cfg["outbounds"] = []any{map[string]any{"type": "direct", "tag": "out", "bind_interface": "lo"}}
	cfg["experimental"] = map[string]any{"cache_file": map[string]any{"enabled": false}, "debug": map[string]any{"max_threads": json.Number("9007199254740993")}, "clash_api": map[string]any{"external_controller": "0.0.0.0:4444", "secret": "profile-secret", "default_mode": "rule"}, "v2ray_api": map[string]any{"listen": "0.0.0.0:5555", "stats": map[string]any{"enabled": false, "users": []any{"wrong"}, "inbounds": []any{"other", "any"}, "outbounds": []any{"out"}}}}
	raw, _ := json.Marshal(cfg)
	original := bytes.Clone(raw)
	p, err := Prepare(raw, management)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, original) {
		t.Fatal("input bytes changed")
	}
	decoded, _ := Decode(raw)
	for _, field := range []string{"dns", "route", "outbounds"} {
		if !reflect.DeepEqual(decoded[field], p.Config[field]) {
			t.Fatalf("%s changed", field)
		}
	}
	exp := p.Config["experimental"].(map[string]any)
	originalExp := decoded["experimental"].(map[string]any)
	for _, field := range []string{"cache_file", "debug"} {
		if !reflect.DeepEqual(originalExp[field], exp[field]) {
			t.Fatal("experimental sibling changed")
		}
	}
	clash := exp["clash_api"].(map[string]any)
	api := exp["v2ray_api"].(map[string]any)
	stats := api["stats"].(map[string]any)
	if clash["secret"] != management.ClashSecret || clash["external_controller"] != management.ClashAddress || clash["default_mode"] != "rule" || api["listen"] != management.StatsAddress {
		t.Fatal("management merge incorrect")
	}
	if stats["enabled"] != true || !reflect.DeepEqual(stats["users"], []string{"1"}) || !reflect.DeepEqual(stats["inbounds"], []string{"any", "other"}) || !reflect.DeepEqual(stats["outbounds"], []any{"out"}) {
		t.Fatal("statistics merge incorrect")
	}
	if len(p.Users["any"].Users) != 1 {
		t.Fatal("users lost")
	}
}

func TestRejectsUnmanagedOrInvalidNativeInput(t *testing.T) {
	tests := []struct {
		name, want string
		change     func(map[string]any)
	}{
		{"unknown-protocol", "not managed", func(c map[string]any) { first(c)["type"] = "trojan" }},
		{"xray-inbound", "not managed", func(c map[string]any) { delete(first(c), "type"); first(c)["protocol"] = "vless" }},
		{"duplicate-tag", "unique", func(c map[string]any) { c["inbounds"] = append(c["inbounds"].([]any), first(c)) }},
		{"missing-tag", "nonempty", func(c map[string]any) { delete(first(c), "tag") }},
		{"null-users", "array", func(c map[string]any) { first(c)["users"] = nil }},
		{"no-tls", "requires TLS", func(c map[string]any) { delete(first(c), "tls") }},
		{"reality-anytls", "ordinary TLS", func(c map[string]any) { first(c)["tls"].(map[string]any)["reality"] = map[string]any{"enabled": true} }},
		{"bad-cert", "invalid TLS", func(c map[string]any) { first(c)["tls"].(map[string]any)["certificate"] = "bad" }},
		{"missing-cert-file", "read TLS certificate file", func(c map[string]any) {
			first(c)["tls"] = map[string]any{"enabled": true, "certificate_path": filepath.Join(t.TempDir(), "missing.pem")}
		}},
		{"vless-transport", "TCP", func(c map[string]any) {
			first(c)["type"] = "vless"
			first(c)["transport"] = map[string]any{"type": "ws"}
		}},
		{"public-direct", "loopback", func(c map[string]any) { first(c)["type"] = "direct"; first(c)["listen"] = "0.0.0.0" }},
		{"only-direct", "managed inbound", func(c map[string]any) {
			c["inbounds"] = []any{map[string]any{"type": "direct", "tag": "d", "listen": "127.0.0.1"}}
		}},
		{"endpoint", "not managed", func(c map[string]any) { c["endpoints"] = []any{map[string]any{"type": "wireguard"}} }},
		{"service", "not managed", func(c map[string]any) { c["services"] = []any{map[string]any{"type": "ssm-api"}} }},
		{"null-experimental", "object", func(c map[string]any) { c["experimental"] = nil }},
		{"invalid-stats-inbounds", "array", func(c map[string]any) {
			c["experimental"] = map[string]any{"v2ray_api": map[string]any{"stats": map[string]any{"inbounds": false}}}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := config(t)
			tc.change(c)
			if _, err := prepare(t, c, management); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q, got %v", tc.want, err)
			}
		})
	}
	for _, raw := range []string{"null", "[]", "{", "{}", "{}{}"} {
		if _, err := Prepare([]byte(raw), management); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}
func TestManagementRequiresLocalDistinctListenersAndSecret(t *testing.T) {
	for _, address := range []string{"0.0.0.0:6450", "[::]:6450", "192.0.2.1:6450", "localhost:6450", "127.0.0.1:0", "127.0.0.1:65536"} {
		t.Run(address, func(t *testing.T) {
			m := management
			m.StatsAddress = address
			if _, err := prepare(t, config(t), m); err == nil {
				t.Fatal("accepted unsafe stats address")
			}
			m = management
			m.ClashAddress = address
			if _, err := prepare(t, config(t), m); err == nil {
				t.Fatal("accepted unsafe Clash address")
			}
		})
	}
	m := management
	m.ClashSecret = ""
	if _, err := prepare(t, config(t), m); err == nil {
		t.Fatal("accepted empty secret")
	}
	m = management
	m.ClashAddress = m.StatsAddress
	if _, err := prepare(t, config(t), m); err == nil {
		t.Fatal("accepted same listeners")
	}
}
func TestEmptyManagedSSAndNativeVlessFlow(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte("1234567890123456"))
	c := map[string]any{"inbounds": []any{map[string]any{"type": "shadowsocks", "tag": "ss", "method": "2022-blake3-aes-128-gcm", "password": key, "users": []any{}}, map[string]any{"type": "vless", "tag": "vl", "users": []any{map[string]any{"name": "1", "uuid": testutil.UUID1, "flow": ""}}}, map[string]any{"type": "direct", "tag": "aux", "listen": "::1"}}}
	p, err := prepare(t, c, management)
	if err != nil {
		t.Fatal(err)
	}
	if first(p.Config)["managed"] != true || len(p.Users) != 2 || p.Users["vl"].Users["1"].Flow != "" {
		t.Fatal("empty SS or flow changed")
	}
	first(c)["managed"] = true
	first(c)["users"] = []any{map[string]any{"name": "1", "password": key}}
	p, err = prepare(t, c, management)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := first(p.Config)["managed"]; ok {
		t.Fatal("managed flag retained with nonempty SS")
	}
	delete(first(c), "users")
	if _, err = prepare(t, c, management); err == nil {
		t.Fatal("accepted shared PSK SS")
	}
}
func TestTLSCertificateFilesAreCheckedBeforeApply(t *testing.T) {
	c := config(t)
	options := first(c)["tls"].(map[string]any)
	for _, field := range []string{"certificate", "key"} {
		path := filepath.Join(t.TempDir(), field+".pem")
		if err := os.WriteFile(path, []byte(options[field].([]string)[0]), 0600); err != nil {
			t.Fatal(err)
		}
		delete(options, field)
		options[field] = []string{} // Empty inline defaults must not hide the file.
		options[field+"_path"] = path
	}
	if _, err := prepare(t, c, management); err != nil {
		t.Fatal(err)
	}
}
