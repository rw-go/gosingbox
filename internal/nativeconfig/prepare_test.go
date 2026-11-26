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
	if stats["enabled"] != true || !reflect.DeepEqual(stats["users"], []string{"1"}) || !reflect.DeepEqual(stats["inbounds"], []string{"any", "other"}) || !reflect.DeepEqual(stats["outbounds"], []string{"out"}) {
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
			first(c)["tls"] = map[string]any{"enabled": true, "certificate_path": "/etc/ssl/nonexistent-gosingbox-test-cert.pem"}
		}},
		{"outside-cert-dir", "outside allowed certificate directories", func(c map[string]any) {
			first(c)["tls"] = map[string]any{"enabled": true, "certificate_path": filepath.Join(t.TempDir(), "unlisted.pem")}
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
		{"invalid-stats-outbounds", "array", func(c map[string]any) {
			c["experimental"] = map[string]any{"v2ray_api": map[string]any{"stats": map[string]any{"outbounds": false}}}
		}},
		{"log-output-path", "log.output", func(c map[string]any) {
			c["log"] = map[string]any{"level": "warn", "output": "/tmp/node.log"}
		}},
		{"cache-file-path", "cache_file.path", func(c map[string]any) {
			c["experimental"] = map[string]any{"cache_file": map[string]any{"enabled": true, "path": "/tmp/cache.db"}}
		}},
		{"acme-data-dir", "acme.data_directory", func(c map[string]any) {
			first(c)["tls"] = map[string]any{"enabled": true, "acme": map[string]any{"data_directory": "/tmp/acme"}}
		}},
		{"relative-cert-path", "clean absolute path", func(c map[string]any) {
			first(c)["tls"] = map[string]any{"enabled": true, "certificate_path": "relative/cert.pem"}
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
	userKey := base64.StdEncoding.EncodeToString([]byte("abcdefghijklmnop"))

	// Unified SS2022 rule: 0-user SS2022 (users omitted, users=[], or users=[]+managed=true)
	// always normalizes to single-user PSK (omitting both users and managed).
	for _, variant := range []struct {
		name   string
		mutate func(ss map[string]any)
	}{
		{"users-omitted", func(ss map[string]any) {}},
		{"users-empty", func(ss map[string]any) { ss["users"] = []any{} }},
		{"users-empty-managed-true", func(ss map[string]any) { ss["users"] = []any{}; ss["managed"] = true }},
		{"managed-true-without-users", func(ss map[string]any) { ss["managed"] = true }},
	} {
		t.Run(variant.name, func(t *testing.T) {
			ss := map[string]any{"type": "shadowsocks", "tag": "ss", "method": "2022-blake3-aes-128-gcm", "password": key}
			variant.mutate(ss)
			c := map[string]any{"inbounds": []any{
				ss,
				map[string]any{"type": "vless", "tag": "vl", "users": []any{map[string]any{"name": "1", "uuid": testutil.UUID1, "flow": ""}}},
				map[string]any{"type": "direct", "tag": "aux", "listen": "::1"},
			}}
			p, err := prepare(t, c, management)
			if err != nil {
				t.Fatal(err)
			}
			ssOut := first(p.Config)
			if _, hasUsers := ssOut["users"]; hasUsers {
				t.Fatalf("0-user SS kept users field: %#v", ssOut["users"])
			}
			if _, hasManaged := ssOut["managed"]; hasManaged {
				t.Fatalf("0-user SS kept managed field: %#v", ssOut["managed"])
			}
			if len(p.Users) != 1 || p.Users["vl"].Users["1"].Flow != "" {
				t.Fatalf("unexpected managed snapshot: %#v", p.Users)
			}
			stats := p.Config["experimental"].(map[string]any)["v2ray_api"].(map[string]any)["stats"].(map[string]any)
			if !reflect.DeepEqual(stats["inbounds"], []string{"vl", "ss"}) {
				t.Fatalf("unexpected stats.inbounds: %#v", stats["inbounds"])
			}
			if !reflect.DeepEqual(stats["users"], []string{"1"}) {
				t.Fatalf("unexpected stats.users: %#v", stats["users"])
			}
		})
	}

	// A native config whose only non-direct inbound is a 0-user SS2022 relay (like hk1sb)
	// must be accepted and tracked in stats.inbounds with empty stats.users.
	ssOnly := map[string]any{"inbounds": []any{
		map[string]any{"type": "shadowsocks", "tag": "ss-only", "method": "2022-blake3-aes-128-gcm", "password": key, "users": []any{}, "managed": true},
		map[string]any{"type": "direct", "tag": "aux", "listen": "127.0.0.1"},
	}}
	pOnly, err := prepare(t, ssOnly, management)
	if err != nil {
		t.Fatalf("0-user SS-only native config rejected: %v", err)
	}
	if len(pOnly.Users) != 0 {
		t.Fatalf("expected 0 managed inbounds for 0-user SS-only config, got %#v", pOnly.Users)
	}
	onlyStats := pOnly.Config["experimental"].(map[string]any)["v2ray_api"].(map[string]any)["stats"].(map[string]any)
	if !reflect.DeepEqual(onlyStats["inbounds"], []string{"ss-only"}) || !reflect.DeepEqual(onlyStats["users"], []string{}) {
		t.Fatalf("unexpected SS-only stats: inbounds=%#v users=%#v", onlyStats["inbounds"], onlyStats["users"])
	}

	// Non-empty users (>0) strips managed=true and runs multi-user EIH.
	cMulti := map[string]any{"inbounds": []any{
		map[string]any{"type": "shadowsocks", "tag": "ss", "method": "2022-blake3-aes-128-gcm", "password": key, "managed": true, "users": []any{map[string]any{"name": "1", "password": userKey}}},
	}}
	pMulti, err := prepare(t, cMulti, management)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := first(pMulti.Config)["managed"]; ok {
		t.Fatal("managed flag retained with nonempty SS")
	}
	if len(pMulti.Users["ss"].Users) != 1 || pMulti.Users["ss"].Users["1"].Credential != userKey {
		t.Fatalf("unexpected multi-user SS snapshot: %#v", pMulti.Users["ss"])
	}
}

func TestFixedPasswordSSIsAuxiliaryButCountedInNodeTraffic(t *testing.T) {
	c := config(t)
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	ss := map[string]any{"type": "shadowsocks", "tag": "fixed", "method": "2022-blake3-aes-256-gcm", "password": key}
	c["inbounds"] = append(c["inbounds"].([]any), ss)
	p, err := prepare(t, c, management)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Users) != 1 {
		t.Fatal("fixed relay became a panel-managed user set")
	}
	if _, ok := p.Users["fixed"]; ok {
		t.Fatal("fixed relay can receive user mutations")
	}
	ib := p.Config["inbounds"].([]any)[1].(map[string]any)
	if _, ok := ib["users"]; ok {
		t.Fatal("single-password service became multi-user")
	}
	if ib["password"] != key {
		t.Fatal("relay PSK changed")
	}
	stats := p.Config["experimental"].(map[string]any)["v2ray_api"].(map[string]any)["stats"].(map[string]any)
	if !reflect.DeepEqual(stats["inbounds"], []string{"any", "fixed"}) {
		t.Fatal("node relay traffic is not accounted")
	}
	if !reflect.DeepEqual(stats["users"], []string{"1"}) {
		t.Fatal("relay was assigned personal usage")
	}
	if !reflect.DeepEqual(stats["outbounds"], []string{"direct"}) {
		t.Fatalf("implicit direct outbound was not accounted: %#v", stats["outbounds"])
	}
	ss["managed"] = "false"
	if _, err = prepare(t, c, management); err == nil || !strings.Contains(err.Error(), "boolean") {
		t.Fatal("invalid managed type accepted")
	}
	ss["managed"] = true
	ss["users"] = "bad"
	if _, err = prepare(t, c, management); err == nil || !strings.Contains(err.Error(), "array") {
		t.Fatal("invalid users type accepted")
	}
}
func TestTLSCertificateFilesAreCheckedBeforeApply(t *testing.T) {
	c := config(t)
	options := first(c)["tls"].(map[string]any)
	certRoot := t.TempDir()
	archiveDir := filepath.Join(certRoot, "archive")
	liveDir := filepath.Join(certRoot, "live")
	if err := os.MkdirAll(archiveDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(liveDir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"certificate", "key"} {
		realFile := filepath.Join(archiveDir, field+"1.pem")
		if err := os.WriteFile(realFile, []byte(options[field].([]string)[0]), 0600); err != nil {
			t.Fatal(err)
		}
		linkFile := filepath.Join(liveDir, field+".pem")
		// Let's Encrypt style symlink within the allowed certificate tree must work.
		if err := os.Symlink(filepath.Join("..", "archive", field+"1.pem"), linkFile); err != nil {
			t.Fatal(err)
		}
		delete(options, field)
		options[field] = []string{} // Empty inline defaults must not hide the file.
		options[field+"_path"] = linkFile
	}
	m := management
	m.AllowedCertDirs = []string{certRoot}
	if _, err := prepare(t, c, m); err != nil {
		t.Fatal(err)
	}
	// Symlink escaping outside AllowedCertDirs must be rejected.
	outsideDir := t.TempDir()
	outsideFile := filepath.Join(outsideDir, "escaped.pem")
	if err := os.WriteFile(outsideFile, []byte("irrelevant"), 0600); err != nil {
		t.Fatal(err)
	}
	escapeLink := filepath.Join(liveDir, "escape.pem")
	if err := os.Symlink(outsideFile, escapeLink); err != nil {
		t.Fatal(err)
	}
	options["certificate_path"] = escapeLink
	if _, err := prepare(t, c, m); err == nil || !strings.Contains(err.Error(), "outside allowed certificate directories") {
		t.Fatalf("expected symlink escape rejection, got %v", err)
	}
}

func TestOutboundStatsAndClashExternalUISanitization(t *testing.T) {
	c := config(t)
	c["outbounds"] = []any{
		map[string]any{"type": "direct", "tag": "DIRECT"},
		map[string]any{"type": "shadowsocks", "tag": "ss_to_hk6"},
		map[string]any{"type": "block", "tag": "block"},
	}
	c["experimental"] = map[string]any{
		"cache_file": map[string]any{
			"enabled": true,
			"path":    "/var/lib/gosingbox/singbox/domain-rule-cache.db",
		},
		"clash_api": map[string]any{
			"external_ui":              "/tmp/ui",
			"external_ui_download_url": "https://example.invalid/ui.zip",
			"default_mode":             "rule",
		},
		"v2ray_api": map[string]any{
			"stats": map[string]any{
				"outbounds": []any{"custom-out", "DIRECT"},
			},
		},
	}
	p, err := prepare(t, c, management)
	if err != nil {
		t.Fatalf("production cache_file.path rejected: %v", err)
	}
	exp := p.Config["experimental"].(map[string]any)
	clash := exp["clash_api"].(map[string]any)
	if _, hasUI := clash["external_ui"]; hasUI {
		t.Fatal("external_ui was not stripped")
	}
	if _, hasURL := clash["external_ui_download_url"]; hasURL {
		t.Fatal("external_ui_download_url was not stripped")
	}
	if clash["default_mode"] != "rule" {
		t.Fatal("benign clash_api field lost")
	}
	stats := exp["v2ray_api"].(map[string]any)["stats"].(map[string]any)
	if !reflect.DeepEqual(stats["outbounds"], []string{"DIRECT", "ss_to_hk6", "custom-out"}) {
		t.Fatalf("unexpected stats.outbounds: %#v", stats["outbounds"])
	}

	// Dot-prefixed .cache.db inside /var/lib/gosingbox is also valid.
	c["experimental"].(map[string]any)["cache_file"].(map[string]any)["path"] = "/var/lib/gosingbox/singbox/geo/.cache.db"
	if _, err := prepare(t, c, management); err != nil {
		t.Fatalf("dot-prefixed cache_file.path rejected: %v", err)
	}

	// Untagged explicit outbounds use zero-based index tags ("0", "2") matching sing-box box.go.
	untagged := config(t)
	untagged["outbounds"] = []any{
		map[string]any{"type": "direct"},
		map[string]any{"type": "block"},
		map[string]any{"type": "shadowsocks"},
	}
	pu, err := prepare(t, untagged, management)
	if err != nil {
		t.Fatal(err)
	}
	uStats := pu.Config["experimental"].(map[string]any)["v2ray_api"].(map[string]any)["stats"].(map[string]any)
	if !reflect.DeepEqual(uStats["outbounds"], []string{"0", "2"}) {
		t.Fatalf("unexpected untagged stats.outbounds: %#v", uStats["outbounds"])
	}
}

func TestCertificateProviderStorageConfinement(t *testing.T) {
	managedRoot := t.TempDir()
	outsideRoot := t.TempDir()
	existingManagedSubdir := filepath.Join(managedRoot, "existing-acme")
	intraTargetDir := filepath.Join(managedRoot, "real-store")
	intraSymlinkDir := filepath.Join(managedRoot, "linked-store")
	escapeSymlinkDir := filepath.Join(managedRoot, "escape-link")
	danglingSymlinkDir := filepath.Join(managedRoot, "dangling-link")
	regularFile := filepath.Join(managedRoot, "not-a-dir.txt")

	for _, dir := range []string{existingManagedSubdir, intraTargetDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(intraTargetDir, intraSymlinkDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideRoot, escapeSymlinkDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outsideRoot, "nonexistent-target"), danglingSymlinkDir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(regularFile, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}

	m := management
	m.AllowedCertDirs = []string{managedRoot}

	providerTLSConfig := func(topProviders any, certProvider any) map[string]any {
		c := config(t)
		tlsCfg := map[string]any{
			"enabled":              true,
			"server_name":          "node.example.test",
			"certificate_provider": certProvider,
		}
		first(c)["tls"] = tlsCfg
		if topProviders != nil {
			c["certificate_providers"] = topProviders
		}
		return c
	}

	// Valid top-level certificate_providers + string reference, inline provider, and default managed dirs.
	validCases := []struct {
		name string
		cfg  map[string]any
	}{
		{
			name: "top-level-acme-default-var-lib",
			cfg: providerTLSConfig(
				[]any{map[string]any{"type": "acme", "tag": "shared-acme", "domain": []any{"node.example.test"}, "data_directory": "/var/lib/gosingbox/acme"}},
				"shared-acme",
			),
		},
		{
			name: "top-level-originca-etc-gosingbox-and-tls",
			cfg: providerTLSConfig(
				[]any{
					map[string]any{"type": "cloudflare-origin-ca", "tag": "cf-ca", "domain": []any{"node.example.test"}, "origin_ca_key": "v1.0-test", "data_directory": "/etc/gosingbox/originca"},
					map[string]any{"type": "acme", "tag": "tls-vol", "domain": []any{"node.example.test"}, "data_directory": "/tls/acme"},
				},
				"cf-ca",
			),
		},
		{
			name: "top-level-acme-omitted-and-empty-data-dir",
			cfg: providerTLSConfig(
				[]any{
					map[string]any{"type": "acme", "tag": "acme-omitted", "domain": []any{"node.example.test"}},
					map[string]any{"type": "acme", "tag": "acme-empty", "domain": []any{"node.example.test"}, "data_directory": ""},
				},
				"acme-omitted",
			),
		},
		{
			name: "inline-acme-existing-and-new-managed-subdir",
			cfg: providerTLSConfig(
				[]any{},
				map[string]any{"type": "acme", "domain": []any{"node.example.test"}, "data_directory": filepath.Join(existingManagedSubdir, "nested")},
			),
		},
		{
			name: "inline-originca-intra-tree-symlink-dir",
			cfg: providerTLSConfig(
				nil,
				map[string]any{"type": "cloudflare-origin-ca", "domain": []any{"node.example.test"}, "api_token": "tok", "data_directory": filepath.Join(intraSymlinkDir, "certs")},
			),
		},
		{
			name: "legacy-tls-acme-managed-dir",
			cfg: func() map[string]any {
				c := config(t)
				first(c)["tls"] = map[string]any{
					"enabled": true,
					"acme":    map[string]any{"domain": []any{"node.example.test"}, "data_directory": "/var/lib/gosingbox/acme-legacy"},
				}
				return c
			}(),
		},
	}
	for _, tc := range validCases {
		t.Run("accept-"+tc.name, func(t *testing.T) {
			if _, err := prepare(t, tc.cfg, m); err != nil {
				t.Fatalf("unexpected rejection for %s: %v", tc.name, err)
			}
		})
	}

	// Reject malformed structures, unmanaged provider types, read-only system CA dirs, and escaping paths/symlinks.
	rejectCases := []struct {
		name string
		want string
		cfg  map[string]any
	}{
		{
			name: "top-level-not-array",
			want: "certificate_providers must be an array",
			cfg: func() map[string]any {
				c := config(t)
				c["certificate_providers"] = map[string]any{}
				return c
			}(),
		},
		{
			name: "top-level-null",
			want: "certificate_providers must be an array",
			cfg: func() map[string]any {
				c := config(t)
				c["certificate_providers"] = nil
				return c
			}(),
		},
		{
			name: "top-level-missing-tag",
			want: "tag must be nonempty",
			cfg: providerTLSConfig(
				[]any{map[string]any{"type": "acme", "domain": []any{"node.example.test"}}},
				"shared-acme",
			),
		},
		{
			name: "top-level-duplicate-tag",
			want: "duplicate certificate provider tag",
			cfg: providerTLSConfig(
				[]any{
					map[string]any{"type": "acme", "tag": "dup", "domain": []any{"a.example.test"}},
					map[string]any{"type": "acme", "tag": "dup", "domain": []any{"b.example.test"}},
				},
				"dup",
			),
		},
		{
			name: "unknown-provider-tag-without-top-level",
			want: "unknown provider",
			cfg:  providerTLSConfig(nil, "missing-provider"),
		},
		{
			name: "unknown-provider-tag-with-top-level",
			want: "unknown provider",
			cfg: providerTLSConfig(
				[]any{map[string]any{"type": "acme", "tag": "declared", "domain": []any{"node.example.test"}}},
				"other",
			),
		},
		{
			name: "empty-provider-tag",
			want: "tag must be nonempty",
			cfg:  providerTLSConfig(nil, ""),
		},
		{
			name: "invalid-provider-ref-type",
			want: "tag string or provider object",
			cfg:  providerTLSConfig(nil, 42),
		},
		{
			name: "inline-provider-with-tag",
			want: "must not specify tag",
			cfg:  providerTLSConfig(nil, map[string]any{"type": "acme", "tag": "bad-inline", "domain": []any{"node.example.test"}}),
		},
		{
			name: "top-level-tailscale-unmanaged",
			want: "not managed",
			cfg: providerTLSConfig(
				[]any{map[string]any{"type": "tailscale", "tag": "ts", "endpoint": "ts-ep"}},
				"ts",
			),
		},
		{
			name: "inline-tailscale-unmanaged",
			want: "not managed",
			cfg:  providerTLSConfig(nil, map[string]any{"type": "tailscale", "endpoint": "ts-ep"}),
		},
		{
			name: "inline-unknown-type",
			want: "not managed",
			cfg:  providerTLSConfig(nil, map[string]any{"type": "custom-fs", "data_directory": "/var/lib/gosingbox/acme"}),
		},
		{
			name: "etc-ssl-rejected-for-writable-provider-dir",
			want: "outside allowed certificate provider directories",
			cfg:  providerTLSConfig(nil, map[string]any{"type": "acme", "domain": []any{"node.example.test"}, "data_directory": "/etc/ssl/acme"}),
		},
		{
			name: "etc-pki-rejected-for-writable-provider-dir",
			want: "outside allowed certificate provider directories",
			cfg:  providerTLSConfig(nil, map[string]any{"type": "acme", "domain": []any{"node.example.test"}, "data_directory": "/etc/pki/acme"}),
		},
		{
			name: "etc-letsencrypt-rejected-for-writable-provider-dir",
			want: "outside allowed certificate provider directories",
			cfg:  providerTLSConfig(nil, map[string]any{"type": "acme", "domain": []any{"node.example.test"}, "data_directory": "/etc/letsencrypt/acme"}),
		},
		{
			name: "outside-temp-dir",
			want: "outside allowed certificate provider directories",
			cfg:  providerTLSConfig(nil, map[string]any{"type": "acme", "domain": []any{"node.example.test"}, "data_directory": filepath.Join(outsideRoot, "acme")}),
		},
		{
			name: "unreferenced-top-level-outside-dir-still-rejected",
			want: "outside allowed certificate provider directories",
			cfg: func() map[string]any {
				c := config(t)
				c["certificate_providers"] = []any{
					map[string]any{"type": "acme", "tag": "unused", "domain": []any{"node.example.test"}, "data_directory": filepath.Join(outsideRoot, "unused")},
				}
				return c
			}(),
		},
		{
			name: "relative-data-dir",
			want: "clean absolute path",
			cfg:  providerTLSConfig(nil, map[string]any{"type": "acme", "domain": []any{"node.example.test"}, "data_directory": "relative/acme"}),
		},
		{
			name: "dotdot-traversal-data-dir",
			want: "clean absolute path",
			cfg:  providerTLSConfig(nil, map[string]any{"type": "acme", "domain": []any{"node.example.test"}, "data_directory": "/var/lib/gosingbox/../etc/gosingbox"}),
		},
		{
			name: "trailing-slash-data-dir",
			want: "clean absolute path",
			cfg:  providerTLSConfig(nil, map[string]any{"type": "acme", "domain": []any{"node.example.test"}, "data_directory": "/var/lib/gosingbox/acme/"}),
		},
		{
			name: "root-slash-data-dir",
			want: "clean absolute path",
			cfg:  providerTLSConfig(nil, map[string]any{"type": "acme", "domain": []any{"node.example.test"}, "data_directory": "/"}),
		},
		{
			name: "env-expansion-data-dir",
			want: "environment variable",
			cfg:  providerTLSConfig(nil, map[string]any{"type": "acme", "domain": []any{"node.example.test"}, "data_directory": "/var/lib/gosingbox/$HOME"}),
		},
		{
			name: "non-string-data-dir",
			want: "must be a string",
			cfg:  providerTLSConfig(nil, map[string]any{"type": "acme", "domain": []any{"node.example.test"}, "data_directory": 123}),
		},
		{
			name: "regular-file-as-data-dir",
			want: "must reference a directory",
			cfg:  providerTLSConfig(nil, map[string]any{"type": "acme", "domain": []any{"node.example.test"}, "data_directory": regularFile}),
		},
		{
			name: "escaping-symlink-leaf-dir",
			want: "resolves outside allowed certificate provider directories",
			cfg:  providerTLSConfig(nil, map[string]any{"type": "acme", "domain": []any{"node.example.test"}, "data_directory": escapeSymlinkDir}),
		},
		{
			name: "escaping-symlink-ancestor-dir",
			want: "resolves outside allowed certificate provider directories",
			cfg:  providerTLSConfig(nil, map[string]any{"type": "acme", "domain": []any{"node.example.test"}, "data_directory": filepath.Join(escapeSymlinkDir, "nested", "certs")}),
		},
		{
			name: "dangling-symlink-dir",
			want: "resolves outside allowed certificate provider directories",
			cfg:  providerTLSConfig(nil, map[string]any{"type": "acme", "domain": []any{"node.example.test"}, "data_directory": filepath.Join(danglingSymlinkDir, "certs")}),
		},
		{
			name: "mutual-exclusion-acme-and-provider",
			want: "mutually exclusive",
			cfg: func() map[string]any {
				c := providerTLSConfig(nil, map[string]any{"type": "acme", "domain": []any{"node.example.test"}, "data_directory": "/var/lib/gosingbox/acme"})
				first(c)["tls"].(map[string]any)["acme"] = map[string]any{"domain": []any{"node.example.test"}}
				return c
			}(),
		},
		{
			name: "disabled-tls-still-validates-provider",
			want: "outside allowed certificate provider directories",
			cfg: func() map[string]any {
				c := config(t)
				c["inbounds"] = append(c["inbounds"].([]any), map[string]any{
					"type": "vless", "tag": "vl-disabled-tls",
					"tls": map[string]any{
						"enabled":              false,
						"certificate_provider": map[string]any{"type": "acme", "domain": []any{"node.example.test"}, "data_directory": "/tmp/evil"},
					},
				})
				return c
			}(),
		},
	}
	for _, tc := range rejectCases {
		t.Run("reject-"+tc.name, func(t *testing.T) {
			if _, err := prepare(t, tc.cfg, m); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}
}
