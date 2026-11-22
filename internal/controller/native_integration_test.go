//go:build with_v2ray_api && with_clash_api

package controller

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rwnode/rwnode-gosingbox/internal/app"
	"github.com/rwnode/rwnode-gosingbox/internal/contract"
	"github.com/rwnode/rwnode-gosingbox/internal/singbox"
	"github.com/rwnode/rwnode-gosingbox/internal/state"
	"github.com/rwnode/rwnode-gosingbox/internal/testutil"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	"github.com/sagernet/sing-vmess/vless"
	M "github.com/sagernet/sing/common/metadata"
)

type nativeHarness struct {
	t      *testing.T
	app    *app.App
	engine *singbox.Engine
	state  *state.State
	mux    *http.ServeMux
	port   int
	config map[string]any
}

func newNativeHarness(t *testing.T) *nativeHarness {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	e := singbox.NewEngine(singbox.Options{StatsAddr: fmt.Sprintf("127.0.0.1:%d", testutil.Port(t)), ClashAddr: fmt.Sprintf("127.0.0.1:%d", testutil.Port(t)), Logger: logger})
	s := state.New()
	a := app.New(logger, e, s, 0, false)
	t.Cleanup(a.Stop)
	mux := http.NewServeMux()
	NewXray(a, logger).Router(mux)
	NewHandler(a, logger).Router(mux)
	NewInternal(a, logger).Router(mux)
	NewStats(a, logger).Router(mux)
	port := testutil.Port(t)
	cfg := map[string]any{"log": map[string]any{"disabled": true}, "inbounds": []any{map[string]any{"type": "anytls", "tag": "any", "listen": "127.0.0.1", "listen_port": port, "tls": testutil.TLS(t), "users": []any{map[string]any{"name": "1", "password": testutil.UUID1}, map[string]any{"name": "2", "password": testutil.UUID2}}}}, "outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}}, "route": map[string]any{"final": "direct"}, "dns": map[string]any{"servers": []any{map[string]any{"type": "local", "tag": "local"}}}}
	return &nativeHarness{t, a, e, s, mux, port, cfg}
}
func (h *nativeHarness) call(method, path string, body any) *httptest.ResponseRecorder {
	h.t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		h.t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, httptest.NewRequest(method, path, bytes.NewReader(raw)))
	return rec
}
func (h *nativeHarness) start(cfg map[string]any, format string, force bool, wantError string) {
	h.t.Helper()
	body := map[string]any{"xrayConfig": cfg, "internals": map[string]any{"forceRestart": force}}
	if format != "" {
		body["coreType"] = format
	}
	rec := h.call("POST", "/node/xray/start", body)
	var result struct {
		Response struct {
			IsStarted bool
			Error     string
		}
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		h.t.Fatal(err)
	}
	if rec.Code != 200 || result.Response.IsStarted != (wantError == "") || !strings.Contains(result.Response.Error, wantError) {
		h.t.Fatalf("start status=%d: %s", rec.Code, rec.Body.String())
	}
}
func (h *nativeHarness) rotate(password string) {
	h.t.Helper()
	rec := h.call("POST", "/node/handler/add-users", map[string]any{"users": []any{map[string]any{
		"userData":    map[string]any{"userId": "1", "vlessUuid": password},
		"inboundData": []any{map[string]any{"type": "anytls", "tag": "any"}},
	}}})
	var result struct{ Response struct{ Success bool } }
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil || !result.Response.Success {
		h.t.Fatalf("rotate: %s", rec.Body.String())
	}
}
func cloneConfig(t *testing.T, cfg map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var copy map[string]any
	if err = json.Unmarshal(raw, &copy); err != nil {
		t.Fatal(err)
	}
	return copy
}
func nativeInbound(cfg map[string]any) map[string]any {
	return cfg["inbounds"].([]any)[0].(map[string]any)
}

func TestNativeStartPreflightHotUpdatesManagementAndRollback(t *testing.T) {
	h := newNativeHarness(t)
	h.start(h.config, "singbox", false, "")
	destination := testutil.Echo(t)
	user1 := testutil.NewClient(t, h.port, testutil.UUID1)
	other := testutil.NewClient(t, h.port, testutil.UUID2)
	active, err := user1.Open(destination)
	if err != nil {
		t.Fatal(err)
	}
	defer active.Close()
	if err = testutil.Ping(active); err != nil {
		t.Fatal(err)
	}
	unaffected, err := other.Open(destination)
	if err != nil {
		t.Fatal(err)
	}
	defer unaffected.Close()
	if err = testutil.Ping(unaffected); err != nil {
		t.Fatal(err)
	}
	// The node replaces profile management endpoints/secrets and authenticates its callers.
	response, err := http.Get("http://" + h.engine.ClashAddr() + "/connections")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != 401 {
		t.Fatalf("unauthenticated Clash status: %d", response.StatusCode)
	}
	entries, err := h.app.OnlineConnections(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	seen := false
	for _, entry := range entries {
		if entry.Metadata.User == "1" && entry.Metadata.SourceIP == "127.0.0.1" {
			seen = true
		}
	}
	if !seen {
		t.Fatal("authenticated online/IP query lost identity")
	}
	counters, err := h.app.QueryUserCounters(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	seen = false
	for _, counter := range counters {
		if strings.Contains(counter.Name, "user>>>1>>>") && counter.Value >= 4 {
			seen = true
		}
	}
	if !seen {
		t.Fatal("native user traffic missing")
	}
	outboundStats, err := h.app.Query(context.Background(), []string{"outbound>>>"}, false)
	if err != nil {
		t.Fatal(err)
	}
	seenOutbound := false
	for _, counter := range outboundStats {
		if strings.Contains(counter.Name, "outbound>>>direct>>>") && counter.Value >= 4 {
			seenOutbound = true
		}
	}
	if !seenOutbound {
		t.Fatalf("native outbound traffic missing from v2ray_api stats: %#v", outboundStats)
	}
	combinedRec := h.call("POST", "/node/stats/get-combined-stats", map[string]any{"reset": false})
	var combined struct {
		Response struct {
			Outbounds []struct {
				Outbound string `json:"outbound"`
				Uplink   int64  `json:"uplink"`
				Downlink int64  `json:"downlink"`
			} `json:"outbounds"`
		} `json:"response"`
	}
	if err := json.Unmarshal(combinedRec.Body.Bytes(), &combined); err != nil {
		t.Fatal(err)
	}
	foundCombined := false
	for _, ob := range combined.Response.Outbounds {
		if ob.Outbound == "direct" && ob.Uplink >= 4 && ob.Downlink >= 4 {
			foundCombined = true
		}
	}
	if !foundCombined {
		t.Fatalf("combined-stats endpoint did not expose native outbound counters: %s", combinedRec.Body.String())
	}
	before, generation := h.state.Snapshot()
	raw := h.state.RawConfig()
	invalids := []struct {
		name, want string
		change     func(map[string]any)
	}{
		{"unknown-schema", "unknown", func(c map[string]any) { c["xray_only_field"] = true }},
		{"invalid-certificate", "invalid TLS", func(c map[string]any) { nativeInbound(c)["tls"].(map[string]any)["certificate"] = "bad" }},
		{"unsupported-inbound", "not managed", func(c map[string]any) { nativeInbound(c)["type"] = "trojan" }},
		{"duplicate-password", "duplicate", func(c map[string]any) {
			nativeInbound(c)["users"].([]any)[1].(map[string]any)["password"] = testutil.UUID1
		}},
		{"invalid-uuid", "invalid VLESS UUID", func(c map[string]any) {
			nativeInbound(c)["type"] = "vless"
			nativeInbound(c)["users"] = []any{map[string]any{"name": "1", "uuid": "not-a-uuid"}}
		}},
	}
	for _, tc := range invalids {
		t.Run(tc.name, func(t *testing.T) {
			c := cloneConfig(t, h.config)
			tc.change(c)
			h.start(c, "singbox", false, tc.want)
			after, g := h.state.Snapshot()
			if g != generation || !reflect.DeepEqual(before, after) || !bytes.Equal(raw, h.state.RawConfig()) {
				t.Fatal("failed preflight committed state")
			}
			if err := testutil.Ping(active); err != nil {
				t.Fatal("failed preflight interrupted old stream", err)
			}
		})
	}
	// Native JSON never auto-selects native mode on the legacy path.
	h.start(h.config, "", false, "transpile")
	if err = testutil.Ping(active); err != nil {
		t.Fatal("mixed format stopped running core")
	}
	h.rotate(testutil.UUID3)
	if err = testutil.Ping(active); err == nil {
		t.Fatal("rotated active session survived")
	}
	fresh := testutil.NewClient(t, h.port, testutil.UUID3)
	if err = fresh.RoundTrip(destination); err != nil {
		t.Fatal(err)
	}
	view := h.call("GET", "/internal/get-config", nil)
	if view.Header().Get("X-Config-Format") != "singbox" || strings.Contains(view.Body.String(), h.engine.ClashSecret()) || strings.Contains(view.Body.String(), testutil.UUID1) || !strings.Contains(view.Body.String(), testutil.UUID3) {
		t.Fatalf("native config view is stale or leaks injected secret: %s", view.Body.String())
	}
	h.start(h.config, "singbox", false, "") // Identical original full push restores its credentials.
	if err = fresh.RoundTrip(destination); err == nil {
		t.Fatal("full push did not revoke changed password")
	}
	if err = user1.RoundTrip(destination); err != nil {
		t.Fatal(err)
	}
	if err = testutil.Ping(unaffected); err != nil || other.Dials.Load() != 1 {
		t.Fatal("user-only full push restarted unaffected stream")
	}
	h.rotate(testutil.UUID3)
	previous, previousGeneration := h.state.Snapshot()
	previousRaw := h.state.RawConfig()
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	broken := cloneConfig(t, h.config)
	nativeInbound(broken)["listen_port"] = busy.Addr().(*net.TCPAddr).Port
	h.start(broken, "singbox", false, "rolled back")
	current, currentGeneration := h.state.Snapshot()
	if !h.engine.IsRunning() || currentGeneration != previousGeneration || !reflect.DeepEqual(previous, current) || !bytes.Equal(previousRaw, h.state.RawConfig()) {
		t.Fatal("failed full push corrupted committed state")
	}
	restored := testutil.NewClient(t, h.port, testutil.UUID3)
	if err = restored.RoundTrip(destination); err != nil {
		t.Fatal("rollback lost latest incremental users", err)
	}
	old := testutil.NewClient(t, h.port, testutil.UUID1)
	if err = old.RoundTrip(destination); err == nil {
		t.Fatal("rollback restored stale initial credentials")
	}
	// Authorized Clash DELETE uses the same secret (App drop skips loopback by policy).
	conn, err := restored.Open(destination)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err = testutil.Ping(conn); err != nil {
		t.Fatal(err)
	}
	entries, err = h.app.OnlineConnections(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, entry := range entries {
		if entry.Metadata.User == "1" {
			ids = append(ids, entry.ID)
		}
	}
	if len(ids) == 0 {
		t.Fatal("no connections to close")
	}
	if _, err = singbox.CloseConnections(context.Background(), h.engine.ClashAddr(), ids, h.engine.ClashSecret()); err != nil {
		t.Fatal(err)
	}
	if err = testutil.Ping(conn); err == nil {
		t.Fatal("authenticated Clash DELETE did not close stream")
	}
	h.start(h.config, "singbox", true, "")
	if err = testutil.Ping(unaffected); err == nil {
		t.Fatal("forced full push did not restart listeners")
	}
	if err = testutil.NewClient(t, h.port, testutil.UUID1).RoundTrip(destination); err != nil {
		t.Fatal(err)
	}
	// A real native route change must affect routing, not disappear in translation.
	blocked := cloneConfig(t, h.config)
	blocked["route"].(map[string]any)["rules"] = []any{map[string]any{"ip_cidr": []any{"127.0.0.1/32"}, "action": "reject"}}
	h.start(blocked, "singbox", false, "")
	if err = testutil.NewClient(t, h.port, testutil.UUID1).RoundTrip(destination); err == nil {
		t.Fatal("native route rule was ignored")
	}
	h.start(h.config, "singbox", false, "")
	if err = testutil.NewClient(t, h.port, testutil.UUID1).RoundTrip(destination); err != nil {
		t.Fatal("failed to restore native route", err)
	}
	// Explicit untagged outbound ("0") must also report combined outbound traffic.
	untaggedCfg := cloneConfig(t, h.config)
	untaggedCfg["outbounds"] = []any{map[string]any{"type": "direct"}}
	delete(untaggedCfg["route"].(map[string]any), "final")
	h.start(untaggedCfg, "singbox", false, "")
	if err = testutil.NewClient(t, h.port, testutil.UUID1).RoundTrip(destination); err != nil {
		t.Fatal("untagged outbound traffic failed", err)
	}
	untaggedRec := h.call("POST", "/node/stats/get-combined-stats", map[string]any{"reset": true})
	var untaggedCombined struct {
		Response struct {
			Outbounds []struct {
				Outbound string `json:"outbound"`
				Uplink   int64  `json:"uplink"`
				Downlink int64  `json:"downlink"`
			} `json:"outbounds"`
		} `json:"response"`
	}
	if err := json.Unmarshal(untaggedRec.Body.Bytes(), &untaggedCombined); err != nil {
		t.Fatal(err)
	}
	foundUntagged := false
	for _, ob := range untaggedCombined.Response.Outbounds {
		if ob.Outbound == "0" && ob.Uplink >= 4 && ob.Downlink >= 4 {
			foundUntagged = true
		}
	}
	if !foundUntagged {
		t.Fatalf("untagged explicit outbound was not counted in combined-stats: %s", untaggedRec.Body.String())
	}
}

func TestNativeVLESSAndEmptySSWithLegacyFormatSwitch(t *testing.T) {
	h := newNativeHarness(t)
	ssPort := testutil.Port(t)
	key := base64.StdEncoding.EncodeToString([]byte("1234567890123456"))
	password := base64.StdEncoding.EncodeToString([]byte("abcdefghijklmnop"))
	dest := testutil.Echo(t)
	dialSS128 := func(secret string) error {
		rawConn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", ssPort), time.Second)
		if err != nil {
			return err
		}
		defer rawConn.Close()
		_ = rawConn.SetDeadline(time.Now().Add(time.Second))
		ss, err := shadowaead_2022.NewWithPassword("2022-blake3-aes-128-gcm", secret, nil)
		if err != nil {
			return err
		}
		sc, err := ss.DialConn(rawConn, M.ParseSocksaddr(dest))
		if err != nil {
			return err
		}
		defer sc.Close()
		return testutil.Ping(sc)
	}
	cfg := cloneConfig(t, h.config)
	cfg["inbounds"] = []any{
		map[string]any{"type": "vless", "tag": "vl", "listen": "127.0.0.1", "listen_port": h.port, "users": []any{map[string]any{"name": "1", "uuid": testutil.UUID1, "flow": ""}}},
		map[string]any{"type": "shadowsocks", "tag": "ss", "listen": "127.0.0.1", "listen_port": ssPort, "method": "2022-blake3-aes-128-gcm", "password": key, "users": []any{}},
	}
	h.start(cfg, "singbox", false, "")
	// Initial 0-user native SS2022 runs in single-password PSK mode.
	if err := dialSS128(key); err != nil {
		t.Fatalf("0-user native SS2022 did not accept single-password PSK: %v", err)
	}
	// Native reconciliation omits unrelated protocol credentials, even when
	// users of different protocols share a batch, and promotes 0-user SS to EIH.
	rec := h.call("POST", "/node/handler/add-users", map[string]any{"users": []any{
		map[string]any{"userData": map[string]any{"userId": "1", "vlessUuid": testutil.UUID1}, "inboundData": []any{map[string]any{"type": "vless", "tag": "vl", "flow": ""}}},
		map[string]any{"userData": map[string]any{"userId": "2", "ssPassword": "abcdefghijklmnop"}, "inboundData": []any{map[string]any{"type": "shadowsocks22", "tag": "ss"}}},
	}})
	var applied struct{ Response struct{ Success bool } }
	if err := json.Unmarshal(rec.Body.Bytes(), &applied); err != nil || !applied.Response.Success {
		t.Fatal("node rejected scoped credentials", err)
	}
	snapshot, _ := h.state.Snapshot()
	if user := snapshot["ss"].Users["2"]; user.Credential != password || user.HashUUID != "" {
		t.Fatal("SS-only user must authenticate without a UUID alias")
	}
	if snapshot["vl"].Users["1"].Flow != "" {
		t.Fatal("native empty flow forced to Vision")
	}
	raw, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", h.port), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	vl, err := vless.NewClient(testutil.UUID1, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	vc, err := vl.DialConn(raw, M.ParseSocksaddr(dest))
	if err != nil {
		t.Fatal(err)
	}
	if err = testutil.Ping(vc); err != nil {
		t.Fatal("native VLESS empty flow traffic", err)
	}
	if err = dialSS128(key + ":" + password); err != nil {
		t.Fatal("native empty SS not promoted to multi-user EIH", err)
	}
	if err = dialSS128(key); err == nil {
		t.Fatal("promoted native SS still accepted bare PSK")
	}
	view := h.call("GET", "/internal/get-config", nil)
	var viewed map[string]any
	if err = json.Unmarshal(view.Body.Bytes(), &viewed); err != nil {
		t.Fatal(err)
	}
	ssView := viewed["inbounds"].([]any)[1].(map[string]any)
	if ssView["managed"] == true || len(ssView["users"].([]any)) != 1 {
		t.Fatal("native getter produced invalid SS user list")
	}
	legacy := map[string]any{"inbounds": []any{map[string]any{"protocol": "shadowsocks", "tag": "ss", "listen": "127.0.0.1", "port": ssPort, "settings": map[string]any{"method": "2022-blake3-aes-128-gcm", "password": key, "clients": []any{map[string]any{"email": "1", "password": password}}}}}}
	h.start(legacy, "", false, "")
	if h.state.Format() != contract.XrayConfig {
		t.Fatal("legacy format not restored")
	}
	legacyClashResp, err := http.Get("http://" + h.engine.ClashAddr() + "/connections")
	if err != nil {
		t.Fatal(err)
	}
	_ = legacyClashResp.Body.Close()
	if legacyClashResp.StatusCode != 401 {
		t.Fatalf("legacy transpiled Clash API was left unauthenticated: %d", legacyClashResp.StatusCode)
	}
	view = h.call("GET", "/internal/get-config", nil)
	var legacyView map[string]any
	_ = json.Unmarshal(view.Body.Bytes(), &legacyView)
	if view.Header().Get("X-Config-Format") != "xray" || !reflect.DeepEqual(legacyView, cloneConfig(t, legacy)) {
		t.Fatal("legacy config getter shape changed")
	}
	h.start(cfg, "singbox", false, "")
	snapshot, _ = h.state.Snapshot()
	if _, managed := snapshot["ss"]; h.state.Format() != contract.SingBoxConfig || managed {
		t.Fatal("format switch retained legacy users on 0-user native SS")
	}
	if err = dialSS128(key); err != nil {
		t.Fatalf("0-user native SS did not restore single-password PSK after format switch: %v", err)
	}
}

func TestNativeRollbackFailureReportsOfflineAndFullPushRecovers(t *testing.T) {
	h := newNativeHarness(t)
	original := cloneConfig(t, h.config)
	certDir := t.TempDir()
	h.app.SetAllowedCertDirs([]string{certDir})
	tlsOptions := nativeInbound(h.config)["tls"].(map[string]any)
	var certificatePath string
	for _, field := range []string{"certificate", "key"} {
		path := filepath.Join(certDir, field+".pem")
		if err := os.WriteFile(path, []byte(tlsOptions[field].([]string)[0]), 0600); err != nil {
			t.Fatal(err)
		}
		delete(tlsOptions, field)
		tlsOptions[field+"_path"] = path
		if field == "certificate" {
			certificatePath = path
		}
	}
	h.start(h.config, "singbox", false, "")
	before, generation := h.state.Snapshot()
	// Make the saved config unavailable only at rollback time, after the old
	// instance has already loaded its certificate into memory.
	if err := os.Remove(certificatePath); err != nil {
		t.Fatal(err)
	}
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	broken := cloneConfig(t, original)
	nativeInbound(broken)["listen_port"] = busy.Addr().(*net.TCPAddr).Port
	h.start(broken, "singbox", false, "core is offline")
	after, g := h.state.Snapshot()
	if h.engine.IsRunning() || generation != g || !reflect.DeepEqual(before, after) {
		t.Fatal("failed rollback misreported runtime or changed last successful state")
	}
	health := h.call("GET", "/node/xray/healthcheck", nil)
	var status struct {
		Response struct {
			Online bool `json:"xrayInternalStatusCached"`
		}
	}
	if err = json.Unmarshal(health.Body.Bytes(), &status); err != nil || status.Response.Online {
		t.Fatal("offline core reported healthy")
	}
	if err = h.app.UpdateUsers([]state.Update{{ID: "1"}}); err == nil {
		t.Fatal("offline user update reported success")
	}
	h.start(original, "singbox", false, "")
	if err = testutil.NewClient(t, h.port, testutil.UUID1).RoundTrip(testutil.Echo(t)); err != nil {
		t.Fatal("full push did not recover offline core", err)
	}
}
