//go:build with_v2ray_api && with_clash_api

package controller

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
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

type loopbackACMEServer struct {
	server    *httptest.Server
	caCert    *x509.Certificate
	caKey     *ecdsa.PrivateKey
	caPEM     []byte
	serial    atomic.Int64
	expiring  atomic.Bool

	mu    sync.Mutex
	certs map[int64][]byte
}

func newLoopbackACMEServer(t *testing.T) *loopbackACMEServer {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Loopback ACME Root CA"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	s := &loopbackACMEServer{
		caCert: caCert,
		caKey:  caKey,
		caPEM:  caPEM,
		certs:  map[int64][]byte{},
	}
	s.serial.Store(200)
	s.expiring.Store(true)

	var nonceSeq atomic.Int64
	setNonce := func(w http.ResponseWriter) {
		w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", nonceSeq.Add(1)))
	}
	decodeJWSPayload := func(r *http.Request) []byte {
		var jws struct {
			Payload string `json:"payload"`
		}
		if err := json.NewDecoder(r.Body).Decode(&jws); err != nil || jws.Payload == "" {
			return nil
		}
		raw, err := base64.RawURLEncoding.DecodeString(jws.Payload)
		if err != nil {
			return nil
		}
		return raw
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/directory", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"newNonce":   s.server.URL + "/new-nonce",
			"newAccount": s.server.URL + "/new-acct",
			"newOrder":   s.server.URL + "/new-order",
		})
	})
	mux.HandleFunc("/new-nonce", func(w http.ResponseWriter, r *http.Request) {
		setNonce(w)
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusNoContent)
		}
	})
	mux.HandleFunc("/new-acct", func(w http.ResponseWriter, _ *http.Request) {
		setNonce(w)
		w.Header().Set("Location", s.server.URL+"/acct/1")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "valid"})
	})
	mux.HandleFunc("/new-order", func(w http.ResponseWriter, r *http.Request) {
		payload := decodeJWSPayload(r)
		var req struct {
			Identifiers []map[string]string `json:"identifiers"`
		}
		_ = json.Unmarshal(payload, &req)
		id := s.serial.Add(1)
		setNonce(w)
		w.Header().Set("Location", fmt.Sprintf("%s/order/%d", s.server.URL, id))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":         "ready",
			"identifiers":    req.Identifiers,
			"authorizations": []string{},
			"finalize":       fmt.Sprintf("%s/finalize/%d", s.server.URL, id),
		})
	})
	mux.HandleFunc("/finalize/", func(w http.ResponseWriter, r *http.Request) {
		var id int64
		_, _ = fmt.Sscanf(strings.TrimPrefix(r.URL.Path, "/finalize/"), "%d", &id)
		payload := decodeJWSPayload(r)
		var req struct {
			CSR string `json:"csr"`
		}
		if err := json.Unmarshal(payload, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		csrDER, err := base64.RawURLEncoding.DecodeString(req.CSR)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		csr, err := x509.ParseCertificateRequest(csrDER)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		now := time.Now()
		notBefore := now.Add(-time.Hour)
		notAfter := now.Add(90 * 24 * time.Hour)
		if s.expiring.Load() {
			// Valid now, and within Certmagic's 1/3 lifetime renewal window.
			notBefore = now.Add(-89 * 24 * time.Hour)
			notAfter = now.Add(time.Hour)
		}
		leafTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(id),
			Subject:      csr.Subject,
			DNSNames:     csr.DNSNames,
			IPAddresses:  csr.IPAddresses,
			NotBefore:    notBefore,
			NotAfter:     notAfter,
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		if len(leafTemplate.DNSNames) == 0 && csr.Subject.CommonName != "" {
			leafTemplate.DNSNames = []string{csr.Subject.CommonName}
		}
		leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, s.caCert, csr.PublicKey, s.caKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		chainPEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), s.caPEM...)
		s.mu.Lock()
		s.certs[id] = chainPEM
		s.mu.Unlock()

		setNonce(w)
		w.Header().Set("Location", fmt.Sprintf("%s/order/%d", s.server.URL, id))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":      "valid",
			"finalize":    fmt.Sprintf("%s/finalize/%d", s.server.URL, id),
			"certificate": fmt.Sprintf("%s/cert/%d", s.server.URL, id),
		})
	})
	mux.HandleFunc("/cert/", func(w http.ResponseWriter, r *http.Request) {
		var id int64
		_, _ = fmt.Sscanf(strings.TrimPrefix(r.URL.Path, "/cert/"), "%d", &id)
		s.mu.Lock()
		chain := s.certs[id]
		s.mu.Unlock()
		setNonce(w)
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		_, _ = w.Write(chain)
	})

	s.server = httptest.NewTLSServer(mux)
	t.Cleanup(s.server.Close)
	return s
}

func peerCertSerial(port int, serverName string) (*big.Int, error) {
	dialer := &net.Dialer{Timeout: time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("127.0.0.1:%d", port), &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         serverName,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no peer certificates")
	}
	return certs[0].SerialNumber, nil
}

func TestNativeCertificateProviderConfinementRenewalAndLiveProtection(t *testing.T) {
	h := newNativeHarness(t)
	managedRoot := t.TempDir()
	outsideRoot := t.TempDir()
	h.app.SetAllowedCertDirs([]string{managedRoot})

	acmeSrv := newLoopbackACMEServer(t)
	sharedDir := filepath.Join(managedRoot, "acme-shared")
	inlineDir := filepath.Join(managedRoot, "acme-inline")

	// Also prepare a Let's Encrypt style intra-tree symlink PEM certificate.
	archiveDir := filepath.Join(managedRoot, "archive")
	liveDir := filepath.Join(managedRoot, "live")
	if err := os.MkdirAll(archiveDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(liveDir, 0o700); err != nil {
		t.Fatal(err)
	}
	pemFixture := testutil.TLS(t)
	for _, field := range []string{"certificate", "key"} {
		realPath := filepath.Join(archiveDir, field+"1.pem")
		if err := os.WriteFile(realPath, []byte(pemFixture[field].([]string)[0]), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join("..", "archive", field+"1.pem"), filepath.Join(liveDir, field+".pem")); err != nil {
			t.Fatal(err)
		}
	}

	sharedPort := h.port
	inlinePort := testutil.Port(t)
	pemPort := testutil.Port(t)
	echoDest := testutil.Echo(t)

	acmeProviderOpts := func(dir, domain string) map[string]any {
		return map[string]any{
			"type":                       "acme",
			"domain":                     []any{domain},
			"default_server_name":        domain,
			"data_directory":             dir,
			"provider":                   acmeSrv.server.URL + "/directory",
			"disable_http_challenge":     true,
			"disable_tls_alpn_challenge": true,
			"http_client": map[string]any{
				"tls": map[string]any{"insecure": true},
			},
		}
	}
	topProvider := acmeProviderOpts(sharedDir, "localhost")
	topProvider["tag"] = "shared-acme"

	validCfg := map[string]any{
		"log":                   map[string]any{"disabled": true},
		"certificate_providers": []any{topProvider},
		"inbounds": []any{
			map[string]any{
				"type": "anytls", "tag": "any-shared", "listen": "127.0.0.1", "listen_port": sharedPort,
				"tls":   map[string]any{"enabled": true, "server_name": "localhost", "certificate_provider": "shared-acme"},
				"users": []any{map[string]any{"name": "1", "password": testutil.UUID1}},
			},
			map[string]any{
				"type": "anytls", "tag": "any-inline", "listen": "127.0.0.1", "listen_port": inlinePort,
				"tls":   map[string]any{"enabled": true, "server_name": "inline.example.test", "certificate_provider": acmeProviderOpts(inlineDir, "inline.example.test")},
				"users": []any{map[string]any{"name": "1", "password": testutil.UUID1}},
			},
			map[string]any{
				"type": "anytls", "tag": "any-pem", "listen": "127.0.0.1", "listen_port": pemPort,
				"tls": map[string]any{
					"enabled":          true,
					"server_name":      "localhost",
					"certificate_path": filepath.Join(liveDir, "certificate.pem"),
					"key_path":         filepath.Join(liveDir, "key.pem"),
				},
				"users": []any{map[string]any{"name": "1", "password": testutil.UUID1}},
			},
		},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
		"route":     map[string]any{"final": "direct"},
	}
	h.start(validCfg, "singbox", false, "")

	// 1. Wait for initial ACME issuance into both confined managed directories (expiring=true).
	deadline := time.Now().Add(8 * time.Second)
	var initialShared, initialInline *big.Int
	for time.Now().Before(deadline) {
		s1, err1 := peerCertSerial(sharedPort, "localhost")
		s2, err2 := peerCertSerial(inlinePort, "inline.example.test")
		if err1 == nil && err2 == nil && s1.Int64() >= 200 && s2.Int64() >= 200 {
			initialShared, initialInline = s1, s2
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if initialShared == nil || initialInline == nil {
		s1, e1 := peerCertSerial(sharedPort, "localhost")
		s2, e2 := peerCertSerial(inlinePort, "inline.example.test")
		t.Fatalf("initial managed ACME obtain did not complete: shared=(%v,%v) inline=(%v,%v)", s1, e1, s2, e2)
	}
	for _, dir := range []string{sharedDir, inlineDir} {
		entries, err := os.ReadDir(filepath.Join(dir, "certificates"))
		if err != nil || len(entries) == 0 {
			t.Fatalf("expected Certmagic certificates persisted in managed dir %q, err=%v", dir, err)
		}
	}

	// 2. Switch ACME server to issue 90-day certs and force-restart node so both
	// providers load existing certificates from their managed directories and renew them.
	acmeSrv.expiring.Store(false)
	h.start(validCfg, "singbox", true, "")
	deadline = time.Now().Add(8 * time.Second)
	var renewed bool
	for time.Now().Before(deadline) {
		s1, err1 := peerCertSerial(sharedPort, "localhost")
		s2, err2 := peerCertSerial(inlinePort, "inline.example.test")
		if err1 == nil && err2 == nil && s1.Cmp(initialShared) > 0 && s2.Cmp(initialInline) > 0 {
			renewed = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !renewed {
		s1, e1 := peerCertSerial(sharedPort, "localhost")
		s2, e2 := peerCertSerial(inlinePort, "inline.example.test")
		t.Fatalf("managed ACME certificate renewal did not advance serials: before=(%v,%v) after=(%v/%v, %v/%v)", initialShared, initialInline, s1, e1, s2, e2)
	}

	sharedClient := testutil.NewClient(t, sharedPort, testutil.UUID1)
	pemClient := testutil.NewClient(t, pemPort, testutil.UUID1)
	for _, cl := range []*testutil.Client{sharedClient, pemClient} {
		if err := cl.RoundTrip(echoDest); err != nil {
			t.Fatalf("AnyTLS traffic failed: %v", err)
		}
	}
	// Also verify AnyTLS traffic on inline.example.test using matching TLS SNI.
	inlineTLSConn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", fmt.Sprintf("127.0.0.1:%d", inlinePort), &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "inline.example.test",
	})
	if err != nil {
		t.Fatalf("inline AnyTLS TLS handshake failed: %v", err)
	}
	_ = inlineTLSConn.Close()

	// Keep a live AnyTLS stream open while pushing out-of-bounds certificate_provider configs.
	activeStream, err := sharedClient.Open(echoDest)
	if err != nil {
		t.Fatal(err)
	}
	defer activeStream.Close()
	if err := testutil.Ping(activeStream); err != nil {
		t.Fatal(err)
	}

	escapeLink := filepath.Join(managedRoot, "escape-provider-link")
	if err := os.Symlink(outsideRoot, escapeLink); err != nil {
		t.Fatal(err)
	}
	danglingLink := filepath.Join(managedRoot, "dangling-provider-link")
	if err := os.Symlink(filepath.Join(outsideRoot, "missing"), danglingLink); err != nil {
		t.Fatal(err)
	}

	beforeSnap, beforeGen := h.state.Snapshot()
	beforeRaw := h.state.RawConfig()

	outOfBounds := []struct {
		name   string
		want   string
		mutate func(c map[string]any)
	}{
		{
			name: "top-level-outside-dir",
			want: "outside allowed certificate provider directories",
			mutate: func(c map[string]any) {
				c["certificate_providers"].([]any)[0].(map[string]any)["data_directory"] = filepath.Join(outsideRoot, "acme")
			},
		},
		{
			name: "inline-outside-dir",
			want: "outside allowed certificate provider directories",
			mutate: func(c map[string]any) {
				c["inbounds"].([]any)[1].(map[string]any)["tls"].(map[string]any)["certificate_provider"].(map[string]any)["data_directory"] = filepath.Join(outsideRoot, "inline")
			},
		},
		{
			name: "etc-ssl-rejected",
			want: "outside allowed certificate provider directories",
			mutate: func(c map[string]any) {
				c["certificate_providers"].([]any)[0].(map[string]any)["data_directory"] = "/etc/ssl/acme"
			},
		},
		{
			name: "relative-dir",
			want: "clean absolute path",
			mutate: func(c map[string]any) {
				c["certificate_providers"].([]any)[0].(map[string]any)["data_directory"] = "relative/acme"
			},
		},
		{
			name: "dotdot-traversal",
			want: "clean absolute path",
			mutate: func(c map[string]any) {
				c["certificate_providers"].([]any)[0].(map[string]any)["data_directory"] = managedRoot + "/../escape"
			},
		},
		{
			name: "env-expansion",
			want: "environment variable",
			mutate: func(c map[string]any) {
				c["certificate_providers"].([]any)[0].(map[string]any)["data_directory"] = filepath.Join(managedRoot, "$HOME")
			},
		},
		{
			name: "escaping-symlink-dir",
			want: "resolves outside allowed certificate provider directories",
			mutate: func(c map[string]any) {
				c["certificate_providers"].([]any)[0].(map[string]any)["data_directory"] = filepath.Join(escapeLink, "certs")
			},
		},
		{
			name: "dangling-symlink-dir",
			want: "resolves outside allowed certificate provider directories",
			mutate: func(c map[string]any) {
				c["certificate_providers"].([]any)[0].(map[string]any)["data_directory"] = filepath.Join(danglingLink, "certs")
			},
		},
		{
			name: "unknown-provider-tag",
			want: "unknown provider",
			mutate: func(c map[string]any) {
				c["inbounds"].([]any)[0].(map[string]any)["tls"].(map[string]any)["certificate_provider"] = "nonexistent-tag"
			},
		},
		{
			name: "unmanaged-tailscale-provider",
			want: "not managed",
			mutate: func(c map[string]any) {
				c["certificate_providers"] = append(c["certificate_providers"].([]any), map[string]any{
					"type": "tailscale", "tag": "ts-cert", "endpoint": "ts-ep",
				})
			},
		},
	}

	for _, tc := range outOfBounds {
		t.Run(tc.name, func(t *testing.T) {
			badCfg := cloneConfig(t, validCfg)
			tc.mutate(badCfg)
			h.start(badCfg, "singbox", true, tc.want)
			afterSnap, afterGen := h.state.Snapshot()
			if !h.engine.IsRunning() || afterGen != beforeGen || !reflect.DeepEqual(beforeSnap, afterSnap) || !bytes.Equal(beforeRaw, h.state.RawConfig()) {
				t.Fatalf("rejected %s mutated node state or stopped engine", tc.name)
			}
			if err := testutil.Ping(activeStream); err != nil {
				t.Fatalf("rejected %s interrupted live AnyTLS stream: %v", tc.name, err)
			}
		})
	}
}

func TestNativeDynamicSS2022CapabilityAndModeTransitionsWithRestart(t *testing.T) {
	h := newNativeHarness(t)

	// 1. Verify GET /node/capabilities advertises both staticShadowsocks2022 and dynamicShadowsocks2022.
	capRec := h.call("GET", "/node/capabilities", nil)
	var capResp struct {
		Response contract.Capabilities `json:"response"`
	}
	if err := json.Unmarshal(capRec.Body.Bytes(), &capResp); err != nil {
		t.Fatal(err)
	}
	if !capResp.Response.StaticShadowsocks2022 || !capResp.Response.DynamicShadowsocks2022 {
		t.Fatalf("expected static & dynamic SS2022 capabilities, got %+v", capResp.Response)
	}

	echoDest := testutil.Echo(t)
	udpDest := startUDPEcho(t)
	managedPort := testutil.Port(t)
	fixedPort := testutil.Port(t)
	pskManaged := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x51}, 32))
	pskFixed := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x62}, 32))
	rawUserSS := "0123456789abcdef0123456789abcdef"
	userSSKey := base64.StdEncoding.EncodeToString([]byte(rawUserSS))

	// Mixed native profile payload as sent by Panel to a dynamicShadowsocks2022 node:
	// managed SS2022 preserves "users": [] at 0 users, while fixed relay omits "users".
	cfg := cloneConfig(t, h.config)
	cfg["inbounds"] = append(cfg["inbounds"].([]any),
		map[string]any{
			"type": "shadowsocks", "tag": "ss-managed",
			"listen": "127.0.0.1", "listen_port": managedPort,
			"method": "2022-blake3-aes-256-gcm", "password": pskManaged,
			"users": []any{},
		},
		map[string]any{
			"type": "shadowsocks", "tag": "ss-fixed",
			"listen": "127.0.0.1", "listen_port": fixedPort,
			"method": "2022-blake3-aes-256-gcm", "password": pskFixed,
		},
	)
	h.start(cfg, "singbox", false, "")

	checkPSKBoth := func(port int, secret string) {
		t.Helper()
		if err := fixedSSPing(port, secret, echoDest); err != nil {
			t.Fatalf("SS2022 TCP failed on port %d: %v", port, err)
		}
		if err := fixedSSPacketPing(port, secret, udpDest); err != nil {
			t.Fatalf("SS2022 UDP failed on port %d: %v", port, err)
		}
	}
	assertHealthy := func() {
		t.Helper()
		rec := h.call("GET", "/node/xray/healthcheck", nil)
		var hs struct {
			Response struct {
				IsAlive bool `json:"isAlive"`
				Online  bool `json:"xrayInternalStatusCached"`
			} `json:"response"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &hs); err != nil || !hs.Response.IsAlive || !hs.Response.Online {
			t.Fatalf("unhealthy node state: %s", rec.Body.String())
		}
	}

	// 2. Initial 0-user state: both ss-managed and ss-fixed operate as single-password PSK relays.
	checkPSKBoth(managedPort, pskManaged)
	checkPSKBoth(fixedPort, pskFixed)
	assertHealthy()

	// 3. 0 -> 1 transition via incremental /node/handler/add-users: ss-managed promotes to EIH, ss-fixed untouched.
	addRec := h.call("POST", "/node/handler/add-users", map[string]any{
		"users": []any{map[string]any{
			"userData": map[string]any{
				"userId":     "1",
				"vlessUuid":  testutil.UUID1,
				"ssPassword": rawUserSS,
			},
			"inboundData": []any{
				map[string]any{"type": "anytls", "tag": "any"},
				map[string]any{"type": "shadowsocks22", "tag": "ss-managed"},
			},
		}},
	})
	var addResp struct{ Response struct{ Success bool } }
	if err := json.Unmarshal(addRec.Body.Bytes(), &addResp); err != nil || !addResp.Response.Success {
		t.Fatalf("0 -> 1 add-users failed: %s", addRec.Body.String())
	}
	checkPSKBoth(managedPort, pskManaged+":"+userSSKey)
	if fixedSSPing(managedPort, pskManaged, echoDest) == nil {
		t.Fatal("promoted ss-managed accepted bare PSK")
	}
	checkPSKBoth(fixedPort, pskFixed)
	assertHealthy()

	// 4. Restart while ss-managed has 1 user: EIH auth and fixed PSK relay both survive cleanly.
	view1 := h.call("GET", "/internal/get-config", nil)
	var cfgWith1User map[string]any
	if err := json.Unmarshal(view1.Body.Bytes(), &cfgWith1User); err != nil {
		t.Fatal(err)
	}
	h.start(cfgWith1User, "singbox", true, "")
	checkPSKBoth(managedPort, pskManaged+":"+userSSKey)
	if fixedSSPing(managedPort, pskManaged, echoDest) == nil {
		t.Fatal("restarted 1-user ss-managed accepted bare PSK")
	}
	checkPSKBoth(fixedPort, pskFixed)
	assertHealthy()

	// 5. 1 -> 0 transition via incremental /node/handler/remove-users: closes active EIH stream and demotes to PSK.
	activeEIH, err := openSS2022Conn(managedPort, pskManaged+":"+userSSKey, echoDest)
	if err != nil {
		t.Fatal(err)
	}
	defer activeEIH.Close()
	if err := testutil.Ping(activeEIH); err != nil {
		t.Fatal(err)
	}

	rmRec := h.call("POST", "/node/handler/remove-users", map[string]any{
		"users": []any{map[string]any{"userId": "1"}},
	})
	var rmResp struct{ Response struct{ Success bool } }
	if err := json.Unmarshal(rmRec.Body.Bytes(), &rmResp); err != nil || !rmResp.Response.Success {
		t.Fatalf("1 -> 0 remove-users failed: %s", rmRec.Body.String())
	}
	if err := testutil.Ping(activeEIH); err == nil {
		t.Fatal("active EIH stream survived 1 -> 0 demotion")
	}
	if fixedSSPing(managedPort, pskManaged+":"+userSSKey, echoDest) == nil {
		t.Fatal("revoked EIH user accepted after 1 -> 0 demotion")
	}
	checkPSKBoth(managedPort, pskManaged)
	checkPSKBoth(fixedPort, pskFixed)
	assertHealthy()

	// 6. Restart at 0 users: managed inbound retains users: [] in get-config while fixed relay omits users,
	// and both run single-password PSK cleanly after restart.
	view0 := h.call("GET", "/internal/get-config", nil)
	var cfgWith0Users map[string]any
	if err := json.Unmarshal(view0.Body.Bytes(), &cfgWith0Users); err != nil {
		t.Fatal(err)
	}
	for _, item := range cfgWith0Users["inbounds"].([]any) {
		ib := item.(map[string]any)
		switch ib["tag"] {
		case "ss-managed":
			uList, ok := ib["users"].([]any)
			if !ok || len(uList) != 0 {
				t.Fatalf("expected ss-managed users=[] after 1->0 demotion, got %#v", ib["users"])
			}
		case "ss-fixed":
			if _, present := ib["users"]; present {
				t.Fatalf("ss-fixed gained users field: %#v", ib["users"])
			}
		}
	}
	h.start(cfgWith0Users, "singbox", true, "")
	checkPSKBoth(managedPort, pskManaged)
	checkPSKBoth(fixedPort, pskFixed)
	assertHealthy()
}
