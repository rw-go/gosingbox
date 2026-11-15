//go:build with_v2ray_api && with_clash_api

package controller

import (
	"encoding/json"
	"fmt"
	"github.com/rwnode/rwnode-gosingbox/internal/contract"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rwnode/rwnode-gosingbox/internal/app"
	"github.com/rwnode/rwnode-gosingbox/internal/singbox"
	"github.com/rwnode/rwnode-gosingbox/internal/state"
	"github.com/rwnode/rwnode-gosingbox/internal/testutil"
)

func TestAnyTLSAuthorizationLifecycleThroughHandlers(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ports := []int{testutil.Port(t), testutil.Port(t)}
	cfg := map[string]any{"log": map[string]any{"disabled": true}, "inbounds": []any{}, "outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}}}
	tlsOptions := testutil.TLS(t)
	for i, tag := range []string{"a", "b"} {
		cfg["inbounds"] = append(cfg["inbounds"].([]any), map[string]any{"type": "anytls", "tag": tag, "listen": "127.0.0.1", "listen_port": ports[i], "tls": tlsOptions, "users": []any{map[string]any{"name": "1", "password": testutil.UUID1}, map[string]any{"name": "2", "password": testutil.UUID2}}})
	}
	engine := singbox.NewEngine(singbox.Options{Logger: logger})
	if err := engine.ApplyConfig(cfg); err != nil {
		t.Fatal(err)
	}
	st := state.New()
	users, err := state.FromConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	st.Commit([]byte(`{"test":"prepared-native"}`), users, contract.SingBoxConfig)
	a := app.New(logger, engine, st, 5000, false)
	t.Cleanup(a.Stop)
	mux := http.NewServeMux()
	NewHandler(a, logger).Router(mux)
	call := func(path, body string, want bool) {
		t.Helper()
		r := httptest.NewRecorder()
		mux.ServeHTTP(r, httptest.NewRequest("POST", "/node/handler/"+path, strings.NewReader(body)))
		var result struct {
			Response struct {
				Success bool
				Error   string
			}
		}
		if err := json.Unmarshal(r.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if r.Code != 200 || result.Response.Success != want {
			t.Fatalf("%s: %s", path, r.Body.String())
		}
	}
	destination := testutil.Echo(t)
	oldA := testutil.NewClient(t, ports[0], testutil.UUID1)
	oldB := testutil.NewClient(t, ports[1], testutil.UUID1)
	other := testutil.NewClient(t, ports[0], testutil.UUID2)
	active, err := oldA.Open(destination)
	if err != nil {
		t.Fatal(err)
	}
	defer active.Close()
	if err = testutil.Ping(active); err != nil {
		t.Fatal(err)
	}
	for _, client := range []*testutil.Client{oldB, other} {
		if err := client.RoundTrip(destination); err != nil {
			t.Fatal(err)
		}
	}
	update := fmt.Sprintf(`{"hashData":{"vlessUuid":%q},"data":[{"type":"anytls","tag":"b","username":"1","password":%q}]}`, testutil.UUID1, testutil.UUID1)
	call("add-user", update, true)
	if err = testutil.Ping(active); err == nil {
		t.Fatal("revoked active stream still works")
	}
	if err = oldA.RoundTrip(destination); err == nil {
		t.Fatal("revoked session/new authentication accepted")
	}
	if err = oldB.RoundTrip(destination); err != nil || oldB.Dials.Load() != 1 {
		t.Fatalf("authorized session interrupted: %v dials=%d", err, oldB.Dials.Load())
	}
	if err = other.RoundTrip(destination); err != nil || other.Dials.Load() != 1 {
		t.Fatal("unaffected user interrupted")
	}
	// Idempotent retry must retain sessions.
	call("add-user", update, true)
	rotate := fmt.Sprintf(`{"affectedInboundTags":["a","b"],"users":[{"inboundData":[{"type":"anytls","tag":"b"}],"userData":{"userId":"1","hashUuid":%q,"vlessUuid":%q}}]}`, testutil.UUID3, testutil.UUID3)
	call("add-users", rotate, true)
	if err = oldB.RoundTrip(destination); err == nil {
		t.Fatal("old idle session/password survived rotation")
	}
	fresh := testutil.NewClient(t, ports[1], testutil.UUID3)
	if err = fresh.RoundTrip(destination); err != nil {
		t.Fatal(err)
	}
	// Bad second entry must not apply the otherwise valid first removal.
	before, _ := st.Snapshot()
	call("add-users", `{"users":[{"userData":{"userId":"2"},"inboundData":[]},{"userData":{"userId":"1"},"inboundData":[{"type":"anytls","tag":"missing"}]}]}`, false)
	after, _ := st.Snapshot()
	if len(after["a"].Users) != len(before["a"].Users) {
		t.Fatal("partial batch applied")
	}
	if err = other.RoundTrip(destination); err != nil {
		t.Fatal(err)
	}
	call("remove-user", fmt.Sprintf(`{"username":"1","hashData":{"vlessUuid":%q}}`, testutil.UUID3), true)
	if err = fresh.RoundTrip(destination); err == nil {
		t.Fatal("idle session survived removal")
	}
	call("remove-user", fmt.Sprintf(`{"username":"1","hashData":{"vlessUuid":%q}}`, testutil.UUID3), true)
	if err = other.RoundTrip(destination); err != nil || other.Dials.Load() != 1 {
		t.Fatal("unrelated session lost")
	}
}
