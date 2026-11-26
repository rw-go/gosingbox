package controller

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rwnode/rwnode-gosingbox/internal/app"
	"github.com/rwnode/rwnode-gosingbox/internal/contract"
	"github.com/rwnode/rwnode-gosingbox/internal/singbox"
	"github.com/rwnode/rwnode-gosingbox/internal/state"
)

func capabilityTestMux(t *testing.T) (*http.ServeMux, *state.State) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	st := state.New()
	a := app.New(logger, singbox.NewEngine(singbox.Options{}), st, 5000, false)
	t.Cleanup(a.Stop)
	mux := http.NewServeMux()
	NewXray(a, logger).Router(mux)
	NewHandler(a, logger).Router(mux)
	return mux, st
}

func TestCapabilitiesReportOnlyImplementedPaths(t *testing.T) {
	mux, _ := capabilityTestMux(t)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/node/capabilities", nil))
	var response struct {
		Response contract.Capabilities `json:"response"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	caps := response.Response
	if caps.StaticShadowsocks2022 != contract.NativeConfigAvailable {
		t.Fatal("fixed-password SS2022 capability does not match native support")
	}
	if caps.DynamicShadowsocks2022 != contract.NativeConfigAvailable {
		t.Fatal("dynamic SS2022 capability does not match native support")
	}
	if caps.AnyTLSSharedListener != contract.NativeConfigAvailable {
		t.Fatal("shared AnyTLS listener capability does not match native support")
	}
	if strings.Contains(rec.Body.String(), `"dynamicShadowsocks2022":true`) != contract.NativeConfigAvailable {
		t.Fatalf("unexpected dynamicShadowsocks2022 JSON serialization: %s", rec.Body.String())
	}
	if rec.Code != http.StatusOK || caps.ContractVersion != 1 || caps.RuntimeCore != "singbox" {
		t.Fatalf("unexpected capabilities: %s", rec.Body.String())
	}
	if !caps.Accepts(contract.XrayConfig) || caps.Accepts(contract.SingBoxConfig) != contract.NativeConfigAvailable || caps.Manages("anytls") != contract.NativeConfigAvailable {
		t.Fatalf("unimplemented capabilities advertised: %+v", caps)
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/node/capabilities", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d", rec.Code)
	}
}

func TestStartConfigFormatCompatibility(t *testing.T) {
	nativeError := "config format is not supported"
	if contract.NativeConfigAvailable {
		nativeError = "native config needs at least one managed inbound"
	}
	for _, tc := range []struct {
		name, field string
		status      int
		errorText   string
	}{
		{"legacy", "", 200, "no supported inbound"},
		{"explicit-xray", `"coreType":"xray",`, 200, "no supported inbound"},
		{"singbox", `"coreType":"singbox",`, 200, nativeError},
		{"unknown", `"coreType":"other",`, 400, "invalid request body"},
		{"null", `"coreType":null,`, 400, "invalid request body"},
		{"empty", `"coreType":"",`, 400, "invalid request body"},
		{"number", `"coreType":1,`, 400, "invalid request body"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mux, st := capabilityTestMux(t)
			previous := []byte(`{"previous":"config"}`)
			st.Commit(previous, state.Snapshot{}, contract.XrayConfig)
			rec := httptest.NewRecorder()
			body := "{" + tc.field + `"internals":{},"xrayConfig":{"inbounds":[]}}`
			mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/node/xray/start", strings.NewReader(body)))
			if rec.Code != tc.status || !strings.Contains(rec.Body.String(), tc.errorText) {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			if !bytes.Equal(previous, st.RawConfig()) {
				t.Fatal("rejected request modified configuration")
			}
		})
	}
}

func TestUnsupportedUserRequestsHaveNoPartialSideEffects(t *testing.T) {
	for _, tc := range []struct{ name, path, body string }{
		{"single", "/node/handler/add-user", `{"hashData":{"vlessUuid":"new","prevVlessUuid":"old"},"data":[{"type":"vless","username":"1001","uuid":"new"},{"type":"anytls","username":"1001","password":"new"}]}`},
		{"bulk", "/node/handler/add-users", `{"users":[{"inboundData":[{"type":"vless","tag":"a"}],"userData":{"userId":"1001","vlessUuid":"new"}},{"inboundData":[{"type":"anytls","tag":"b"}],"userData":{"userId":"1002","vlessUuid":"other"}}]}`},
		{"unknown", "/node/handler/add-user", `{"data":[{"type":"unknown"}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mux, st := capabilityTestMux(t)
			st.Commit([]byte(`{}`), state.Snapshot{"a": {Protocol: "vless", Users: map[string]state.User{"1001": {ID: "1001", Credential: "old"}}}}, contract.XrayConfig)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body)))
			var result struct {
				Response struct {
					Success bool   `json:"success"`
					Error   string `json:"error"`
				} `json:"response"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if rec.Code != 200 || result.Response.Success || result.Response.Error == "" {
				t.Fatalf("unexpected response: %s", rec.Body.String())
			}
			snapshot, _ := st.Snapshot()
			users := snapshot["a"].Users
			if len(users) != 1 || users["1001"].Credential != "old" {
				t.Fatalf("partial user mutation: %+v", users)
			}
		})
	}
}
