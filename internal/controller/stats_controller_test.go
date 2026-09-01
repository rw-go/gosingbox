package controller

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rwnode/rwnode-gosingbox/internal/app"
	"github.com/rwnode/rwnode-gosingbox/internal/singbox"
	"github.com/rwnode/rwnode-gosingbox/internal/state"
)

// TestSystemStatsReturnsOfficialErrorWhenDataPlaneDown guards the panel
// liveness-probe contract: when sing-box is not running, get-system-stats must
// return the FAILED_TO_GET_SYSTEM_STATS error (HTTP 500), not a 200 with a null
// xrayInfo. The panel treats the former as "disconnected -> start the node",
// while the latter is reported as "Required info is missing. Outdated version?"
// and never self-heals.
func TestSystemStatsReturnsOfficialErrorWhenDataPlaneDown(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	a := app.New(logger, singbox.NewEngine(singbox.Options{}), state.New(), 5000, false)
	s := NewStats(a, logger)

	req := httptest.NewRequest(http.MethodGet, "/node/stats/get-system-stats", nil)
	rec := httptest.NewRecorder()
	s.systemStats(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}

	var env errorEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode error envelope: %v", err)
	}
	if env.ErrorCode != "A010" {
		t.Fatalf("errorCode = %q, want A010", env.ErrorCode)
	}
	if env.Message != "Failed to get system stats" {
		t.Fatalf("message = %q, want %q", env.Message, "Failed to get system stats")
	}
	if env.Timestamp == "" || env.Path != "/node/stats/get-system-stats" {
		t.Fatalf("envelope missing timestamp/path: %+v", env)
	}
}
