package controller

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/rwnode/rwnode-gosingbox/internal/app"
)

// Internal handles the /internal/* routes (query-token authenticated). These mirror the
// Node.js InternalController: get-config returns the stored panel config and
// webhook accepts a POST (used by the Xray data plane; here a no-op since
// sing-box has no streaming webhook).
type Internal struct {
	app *app.App
	log *slog.Logger
}

func NewInternal(a *app.App, log *slog.Logger) *Internal {
	return &Internal{app: a, log: log}
}

// Router mounts /internal/* sub-paths.
func (i *Internal) Router(mux *http.ServeMux) {
	mux.HandleFunc("/internal/get-config", i.getConfig)
	mux.HandleFunc("/internal/webhook", i.webhook)
}

func (i *Internal) getConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, i.app.RawConfigJSON())
}

func (i *Internal) webhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}
	// Drain body; sing-box has no streaming webhook consumer, so this endpoint
	// reports a degraded result instead of a fixed success (torrent detection is
	// not implemented by the sing-box data plane; see UNIMPLEMENTED.md).
	_ = json.NewDecoder(r.Body).Decode(&struct{}{})
	i.log.Warn("internal webhook received but sing-box data plane has no webhook consumer")
	writeJSON(w, http.StatusNotImplemented, map[string]any{"ok": false, "error": "webhook not supported by sing-box data plane"})
}
