package controller

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"rwnode-singbox/internal/app"
)

// Internal handles the /internal/* routes (unauthenticated). These mirror the
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
	// Drain body; sing-box has no webhook consumers.
	_ = json.NewDecoder(r.Body).Decode(&struct{}{})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}