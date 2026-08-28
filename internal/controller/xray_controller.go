// Package controller implements the panel-facing HTTP endpoint handlers,
// mirroring the Node.js v3.3.2 controllers where applicable.
package controller

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"rwnode-singbox/internal/app"
)

// Xray handles /node/xray/* routes.
type Xray struct {
	app *app.App
	log *slog.Logger
}

func NewXray(a *app.App, log *slog.Logger) *Xray {
	return &Xray{app: a, log: log}
}

// Router mounts /node/xray/* sub-paths.
func (x *Xray) Router(mux *http.ServeMux) {
	mux.HandleFunc("/node/xray/start", x.start)
	mux.HandleFunc("/node/xray/stop", x.stop)
	mux.HandleFunc("/node/xray/healthcheck", x.health)
}

// StartXrayRequest is the body of POST /node/xray/start (panel pushes config).
type StartXrayRequest struct {
	Internals struct {
		ForceRestart bool `json:"forceRestart"`
	} `json:"internals"`
	XrayConfig json.RawMessage `json:"xrayConfig"`
}

func (x *Xray) start(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}
	var req StartXrayRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		x.log.Error("start: body decode failed", "error", err)
		writeJSON(w, http.StatusBadRequest, envelope{Response: map[string]any{
			"isStarted": false,
			"error":     "invalid request body",
		}})
		return
	}
	x.log.Debug("start: decoded request", "xrayConfigBytes", len(req.XrayConfig), "internals", fmt.Sprintf("%+v", req.Internals))
	if len(req.XrayConfig) == 0 {
		x.log.Error("start: xrayConfig is empty")
		writeJSON(w, http.StatusBadRequest, envelope{Response: map[string]any{
			"isStarted": false,
			"error":     "xrayConfig is empty",
		}})
		return
	}

	if err := x.app.Start(req.XrayConfig); err != nil {
		x.log.Error("start failed", "error", err)
		x.writeStartResponse(w, false, err.Error())
		return
	}
	x.log.Info("start: sing-box started successfully")
	x.writeStartResponse(w, true, "")
}

// writeStartResponse emits the panel's StartXrayCommand.ResponseSchema shape:
// { isStarted, version, error, nodeInformation:{version}, system:{info,stats} }.
func (x *Xray) writeStartResponse(w http.ResponseWriter, started bool, errMsg string) {
	sys := x.app.SystemStats()
	resp := map[string]any{
		"isStarted":       started,
		"version":         errOrNil(x.app.Version()),
		"error":           errOrNil(errMsg),
		"nodeInformation": map[string]any{"version": app.NodeVersion},
		"system":          sys,
	}
	writeJSON(w, http.StatusOK, envelope{Response: resp})
}

func (x *Xray) stop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}
	x.app.Stop()
	writeJSON(w, http.StatusOK, envelope{Response: map[string]any{
		"isStopped": true,
	}})
}

func (x *Xray) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}
	h := x.app.Health()
	writeJSON(w, http.StatusOK, envelope{Response: map[string]any{
		"isAlive":                  h.IsAlive,
		"xrayInternalStatusCached": h.IsXrayOnline,
		"xrayVersion":              errOrNil(h.Version),
		"nodeVersion":              h.NodeVersion,
	}})
}

func errOrNil(s string) any {
	if s == "" {
		return nil
	}
	return s
}

type envelope struct {
	Response any `json:"response"`
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeMethodNotAllowed(w http.ResponseWriter) {
	writeJSON(w, http.StatusMethodNotAllowed, envelope{Response: map[string]any{"error": "method not allowed"}})
}
