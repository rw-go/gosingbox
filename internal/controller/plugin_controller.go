package controller

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/rwsbnode/gosingbox/internal/app"
	"github.com/rwsbnode/gosingbox/internal/nftables"
)

// Plugin handles /node/plugin/* routes (sync, torrent-blocker collect,
// nftables block/unblock/recreate). It mirrors the Node.js PluginController.
//
// Torrent detection itself is a data-plane concern that sing-box does not
// implement (no streaming webhook), so collectReports always returns an empty
// report list. The nftables endpoints delegate to the nft-backed manager and
// return accepted=false when the firewall backend is unavailable.
type Plugin struct {
	app *app.App
	log *slog.Logger
}

func NewPlugin(a *app.App, log *slog.Logger) *Plugin {
	return &Plugin{app: a, log: log}
}

// Router mounts /node/plugin/* sub-paths.
func (p *Plugin) Router(mux *http.ServeMux) {
	mux.HandleFunc("/node/plugin/sync", p.sync)
	mux.HandleFunc("/node/plugin/torrent-blocker/collect", p.collectReports)
	mux.HandleFunc("/node/plugin/nftables/block-ips", p.blockIPs)
	mux.HandleFunc("/node/plugin/nftables/unblock-ips", p.unblockIPs)
	mux.HandleFunc("/node/plugin/nftables/recreate-tables", p.recreateTables)
}

// sync accepts the plugin config push. The sing-box data plane has no plugin
// engine and no torrent detection; shared lists (IP/ASN) and the ingress/egress
// filters are resolved and applied to nftables, while torrent-blocker reports
// stay empty and connection-drop whitelisting has no effect.
func (p *Plugin) sync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}
	var body struct {
		Plugin *struct {
			Config app.PluginSpec `json:"config"`
			UUID   string         `json:"uuid"`
			Name   string         `json:"name"`
		} `json:"plugin"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusOK, envelope{Response: map[string]any{"accepted": false}})
		return
	}
	if body.Plugin == nil {
		// Empty plugin push: tear down the firewall table.
		_ = p.app.NftRecreateTables()
		writeJSON(w, http.StatusOK, envelope{Response: map[string]any{"accepted": true}})
		return
	}
	ok := p.app.SyncPlugins(body.Plugin.Config)
	writeJSON(w, http.StatusOK, envelope{Response: map[string]any{"accepted": ok}})
}

// collectReports returns an empty report list (no torrent detection).
func (p *Plugin) collectReports(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, envelope{Response: map[string]any{"reports": []any{}}})
}

// blockIPs blocks a list of {ip, timeout} entries.
func (p *Plugin) blockIPs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}
	var body struct {
		IPs []nftables.BlockEntry `json:"ips"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusOK, envelope{Response: map[string]any{"accepted": false}})
		return
	}
	ok := p.app.NftBlockIPs(body.IPs)
	writeJSON(w, http.StatusOK, envelope{Response: map[string]any{"accepted": ok}})
}

// unblockIPs removes IPs from the block sets.
func (p *Plugin) unblockIPs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}
	var body struct {
		IPs []string `json:"ips"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusOK, envelope{Response: map[string]any{"accepted": false}})
		return
	}
	ok := p.app.NftUnblockIPs(body.IPs)
	writeJSON(w, http.StatusOK, envelope{Response: map[string]any{"accepted": ok}})
}

// recreateTables rebuilds the firewall table.
func (p *Plugin) recreateTables(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}
	ok := p.app.NftRecreateTables()
	writeJSON(w, http.StatusOK, envelope{Response: map[string]any{"accepted": ok}})
}
