package controller

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/rwnode/rwnode-gosingbox/internal/app"
	"github.com/rwnode/rwnode-gosingbox/internal/singbox"
)

// Stats handles /node/stats/* routes.
type Stats struct {
	app *app.App
	log *slog.Logger
}

func NewStats(a *app.App, log *slog.Logger) *Stats {
	return &Stats{app: a, log: log}
}

// Router mounts /node/stats/* sub-paths.
func (s *Stats) Router(mux *http.ServeMux) {
	mux.HandleFunc("/node/stats/get-users-stats", s.usersStats)
	mux.HandleFunc("/node/stats/get-system-stats", s.systemStats)
	mux.HandleFunc("/node/stats/get-inbound-stats", s.inboundStats)
	mux.HandleFunc("/node/stats/get-outbound-stats", s.outboundStats)
	mux.HandleFunc("/node/stats/get-all-inbounds-stats", s.allInboundsStats)
	mux.HandleFunc("/node/stats/get-all-outbounds-stats", s.allOutboundsStats)
	mux.HandleFunc("/node/stats/get-combined-stats", s.combinedStats)
	mux.HandleFunc("/node/stats/get-user-ip-list", s.userIPList)
	mux.HandleFunc("/node/stats/get-users-ip-list", s.usersIPList)
	mux.HandleFunc("/node/stats/get-user-online-status", s.userOnlineStatus)
	mux.HandleFunc("/node/stats/get-geocheck", s.geocheck)
}

type statBody struct {
	Reset bool   `json:"reset"`
	Tag   string `json:"tag"`
	User  string `json:"user"`
	IP    string `json:"ip"`
}

func decodeStatBody(r *http.Request) (statBody, error) {
	var b statBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		return statBody{}, err
	}
	return b, nil
}

// result is a compact stat line (username/downlink/uplink).
func (s *Stats) usersStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}
	b, err := decodeStatBody(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, envelope{Response: map[string]any{"users": []any{}}})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	counters, err := s.app.QueryUserCounters(ctx, b.Reset)
	if err != nil {
		writeJSON(w, http.StatusOK, envelope{Response: map[string]any{"users": []any{}}})
		return
	}
	users := aggregateUsers(counters)
	if len(users) == 0 {
		users = []any{}
	}
	writeJSON(w, http.StatusOK, envelope{Response: map[string]any{"users": users}})
}

func (s *Stats) systemStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}

	// The panel uses get-system-stats as the node liveness probe: if it returns
	// HTTP 200 it marks the node connected, and if `xrayInfo` is null it reports
	// "Required info is missing. Outdated version?" WITHOUT ever starting the
	// node. Mirror the official node here — when the data plane is down, return
	// the FAILED_TO_GET_SYSTEM_STATS error (500) so the panel treats the node as
	// disconnected and pushes a start (self-healing on fresh installs).
	if !s.app.IsOnline() {
		s.log.Debug("system stats: sing-box not running")
		writeOfficialError(w, r, http.StatusInternalServerError, "Failed to get system stats", "A010")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	sysStats, err := s.app.SysStats(ctx)
	if err != nil {
		s.log.Warn("system stats: xray stats unavailable", "error", err)
		writeOfficialError(w, r, http.StatusInternalServerError, "Failed to get system stats", "A010")
		return
	}

	sys := s.app.SystemStats()
	writeJSON(w, http.StatusOK, envelope{Response: map[string]any{
		"xrayInfo": sysStats,
		"plugins": map[string]any{
			"torrentBlocker": map[string]any{"reportsCount": 0},
		},
		"system": map[string]any{"stats": sys.Stats},
	}})
}

func (s *Stats) inboundStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}
	b, err := decodeStatBody(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, envelope{Response: map[string]any{"inbound": "", "downlink": 0, "uplink": 0}})
		return
	}
	res := s.queryAggregated(r, "inbound", b.Tag, b.Reset)
	writeJSON(w, http.StatusOK, envelope{Response: map[string]any{
		"inbound": b.Tag, "downlink": res.Downlink, "uplink": res.Uplink,
	}})
}

func (s *Stats) outboundStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}
	b, err := decodeStatBody(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, envelope{Response: map[string]any{"outbound": "", "downlink": 0, "uplink": 0}})
		return
	}
	res := s.queryAggregated(r, "outbound", b.Tag, b.Reset)
	writeJSON(w, http.StatusOK, envelope{Response: map[string]any{
		"outbound": b.Tag, "downlink": res.Downlink, "uplink": res.Uplink,
	}})
}

func (s *Stats) allInboundsStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}
	b, err := decodeStatBody(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, envelope{Response: map[string]any{"inbounds": []any{}}})
		return
	}
	writeJSON(w, http.StatusOK, envelope{Response: map[string]any{
		"inbounds": s.queryAll(r, "inbound", b.Reset),
	}})
}

func (s *Stats) allOutboundsStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}
	b, err := decodeStatBody(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, envelope{Response: map[string]any{"outbounds": []any{}}})
		return
	}
	writeJSON(w, http.StatusOK, envelope{Response: map[string]any{
		"outbounds": s.queryAll(r, "outbound", b.Reset),
	}})
}

func (s *Stats) combinedStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}
	b, err := decodeStatBody(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, envelope{Response: map[string]any{"inbounds": []any{}, "outbounds": []any{}}})
		return
	}
	writeJSON(w, http.StatusOK, envelope{Response: map[string]any{
		"inbounds":  s.queryAll(r, "inbound", b.Reset),
		"outbounds": s.queryAll(r, "outbound", b.Reset),
	}})
}

// UserIPList returns the online source IPs for a single user, each with the
// time it was last seen (newest connection start). Data comes from the
// sing-box clash API /connections.
func (s *Stats) userIPList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}
	var b struct {
		UserID string `json:"userId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeJSON(w, http.StatusBadRequest, envelope{Response: map[string]any{"ips": []any{}}})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	users, err := s.app.OnlineUsers(ctx)
	if err != nil {
		s.log.Debug("user ip list: clash api unavailable", "error", err)
		writeJSON(w, http.StatusOK, envelope{Response: map[string]any{"ips": []any{}}})
		return
	}

	ips := []any{}
	for _, u := range users {
		if u.UserName != b.UserID {
			continue
		}
		for _, ip := range u.IPs {
			ips = append(ips, map[string]any{
				"ip":       ip.IP,
				"lastSeen": ip.LastSeen.UTC().Format(time.RFC3339Nano),
			})
		}
	}
	writeJSON(w, http.StatusOK, envelope{Response: map[string]any{"ips": ips}})
}

func (s *Stats) usersIPList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	users, err := s.app.OnlineUsers(ctx)
	if err != nil {
		s.log.Debug("users ip list: clash api unavailable", "error", err)
		writeJSON(w, http.StatusOK, envelope{Response: map[string]any{"users": []any{}}})
		return
	}

	out := []any{}
	for _, u := range users {
		ips := []any{}
		for _, ip := range u.IPs {
			ips = append(ips, map[string]any{
				"ip":       ip.IP,
				"lastSeen": ip.LastSeen.UTC().Format(time.RFC3339Nano),
			})
		}
		out = append(out, map[string]any{"userId": u.UserName, "ips": ips})
	}
	writeJSON(w, http.StatusOK, envelope{Response: map[string]any{"users": out}})
}

func (s *Stats) userOnlineStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}
	var b struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeJSON(w, http.StatusBadRequest, envelope{Response: map[string]any{"isOnline": false}})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	users, err := s.app.OnlineUsers(ctx)
	if err != nil {
		s.log.Debug("user online status: clash api unavailable", "error", err)
		writeJSON(w, http.StatusOK, envelope{Response: map[string]any{"isOnline": false}})
		return
	}

	isOnline := false
	for _, u := range users {
		if u.UserName == b.Username {
			isOnline = true
			break
		}
	}
	writeJSON(w, http.StatusOK, envelope{Response: map[string]any{"isOnline": isOnline}})
}

func (s *Stats) geocheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}
	var b struct {
		IP        string `json:"ip"`
		Interface string `json:"interface"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeJSON(w, http.StatusBadRequest, envelope{Response: map[string]any{"error": "invalid request body"}})
		return
	}

	res, err := geocheckRun(b.IP, b.Interface)
	if err != nil {
		s.log.Warn("geocheck failed", "error", err)
		writeJSON(w, http.StatusOK, envelope{Response: map[string]any{
			"error": err.Error(),
		}})
		return
	}
	writeJSON(w, http.StatusOK, envelope{Response: res})
}

// errorEnvelope mirrors the official HttpExceptionFilter error shape the panel
// parses from 5xx responses: { timestamp, path, message, errorCode }.
type errorEnvelope struct {
	Timestamp string `json:"timestamp"`
	Path      string `json:"path"`
	Message   string `json:"message"`
	ErrorCode string `json:"errorCode"`
}

func writeOfficialError(w http.ResponseWriter, r *http.Request, code int, message, errorCode string) {
	writeJSON(w, code, errorEnvelope{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Path:      r.URL.Path,
		Message:   message,
		ErrorCode: errorCode,
	})
}

// queryAggregated queries one tag's traffic for inbound/outbound.
func (s *Stats) queryAggregated(r *http.Request, prefix, tag string, reset bool) statistical {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	counters, err := s.app.Query(ctx, []string{prefix + ">>>" + tag + ">>>"}, reset)
	if err != nil {
		return statistical{}
	}
	return aggregateSingleTag(prefix, tag, counters)
}

// queryAll aggregates all inbound/outbound tags.
func (s *Stats) queryAll(r *http.Request, prefix string, reset bool) []any {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	counters, err := s.app.Query(ctx, []string{prefix + ">>>"}, reset)
	if err != nil {
		return []any{}
	}
	return aggregateAll(prefix, counters)
}

type statistical struct {
	Inbound  string `json:"inbound,omitempty"`
	Outbound string `json:"outbound,omitempty"`
	Downlink int64  `json:"downlink"`
	Uplink   int64  `json:"uplink"`
}

// aggregateUsers turns per-user QueryStats counters into the panel's
// [{username,uplink,downlink}] shape, filtering zero-traffic users.
func aggregateUsers(counters []singbox.Counter) []any {
	byUser := map[string]*[2]int64{} // [uplink, downlink]
	for _, c := range counters {
		name := c.Name
		if !strings.HasPrefix(name, "user>>>") {
			continue
		}
		parts := strings.SplitN(strings.TrimPrefix(name, "user>>>"), ">>>", 2)
		if len(parts) != 2 {
			continue
		}
		user := parts[0]
		if user == "" {
			continue
		}
		u, ok := byUser[user]
		if !ok {
			u = &[2]int64{}
			byUser[user] = u
		}
		if strings.HasSuffix(parts[1], ">>>uplink") {
			u[0] += c.Value
		} else if strings.HasSuffix(parts[1], ">>>downlink") {
			u[1] += c.Value
		}
	}
	out := []any{}
	for user, v := range byUser {
		if v[0] == 0 && v[1] == 0 {
			continue
		}
		out = append(out, map[string]any{"username": user, "uplink": v[0], "downlink": v[1]})
	}
	return out
}

func aggregateSingleTag(prefix, tag string, counters []singbox.Counter) statistical {
	out := statistical{Downlink: 0, Uplink: 0}
	if prefix == "inbound" {
		out.Inbound = tag
	} else {
		out.Outbound = tag
	}
	for _, c := range counters {
		if !strings.HasPrefix(c.Name, prefix+">>>"+tag+">>>") {
			continue
		}
		if strings.HasSuffix(c.Name, ">>>uplink") {
			out.Uplink += c.Value
		} else if strings.HasSuffix(c.Name, ">>>downlink") {
			out.Downlink += c.Value
		}
	}
	return out
}

func aggregateAll(prefix string, counters []singbox.Counter) []any {
	type row struct {
		Tag      string `json:"-"`
		Downlink int64  `json:"downlink"`
		Uplink   int64  `json:"uplink"`
	}
	byTag := map[string]*row{}
	for _, c := range counters {
		parts := strings.Split(c.Name, ">>>")
		if len(parts) < 4 || parts[0] != prefix || parts[2] != "traffic" {
			continue
		}
		tag := parts[1]
		item, ok := byTag[tag]
		if !ok {
			item = &row{Tag: tag}
			byTag[tag] = item
		}
		if parts[3] == "uplink" {
			item.Uplink += c.Value
		} else if parts[3] == "downlink" {
			item.Downlink += c.Value
		}
	}
	out := []any{}
	for tag, item := range byTag {
		if prefix == "inbound" {
			out = append(out, map[string]any{"inbound": tag, "downlink": item.Downlink, "uplink": item.Uplink})
		} else {
			out = append(out, map[string]any{"outbound": tag, "downlink": item.Downlink, "uplink": item.Uplink})
		}
	}
	return out
}
