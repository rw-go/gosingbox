// Package app wires the panel-facing server, state, transpiler, and sing-box
// process together. It is the Go equivalent of the Node.js XrayService +
// UserChangePipelineService.
package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rwnode/rwnode-gosingbox/internal/asn"
	"github.com/rwnode/rwnode-gosingbox/internal/contract"
	"github.com/rwnode/rwnode-gosingbox/internal/nativeconfig"
	"github.com/rwnode/rwnode-gosingbox/internal/nftables"
	"github.com/rwnode/rwnode-gosingbox/internal/prestart"
	"github.com/rwnode/rwnode-gosingbox/internal/singbox"
	"github.com/rwnode/rwnode-gosingbox/internal/state"
	"github.com/rwnode/rwnode-gosingbox/internal/systemstats"
	"github.com/rwnode/rwnode-gosingbox/internal/transpiler"
)

// NodeVersion is the reported node version (set via ldflags at build time).
// Must be a bare semver — the panel parses this to decide node compatibility,
// and a suffix like "-go" is treated as an outdated/unknown version.
var NodeVersion = "3.4.1"

// webhookTimeout mirrors the official send-webhook util's WEBHOOK_TIMEOUT_MS.
const webhookTimeout = 5 * time.Second

// defaultIgnoredIPs mirrors the official node's DEFAULT_IGNORED_IPS: source
// addresses that are never torn down by drop-ips / drop-users-connections
// (loopback, unspecified, broadcast and their CIDR forms).
var defaultIgnoredIPs = map[string]struct{}{
	"::":              {},
	"::1":             {},
	"0.0.0.0":         {},
	"0.0.0.0/0":       {},
	"127.0.0.0/8":     {},
	"127.0.0.1":       {},
	"255.255.255.255": {},
}

// App is the top-level orchestrator.
type App struct {
	logger             *slog.Logger
	state              *state.State
	proc               *singbox.Engine
	cfg                *singbox.Options
	sys                *systemstats.Reader
	nft                *nftables.Manager
	asnIdx             *asn.Index
	configMu           sync.Mutex
	pendingRevocations map[string]struct{}

	// desired working config derived from the last panel push
	statsAddr string
	clashAddr string
	logLevel  string

	// preStart cleanupSockets config from the last plugin sync.
	preMu      sync.Mutex
	preCleanup *CleanupSocketsSpec
	// postStart webhook config from the last plugin sync (fires
	// service.core_started after every successful core start).
	postMu      sync.Mutex
	postWebhook *PostStartWebhookSpec
	// connection-drop whitelist from the last plugin sync (drop-ips / drop-users
	// skip whitelisted and default-ignored source IPs, mirroring the official
	// connection-drop state).
	dropMu        sync.Mutex
	dropWhitelist map[string]struct{}
}

// New creates an App around the embedded engine. The legacy debounce argument
// remains accepted for deployment compatibility; user requests apply synchronously.
func New(logger *slog.Logger, proc *singbox.Engine, st *state.State, _ int, acceptReplyTraffic bool) *App {
	nft := nftables.New(acceptReplyTraffic)
	if nft.Available() {
		if err := nft.CreateTable(); err != nil {
			logger.Warn("nftables table setup failed", "error", err)
		} else {
			logger.Info("nftables firewall ready")
		}
	} else {
		logger.Warn("nftables unavailable (no nft binary or no CAP_NET_ADMIN); plugin firewall endpoints degraded")
	}
	return &App{
		logger:             logger,
		pendingRevocations: map[string]struct{}{},
		proc:               proc,
		state:              st,
		sys:                systemstats.NewReader(),
		nft:                nft,
		statsAddr:          proc.StatsAddr(),
		clashAddr:          proc.ClashAddr(),
		logLevel:           proc.LogLevel(),
		dropWhitelist:      map[string]struct{}{},
	}
}

// Start transplies the panel config and applies it immediately (full push).
func (a *App) Start(raw []byte) error {
	return a.StartWithForce(raw, true)
}

// StartWithForce applies a panel config. Repeated identical starts reuse the
// running data plane unless the panel explicitly requests a restart.
//
// The config is parsed, transpiled and applied before any state is committed:
// on failure, the previous config/users/inbound-tags all remain intact.
func (a *App) StartWithForce(raw []byte, force bool) error {
	return a.StartConfig(raw, contract.XrayConfig, force)
}

// StartConfig dispatches explicit input formats; native input never enters the transpiler.
func (a *App) StartConfig(raw []byte, format contract.ConfigFormat, force bool) error {
	a.configMu.Lock()
	defer a.configMu.Unlock()

	format = format.WithDefault()
	var prepared map[string]any
	switch format {
	case contract.XrayConfig:
		res, err := transpiler.Transpile(raw, a.statsAddr, a.clashAddr, a.logLevel, nil, nil)
		if err != nil {
			return fmt.Errorf("transpile: %w", err)
		}
		prepared = res.Config
	case contract.SingBoxConfig:
		if !contract.NativeConfigAvailable {
			return fmt.Errorf("native config requires with_clash_api and with_v2ray_api build tags")
		}
		res, err := nativeconfig.Prepare(raw, nativeconfig.Management{StatsAddress: a.statsAddr, ClashAddress: a.clashAddr, ClashSecret: a.proc.ClashSecret()})
		if err != nil {
			return fmt.Errorf("prepare native config: %w", err)
		}
		prepared = res.Config
		if err = a.proc.ValidateConfig(prepared); err != nil {
			return fmt.Errorf("validate native config: %w", err)
		}
	default:
		return fmt.Errorf("unsupported config format: %q", format)
	}
	users, err := state.FromConfig(prepared)
	if err != nil {
		return err
	}
	if !force && a.state.Format() == format && a.proc.SameBase(prepared) {
		current, _ := a.state.Snapshot()
		if err = a.proc.ApplyUsers(users); err != nil {
			return err
		}
		a.queueRevocations(current, users)
	} else {
		a.runPreCleanup()
		if err = a.proc.ApplyConfigForFormat(prepared, format); err != nil {
			return err
		}
		clear(a.pendingRevocations)
	}
	a.state.Commit(raw, users, format)
	return a.flushRevocations()
}

// UpdateUsers serializes full authorization replacements with config changes.
// Success means applied; no delayed timer can replay an older generation.
func (a *App) UpdateUsers(updates []state.Update) error {
	a.configMu.Lock()
	defer a.configMu.Unlock()
	if !a.state.HasConfig() {
		return fmt.Errorf("no panel config available")
	}
	current, generation := a.state.Snapshot()
	if a.state.Format() == contract.XrayConfig {
		normalized := make([]state.Update, len(updates))
		for i, update := range updates {
			normalized[i] = update
			normalized[i].Memberships = append([]state.Membership(nil), update.Memberships...)
			for j, member := range normalized[i].Memberships {
				if member.Protocol == "vless" {
					normalized[i].Memberships[j].User.Flow = transpiler.NormalizeFlow(member.User.Flow)
				}
			}
		}
		updates = normalized
	}
	next, err := current.Replace(updates)
	if err != nil {
		return err
	}
	if err = a.proc.ApplyUsers(next); err != nil {
		return err
	}
	if err = a.state.CommitUsers(next, generation); err != nil {
		return err
	}
	a.queueRevocations(current, next)
	return a.flushRevocations()
}

func (a *App) queueRevocations(current, next state.Snapshot) {
	if a.pendingRevocations == nil {
		a.pendingRevocations = map[string]struct{}{}
	}
	for tag, ib := range current {
		if ib.Protocol == "anytls" {
			continue
		}
		for id, u := range ib.Users {
			newer, ok := next[tag].Users[id]
			if !ok || newer.Credential != u.Credential || newer.Flow != u.Flow {
				a.pendingRevocations[id] = struct{}{}
			}
		}
	}
}
func (a *App) flushRevocations() error {
	if len(a.pendingRevocations) == 0 {
		return nil
	}
	users := make([]string, 0, len(a.pendingRevocations))
	for id := range a.pendingRevocations {
		users = append(users, id)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := a.DropUsers(ctx, users); err != nil {
		return fmt.Errorf("users applied but active connection revocation pending: %w", err)
	}
	clear(a.pendingRevocations)
	return nil
}

func (a *App) Stop() { a.configMu.Lock(); defer a.configMu.Unlock(); a.proc.Shutdown() }

// Query runs QueryStats against the sing-box v2ray_api.
func (a *App) Query(ctx context.Context, patterns []string, reset bool) ([]singbox.Counter, error) {
	return a.proc.Query(ctx, patterns, reset)
}

// QueryUserCounters queries per-user traffic counters.
func (a *App) QueryUserCounters(ctx context.Context, reset bool) ([]singbox.Counter, error) {
	return a.proc.QueryUserStats(ctx, reset)
}

// SysStats returns sing-box runtime stats.
func (a *App) SysStats(ctx context.Context) (*singbox.SysStats, error) {
	return a.proc.Stats(ctx)
}

// OnlineConnections returns the connections currently online, queried from the
// sing-box clash API (/connections).
func (a *App) OnlineConnections(ctx context.Context) ([]singbox.ClashConnection, error) {
	return singbox.FetchOnlineConnections(ctx, a.clashAddr, a.proc.ClashSecret())
}

// DropIPs terminates every active connection whose source IP is in the given
// list, via the clash API DELETE /connections/:id endpoint. Whitelisted and
// default-ignored source IPs are skipped. Returns the number of connections
// closed.
func (a *App) DropIPs(ctx context.Context, ips []string) (int, error) {
	conns, err := a.OnlineConnections(ctx)
	if err != nil {
		return 0, err
	}
	set := make(map[string]struct{}, len(ips))
	for _, ip := range ips {
		set[ip] = struct{}{}
	}
	ids := make([]string, 0, len(conns))
	for _, c := range conns {
		if _, ok := set[c.Metadata.SourceIP]; !ok {
			continue
		}
		if a.isIgnoredIP(c.Metadata.SourceIP) {
			continue
		}
		ids = append(ids, c.ID)
	}
	return singbox.CloseConnections(ctx, a.clashAddr, ids, a.proc.ClashSecret())
}

// DropUsers terminates every active connection for the given users (panel
// email) via the clash API, skipping whitelisted/default-ignored source IPs.
// Returns the number of connections closed.
func (a *App) DropUsers(ctx context.Context, userIds []string) (int, error) {
	conns, err := a.OnlineConnections(ctx)
	if err != nil {
		return 0, err
	}
	set := make(map[string]struct{}, len(userIds))
	for _, u := range userIds {
		set[u] = struct{}{}
	}
	ids := make([]string, 0, len(conns))
	for _, c := range conns {
		if _, ok := set[c.Metadata.User]; !ok {
			continue
		}
		if a.isIgnoredIP(c.Metadata.SourceIP) {
			continue
		}
		ids = append(ids, c.ID)
	}
	return singbox.CloseConnections(ctx, a.clashAddr, ids, a.proc.ClashSecret())
}

// OnlineIP is one source IP currently served for a user, with the time it was
// last seen (the newest connection start time for that address).
type OnlineIP struct {
	IP       string
	LastSeen time.Time
}

// OnlineUser aggregates the current online connections per user. UserName is
// the panel user identifier (email), which is what the panel contract calls
// "userId" in the stats endpoints (matching Xray's user>>>{email}>>>online).
type OnlineUser struct {
	UserName string
	IPs      []OnlineIP
}

// OnlineUsers groups the current online connections (from the sing-box clash
// API /connections) by VLESS user name and resolves each to a panel userId.
func (a *App) OnlineUsers(ctx context.Context) ([]OnlineUser, error) {
	conns, err := singbox.FetchOnlineConnections(ctx, a.clashAddr, a.proc.ClashSecret())
	if err != nil {
		return nil, err
	}

	byUser := map[string]map[string]time.Time{}
	for _, c := range conns {
		name := c.Metadata.User
		ip := c.Metadata.SourceIP
		if name == "" || ip == "" {
			continue
		}
		ips := byUser[name]
		if ips == nil {
			ips = map[string]time.Time{}
			byUser[name] = ips
		}
		if prev, ok := ips[ip]; !ok || c.Start.After(prev) {
			ips[ip] = c.Start
		}
	}

	out := make([]OnlineUser, 0, len(byUser))
	for name, ips := range byUser {
		u := OnlineUser{UserName: name}
		for ip, ts := range ips {
			u.IPs = append(u.IPs, OnlineIP{IP: ip, LastSeen: ts})
		}
		out = append(out, u)
	}
	return out, nil
}

// SystemInfo returns node system info/stats for panel responses.
func (a *App) SystemStats() systemstats.System {
	return a.sys.System()
}

// NodeInfo is exposed for the health endpoint.
func (a *App) Health() singleHealth {
	status := a.proc.Status()
	return singleHealth{
		IsAlive:      true,
		IsXrayOnline: status.Up,
		Version:      status.Version,
		NodeVersion:  NodeVersion,
	}
}

// SingleHealth mirrors the GetNodeHealthCheck response model.
type singleHealth struct {
	IsAlive      bool   `json:"isAlive"`
	IsXrayOnline bool   `json:"xrayInternalStatusCached"`
	Version      string `json:"xrayVersion"`
	NodeVersion  string `json:"nodeVersion"`
}

// ToJSON is a helper (kept for parity with CLI driver).
func (a *App) ToJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// Version returns the current sing-box binary version (or empty).
func (a *App) Version() string {
	return a.proc.Version()
}

// IsOnline reports whether the sing-box child is running.
func (a *App) IsOnline() bool {
	return a.proc.IsRunning()
}

// ConfigView returns the submitted config in its original format. Native views
// include current managed users, but never expose the injected management secret.
func (a *App) ConfigView() (contract.ConfigFormat, map[string]any) {
	a.configMu.Lock()
	defer a.configMu.Unlock()
	format := a.state.Format()
	raw := a.state.RawConfig()
	if raw == nil {
		return format, map[string]any{}
	}
	config, err := nativeconfig.Decode(raw)
	if err != nil {
		return format, map[string]any{}
	}
	if format == contract.SingBoxConfig {
		users, _ := a.state.Snapshot()
		users.WriteConfig(config)
	}
	return format, config
}
func (a *App) RawConfigJSON() map[string]any { _, config := a.ConfigView(); return config }

// NftAvailable reports whether the nftables backend is usable.
func (a *App) NftAvailable() bool {
	return a.nft.Available()
}

// NftBlockIPs blocks a list of {ip, timeout} entries via nftables.
func (a *App) NftBlockIPs(entries []nftables.BlockEntry) bool {
	if !a.nft.Available() {
		return false
	}
	for _, e := range entries {
		if err := a.nft.BlockIP(e.IP, e.Timeout); err != nil {
			a.logger.Warn("nft block ip failed", "ip", e.IP, "error", err)
			return false
		}
	}
	return true
}

// NftUnblockIPs removes IPs from the torrent/ingress sets.
func (a *App) NftUnblockIPs(ips []string) bool {
	if err := a.nft.UnblockIPs(ips); err != nil {
		a.logger.Warn("nft unblock ips failed", "error", err)
		return false
	}
	return true
}

// NftRecreateTables rebuilds the firewall table.
func (a *App) NftRecreateTables() bool {
	if err := a.nft.CreateTable(); err != nil {
		a.logger.Warn("nft recreate tables failed", "error", err)
		return false
	}
	return true
}

// setPreCleanup caches the preStart cleanupSockets config from plugin sync.
func (a *App) setPreCleanup(spec *CleanupSocketsSpec) {
	a.preMu.Lock()
	a.preCleanup = spec
	a.preMu.Unlock()
}

// setPostStartWebhook caches the postStart webhook config from plugin sync.
func (a *App) setPostStartWebhook(spec *PostStartWebhookSpec) {
	a.postMu.Lock()
	a.postWebhook = spec
	a.postMu.Unlock()
}

// setDropWhitelist replaces the connection-drop whitelist (nil/empty clears it).
func (a *App) setDropWhitelist(ips []string) {
	m := make(map[string]struct{}, len(ips))
	for _, ip := range ips {
		if ip != "" {
			m[ip] = struct{}{}
		}
	}
	a.dropMu.Lock()
	a.dropWhitelist = m
	a.dropMu.Unlock()
}

// isIgnoredIP reports whether a source IP is default-ignored or whitelisted.
func (a *App) isIgnoredIP(ip string) bool {
	if _, ok := defaultIgnoredIPs[ip]; ok {
		return true
	}
	a.dropMu.Lock()
	_, ok := a.dropWhitelist[ip]
	a.dropMu.Unlock()
	return ok
}

// runPreCleanup executes the preStart cleanupSockets stage before the sing-box
// (re)start, mirroring the official node's restart sequence.
func (a *App) runPreCleanup() {
	a.preMu.Lock()
	spec := a.preCleanup
	a.preMu.Unlock()
	if spec == nil || !spec.Enabled {
		return
	}
	if removed := prestart.CleanupSockets(spec.Files); removed > 0 {
		a.logger.Info("pre-start cleanup removed stale sockets", "count", removed)
	}
}

// RunPostStart fires the postStart core_started webhook after the data plane is
// up, mirroring the official node's RunPostStartCommand. Errors are logged and
// never fail the start.
func (a *App) RunPostStart(metadata json.RawMessage) {
	a.postMu.Lock()
	webhook := a.postWebhook
	a.postMu.Unlock()
	if webhook == nil || !webhook.Enabled || webhook.URL == "" {
		return
	}
	if metadata == nil {
		metadata = json.RawMessage("{}")
	}
	payload, err := json.Marshal(map[string]any{
		"scope":     "service",
		"event":     "service.core_started",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"metadata":  metadata,
	})
	if err != nil {
		a.logger.Warn("post-start webhook encode failed", "error", err)
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), webhookTimeout)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhook.URL, bytes.NewReader(payload))
		if err != nil {
			a.logger.Warn("post-start webhook request build failed", "error", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			a.logger.Warn("post-start webhook failed", "error", err)
			return
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		if resp.StatusCode >= 400 {
			a.logger.Warn("post-start webhook failed", "error", fmt.Sprintf("HTTP %d", resp.StatusCode))
		}
	}()
}

// SetAsnIndex wires in an optional ASN index used to resolve "asList" shared
// lists. May be nil (ASN resolution disabled).
func (a *App) SetAsnIndex(idx *asn.Index) {
	a.asnIdx = idx
}

// PluginSpec is the panel plugin config (NodePluginSchema).
type PluginSpec struct {
	SharedLists    []SharedList        `json:"sharedLists"`
	IngressFilter  *IngressFilterSpec  `json:"ingressFilter"`
	EgressFilter   *EgressFilterSpec   `json:"egressFilter"`
	ConnectionDrop *ConnectionDropSpec `json:"connectionDrop"`
	TorrentBlocker json.RawMessage     `json:"torrentBlocker"`
	PreStart       *PreStartSpec       `json:"preStart"`
	PostStart      *PostStartSpec      `json:"postStart"`
}

// PreStartSpec mirrors the preStart plugin section.
type PreStartSpec struct {
	Enabled        bool                `json:"enabled"`
	CleanupSockets *CleanupSocketsSpec `json:"cleanupSockets"`
}

// PostStartSpec mirrors the postStart plugin section.
type PostStartSpec struct {
	Enabled bool                  `json:"enabled"`
	Webhook *PostStartWebhookSpec `json:"webhook"`
}

// PostStartWebhookSpec mirrors the postStart webhook config.
type PostStartWebhookSpec struct {
	Enabled bool   `json:"enabled"`
	URL     string `json:"url"`
}

// CleanupSocketsSpec mirrors the preStart cleanupSockets config.
type CleanupSocketsSpec struct {
	Enabled bool     `json:"enabled"`
	Files   []string `json:"files"`
}

// SharedList is one entry of plugin sharedLists (ipList or asList).
type SharedList struct {
	Type  string            `json:"type"`
	Name  string            `json:"name"`
	Items []json.RawMessage `json:"items"`
}

// IngressFilterSpec mirrors the ingressFilter plugin section.
type IngressFilterSpec struct {
	Enabled    bool     `json:"enabled"`
	BlockedIPs []string `json:"blockedIps"`
}

// EgressFilterSpec mirrors the egressFilter plugin section.
type EgressFilterSpec struct {
	Enabled      bool     `json:"enabled"`
	BlockedIPs   []string `json:"blockedIps"`
	BlockedPorts []int    `json:"blockedPorts"`
}

// ConnectionDropSpec mirrors the connectionDrop plugin section.
type ConnectionDropSpec struct {
	Enabled      bool     `json:"enabled"`
	WhitelistIPs []string `json:"whitelistIps"`
}

// SyncPlugins applies the resolved plugin filters to nftables. It rebuilds the
// firewall table and then populates the ingress/egress IP (and egress port)
// sets. Torrent detection is not implemented by the sing-box data plane
// (torrent reports stay empty); the connection-drop whitelist is applied to
// drop-ips / drop-users-connections.
func (a *App) SyncPlugins(p PluginSpec) bool {
	ok := true
	var cleanup *CleanupSocketsSpec
	if p.PreStart != nil && p.PreStart.Enabled {
		cleanup = p.PreStart.CleanupSockets
	}
	a.setPreCleanup(cleanup)

	var postWebhook *PostStartWebhookSpec
	if p.PostStart != nil && p.PostStart.Enabled {
		postWebhook = p.PostStart.Webhook
	}
	a.setPostStartWebhook(postWebhook)

	sharedMap := a.resolveSharedLists(p.SharedLists)

	if p.ConnectionDrop != nil && p.ConnectionDrop.Enabled {
		a.setDropWhitelist(a.resolveIpList(p.ConnectionDrop.WhitelistIPs, sharedMap))
	} else {
		a.setDropWhitelist(nil)
	}

	if err := a.nft.CreateTable(); err != nil {
		a.logger.Warn("plugin sync: recreate tables failed", "error", err)
		return false
	}

	if p.IngressFilter != nil && p.IngressFilter.Enabled {
		ips := a.resolveIpList(p.IngressFilter.BlockedIPs, sharedMap)
		if err := a.nft.AddIngressIPs(ips); err != nil {
			a.logger.Warn("plugin sync: ingress filter failed", "error", err)
			ok = false
		}
	}

	if p.EgressFilter != nil && p.EgressFilter.Enabled {
		ips := a.resolveIpList(p.EgressFilter.BlockedIPs, sharedMap)
		if err := a.nft.AddEgressIPs(ips); err != nil {
			a.logger.Warn("plugin sync: egress filter failed", "error", err)
			ok = false
		}
		if err := a.nft.AddEgressPorts(p.EgressFilter.BlockedPorts); err != nil {
			a.logger.Warn("plugin sync: egress port filter failed", "error", err)
			ok = false
		}
	}

	return ok
}

// resolveSharedLists builds a name → prefixes/IPs map from the plugin's
// sharedLists. ipList entries are passed through verbatim; asList entries are
// resolved to IP prefixes via the ASN index.
func (a *App) resolveSharedLists(lists []SharedList) map[string][]string {
	sharedMap := map[string][]string{}
	for _, l := range lists {
		switch l.Type {
		case "ipList":
			var items []string
			for _, it := range l.Items {
				var s string
				if json.Unmarshal(it, &s) == nil {
					items = append(items, s)
				}
			}
			sharedMap[l.Name] = items
		case "asList":
			if a.asnIdx == nil {
				a.logger.Warn("ASN index unavailable; skipping asList", "name", l.Name)
				continue
			}
			var prefixes []string
			for _, it := range l.Items {
				var asn int
				if json.Unmarshal(it, &asn) != nil {
					continue
				}
				p, ok := a.asnIdx.PrefixesFor(asn)
				if !ok {
					a.logger.Warn("ASN not found in index", "asn", asn)
					continue
				}
				prefixes = append(prefixes, p...)
			}
			sharedMap[l.Name] = prefixes
		default:
			a.logger.Warn("unknown shared list type", "type", l.Type, "name", l.Name)
		}
	}
	return sharedMap
}

// resolveIpList expands "ext:<name>" references against the shared map and
// returns the resulting flat IP/CIDR list.
func (a *App) resolveIpList(ips []string, sharedMap map[string][]string) []string {
	var out []string
	for _, ip := range ips {
		if strings.HasPrefix(ip, "ext:") {
			out = append(out, sharedMap[ip]...)
			continue
		}
		out = append(out, ip)
	}
	return out
}
