// Package app wires the panel-facing server, state, transpiler, and sing-box
// process together. It is the Go equivalent of the Node.js XrayService +
// UserChangePipelineService.
package app

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/sagernet/sing-box/option"

	"github.com/rwnode/rwnode-gosingbox/internal/asn"
	"github.com/rwnode/rwnode-gosingbox/internal/nftables"
	"github.com/rwnode/rwnode-gosingbox/internal/singbox"
	"github.com/rwnode/rwnode-gosingbox/internal/state"
	"github.com/rwnode/rwnode-gosingbox/internal/systemstats"
	"github.com/rwnode/rwnode-gosingbox/internal/transpiler"
)

// NodeVersion is the reported node version (set via ldflags at build time).
// Must be a bare semver — the panel parses this to decide node compatibility,
// and a suffix like "-go" is treated as an outdated/unknown version.
var NodeVersion = "3.3.2"

// App is the top-level orchestrator.
type App struct {
	logger *slog.Logger
	state  *state.State
	proc   *singbox.Engine
	cfg    *singbox.Options
	sys    *systemstats.Reader
	nft    *nftables.Manager
	asnIdx *asn.Index

	debounceMs time.Duration

	// desired working config derived from the last panel push
	statsAddr string
	clashAddr string
	logLevel  string
}

// New creates an App around the given embedded sing-box engine.
func New(logger *slog.Logger, proc *singbox.Engine, st *state.State, debounceMs int) *App {
	nft := nftables.New()
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
		logger:     logger,
		proc:       proc,
		state:      st,
		sys:        systemstats.NewReader(),
		nft:        nft,
		debounceMs: time.Duration(debounceMs) * time.Millisecond,
		statsAddr:  proc.StatsAddr(),
		clashAddr:  proc.ClashAddr(),
		logLevel:   proc.LogLevel(),
	}
}

// Start transplies the panel config and applies it immediately (full push).
func (a *App) Start(raw []byte) error {
	a.state.SetRawConfig(raw)
	return a.applyToSingbox()
}

// applyToSingbox transpiles the current state and applies it to sing-box.
func (a *App) applyToSingbox() error {
	raw := a.state.RawConfig()
	if raw == nil {
		return fmt.Errorf("no panel config available")
	}

	res, err := transpiler.Transpile(raw, a.statsAddr, a.clashAddr, a.logLevel, a.state.VlessUsers())
	if err != nil {
		return fmt.Errorf("transpile: %w", err)
	}

	// Record inbound tags for stats/lookup.
	a.state.SetInboundTags(inboundTagsOf(res.Config))

	err = a.proc.ApplyConfig(res.Config)
	if err != nil {
		return err
	}
	return nil
}

func inboundTagsOf(cfg map[string]any) []string {
	var tags []string
	if in, ok := cfg["inbounds"].([]any); ok {
		for _, ibAny := range in {
			if ib, ok := ibAny.(map[string]any); ok {
				if tag, ok := ib["tag"].(string); ok {
					tags = append(tags, tag)
				}
			}
		}
	}
	return tags
}

// UserChanged is called after user add/remove; schedules a debounced user
// hot-swap (no listener restart).
func (a *App) UserChanged() {
	a.logger.Info("user change; scheduling debounced hot-swap")
	time.AfterFunc(a.debounceMs, func() {
		if err := a.applyUserHotSwap(); err != nil {
			a.logger.Error("hot-swap users failed; falling back to full apply", "error", err)
			if err := a.applyToSingbox(); err != nil {
				a.logger.Error("full apply fallback failed", "error", err)
			}
		}
	})
}

// applyUserHotSwap pushes the current VLESS user set into the running inbound
// via UpdatableInbound.UpdateUsers, avoiding a configuration rebuild/restart.
func (a *App) applyUserHotSwap() error {
	tags := a.state.InboundTags()
	users := make([]option.VLESSUser, 0, len(a.state.VlessUsers()))
	for _, u := range a.state.VlessUsers() {
		users = append(users, option.VLESSUser{Name: u.Name, UUID: u.UUID, Flow: u.Flow})
	}
	n, err := a.proc.UpdateVLESSUsers(tags, users)
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("no vless inbound updated")
	}
	a.logger.Info("vless users hot-swapped", "inbounds", n, "users", len(users))
	return nil
}

// AddUser adds a VLESS user to desired state and schedules apply.
func (a *App) AddUser(u transpiler.VlessUser) {
	a.state.AddUser(u)
	a.UserChanged()
}

// RemoveUser removes a VLESS user by UUID and schedules apply.
func (a *App) RemoveUser(uuid string) bool {
	if !a.state.RemoveUser(uuid) {
		return false
	}
	a.UserChanged()
	return true
}

// Stop shuts down the sing-box process.
func (a *App) Stop() {
	a.proc.Shutdown()
}

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
	return singbox.FetchOnlineConnections(ctx, a.clashAddr)
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
	conns, err := singbox.FetchOnlineConnections(ctx, a.clashAddr)
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

// RawConfigJSON returns the last stored panel config as a parsed map (or an
// empty map if none), used by the /internal/get-config endpoint.
func (a *App) RawConfigJSON() map[string]any {
	raw := a.state.RawConfig()
	if raw == nil {
		return map[string]any{}
	}
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	if m == nil {
		m = map[string]any{}
	}
	return m
}

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
	PreStart       json.RawMessage     `json:"preStart"`
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
// sets. Torrent detection and connection-drop are not implemented by the
// sing-box data plane (documented gaps): torrent reports stay empty and
// connection-drop whitelisting has no effect.
func (a *App) SyncPlugins(p PluginSpec) bool {
	sharedMap := a.resolveSharedLists(p.SharedLists)

	if err := a.nft.CreateTable(); err != nil {
		a.logger.Warn("plugin sync: recreate tables failed", "error", err)
		return false
	}

	if p.IngressFilter != nil && p.IngressFilter.Enabled {
		ips := a.resolveIpList(p.IngressFilter.BlockedIPs, sharedMap)
		if err := a.nft.AddIngressIPs(ips); err != nil {
			a.logger.Warn("plugin sync: ingress filter failed", "error", err)
		}
	}

	if p.EgressFilter != nil && p.EgressFilter.Enabled {
		ips := a.resolveIpList(p.EgressFilter.BlockedIPs, sharedMap)
		if err := a.nft.AddEgressIPs(ips); err != nil {
			a.logger.Warn("plugin sync: egress filter failed", "error", err)
		}
		if err := a.nft.AddEgressPorts(p.EgressFilter.BlockedPorts); err != nil {
			a.logger.Warn("plugin sync: egress port filter failed", "error", err)
		}
	}

	return true
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
