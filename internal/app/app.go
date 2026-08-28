// Package app wires the panel-facing server, state, transpiler, and sing-box
// process together. It is the Go equivalent of the Node.js XrayService +
// UserChangePipelineService.
package app

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"rwnode-singbox/internal/nftables"
	"rwnode-singbox/internal/singbox"
	"rwnode-singbox/internal/state"
	"rwnode-singbox/internal/systemstats"
	"rwnode-singbox/internal/transpiler"
)

// NodeVersion is the reported node version (set via ldflags at build time).
// Must be a bare semver — the panel parses this to decide node compatibility,
// and a suffix like "-go" is treated as an outdated/unknown version.
var NodeVersion = "3.3.2"

// App is the top-level orchestrator.
type App struct {
	logger *slog.Logger
	state  *state.State
	proc   *singbox.Process
	cfg    *singbox.Options
	sys    *systemstats.Reader
	nft    *nftables.Manager

	debounceMs time.Duration

	// desired working config derived from the last panel push
	statsAddr string
	logLevel  string
}

// New creates an App around the given sing-box process.
func New(logger *slog.Logger, proc *singbox.Process, st *state.State, debounceMs int) *App {
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

	res, err := transpiler.Transpile(raw, a.statsAddr, a.logLevel, a.state.VlessUsers())
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

// UserChanged is called after user add/remove; schedules a debounced apply.
func (a *App) UserChanged() {
	a.logger.Info("user change; scheduling debounced apply")
	time.AfterFunc(a.debounceMs, func() {
		if err := a.applyToSingbox(); err != nil {
			a.logger.Error("debounced apply failed", "error", err)
		}
	})
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

// CurrentUsers returns the desired VLESS user names (for the handler count/list
// endpoints).
func (a *App) CurrentUsers() []string {
	users := a.state.VlessUsers()
	out := make([]string, 0, len(users))
	for _, u := range users {
		out = append(out, u.Name)
	}
	return out
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
