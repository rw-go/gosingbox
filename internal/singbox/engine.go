// Package singbox embeds sing-box as an in-process library (replacing the
// previous subprocess model). Running sing-box in the same process is what makes
// user hot-swapping possible: we can call the UpdatableInbound.UpdateUsers API
// directly instead of regenerating the config and restarting a child.
package singbox

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	singJSON "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
)

// Engine runs sing-box in-process.
type Engine struct {
	logger    *slog.Logger
	statsAddr string
	clashAddr string
	logLevel  string
	version   string

	mu            sync.Mutex
	ctx           context.Context
	cancel        context.CancelFunc
	box           *box.Box
	online        bool
	currentConfig map[string]any // last successfully applied config (for rollback)
}

// Status is a runtime snapshot.
type Status struct {
	Up      bool
	Pid     int
	Version string
}

// Options configures the embedded engine.
type Options struct {
	StatsAddr string
	ClashAddr string
	LogLevel  string
	Logger    *slog.Logger
}

// NewEngine creates an embedded sing-box engine.
func NewEngine(opts Options) *Engine {
	if opts.StatsAddr == "" {
		opts.StatsAddr = "127.0.0.1:6450"
	}
	if opts.ClashAddr == "" {
		opts.ClashAddr = "127.0.0.1:9090"
	}
	if opts.LogLevel == "" {
		opts.LogLevel = "warn"
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return &Engine{
		logger:    opts.Logger,
		statsAddr: opts.StatsAddr,
		clashAddr: opts.ClashAddr,
		logLevel:  opts.LogLevel,
		version:   constant.Version,
	}
}

func (e *Engine) StatsAddr() string { return e.statsAddr }
func (e *Engine) ClashAddr() string { return e.clashAddr }
func (e *Engine) LogLevel() string  { return e.logLevel }

// IsRunning reports whether the embedded box is started.
func (e *Engine) IsRunning() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.box != nil && e.online
}

// Pid returns 0 (no child process in embedded mode).
func (e *Engine) Pid() int { return 0 }

// Version returns the sing-box library version.
func (e *Engine) Version() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.version
}

// Status returns a runtime snapshot.
func (e *Engine) Status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	return Status{Up: e.online, Pid: 0, Version: e.version}
}

// parseOptions marshals a config map into sing-box options without touching the
// running instance.
func (e *Engine) parseOptions(config map[string]any) (context.Context, option.Options, error) {
	data, err := json.Marshal(config)
	if err != nil {
		return nil, option.Options{}, fmt.Errorf("marshal config: %w", err)
	}
	ctx := include.Context(context.Background())
	opts, err := singJSON.UnmarshalExtendedContext[option.Options](ctx, data)
	if err != nil {
		return nil, option.Options{}, fmt.Errorf("parse sing-box options: %w", err)
	}
	return ctx, opts, nil
}

// startLocked builds and starts a sing-box instance from the given options and
// makes it the current one. The caller must hold e.mu.
func (e *Engine) startLocked(ctx context.Context, opts option.Options) error {
	instCtx, cancel := context.WithCancel(ctx)
	instance, err := box.New(box.Options{Context: instCtx, Options: opts})
	if err != nil {
		cancel()
		return fmt.Errorf("create sing-box instance: %w", err)
	}
	if err := instance.Start(); err != nil {
		instance.Close()
		cancel()
		return fmt.Errorf("start sing-box: %w", err)
	}
	e.ctx = instCtx
	e.cancel = cancel
	e.box = instance
	e.online = true
	return nil
}

// ApplyConfig transpile output (already JSON-marshalable) into an option.Options
// and (re)start the embedded box. Because this path fully re-binds listeners it
// is the "restart" fallback; user changes should use UpdateVLESSUsers instead.
//
// The new config is parsed before the previous instance is stopped, and on a
// create/start failure the previous instance is restored best-effort so a bad
// config never leaves the node fully down.
func (e *Engine) ApplyConfig(config map[string]any) error {
	ctx, opts, err := e.parseOptions(config)
	if err != nil {
		return err
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	prev := e.currentConfig

	// Stop the previous instance first so listeners release their ports.
	if e.box != nil {
		e.stopLocked()
	}

	if err := e.startLocked(ctx, opts); err != nil {
		if prev != nil {
			if rctx, ropts, rerr := e.parseOptions(prev); rerr == nil {
				if serr := e.startLocked(rctx, ropts); serr != nil {
					e.logger.Warn("rollback to previous config failed", "error", serr)
				} else {
					e.currentConfig = prev
					return fmt.Errorf("apply config: %w (rolled back)", err)
				}
			} else {
				e.logger.Warn("rollback config parse failed", "error", rerr)
			}
		}
		e.currentConfig = nil
		return fmt.Errorf("apply config: %w", err)
	}

	e.currentConfig = config
	return nil
}

// UpdateVLESSUsers hot-swaps the VLESS user set on all the given inbound tags
// without restarting listeners. Returns the number of updated inbounds.
func (e *Engine) UpdateVLESSUsers(tags []string, users []option.VLESSUser) (int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.box == nil || !e.online {
		return 0, fmt.Errorf("not running")
	}
	im := service.FromContext[adapter.InboundManager](e.ctx)
	if im == nil {
		return 0, fmt.Errorf("inbound manager unavailable")
	}

	updated := 0
	for _, tag := range tags {
		ib, ok := im.Get(tag)
		if !ok {
			continue
		}
		if u, ok := ib.(adapter.UpdatableInbound[option.VLESSUser]); ok {
			if err := u.UpdateUsers(users); err != nil {
				return updated, fmt.Errorf("update users on %q: %w", tag, err)
			}
			e.updateCurrentUsersLocked("vless", tag, users)
			updated++
		}
	}
	return updated, nil
}

// UpdateSSUsers hot-swaps the Shadowsocks 2022 user set (with passwords) on the
// given inbound tags without restarting listeners. Returns the number of
// updated inbounds.
func (e *Engine) UpdateSSUsers(tags []string, users []option.ShadowsocksUser) (int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.box == nil || !e.online {
		return 0, fmt.Errorf("not running")
	}
	im := service.FromContext[adapter.InboundManager](e.ctx)
	if im == nil {
		return 0, fmt.Errorf("inbound manager unavailable")
	}

	updated := 0
	for _, tag := range tags {
		ib, ok := im.Get(tag)
		if !ok {
			continue
		}
		if u, ok := ib.(adapter.UpdatableShadowsocksInbound); ok {
			if err := u.UpdateUsersByOptions(users); err != nil {
				return updated, fmt.Errorf("update ss users on %q: %w", tag, err)
			}
			e.updateCurrentUsersLocked("shadowsocks", tag, users)
			updated++
		}
	}
	return updated, nil
}

// updateCurrentUsersLocked keeps the rollback config aligned with successful
// in-place user updates. The caller must hold e.mu.
func (e *Engine) updateCurrentUsersLocked(inboundType, tag string, users any) {
	if e.currentConfig == nil {
		return
	}
	inbounds, ok := e.currentConfig["inbounds"].([]any)
	if !ok {
		return
	}
	for _, value := range inbounds {
		inbound, ok := value.(map[string]any)
		if !ok || inbound["type"] != inboundType || inbound["tag"] != tag {
			continue
		}
		inbound["users"] = users
		e.refreshCurrentStatUsersLocked()
		return
	}
}

// refreshCurrentStatUsersLocked rebuilds the rollback config's v2ray stats user
// list from the current inbound users. The caller must hold e.mu.
func (e *Engine) refreshCurrentStatUsersLocked() {
	inbounds, ok := e.currentConfig["inbounds"].([]any)
	if !ok {
		return
	}
	var names []string
	for _, value := range inbounds {
		inbound, ok := value.(map[string]any)
		if !ok || (inbound["type"] != "vless" && inbound["type"] != "shadowsocks") {
			continue
		}
		data, err := json.Marshal(inbound["users"])
		if err != nil {
			continue
		}
		var users []struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(data, &users) != nil {
			continue
		}
		for _, user := range users {
			if user.Name != "" {
				names = append(names, user.Name)
			}
		}
	}

	experimental, ok := e.currentConfig["experimental"].(map[string]any)
	if !ok {
		return
	}
	v2rayAPI, ok := experimental["v2ray_api"].(map[string]any)
	if !ok {
		return
	}
	stats, ok := v2rayAPI["stats"].(map[string]any)
	if !ok {
		return
	}
	stats["users"] = names
}

func (e *Engine) stopLocked() {
	if e.box == nil {
		return
	}
	e.box.Close()
	e.box = nil
	if e.cancel != nil {
		e.cancel()
		e.cancel = nil
	}
	e.ctx = nil
	e.online = false
}

// Shutdown stops the embedded box.
func (e *Engine) Shutdown() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stopLocked()
}

// Query runs QueryStats with the given patterns.
func (e *Engine) Query(ctx context.Context, patterns []string, reset bool) ([]Counter, error) {
	c, err := newStatsClient(e.statsAddr)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return c.QueryStats(ctx, patterns, reset)
}

// QueryUserStats queries per-user traffic counters (patterns ["user>>>"]).
func (e *Engine) QueryUserStats(ctx context.Context, reset bool) ([]Counter, error) {
	c, err := newStatsClient(e.statsAddr)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return c.QueryStats(ctx, []string{"user>>>"}, reset)
}

// Stats returns sing-box runtime stats via v2ray_api GetSysStats.
func (e *Engine) Stats(ctx context.Context) (*SysStats, error) {
	c, err := newStatsClient(e.statsAddr)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return c.GetSysStats(ctx)
}

// Ping performs a lightweight health check via GetSysStats.
func (e *Engine) Ping(ctx context.Context) bool {
	c, err := newStatsClient(e.statsAddr)
	if err != nil {
		return false
	}
	defer c.Close()
	_, err = c.GetSysStats(ctx)
	return err == nil
}
