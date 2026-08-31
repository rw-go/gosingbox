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

	mu     sync.Mutex
	ctx    context.Context
	cancel context.CancelFunc
	box    *box.Box
	online bool
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

// ApplyConfig transpile output (already JSON-marshalable) into an option.Options
// and (re)start the embedded box. Because this path fully re-binds listeners it
// is the "restart" fallback; user changes should use UpdateVLESSUsers instead.
func (e *Engine) ApplyConfig(config map[string]any) error {
	data, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	ctx := include.Context(context.Background())
	opts, err := singJSON.UnmarshalExtendedContext[option.Options](ctx, data)
	if err != nil {
		return fmt.Errorf("parse sing-box options: %w", err)
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Stop the previous instance first so listeners release their ports.
	if e.box != nil {
		e.stopLocked()
	}

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
			updated++
		}
	}
	return updated, nil
}

func (e *Engine) stopLocked() {
	if e.box == nil {
		return
	}
	if im := service.FromContext[adapter.InboundManager](e.ctx); im != nil {
		_ = im.Close()
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
