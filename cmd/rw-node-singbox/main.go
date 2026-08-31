// Command rw-node-singbox is the Go remnawave node with a sing-box data plane.
//
// Two modes:
//
//	-config <file>   : data-plane driver — transpiles a panel config, starts
//	                   sing-box, polls stats (for low-level validation).
//	-serve           : full panel-facing HTTPS server (mTLS + JWT), equivalent
//	                   to the Node.js remnawave node.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/rwnode/rwnode-gosingbox/internal/app"
	"github.com/rwnode/rwnode-gosingbox/internal/asn"
	"github.com/rwnode/rwnode-gosingbox/internal/config"
	"github.com/rwnode/rwnode-gosingbox/internal/controller"
	"github.com/rwnode/rwnode-gosingbox/internal/payload"
	"github.com/rwnode/rwnode-gosingbox/internal/server"
	"github.com/rwnode/rwnode-gosingbox/internal/singbox"
	"github.com/rwnode/rwnode-gosingbox/internal/state"
	"github.com/rwnode/rwnode-gosingbox/internal/transpiler"
)

func main() {
	serveMode := flag.Bool("serve", false, "run as full panel-facing HTTPS server")
	configPath := flag.String("config", "", "panel xrayConfig JSON file (data-plane driver)")
	restartAfter := flag.Duration("demo-restart", 0, "if >0, trigger a graceful restart after this delay (driver)")
	flag.Parse()

	cfg, err := config.Load()
	if err != nil {
		slog.New(slog.NewTextHandler(os.Stdout, nil)).Error("config", "error", err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: parseLogLevel(cfg.LogLevel)}))

	proc := singbox.NewEngine(singbox.Options{
		StatsAddr: cfg.SingboxStatsAddr,
		ClashAddr: cfg.SingboxClashAddr,
		LogLevel:  cfg.SingboxLogLevel,
		Logger:    logger,
	})

	st := state.New()
	application := app.New(logger, proc, st, cfg.SingboxDebounceMs)

	if cfg.AsnIndexPath != "" {
		if idx, err := asn.Load(cfg.AsnIndexPath); err != nil {
			logger.Warn("asn index load failed", "path", cfg.AsnIndexPath, "error", err)
		} else {
			application.SetAsnIndex(idx)
			logger.Info("asn index loaded", "path", cfg.AsnIndexPath)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *serveMode {
		runServer(logger, cfg, application, proc)
		<-ctx.Done()
		logger.Info("shutting down")
		application.Stop()
		return
	}

	// Data-plane driver mode.
	runDriver(logger, cfg, application, proc, *configPath, *restartAfter)
	<-ctx.Done()
	logger.Info("shutting down")
	application.Stop()
}

func runServer(logger *slog.Logger, cfg *config.Config, application *app.App, proc *singbox.Engine) {
	if cfg.SecretKey == "" {
		logger.Error("SECRET_KEY is required in serve mode")
		os.Exit(1)
	}
	p, err := payload.Parse(cfg.SecretKey)
	if err != nil {
		logger.Error("parse SECRET_KEY payload", "error", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	controller.NewXray(application, logger).Router(mux)
	controller.NewStats(application, logger).Router(mux)
	controller.NewHandler(application, logger).Router(mux)
	controller.NewInternal(application, logger).Router(mux)
	controller.NewPlugin(application, logger).Router(mux)

	srv := &server.ServerFactory{
		Mux:     mux,
		Payload: p,
		Logger:  logger,
	}
	addr := fmt.Sprintf(":%d", cfg.NodePort)
	logger.Info("panel HTTPS server starting", "addr", addr)
	go func() {
		if err := srv.ListenAndServe(addr); err != nil && err != http.ErrServerClosed {
			logger.Error("server failed", "error", err)
			os.Exit(1)
		}
	}()
}

func runDriver(logger *slog.Logger, cfg *config.Config, application *app.App, proc *singbox.Engine, configPath string, restartAfter time.Duration) {
	if configPath == "" {
		logger.Error("data-plane driver requires -config")
		os.Exit(1)
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		logger.Error("read panel config", "error", err)
		os.Exit(1)
	}
	res, err := transpiler.Transpile(raw, cfg.SingboxStatsAddr, cfg.SingboxClashAddr, cfg.SingboxLogLevel, nil, nil)
	if err != nil {
		logger.Error("transpile", "error", err)
		os.Exit(1)
	}
	logger.Info("transpiled",
		"inbounds", len(res.Config["inbounds"].([]any)),
		"outbounds", len(res.Config["outbounds"].([]any)),
		"inboundTag", res.InboundTag,
	)
	if err := application.Start(raw); err != nil {
		logger.Error("apply config", "error", err)
		os.Exit(1)
	}
	logger.Info("sing-box online", "version", proc.Version(), "pid", proc.Pid())

	if restartAfter > 0 {
		go func() {
			time.Sleep(restartAfter)
			logger.Info("driver: applying same config to test graceful restart")
			if err := application.Start(raw); err != nil {
				logger.Error("driver restart", "error", err)
			}
		}()
	}

	// Poll stats every 5s.
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-time.After(5 * time.Second):
			reportStats(logger, cfg.SingboxStatsAddr)
			ticker.Reset(5 * time.Second)
		}
	}
}

func reportStats(logger *slog.Logger, addr string) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := singbox.NewStatsClientForTest(addr)
	if err != nil {
		logger.Debug("dial stats", "error", err)
		return
	}
	defer c.Close()
	sys, err := c.GetSysStats(ctx)
	if err != nil {
		logger.Debug("GetSysStats", "error", err)
	} else {
		logger.Info("sysstats", "uptime", sys.Uptime, "goroutines", sys.NumGoroutine)
	}
	stats, err := c.QueryStats(ctx, []string{"user>>>"}, false)
	if err != nil {
		logger.Debug("QueryStats", "error", err)
		return
	}
	if len(stats) == 0 {
		logger.Debug("querystats: no user counters")
		return
	}
	for _, s := range stats {
		logger.Info("counter", "name", s.Name, "value", s.Value)
	}
}

// parseLogLevel maps a LOG_LEVEL env string (debug/info/warn/error) to a
// slog.Level. Defaults to info.
func parseLogLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
