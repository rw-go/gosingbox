// Package config loads runtime environment configuration. It mirrors the
// env semantics of the Node.js version (src/common/config/app-config).
package config

import (
	"fmt"
	"os"
	"strconv"
)

type Config struct {
	NodePort int

	SecretKey string

	// LogLevel controls the node's own log verbosity (debug|info|warn|error).
	LogLevel string

	InternalRESTToken  string
	InternalSocketPath string

	SingboxBinPath    string
	SingboxConfigPath string
	SingboxStatsAddr  string
	SingboxLogDir     string
	SingboxLogLevel   string
	SingboxDebounceMs int
	SingboxDrainMs    int
	SingboxListen     string
	SingboxGeoDir     string
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// Load reads and validates all runtime env vars.
func Load() (*Config, error) {
	cfg := &Config{
		NodePort:           envInt("NODE_PORT", 2222),
		SecretKey:          os.Getenv("SECRET_KEY"),
		LogLevel:           envOr("LOG_LEVEL", "info"),
		InternalRESTToken:  envOr("INTERNAL_REST_TOKEN", ""),
		InternalSocketPath: envOr("INTERNAL_SOCKET_PATH", ""),
		SingboxBinPath:     envOr("SINGBOX_BIN_PATH", "/usr/local/bin/sing-box"),
		SingboxConfigPath:  envOr("SINGBOX_CONFIG_PATH", "/var/lib/rnode/singbox/config.json"),
		SingboxStatsAddr:   envOr("SINGBOX_STATS_ADDRESS", "127.0.0.1:6450"),
		SingboxLogDir:      envOr("SINGBOX_LOG_DIR", "/var/log/rnode"),
		SingboxLogLevel:    envOr("SINGBOX_LOG_LEVEL", "warn"),
		SingboxDebounceMs:  envInt("SINGBOX_DEBOUNCE_MS", 5000),
		SingboxDrainMs:     envInt("SINGBOX_DRAIN_MS", 3000),
		SingboxListen:      os.Getenv("SINGBOX_LISTEN"),
		SingboxGeoDir:      os.Getenv("SINGBOX_GEO_DIR"),
	}

	if cfg.SecretKey == "" {
		// SECRET_KEY is required for serve mode; the data-plane driver does not
		// need it, so we defer enforcement to the caller.
		cfg.SecretKey = ""
	}
	if cfg.NodePort <= 0 || cfg.NodePort > 65535 {
		return nil, fmt.Errorf("NODE_PORT out of range: %d", cfg.NodePort)
	}
	return cfg, nil
}
