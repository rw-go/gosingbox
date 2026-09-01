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

	SingboxStatsAddr  string
	SingboxClashAddr  string
	SingboxLogLevel   string
	SingboxDebounceMs int
	SingboxListen     string
	SingboxGeoDir     string

	// AsnIndexPath points to an asn-prefixes.json file (remnawave/asn-index
	// JSON asset). When empty the ASN shared-list resolver stays disabled.
	AsnIndexPath string

	// SNIVerification enables private-SNI checks on the panel mTLS handshake
	// (SNI must equal the value derived from the SECRET_KEY material).
	SNIVerification bool

	// NftablesAcceptReplyTraffic mirrors official NFTABLES_ACCEPT_REPLY_TRAFFIC:
	// the egress filter accepts established/related reply flows.
	NftablesAcceptReplyTraffic bool
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) (int, error) {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n, nil
		} else {
			return 0, fmt.Errorf("%s must be an integer: %w", key, err)
		}
	}
	return def, nil
}

// Load reads and validates all runtime env vars.
func Load() (*Config, error) {
	nodePort, err := envInt("NODE_PORT", 2222)
	if err != nil {
		return nil, err
	}
	debounceMs, err := envInt("SINGBOX_DEBOUNCE_MS", 5000)
	if err != nil {
		return nil, err
	}
	cfg := &Config{
		NodePort:                   nodePort,
		SecretKey:                  os.Getenv("SECRET_KEY"),
		LogLevel:                   envOr("LOG_LEVEL", "info"),
		InternalRESTToken:          envOr("INTERNAL_REST_TOKEN", ""),
		InternalSocketPath:         envOr("INTERNAL_SOCKET_PATH", ""),
		SingboxStatsAddr:           envOr("SINGBOX_STATS_ADDRESS", "127.0.0.1:6450"),
		SingboxClashAddr:           envOr("SINGBOX_CLASH_ADDRESS", "127.0.0.1:9090"),
		SingboxLogLevel:            envOr("SINGBOX_LOG_LEVEL", "warn"),
		SingboxDebounceMs:          debounceMs,
		SingboxListen:              os.Getenv("SINGBOX_LISTEN"),
		SingboxGeoDir:              os.Getenv("SINGBOX_GEO_DIR"),
		AsnIndexPath:               os.Getenv("ASN_INDEX_PATH"),
		SNIVerification:            os.Getenv("SNI_VERIFICATION") == "true",
		NftablesAcceptReplyTraffic: os.Getenv("NFTABLES_ACCEPT_REPLY_TRAFFIC") == "true",
	}

	if cfg.SecretKey == "" {
		// SECRET_KEY is required for serve mode; the data-plane driver does not
		// need it, so we defer enforcement to the caller.
		cfg.SecretKey = ""
	}
	if cfg.NodePort <= 0 || cfg.NodePort > 65535 {
		return nil, fmt.Errorf("NODE_PORT out of range: %d", cfg.NodePort)
	}
	if cfg.SingboxDebounceMs < 0 {
		return nil, fmt.Errorf("SINGBOX_DEBOUNCE_MS must be non-negative: %d", cfg.SingboxDebounceMs)
	}
	return cfg, nil
}
