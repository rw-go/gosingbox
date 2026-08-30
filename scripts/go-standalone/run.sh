#!/bin/sh
# Launcher for the self-contained gosingbox (sing-box embedded data plane).
# POSIX sh (runs on Alpine/busybox and any Linux).
# Usage:
#   ./bin/run.sh                # start in foreground (Ctrl-C to stop)
# Environment is read from ./env (or the process environment).
set -eu

BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
MAIN_BIN="$BASE_DIR/bin/gosingbox"

# Load env file if present (env takes precedence, then .env).
ENV_FILE=""
if [ -f "$BASE_DIR/env" ]; then
    ENV_FILE="$BASE_DIR/env"
elif [ -f "$BASE_DIR/.env" ]; then
    ENV_FILE="$BASE_DIR/.env"
fi
if [ -n "$ENV_FILE" ]; then
    set -a
    # shellcheck disable=SC1090
    . "$ENV_FILE"
    set +a
fi

# Defaults.
: "${SINGBOX_STATS_ADDRESS:=127.0.0.1:6450}"
: "${SINGBOX_LOG_LEVEL:=warn}"
: "${SINGBOX_DEBOUNCE_MS:=5000}"
: "${SINGBOX_GEO_DIR:=$BASE_DIR/var/geo}"
: "${NODE_PORT:=2222}"
: "${LOG_LEVEL:=info}"

# geocheck binary: prefer in-package if present.
GEOCHECK_BIN="$BASE_DIR/bin/geocheck"
if [ -x "$GEOCHECK_BIN" ]; then
    GEOCHECK_BIN_PATH="$GEOCHECK_BIN"
fi

export SINGBOX_STATS_ADDRESS SINGBOX_LOG_LEVEL SINGBOX_DEBOUNCE_MS \
    SINGBOX_GEO_DIR NODE_PORT LOG_LEVEL
if [ -n "${GEOCHECK_BIN_PATH:-}" ]; then
    export GEOCHECK_BIN_PATH
fi

mkdir -p "$SINGBOX_GEO_DIR"

# SECRET_KEY is required (issued by the panel).
if [ -z "${SECRET_KEY:-}" ]; then
    echo "ERROR: SECRET_KEY is not set." >&2
    echo "       Copy env.example to env and set SECRET_KEY to the value from your panel:" >&2
    echo "         cp env.example env && vi env   # then set SECRET_KEY=..." >&2
    echo "       (or export SECRET_KEY before running)." >&2
    exit 1
fi

# Validate the gosingbox binary is present.
if [ ! -x "$MAIN_BIN" ]; then
    echo "ERROR: gosingbox binary not found at $MAIN_BIN" >&2
    exit 1
fi

exec "$MAIN_BIN" -serve