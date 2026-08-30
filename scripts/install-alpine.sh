#!/bin/sh
# One-shot installer for the Go gosingbox (sing-box data plane) on Alpine
# (OpenRC / rc-service). Interactive: asks NODE_PORT (default 2222) and the
# panel SECRET_KEY, then installs binaries, writes /opt/gosingbox/env, and sets up
# an OpenRC service that auto-starts on boot.
#
# Usage (as root on the Alpine target):
#   wget -qO- https://raw.githubusercontent.com/rwsbnode/rwnode-gosingbox/main/scripts/install-alpine.sh | sh
#   # 若缓存导致拿到旧版, 加版本参数强制新域名:
#   wget -qO- https://raw.githubusercontent.com/rwsbnode/rwnode-gosingbox/main/scripts/install-alpine.sh | sh
#
# Optional overrides via env:
#   GOSINGBOX_RELEASE_OWNER  GitHub owner          (default rwsbnode)
#   GOSINGBOX_RELEASE_REPO   GitHub repo           (default rwnode-gosingbox)
#   GOSINGBOX_RELEASE_TAG    release tag           (default latest)
#   GOSINGBOX_VER            package version      (default 3.3.2-go)
#   GOSINGBOX_INSTALL_DIR    install dir          (default /opt/gosingbox)
set -eu

# Installer version. Bump the patch number on EVERY change to this script so
# users can tell the CDN stopped serving the latest revision. (See AGENTS.md.)
INSTALLER_VERSION="3.3.2.10"

# `--version` / `-v` prints the installer version and exits (for cache checks).
if [ "${1:-}" = "--version" ] || [ "${1:-}" = "-v" ]; then
    echo "install-alpine.sh v${INSTALLER_VERSION}"
    exit 0
fi

OWNER="${GOSINGBOX_RELEASE_OWNER:-rwsbnode}"
REPO="${GOSINGBOX_RELEASE_REPO:-rwnode-gosingbox}"
TAG="${GOSINGBOX_RELEASE_TAG:-go-v3.3.2-go}"
VER="${GOSINGBOX_VER:-3.3.2-go}"
ARCH="amd64"
INSTALL_DIR="${GOSINGBOX_INSTALL_DIR:-/opt/gosingbox}"
TARBALL="gosingbox-${VER}-linux-${ARCH}.tar.gz"

log()  { printf '%s\n' "$*" >&2; }
die()  { printf '%s\n' "ERROR: $*" >&2; exit 1; }

# Interactive answers are read from the controlling terminal (/dev/tty), never
# from the script's own stdin — so `curl ... | sh` works. Each read uses a
# one-shot redirection (not `exec`) so a missing /dev/tty never kills the
# non-interactive shell. If there is no terminal, NODE_PORT/SECRET_KEY must be
# supplied via environment variables.
read_answer() { # reads a line into REPLY from /dev/tty, else stdin
    if IFS= read -r REPLY </dev/tty 2>/dev/null; then
        :
    else
        IFS= read -r REPLY 2>/dev/null || REPLY=""
    fi
}

ask()  { # $1=prompt $2=default
    _prompt="$1"; _default="$2"
    printf '%s [%s]: ' "$_prompt" "$_default" >&2
    read_answer
    _ans="$REPLY"
    [ -z "$_ans" ] && _ans="$_default"
    printf '%s\n' "$_ans"
}

# --- prerequisites ---
[ "$(id -u)" -eq 0 ] || die "please run as root (sudo sh)"
[ -f /etc/alpine-release ] || log "WARN: this script targets Alpine; continuing anyway"

command -v curl >/dev/null 2>&1 || { log "installing curl..."; apk add --no-cache curl >/dev/null || die "apk add curl failed"; }
command -v tar >/dev/null 2>&1 || die "tar missing"

# --- interactive config (env vars can pre-answer; otherwise prompt on tty) ---
echo "==> gosingbox (Go) installer v${INSTALLER_VERSION}" >&2
echo "    Data plane: sing-box (VLESS+Reality + Shadowsocks 2022)" >&2
echo >&2

if [ -n "${NODE_PORT:-}" ]; then
    log "NODE_PORT=$NODE_PORT (from env)"
else
    NODE_PORT="$(ask "Panel port (NODE_PORT)" "2222")"
fi
case "$NODE_PORT" in
  ''|*[!0-9]*) die "invalid port: $NODE_PORT" ;;
esac

TRIES=0
while [ -z "${SECRET_KEY:-}" ]; do
    printf 'Panel connection secret (SECRET_KEY): ' >&2
    read_answer
    SECRET_KEY="$REPLY"
    [ -n "$SECRET_KEY" ] && break
    TRIES=$((TRIES+1))
    [ "$TRIES" -ge 3 ] && die "SECRET_KEY required (copy the connection secret from the panel)"
done

# --- download ---
DL_BASE="https://github.com/${OWNER}/${REPO}/releases/download/${TAG}"
DL_URL="${DL_BASE}/${TARBALL}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

log "downloading $DL_URL"
curl -fsSL -o "$TMP/$TARBALL" "$DL_URL" || die "download failed; is the release published?"
log "extracting to $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
tar -xzf "$TMP/$TARBALL" -C "$TMP"
PKG_DIR="$TMP/gosingbox-${VER}-linux-${ARCH}"
[ -d "$PKG_DIR" ] || die "unexpected tarball layout (missing $PKG_DIR)"

cp -r "$PKG_DIR/." "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/bin/run.sh" "$INSTALL_DIR/bin/gosingbox"

# --- env config ---
# SECRET_KEY is a JSON document (may contain double quotes and literal \n);
# single-quote wrap it so the env file survives `source`-ing by run.sh.
ESCAPED_KEY=$(printf '%s' "$SECRET_KEY" | sed "s/'/'\\\\''/g")
cat > "$INSTALL_DIR/env" <<EOF
NODE_PORT=$NODE_PORT
SECRET_KEY='$ESCAPED_KEY'
SINGBOX_GEO_DIR=/var/lib/gosingbox/singbox/geo
SINGBOX_LOG_LEVEL=warn
# Node 自身日志等级: debug | info | warn | error（排查面板连接问题时可设 debug）
LOG_LEVEL=${LOG_LEVEL:-info}
SINGBOX_DEBOUNCE_MS=5000
EOF
chmod 600 "$INSTALL_DIR/env"

# --- nftables (optional plugin firewall) ---
if command -v nft >/dev/null 2>&1; then
    log "nft present; plugin firewall (block/unblock) will be available"
else
    log "installing nftables (optional plugin firewall)..."
    apk add --no-cache nftables >/dev/null 2>&1 || log "WARN: nftables install failed; block/unblock endpoints will be degraded"
fi

# --- OpenRC service ---
mkdir -p /etc/init.d
cat > /etc/init.d/gosingbox <<'EOF'
#!/sbin/openrc-run
description="gosingbox (Go, sing-box data plane)"
supervisor=supervise-daemon
command="/opt/gosingbox/bin/run.sh"
command_background=false
pidfile="/run/gosingbox.pid"
output_log="/var/log/gosingbox/gosingbox.log"
error_log="/var/log/gosingbox/gosingbox-error.log"
depend() {
    need net
    after firewall
}
EOF
chmod +x /etc/init.d/gosingbox
mkdir -p /var/log/gosingbox /var/lib/gosingbox/singbox

# The launcher reads env from /opt/gosingbox/env; export SECRET_KEY is handled there.
if command -v rc-update >/dev/null 2>&1; then
    rc-update add gosingbox default 2>/dev/null || log "WARN: rc-update add failed"
fi
if command -v rc-service >/dev/null 2>&1; then
    if rc-service gosingbox start; then
        log "started gosingbox"
    else
        log "WARN: failed to start; check /var/log/gosingbox/gosingbox.log"
    fi
else
    log "rc-service not found (install openrc); starting in foreground for smoke-test"
    log "Run later: /opt/gosingbox/bin/run.sh"
    cd "$INSTALL_DIR" && ./bin/run.sh &
fi

# --- summary ---
echo >&2
echo "==> Installed to $INSTALL_DIR (installer v${INSTALLER_VERSION})" >&2
echo "    Port:      $NODE_PORT" >&2
echo "    Service:   gosingbox (openrc)" >&2
echo "    Logs:      /var/log/gosingbox/*.log" >&2
echo "    Control:   rc-service gosingbox {start|stop|restart|status}" >&2
echo "    Config:    $INSTALL_DIR/env" >&2
echo >&2
echo "    Verify:    curl -k https://127.0.0.1:$NODE_PORT/node/xray/healthcheck" >&2
echo >&2