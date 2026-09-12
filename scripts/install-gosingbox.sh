#!/bin/sh
# One-shot installer / upgrader / uninstaller for the Go gosingbox
# (embedded sing-box data plane). Supports OpenRC (Alpine) and systemd
# (Debian/Ubuntu/Arch/...) — the right service is selected by detecting the init.
#
# Modes (first argument):
#   (none) | install   — fresh install (asks NODE_PORT + SECRET_KEY); if already
#                        installed, asks whether to upgrade or uninstall
#   upgrade            — keep config, replace binaries, restart
#   uninstall          — stop + remove service, binaries and config
#   -v | --version     — print installer version
#   -h | --help        — usage
#
# Usage (as root):
#   GitHub:
#     curl -fsSL https://raw.githubusercontent.com/rw-go/gosingbox/main/scripts/install-gosingbox.sh | GOSINGBOX_RELEASE_SOURCE=github sh
#   Bitbucket:
#     wget -qO- https://bitbucket.org/rwnode/rwnode-gosingbox/raw/main/scripts/install-gosingbox.sh | sh
#     wget -qO- ... | sh -s -- upgrade
#     wget -qO- ... | sh -s -- uninstall
#
# Optional overrides via env:
#   GOSINGBOX_RELEASE_SOURCE source platform     (github | bitbucket, auto-detected by script origin)
#   GOSINGBOX_RELEASE_OWNER  repo owner          (default: rw-go for github, rwnode for bitbucket)
#   GOSINGBOX_RELEASE_REPO   repo name           (default: gosingbox for github, rwnode-gosingbox for bitbucket)
#   GOSINGBOX_RELEASE_TAG    release tag         (default: latest release)
#   GOSINGBOX_VER            package version     (default: same as tag)
#   GOSINGBOX_INSTALL_DIR    install dir         (default /opt/gosingbox)
#   NODE_PORT / SECRET_KEY / INTERNAL_SOCKET_PATH / INTERNAL_REST_TOKEN / LOG_LEVEL
set -eu

# Installer version. Bump the patch number on EVERY change to this script so
# users can tell the CDN stopped serving the latest revision. (See AGENTS.md.)
INSTALLER_VERSION="3.4.3.2"

SOURCE="${GOSINGBOX_RELEASE_SOURCE:-bitbucket}"
if [ "$SOURCE" = "github" ]; then
    OWNER="${GOSINGBOX_RELEASE_OWNER:-rw-go}"
    REPO="${GOSINGBOX_RELEASE_REPO:-gosingbox}"
else
    OWNER="${GOSINGBOX_RELEASE_OWNER:-rwnode}"
    REPO="${GOSINGBOX_RELEASE_REPO:-rwnode-gosingbox}"
fi
# 默认留空：下载时自动解析 latest release；显式设置则固定版本。
TAG="${GOSINGBOX_RELEASE_TAG:-}"
VER="${GOSINGBOX_VER:-}"
ARCH="amd64"
INSTALL_DIR="${GOSINGBOX_INSTALL_DIR:-/opt/gosingbox}"
SERVICE="gosingbox"
GEOCHECK_LINK="/usr/local/bin/geocheck"

TMP=""
cleanup_tmp() { [ -n "${TMP:-}" ] && rm -rf "$TMP"; return 0; }
trap cleanup_tmp EXIT

log()  { printf '%s\n' "$*" >&2; }
die()  { printf '%s\n' "ERROR: $*" >&2; exit 1; }

usage() {
    cat >&2 <<EOF
Usage: install-gosingbox.sh [install|upgrade|uninstall|--version|--help]
  install    fresh install (default); if already installed, asks what to do
  upgrade    keep config, replace binaries, restart service
  uninstall  stop and remove service, binaries and config
  --version  print installer version and exit
EOF
    exit 0
}

# Interactive answers are read from the controlling terminal (/dev/tty), never
# from the script's own stdin — so `curl ... | sh` works. Each read uses a
# one-shot redirection (not `exec`) so a missing /dev/tty never kills the
# non-interactive shell. If there is no terminal, NODE_PORT/SECRET_KEY must be
# supplied via environment variables.
read_answer() {
    if IFS= read -r REPLY </dev/tty 2>/dev/null; then
        :
    else
        IFS= read -r REPLY 2>/dev/null || REPLY=""
    fi
    # strip any trailing CR some terminals send
    REPLY="$(printf '%s' "$REPLY" | tr -d '\r')"
}

ask() {
    _prompt="$1"; _default="$2"
    printf '%s [%s]: ' "$_prompt" "$_default" >&2
    read_answer
    _ans="$REPLY"
    [ -z "$_ans" ] && _ans="$_default"
    printf '%s\n' "$_ans"
}

# --- mode dispatch ---
MODE="${1:-install}"
case "$MODE" in
    --version|-v) echo "install-gosingbox.sh v${INSTALLER_VERSION}"; exit 0 ;;
    --help|-h|help) usage ;;
    install|upgrade|uninstall) ;;
    *) die "unknown argument '$MODE'; use install, upgrade, uninstall, --version or --help" ;;
esac

# --- prerequisites ---
[ "$(id -u)" -eq 0 ] || die "please run as root (sudo sh)"

command -v curl >/dev/null 2>&1 || {
    log "installing curl..."
    if [ -f /etc/alpine-release ]; then
        apk add --no-cache curl >/dev/null || die "apk add curl failed"
    elif command -v apt-get >/dev/null 2>&1; then
        apt-get update >/dev/null 2>&1 || true
        apt-get install -y curl >/dev/null 2>&1 || die "apt-get install curl failed"
    else
        die "curl required but not installed"
    fi
}
command -v tar >/dev/null 2>&1 || die "tar missing"

# --- init system detection ---
detect_init() {
    if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
        echo systemd
    elif command -v rc-service >/dev/null 2>&1; then
        echo openrc
    else
        echo unknown
    fi
}
INIT="$(detect_init)"

is_installed() {
    [ -x "$INSTALL_DIR/bin/gosingbox" ] || [ -f "$INSTALL_DIR/env" ]
}

get_release_base() {
    if [ "$SOURCE" = "github" ]; then
        echo "https://raw.githubusercontent.com/${OWNER}/${REPO}/release"
    else
        echo "https://bitbucket.org/${OWNER}/${REPO}/raw/release"
    fi
}

resolve_release() {
    if [ -z "$TAG" ]; then
        log "resolving latest release from ${SOURCE} (${OWNER}/${REPO}) ..."
        DL_BASE="$(get_release_base)"
        TAG="$(curl -fsSL "${DL_BASE}/latest.txt" 2>/dev/null | tr -d '\r\n')"
        [ -n "$TAG" ] || die "could not resolve latest release for $OWNER/$REPO"
    fi
    [ -z "$VER" ] && VER="$TAG"
}

download_package() {
    resolve_release
    TARBALL="gosingbox-${VER}-linux-${ARCH}.tar.gz"
    DL_BASE="$(get_release_base)"
    DL_URL="${DL_BASE}/${TARBALL}"
    TMP="$(mktemp -d)"

    log "downloading $DL_URL"
    curl -fsSL -o "$TMP/$TARBALL" "$DL_URL" || die "download failed; is the release published?"
    log "verifying checksum"
    curl -fsSL -o "$TMP/$TARBALL.sha256" "${DL_URL}.sha256" || die "checksum download failed"
    (cd "$TMP" && sha256sum -c "${TARBALL}.sha256") || die "checksum verification failed"
    log "extracting to $TMP"
    mkdir -p "$TMP/pkg"
    tar -xzf "$TMP/$TARBALL" -C "$TMP/pkg"
    PKG_DIR="$TMP/pkg/gosingbox-${VER}-linux-${ARCH}"
    [ -d "$PKG_DIR" ] || die "unexpected tarball layout (missing $PKG_DIR)"
}

write_env() {
    # SECRET_KEY is a JSON document (may contain double quotes and literal \n);
    # single-quote wrap it so the env file survives `source`-ing by run.sh.
    ESCAPED_KEY=$(printf '%s' "$SECRET_KEY" | sed "s/'/'\\\\''/g")
    cat > "$INSTALL_DIR/env" <<EOF
NODE_PORT=$NODE_PORT
SECRET_KEY='$ESCAPED_KEY'
INTERNAL_SOCKET_PATH=${INTERNAL_SOCKET_PATH:-/run/gosingbox/internal.sock}
INTERNAL_REST_TOKEN=${INTERNAL_REST_TOKEN:-$(openssl rand -hex 32 2>/dev/null || dd if=/dev/urandom bs=32 count=1 2>/dev/null | base64 | tr -d '\n')}
SINGBOX_LOG_LEVEL=warn
# Node 自身日志等级: debug | info | warn | error（排查面板连接问题时可设 debug）
LOG_LEVEL=${LOG_LEVEL:-info}
SINGBOX_DEBOUNCE_MS=5000
SINGBOX_GEO_DIR=/var/lib/gosingbox/singbox/geo
EOF
    chmod 600 "$INSTALL_DIR/env"
}

# --- service management (systemd + openrc) ---
setup_service() {
    if [ "$INIT" = systemd ]; then
        mkdir -p /etc/systemd/system /var/log/gosingbox /var/lib/gosingbox/singbox
        cat > "/etc/systemd/system/$SERVICE.service" <<EOF
[Unit]
Description=gosingbox (sing-box data plane)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/bin/run.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
    elif [ "$INIT" = openrc ]; then
        mkdir -p /etc/init.d /var/log/gosingbox /var/lib/gosingbox/singbox
        cat > "/etc/init.d/$SERVICE" <<EOF
#!/sbin/openrc-run
description="gosingbox (Go, sing-box data plane)"
supervisor=supervise-daemon
command="$INSTALL_DIR/bin/run.sh"
command_background=false
pidfile="/run/$SERVICE.pid"
output_log="/var/log/gosingbox/gosingbox.log"
error_log="/var/log/gosingbox/gosingbox-error.log"
depend() {
    need net
    after firewall
}
EOF
        chmod +x "/etc/init.d/$SERVICE"
    else
        die "neither systemd nor OpenRC detected — cannot install a service"
    fi
}

enable_service() {
    if [ "$INIT" = systemd ]; then
        systemctl enable "$SERVICE" >/dev/null 2>&1 || log "WARN: systemctl enable failed"
    else
        command -v rc-update >/dev/null 2>&1 && rc-update add "$SERVICE" default 2>/dev/null || log "WARN: rc-update add failed"
    fi
}

start_service() {
    if [ "$INIT" = systemd ]; then
        systemctl restart "$SERVICE" >/dev/null 2>&1 || systemctl start "$SERVICE"
    else
        command -v rc-service >/dev/null 2>&1 && { rc-service "$SERVICE" restart >/dev/null 2>&1 || rc-service "$SERVICE" start; }
    fi
}

stop_service() {
    if [ "$INIT" = systemd ]; then
        systemctl stop "$SERVICE" >/dev/null 2>&1 || true
    elif [ "$INIT" = openrc ]; then
        command -v rc-service >/dev/null 2>&1 && rc-service "$SERVICE" stop >/dev/null 2>&1 || true
    fi
}

disable_service() {
    if [ "$INIT" = systemd ]; then
        systemctl disable "$SERVICE" >/dev/null 2>&1 || true
    elif [ "$INIT" = openrc ]; then
        command -v rc-update >/dev/null 2>&1 && rc-update del "$SERVICE" 2>/dev/null || true
    fi
}

SVC_CTL=""
case "$INIT" in
    systemd) SVC_CTL="systemctl $SERVICE" ;;
    openrc)  SVC_CTL="rc-service $SERVICE" ;;
esac

print_summary() {
    echo >&2
    echo "==> Installed to $INSTALL_DIR (installer v${INSTALLER_VERSION})" >&2
    echo "    Port:      $NODE_PORT" >&2
    echo "    Init:      $INIT" >&2
    echo "    Service:   $SERVICE" >&2
    echo "    Logs:      /var/log/gosingbox/*.log" >&2
    [ -n "$SVC_CTL" ] && echo "    Control:   $SVC_CTL {start|stop|restart|status}" >&2
    echo "    Config:    $INSTALL_DIR/env" >&2
    echo >&2
    echo "    Verify:    curl -k https://127.0.0.1:$NODE_PORT/node/xray/healthcheck" >&2
    echo >&2
}

do_install() {
    if is_installed; then
        echo ">> gosingbox is already installed at $INSTALL_DIR" >&2
        while :; do
            CHOICE="$(ask "What do you want to do? [upgrade/uninstall/cancel]" "upgrade")"
            case "$CHOICE" in
                upgrade|u|U) do_upgrade; return ;;
                uninstall|remove|r|R) do_uninstall; return ;;
                cancel|c|C|"") log "cancelled"; exit 0 ;;
                *) log "please answer upgrade, uninstall or cancel" ;;
            esac
        done
    fi

    echo "==> gosingbox (Go) installer v${INSTALLER_VERSION}" >&2
    echo "    Data plane: sing-box (VLESS+Reality + Shadowsocks 2022)" >&2
    echo "    Init detected: $INIT" >&2
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

    download_package

    log "installing to $INSTALL_DIR"
    mkdir -p "$INSTALL_DIR"
    cp -r "$PKG_DIR/." "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/bin/run.sh" "$INSTALL_DIR/bin/gosingbox" "$INSTALL_DIR/bin/geocheck"
    ln -sf "$INSTALL_DIR/bin/geocheck" "$GEOCHECK_LINK"

    write_env
    setup_service
    enable_service

    print_summary
    start_service
}

do_upgrade() {
    is_installed || die "not installed at $INSTALL_DIR; run install first"

    log "upgrading existing install at $INSTALL_DIR (keeping env config)"
    download_package

    # Stop service before replacing running binaries to avoid Linux "Text file busy" ETXTBSY error
    stop_service || true

    cp -r "$PKG_DIR/." "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/bin/run.sh" "$INSTALL_DIR/bin/gosingbox" "$INSTALL_DIR/bin/geocheck"
    ln -sf "$INSTALL_DIR/bin/geocheck" "$GEOCHECK_LINK"

    for f in "$INSTALL_DIR/env.example" "$INSTALL_DIR/README.md"; do
        [ -f "$f" ] && chmod 644 "$f" 2>/dev/null || true
    done

    setup_service
    enable_service
    start_service

    log "upgraded to $VER; env config at $INSTALL_DIR/env was preserved"
}

do_uninstall() {
    log "uninstalling $SERVICE"

    stop_service
    disable_service

    if [ "$INIT" = systemd ]; then
        rm -f "/etc/systemd/system/$SERVICE.service"
        systemctl daemon-reload 2>/dev/null || true
    else
        rm -f "/etc/init.d/$SERVICE"
        rm -f "/run/$SERVICE.pid"
    fi

    if [ -L "$GEOCHECK_LINK" ] || [ -e "$GEOCHECK_LINK" ]; then
        log "removing $GEOCHECK_LINK"
        rm -f "$GEOCHECK_LINK"
    fi

    if [ -d "$INSTALL_DIR" ]; then
        log "removing install dir $INSTALL_DIR"
        rm -rf "$INSTALL_DIR"
    fi

    rm -rf /var/log/gosingbox /var/lib/gosingbox

    log "uninstall complete"
}

case "$MODE" in
    install) do_install ;;
    upgrade) do_upgrade ;;
    uninstall) do_uninstall ;;
esac
