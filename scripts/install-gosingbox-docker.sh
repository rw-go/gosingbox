#!/bin/sh
# One-shot Docker installer / upgrader / uninstaller for gosingbox.
set -eu

INSTALLER_VERSION="3.4.1.1"
INSTALL_DIR="${GOSINGBOX_DOCKER_DIR:-/opt/gosingbox-docker}"
IMAGE="${GOSINGBOX_DOCKER_IMAGE:-rwnode/gosingbox:latest}"
COMPOSE_FILE="$INSTALL_DIR/compose.yaml"
ENV_FILE="$INSTALL_DIR/.env"

log() { printf '%s\n' "$*" >&2; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

read_answer() {
    if IFS= read -r REPLY </dev/tty 2>/dev/null; then
        :
    else
        IFS= read -r REPLY 2>/dev/null || REPLY=""
    fi
    REPLY="$(printf '%s' "$REPLY" | tr -d '\r')"
}

ask() {
    _prompt="$1"; _default="$2"
    printf '%s [%s]: ' "$_prompt" "$_default" >&2
    read_answer
    _answer="$REPLY"
    [ -z "$_answer" ] && _answer="$_default"
    printf '%s\n' "$_answer"
}

compose() {
    if docker compose version >/dev/null 2>&1; then
        docker compose "$@"
    elif command -v docker-compose >/dev/null 2>&1; then
        docker-compose "$@"
    else
        die "Docker Compose plugin is required"
    fi
}

is_installed() {
    [ -f "$COMPOSE_FILE" ] && [ -f "$ENV_FILE" ]
}

write_files() {
    mkdir -p "$INSTALL_DIR"
    cat > "$ENV_FILE" <<EOF
NODE_PORT=$NODE_PORT
SECRET_KEY=$SECRET_KEY
SINGBOX_LOG_LEVEL=${SINGBOX_LOG_LEVEL:-warn}
LOG_LEVEL=${LOG_LEVEL:-info}
NFTABLES_ACCEPT_REPLY_TRAFFIC=${NFTABLES_ACCEPT_REPLY_TRAFFIC:-false}
SNI_VERIFICATION=${SNI_VERIFICATION:-false}
EOF
    chmod 600 "$ENV_FILE"

    cat > "$COMPOSE_FILE" <<EOF
services:
  gosingbox:
    image: $IMAGE
    container_name: gosingbox
    hostname: gosingbox
    network_mode: host
    restart: always
    cap_add:
      - NET_ADMIN
    ulimits:
      nofile:
        soft: 1048576
        hard: 1048576
    env_file:
      - .env
    volumes:
      - gosingbox-data:/var/lib/gosingbox
    logging:
      driver: json-file
      options:
        max-size: 20m
        max-file: "3"

volumes:
  gosingbox-data:
EOF
}

do_install() {
    if is_installed; then
        log ">> gosingbox Docker is already installed at $INSTALL_DIR"
        while :; do
            CHOICE="$(ask "What do you want to do? [upgrade/uninstall/cancel]" "upgrade")"
            case "$CHOICE" in
                upgrade|u|U) do_upgrade; return ;;
                uninstall|remove|r|R) do_uninstall keep; return ;;
                cancel|c|C|"") exit 0 ;;
                *) log "please answer upgrade, uninstall or cancel" ;;
            esac
        done
    fi

    if [ -z "${NODE_PORT:-}" ]; then
        NODE_PORT="$(ask "Panel port (NODE_PORT)" "2222")"
    fi
    case "$NODE_PORT" in ''|*[!0-9]*) die "invalid port: $NODE_PORT" ;; esac

    if [ -z "${SECRET_KEY:-}" ]; then
        printf 'Panel connection secret (SECRET_KEY): ' >&2
        read_answer
        SECRET_KEY="$REPLY"
    fi
    [ -n "$SECRET_KEY" ] || die "SECRET_KEY is required"

    write_files
    compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" pull
    compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" up -d
    log "installed: $INSTALL_DIR"
    log "logs: docker logs -f gosingbox"
}

do_upgrade() {
    is_installed || die "not installed at $INSTALL_DIR"
    compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" pull
    compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" up -d --remove-orphans
    log "upgraded image: $IMAGE"
}

do_uninstall() {
    mode="${1:-keep}"
    is_installed || { log "not installed"; return; }
    case "$mode" in
        keep) compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" down ;;
        full) compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" down -v; rm -rf "$INSTALL_DIR" ;;
        *) die "usage: $0 uninstall [keep|full]" ;;
    esac
    log "uninstalled ($mode)"
}

case "${1:-install}" in
    install|"") do_install ;;
    upgrade) do_upgrade ;;
    uninstall|remove) do_uninstall "${2:-keep}" ;;
    uninstall-full|purge) do_uninstall full ;;
    --version|-v) echo "install-gosingbox-docker.sh v${INSTALLER_VERSION}" ;;
    *) die "usage: $0 {install|upgrade|uninstall [keep|full]|--version}" ;;
esac
