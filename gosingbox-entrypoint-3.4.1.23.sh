#!/bin/sh
set -eu

random_alnum() {
    tr -dc 'A-Za-z0-9' </dev/urandom | head -c "$1"
}

# Abstract Unix socket names and the internal token are generated per
# container by default. They can be explicitly supplied for reproducible
# deployments or external tooling.
: "${INTERNAL_SOCKET_PATH:=rwint-$(random_alnum 10)}"
: "${INTERNAL_REST_TOKEN:=$(random_alnum 64)}"
: "${NODE_PORT:=2222}"
: "${SINGBOX_GEO_DIR:=/var/lib/gosingbox/singbox/geo}"

export INTERNAL_SOCKET_PATH INTERNAL_REST_TOKEN NODE_PORT SINGBOX_GEO_DIR

if [ -z "${SECRET_KEY:-}" ]; then
    printf '%s\n' 'ERROR: SECRET_KEY is required.' >&2
    exit 1
fi

mkdir -p "$SINGBOX_GEO_DIR"
exec /usr/local/bin/gosingbox -serve
