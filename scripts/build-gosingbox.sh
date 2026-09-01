#!/usr/bin/env bash
# Build a self-contained Go gosingbox (sing-box data plane) for
# linux/amd64 (static binary, musl-compatible → runs on Alpine 3.21 / LXC).
# Output: dist-go/<name>/... and dist-go/<name>.tar.gz
#
# Unlike build-standalone.sh (Node.js), the Go binary is a single static binary
# with no runtime dependency; we only bundle sing-box + geocheck helpers.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
GOSN_DIR="$ROOT_DIR"
OUT_DIR="$ROOT_DIR/dist-go"
STAGE="$OUT_DIR/stage"
VER="${GO_NODE_VERSION:-3.4.1-go.1}"   # package/release identifier (may carry a suffix)
NODE_SEMVER="${GO_NODE_SEMVER:-3.4.1}" # value reported to the panel (must be bare semver)
SINGBOX_VERSION="${SINGBOX_VERSION:-1.13.20}"
GEOCHECK_VERSION="${GEOCHECK_VERSION:-v0.3.0-cn}"
ARCH="${ARCH:-amd64}"
PKG_NAME="gosingbox-${VER}-linux-${ARCH}"

echo "==> Go gosingbox ${VER} standalone build (linux/${ARCH})"

rm -rf "$OUT_DIR"
mkdir -p "$STAGE/$PKG_NAME"/{bin,var/singbox,var/log,var/geo}

# --- 1. Build the Go binary (static, CGO_ENABLED=0, sing-box embedded) ---
echo "==> [1/2] build gosingbox (sing-box embedded, static)"
(
    cd "$GOSN_DIR"
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
        -tags "with_clash_api,with_v2ray_api,with_utls,with_acme,with_quic" \
        -ldflags "-s -w -X github.com/rwnode/rwnode-gosingbox/internal/app.NodeVersion=${NODE_SEMVER} -X github.com/sagernet/sing-box/constant.Version=${SINGBOX_VERSION}" \
        -o "$STAGE/$PKG_NAME/bin/gosingbox" ./cmd/rw-node-singbox
)
chmod +x "$STAGE/$PKG_NAME/bin/gosingbox"

# --- 2. Fetch geocheck binary (geo detection) ---
echo "==> [2/2] fetch geocheck ${GEOCHECK_VERSION}"
GEOCHECK_TGZ="geocheck_linux_${ARCH}.tar.gz"
GEOCHECK_URL="https://github.com/rwnode/geocheck/releases/download/${GEOCHECK_VERSION}/${GEOCHECK_TGZ}"
curl -fsSL -o "$OUT_DIR/$GEOCHECK_TGZ" "$GEOCHECK_URL"
mkdir -p "$OUT_DIR/geocheck-extract"
tar -xzf "$OUT_DIR/$GEOCHECK_TGZ" -C "$OUT_DIR/geocheck-extract" geocheck
install -m 0755 "$OUT_DIR/geocheck-extract/geocheck" "$STAGE/$PKG_NAME/bin/geocheck"
rm -rf "$OUT_DIR/geocheck-extract" "$OUT_DIR/$GEOCHECK_TGZ"

# --- 3. Assemble support files + tarball ---
echo "==> [3/3] assemble + pack"
cp "$SCRIPT_DIR/go-standalone/run.sh" "$STAGE/$PKG_NAME/bin/run.sh"
cp "$SCRIPT_DIR/go-standalone/gosingbox.service" "$STAGE/$PKG_NAME/"
cp "$SCRIPT_DIR/go-standalone/env.example" "$STAGE/$PKG_NAME/env.example"
chmod +x "$STAGE/$PKG_NAME/bin/run.sh"

cat > "$STAGE/$PKG_NAME/README.md" <<EOF
# gosingbox (Go, sing-box data plane) — standalone package

Linux ${ARCH} self-contained static build (no Docker, no Node.js, no glibc
dependency — runs on Alpine 3.21 / 128MB LXC).

## Run
    ./bin/run.sh
    # or set env vars first (see env.example)

## Systemd
    sudo cp gosingbox.service /etc/systemd/system/
    sudo mkdir -p /opt/gosingbox
    sudo cp -r . /opt/gosingbox/
    # edit /opt/gosingbox/env.example -> /opt/gosingbox/env with your panel SECRET_KEY
    sudo systemctl daemon-reload
    sudo systemctl enable --now gosingbox

## Binary layout
    bin/gosingbox   Go binary (static, sing-box ${SINGBOX_VERSION} embedded)
    bin/geocheck    geo detection helper (${GEOCHECK_VERSION})
    bin/run.sh      launcher

## Memory
    gosingbox RSS ~45MB (sing-box embedded, single binary).
EOF

(cd "$STAGE" && tar -czf "$OUT_DIR/${PKG_NAME}.tar.gz" "$PKG_NAME")

echo "==> DONE: $OUT_DIR/${PKG_NAME}.tar.gz"
du -h "$OUT_DIR/${PKG_NAME}.tar.gz"
