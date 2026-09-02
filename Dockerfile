# syntax=docker/dockerfile:1.7

FROM golang:1.26.5-alpine AS build

ARG TARGETARCH
ARG SINGBOX_VERSION=1.13.20
ARG GEOCHECK_VERSION=0.3.0-cn

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    go build -trimpath -tags "with_clash_api,with_v2ray_api,with_utls,with_acme,with_quic" \
    -ldflags "-s -w -X github.com/rwnode/rwnode-gosingbox/internal/app.NodeVersion=3.4.1 -X github.com/sagernet/sing-box/constant.Version=${SINGBOX_VERSION}" \
    -o /out/gosingbox ./cmd/rw-node-singbox

FROM alpine:3.21 AS geocheck

ARG TARGETARCH
ARG GEOCHECK_VERSION=0.3.0-cn

RUN apk add --no-cache ca-certificates curl \
    && case "${TARGETARCH}" in \
         amd64|arm64) ;; \
         *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
       esac \
    && cd /tmp \
    && ARCHIVE="geocheck_linux_${TARGETARCH}.tar.gz" \
    && BASE="https://github.com/rwnode/geocheck/releases/download/v${GEOCHECK_VERSION}" \
    && curl -fsSL "${BASE}/${ARCHIVE}" -o "${ARCHIVE}" \
    && curl -fsSL "${BASE}/checksums.txt" -o checksums.txt \
    && grep "  ${ARCHIVE}$" checksums.txt | sha256sum -c - \
    && tar -xzf "${ARCHIVE}" geocheck \
    && install -m 0755 /tmp/geocheck /usr/local/bin/geocheck \
    && rm -f "/tmp/${ARCHIVE}" /tmp/checksums.txt /tmp/geocheck

FROM alpine:3.21

LABEL org.opencontainers.image.title="gosingbox" \
      org.opencontainers.image.description="Remnawave node with embedded sing-box data plane" \
      org.opencontainers.image.url="https://github.com/rwnode/rwnode-gosingbox" \
      org.opencontainers.image.source="https://github.com/rwnode/rwnode-gosingbox" \
      org.opencontainers.image.vendor="rwnode" \
      org.opencontainers.image.licenses="AGPL-3.0"

RUN apk add --no-cache ca-certificates nftables

COPY --from=build /out/gosingbox /usr/local/bin/gosingbox
COPY --from=geocheck /usr/local/bin/geocheck /usr/local/bin/geocheck
COPY scripts/docker/entrypoint.sh /usr/local/bin/gosingbox-entrypoint

RUN chmod 0755 /usr/local/bin/gosingbox-entrypoint \
    && mkdir -p /var/lib/gosingbox/singbox/geo

ENV NODE_ENV=production \
    NODE_PORT=2222 \
    SINGBOX_STATS_ADDRESS=127.0.0.1:6450 \
    SINGBOX_CLASH_ADDRESS=127.0.0.1:9090 \
    SINGBOX_LOG_LEVEL=warn \
    SINGBOX_DEBOUNCE_MS=5000 \
    SINGBOX_GEO_DIR=/var/lib/gosingbox/singbox/geo \
    LOG_LEVEL=info

VOLUME ["/var/lib/gosingbox"]

ENTRYPOINT ["/usr/local/bin/gosingbox-entrypoint"]
