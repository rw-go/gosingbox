# syntax=docker/dockerfile:1.7

FROM golang:1.26.5-alpine AS build

ARG TARGETARCH
ARG SINGBOX_VERSION=1.14.3
ARG GEOCHECK_VERSION=0.3.0-cn

WORKDIR /src
COPY go.mod go.sum ./
# cache mount：与 aialloy 项目共用同一份 Go 模块缓存（同一 target 即共享），
# 两边都依赖 xray/sing 生态，重复的模块只下载一次。
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    go mod download
COPY . .

# 编译缓存同样持久化：改代码后增量编译，不再全量重编
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,target=/root/.cache/go-build,sharing=locked \
    CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    go build -trimpath -tags "with_clash_api,with_v2ray_api,with_utls,with_acme,with_quic" \
    -ldflags "-s -w -X github.com/rwnode/rwnode-gosingbox/internal/app.NodeVersion=3.4.3 -X github.com/sagernet/sing-box/constant.Version=${SINGBOX_VERSION}" \
    -o /out/gosingbox ./cmd/rw-node-singbox

FROM alpine:3.21 AS geocheck

ARG TARGETARCH
ARG GEOCHECK_VERSION=0.3.0-cn

RUN --mount=type=cache,target=/var/cache/apk,sharing=locked \
    apk add --update-cache ca-certificates curl \
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

RUN --mount=type=cache,target=/var/cache/apk,sharing=locked \
    apk add --update-cache ca-certificates nftables

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
