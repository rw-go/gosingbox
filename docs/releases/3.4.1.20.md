# 3.4.1.20 — AnyTLS shared listener

Release channels: Docker Hub `rwnode/gosingbox:3.4.1.20` and `latest`, plus
Bitbucket `rwnode/rwnode-gosingbox` source and Linux amd64 standalone package.

This release adds an opt-in `shared_listener` field to native AnyTLS inbounds.
Members with identical listen options and distinct `tls.server_name` values share
one TCP socket. Each member keeps its own tag, certificate, authorized users and
hot-update lifecycle. Existing `route.rules` can select different SS2022 outbounds
by inbound tag. The Panel's existing native profile and Host APIs support the
configuration; this change does not require a Panel database or image upgrade.

```json
{
  "type": "anytls",
  "tag": "anytls-jp1-wyx",
  "listen": "::",
  "listen_port": 443,
  "shared_listener": "jp1sb-443",
  "users": [],
  "tls": { "enabled": true, "server_name": "wyx.cloud" }
}
```

The managed Panel supplies users and the persistent default certificate. A
standalone node configuration still needs actual TLS certificate material.
All members of the group must opt in, including an existing default entry.
There is no implicit catch-all: absent or unknown SNI fails closed. Name matching
is case insensitive; duplicate names, invalid names and differing listen options
are rejected. No TLS termination proxy or Nginx is added, and the source address
is retained. ClientHello parsing is bounded to 128 KiB and five seconds. ECH
routing is not supported; the configured SNI must appear in the outer hello.

The node advertises `anytlsSharedListener: true` under `/node/capabilities`.
Its Panel-facing `nodeVersion` remains `3.4.1` and embedded core is `1.14.3`.

Validation includes the default and release-tag Go checks, race tests, and a
live single-443 deployment with two distinct SS2022 next hops. The live checks
cover sing-box, Mihomo and URI subscriptions, independent permission revocation
without restarting the core, source IP, traffic counters and restart recovery.
Existing ordinary AnyTLS, VLESS Reality Vision and SS2022 traffic also passed.

Upgrade the node before enabling this extension in a Profile. Restore a profile
without `shared_listener` before downgrading to an older image. This extension
shares listeners between AnyTLS inbounds only; VLESS/AnyTLS mixed listeners and
automatic conversion of existing profiles are not included.
