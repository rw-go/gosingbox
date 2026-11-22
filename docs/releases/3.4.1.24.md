# 3.4.1.24

Shadowsocks 2022 password mode is now unified across both Xray-transpiled
(`coreType = "xray"` or omitted) and native sing-box (`coreType = "singbox"`)
configurations:

- **0 bound users**: runs in single-password PSK relay mode using the inbound
  server `password` (tracking node-level inbound traffic in `v2ray_api` with 0
  personal user billing), regardless of whether `clients`/`users` is omitted or
  empty (`[]`) or whether `managed: true` is present.
- **>= 1 bound users**: runs in multi-user EIH (`<serverPSK>:<userKey>`) mode
  and rejects bare server PSK authentication.
- **Dynamic `0 <-> N` transitions**: both full `/node/xray/start` reloads and
  incremental `add-user(s)` / `remove-user(s)` updates switch cleanly between
  single-password PSK relay mode and multi-user EIH mode in both directions,
  closing active connections from the previous mode on transition.

The panel-facing node version remains 3.4.1 and the embedded sing-box version
remains 1.14.3.
