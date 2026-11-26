# 3.4.1.25

Native sing-box (`coreType = "singbox"`) certificate provider validation and
Shadowsocks 2022 capability negotiation are updated:

- **Certificate provider storage directory confinement**: validates top-level
  `certificate_providers`, inline inbound `tls.certificate_provider` objects or
  tag references, and `tls.acme` options. Only `acme` and `cloudflare-origin-ca`
  provider types are accepted (`tailscale` and unknown types are rejected),
  string `tls.certificate_provider` values must reference a declared top-level
  `certificate_providers[].tag`, and non-empty `data_directory` paths must be
  clean absolute directories confined under `/var/lib/gosingbox`,
  `/etc/gosingbox`, or `/tls` without `$` environment expansion or escaping /
  dangling symlinks.
- **`dynamicShadowsocks2022` capability**: `GET /node/capabilities` now
  advertises `"dynamicShadowsocks2022": true` on management-enabled builds,
  allowing compatible panels to retain `"users": []` on managed native SS2022
  inbounds and switch between 0-user single-password PSK relay mode and
  multi-user EIH mode via incremental user handlers without full config reloads.

The panel-facing node version remains 3.4.1 and the embedded sing-box version
remains 1.14.3.
