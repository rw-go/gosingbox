# 3.4.1.23

Native sing-box configurations now register outbound traffic counters across
implicit `direct`, explicit tagged outbounds, and untagged explicit outbounds
(`"0"`, `"1"`, ...) so node-level traffic reporting covers direct and relay
egress without charging fixed-password SS2022 relays to individual users.

Native path validation permits rule-set/domain `.db` cache files under
`/var/lib/gosingbox` (and `SINGBOX_GEO_DIR`) while confining `tls.certificate_path`
and `tls.key_path` to standard certificate directories (preserving intra-tree
symlinks such as Let's Encrypt `live -> archive` and rejecting escaping links).
Xray-transpiled configurations share the same loopback management-port dial guard
and random Clash API secret protection as native configurations.

Authenticated AnyTLS sessions enforce a per-session concurrent stream cap (512)
with immediate slot reclamation on stream close, a 10-second destination header
read deadline on new streams, a TLS server handshake deadline, and full buffering
across fragmented initial authentication records and large padding frames.

The panel-facing node version remains 3.4.1 and the embedded sing-box version
remains 1.14.3.
