# 3.4.1.22

Native sing-box direct outbounds now protect the node's local statistics and
Clash management endpoints, including configurations that use an implicit direct
outbound. Startup, internal restart and recovery retain the native policy.

AnyTLS limits concurrent pending handshakes and authentication across listeners.
Authenticated sessions release this capacity. A deadline bounds the first
authentication record after the TLS handshake.

The panel-facing node version remains 3.4.1 and the embedded sing-box version
remains 1.14.3. This release works with existing native profiles and fixed SS2022
relay configurations. The matching panel update reduces credentials sent to each
node during user synchronization.
