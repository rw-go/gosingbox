# Managed AnyTLS adapter

`inbound.go` derives from `protocol/anytls/inbound.go` in `bitbucket.org/rwnode/sing-box-fork v1.14.3-updatable.1`, commit `591115932b1172cf439a189085c530316e1a47b8`. Original file SHA-256: `cd9c302d763f4a7c19efd7caf0cd79c702b54c309cc40d0bea6e3db0760e1d80`. The fork license is retained in this directory.

The embedded engine registers this adapter over the AnyTLS constructor in its own sing-box inbound registry. All other constructors, routing, TLS implementation and option parsing still come from the pinned fork. This keeps the adapter small and buildable in the node repository without publishing or using a machine-specific replacement for the entire sing-box module.

Local changes:

- Require ordinary TLS; reject missing TLS and Reality for this integration phase.
- Implement the existing fork's `adapter.UpdatableInbound[option.AnyTLSUser]` interface.
- Delegate updates to the locally patched `sing-anytls` service, which handles concurrent authentication and revokes old sessions.
- Register service shutdown with the sing-box lifecycle scope so active, idle and pending plaintext sessions close with the inbound.
- Add the opt-in `shared_listener` node extension. Each engine configuration owns
  its listener groups; matching listen options and distinct `tls.server_name`
  values share one TCP listener. A bounded ClientHello parser selects the member
  and replays the original bytes into its unchanged TLS/authentication path.
  Each member retains independent users, hot updates and route metadata, and the
  real source address is preserved without a local TCP forwarding hop. Unknown
  or missing SNI is rejected. The group starts only after every member is ready,
  and shutdown also closes pre-authentication connections.

`shared_listener` is a gosingbox extension, not an upstream sing-box option. The
existing Panel native JSON path preserves it without a Panel image upgrade.
The public SNI must be visible in the outer ClientHello; ECH routing is not
supported by this extension. Other protocols and ordinary AnyTLS inbounds do not
participate unless explicitly configured.

The node's public native configuration entry point now uses this adapter when compiled with both management APIs. Isolated tests cover the public handler, TLS/AnyTLS traffic, hot updates, management authentication and rollback. Panel business integration remains a separate stage. The local AnyTLS service patch and its provenance are documented in `third_party/sing-anytls/RWNODE_PATCH.md`.
