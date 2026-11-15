# Local AnyTLS lifecycle patch

Baseline: `github.com/anytls/sing-anytls v0.0.11`, commit `130d2e61b8895727bfed4942c535e91b246a9603`. Local patch identifier: `rwnode.1`. The original license is retained in `LICENSE`; `UPSTREAM.json` records hashes of every original module file. This directory is a source replacement in the root `go.mod`, not a separately published version.

The root module continues to use the locked sing-box fork and selected sing version. The copied `go.mod` retains the upstream requirements; run tests from the **root module** to exercise the actual selected dependency graph:

```bash
go test -race github.com/anytls/sing-anytls/...
```

Changes are limited to:

- `service.go`: synchronize authentication reads and updates; retain immutable account generations across identical updates; track and synchronously close authenticated sessions after deletion, identity change or password rotation. Register sessions under the same lock after checking the account generation again, rejecting late handshakes after removal/re-add. Recheck authorization before routing new streams; close pending unauthenticated connections and sessions on shutdown.
- `session/session.go`: prevent adding a stream after session closure; synchronize peer-version and buffered-write state used concurrently during connection shutdown and session reuse.
- `session/stream.go`: synchronize stream error state and close-hook attachment with peer-driven closure.
- `session/client.go`: attach the pool hook using the synchronized stream API. The existing unsynchronized attachment was reproduced by the revocation race tests.
- `service_test.go`: use the actual AnyTLS client/service to test credential replacement, session revocation, concurrent handshakes, late registration and shutdown.

An update is serialized with authentication and session registration. An unchanged `(password, name)` retains its generation and sessions. Revoked sessions close their transport and streams; the check at stream dispatch prevents a queued old stream from gaining usable access. A failed higher-level multi-inbound transaction may restore credentials, but cannot restore already closed sessions.

This patch is required by the local managed AnyTLS inbound adapter. It does not implement native Panel configuration parsing, client subscription generation, or every upstream protocol feature. Rebase explicitly against a future upstream/fork version, preserving the tests; do not replace this directory with an unverified newer release.
