# 3.4.1.26

Runtime firewall table isolation and multi-instance host co-tenancy are aligned
with upstream Remnawave Node 3.4.4–3.4.6:

- **`NFTABLES_TABLE_NAME`**: allows customizing the `inet` nftables table name
  managed across startup initialization, `/node/plugin/sync` (including empty
  `plugin: null` resets), `/node/plugin/nftables/block-ips`,
  `/node/plugin/nftables/unblock-ips`, and
  `/node/plugin/nftables/recreate-tables`. Empty or whitespace-only values
  default to `remnanode`; non-empty values must match
  `^[A-Za-z_][A-Za-z0-9_-]{0,62}$` with no newline or shell/nft metacharacters,
  failing closed at startup if invalid.
- **`SUPPRESS_DUPLICATE_INSTANCE_WARNING`**: acquires the global abstract-socket
  instance lock (`\0rwnode-lock`) before initializing nftables or starting the
  data plane so an accidental duplicate instance exits immediately without
  touching existing firewall rules; setting
  `SUPPRESS_DUPLICATE_INSTANCE_WARNING=true` explicitly allows co-hosting
  multiple node instances on the same host (typically paired with distinct
  `NFTABLES_TABLE_NAME`, `NODE_PORT`, and management addresses).

The panel-facing node version remains 3.4.1 and the embedded sing-box version
remains 1.14.3.
