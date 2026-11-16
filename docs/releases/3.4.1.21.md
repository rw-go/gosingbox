# 3.4.1.21 — Native fixed-password SS2022 relays

Native sing-box input now preserves SS2022 single-password inbounds when `users`
is absent and `managed` is not true. They stay outside Panel user hot updates and
personal accounting, while retaining node inbound traffic counters. This fills
the native-input gap; the existing Xray-input translator is unchanged.

An explicit `users: []` remains a closed managed port. Revoking its last user
never enables access with the server key. Use separate ports for fixed inter-node
relays and public managed SS2022 users. Both AES-128-GCM and AES-256-GCM are
supported. At least one managed inbound is still required in a native Profile.

The node advertises `staticShadowsocks2022: true`; the matching Panel extension
checks it before sending fixed-password configurations. Older node builds are
rejected before start, and existing managed configurations keep their behavior.
Node semver remains `3.4.1`; the embedded core remains `1.14.3`.

Validation covers real TCP/UDP traffic, a chained SS relay, rejected wrong keys,
closed empty managed ports, add/revoke operations, internal config recovery,
forced restart, per-inbound counters and absence of personal relay usage. Full
default/release-tag Go build, vet, tests and scoped race tests passed.

Coordinate migrations from official Xray nodes with the matching Panel and
native Profile. Installing this image while the Panel still sends a legacy
managed-empty Xray configuration does not convert it into a fixed relay. Before
downgrading, restore a configuration accepted by the older native validator.
