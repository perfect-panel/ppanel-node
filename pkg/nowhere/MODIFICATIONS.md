# Nowhere implementation notes

This module implements NW3 in native Go for PPanel-node. It does not embed or
link a Rust runtime. Original third-party notices are retained in source files
and the accompanying license files.

- Wire reference: NodePassProject/Nowhere 3.3.0 (`000007b2482b8acf3a609888921fd847cad56c33`).
- Original project: https://github.com/NodePassProject/Nowhere
- Original license: GPL-3.0-only; see `LICENSE`.
- Additional implementation and integration work: PPanel contributors,
  GPL-3.0-or-later where marked in source headers.

## Changes

- 2026-11-10: Added the native NW3 implementation: exporter-bound authentication,
  TLS/QUIC carriers, connection and flow registry, setup results, UoT and QUIC
  DATAGRAM fragmentation, Morph TCP/UDP, authenticated Prelude replay protection,
  and selected-key verification without a fallback user scan.
- 2026-11-10: Isolated authentication scan guards and congestion helpers under
  `internal/`, keeping the host application's existing sing dependency.
  Congestion helpers retain their SagerNet/sing-quic and MetaCubeX origin notices.
- 2026-11-10: Published the local module as `github.com/perfect-panel/nowhere`
  under `pkg/nowhere`; added the Xray adapter and interoperability tests in the
  host application. Xray's dependency source and pinned version are unchanged.
- 2026-11-10: Removed per-candidate Morph allocations using short-message HMAC,
  shared Prelude preprocessing, immutable credential references, short QUIC
  header filtering and pooled read scratch. Replaced full-table rebuilds for
  deltas with copy-on-write index shards and stable candidate IDs; retained
  work budgets, AEAD checks, exporter binding, replay protection and revocation.
