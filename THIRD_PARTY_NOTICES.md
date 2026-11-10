# Third-party source included in PPanel-node

## Nowhere / NW3

`pkg/nowhere` contains a native Go implementation of
[NodePassProject/Nowhere](https://github.com/NodePassProject/Nowhere) NW3,
matching version 3.3.0 (`000007b2482b8acf3a609888921fd847cad56c33`). Original wire
implementation files retain the NodePassProject copyright and GPL-3.0-only
headers. Additional code is GPL-3.0-or-later where marked. The license text and
implementation notes are included in that directory.

`pkg/nowhere/internal/authscan` uses SagerNet/sing's network types with local
authentication admission and cache helpers. The congestion helpers under
`internal/congestion_meta1` and `internal/congestion_meta2` derive from
SagerNet/sing-quic and retain their MetaCubeX origin notices. The accompanying
GPL-3.0 license texts are preserved. These packages are isolated inside the
Nowhere module and do not replace Xray's sing module.

The adapter in `core/protocol/nowhere` uses Xray's public interfaces; the pinned
Xray dependency is unchanged. Source headers identify the licenses of the
adapter and interoperability tests.

The NW3 Core specification is published separately by
[NodePassProject/Nowhere-Protocol](https://github.com/NodePassProject/Nowhere-Protocol)
under CC BY 4.0.
