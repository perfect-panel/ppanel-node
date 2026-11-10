# nowhere

> Native Go implementation of [NodePassProject/Nowhere](https://github.com/NodePassProject/Nowhere) NW3 (GPL-3.0-only), exposed through sing network interfaces. See `MODIFICATIONS.md` for implementation notes.

`nowhere` implements the server side of NW3, pinned to Nowhere **3.3.0**
(`000007b2482b8acf3a609888921fd847cad56c33`). It is native Go and does not embed
or link the Rust runtime. The independent [NW3 Core specification](https://github.com/NodePassProject/Nowhere-Protocol/blob/main/PROTOCOL.md)
is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

The module owns exporter-bound authentication, TLS 1.3 / QUIC carriers, flow
admission and lifetime, setup results, UoT / QUIC DATAGRAM fragmentation, and
optional Morph. TCP Morph requires the authenticated Prelude Extension used
by Rust 3.3.0, including its replay window and silent rejection policy. QUIC
Morph uses one fresh nonce per UDP datagram and tracks connection ID rotation.
After Morph selects a credential, the AuthFrame checks only that current key
and owner. A failed tag is rejected without scanning other users. The selected
check consumes one authentication work unit; only full AuthFrame success warms
the source cache and clears failure cooldown.

Applications provide a `ServerHandler`, `Authenticator`, and `FlowRegistry` to
`NewPortal`. `HandleTLS` takes a raw TCP connection. For QUIC with Morph, call
`ConfigureQUICTransport` before `quic.Transport.Listen`, use its returned config,
and pass accepted connections to `HandleQUIC`. The wrapper deliberately uses
ordinary `net.PacketConn` I/O and a 1200-byte QUIC packet size, accounting for
the 12-byte Morph envelope without GSO/GRO or path MTU discovery.

Authenticated connections use sing's `TCPConnectionHandlerEx` and
`UDPConnectionHandlerEx`; `auth.UserFromContext[string]` returns `User.Name`.
Handlers report handshake success before accessing payload. Applications build
initial tables with `PrepareAuthUpdate`. Subsequent additions, rotations and
removals use `Authenticator.PrepareChanges` followed by `Commit`; stale deltas
return `ErrStaleAuthUpdate` and must be prepared again. Delta updates copy only
affected index shards and reuse unchanged credentials and derived keys. After
publication, call `FlowRegistry.CloseStale` to close revoked carriers. Admission
checks current credentials even between publication and that sweep.

Candidate caches retain stable, never-reused credential IDs across updates.
Removed IDs cannot authenticate or bypass failure cooldown, even if the same
key and identity are later re-added. A cold source still requires a linear key
search. Prelude checks use stack-backed HMAC inputs and unpack request fields
once; QUIC rejects wrong keys from a short header before decrypting and
authenticating the complete Initial. Authentication work budgets are unchanged.

Measure the complete Morph selection plus AuthFrame checks, and an incremental
add/remove cycle, with:

```sh
go test -run '^$' -bench '^(BenchmarkMorphAuthentication|BenchmarkAuthUserChanges)$' -benchmem
```

The cold benchmark targets the final index shard (near-worst scan length),
excludes network/TLS handshake time, and expands the test work budget to measure
algorithm cost rather than production throttling. `morph-selected` in the older
microbenchmark measures only the final AuthFrame check, not key selection.

Shared keys are exactly **32 lowercase hexadecimal ASCII characters**. They are
used as text, not hex-decoded bytes. ALPN is exactly `nw3`. TLS carries one flow
per connection; QUIC authenticates on client bidirectional stream 0 and carries
subsequent flows on client bidirectional streams. Old `now/1`, split-direction
pairing, and the old TLS mux are not supported. The optional remote Egress
extension is outside this Portal implementation.

Panel models, certificate provisioning, listener transactions, routing,
accounting, and device limits belong to the calling application. This copy is
integrated by `core/protocol/nowhere` in PPanel-node. See `LICENSE` and the
repository's `THIRD_PARTY_NOTICES.md` for attribution.

Run module validation with `go test -race ./...`. From the PPanel-node root, run the
independent Rust interoperability matrix with:

```sh
NOWHERE_RUST_VECTOR_BINARY=/path/to/nowhere-3.3.0 \
  go test ./core -run '^TestNowhereRustInterop$' -count=1 -timeout=5m
```

The matrix covers TLS and QUIC with Morph disabled/enabled, TCP, UDP, and
concurrent TCP transfers. It requires a separately built upstream Rust binary.
