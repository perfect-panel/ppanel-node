# TUIC transport compatibility

`service.go`, `packet.go`, `protocol.go`, and `hub.go` are derived from
`wyx2685/Xray-core` commit `83ad74c463351e01c7cde391abfd9dded9e78300`, under MPL-2.0.
The original source is at:
https://github.com/wyx2685/Xray-core/tree/83ad74c463351e01c7cde391abfd9dded9e78300/transport/internet/tuic

The upstream listener checks `authReady()` and then queues work separately.
Authentication can drain the queue between those operations, leaving the first
TCP stream or UDP datagram waiting forever. Queued unidirectional UDP streams
also return through `defer stream.CancelRead(0)` before being consumed.

This copy replaces that queue with waits on `authDone` in the existing stream
and datagram goroutines. Waiting also observes the connection context so shutdown
and peer disconnects release pending operations. It keeps upstream's proxy,
authenticator, settings, packet interfaces, and congestion control.

The listener is registered as `ppnode-tuic`; the inbound builder selects it after
building the normal TUIC configuration. No global Go module cache is modified.
Remove this compatibility module and the builder remapping once the pinned
upstream version fixes these races and the TCP/UDP regression tests pass.
