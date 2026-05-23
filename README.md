# aire-go

Reference Go implementation of [AIRE](../aire-spec) — the QUIC-native agent protocol.

> Status: v0.1 conformant. v0.2 in progress.

## Status

This is the canonical Go implementation of the AIRE spec. It tracks the spec and is the reference any other implementation should match for behavior. v0.1 is complete — frame codec, QUIC transport, HELLO handshake, Operation stream multiplexing, Node runtime, and a conformance harness that round-trips every vector in [`aire-spec/vectors/v0.1.json`](https://github.com/aire-protocol/aire-spec/blob/main/vectors/v0.1.json). v0.2 work in flight: DID + handle resolver landed; capability negotiation and per-frame signing are still open.

## Install

```bash
go get github.com/aire-protocol/aire-go
```

## Demo

```bash
# Two-node v0.1 demo: streaming with cancel mid-stream
go run ./cmd/aire-demo
```

## Layout

- `frame.go` — frame type definitions and wire encoding (spec §2)
- `handshake.go` — HELLO exchange, version + capability negotiation (spec §4)
- `conn.go` — connection abstraction over QUIC, including `DevTLSConfig` for local development
- `operation.go` — per-Operation stream multiplexing (spec §2.4)
- `node.go` — local node runtime: accept loop, dispatch, agent registry
- `addressing.go` — `did:web` + handle resolver, AIREv1 service entry parser (spec §§5–6)
- `conformance_test.go` — round-trips every vector in `aire-spec/vectors/v0.1.json`
- `cmd/aire-demo` — two-node demo for v0.1

## Relationship to Vega

This library has zero Vega dependencies. AIRE is independent of any specific runtime. [Vega](https://github.com/everydev1618/govega) is the canonical OTP-style runtime that fully exploits AIRE's distribution semantics, but you can use `aire-go` directly without Vega.

## License

Apache 2.0 — see [LICENSE](./LICENSE).
