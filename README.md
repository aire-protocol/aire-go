# aire-go

Reference Go implementation of [AIRE](../aire-spec) — the QUIC-native agent protocol.

> Status: v0.2 conformant.

## Status

This is the canonical Go implementation of the AIRE spec. It tracks the spec and is the reference any other implementation should match for behavior. v0.2 is complete — frame codec, QUIC transport, signed HELLO handshake (Ed25519 over `did:key` / `did:web`), capability negotiation (naming, versioning, active set), AIREv1 service-entry + handle resolution, Operation stream multiplexing, Node runtime, replay protection, and conformance harnesses that round-trip every vector in [`aire-spec/vectors/v0.1.json`](https://github.com/aire-protocol/aire-spec/blob/main/vectors/v0.1.json) and [`aire-spec/vectors/v0.2.json`](https://github.com/aire-protocol/aire-spec/blob/main/vectors/v0.2.json). v0.3 work (CANCEL frame, BUDGET, DELEGATE propagation) is not started.

## Install

```bash
go get github.com/aire-protocol/aire-go
```

## Demo

```bash
# Two-node demo: streaming with cancel mid-stream
go run ./cmd/aire-demo

# Federation demo: Node A delegates to Node B over AIRE
go run ./cmd/aire-peers
```

## Layout

- `frame.go` — frame type definitions and wire encoding (spec §2)
- `handshake.go` — signed HELLO exchange, version + capability negotiation (spec §4)
- `capability.go` — capability naming, versioning, active-set negotiation (spec §4.5 / §4.6)
- `identity.go` — Ed25519, multibase, did:key, signature block codec, replay cache (spec §5.4)
- `addressing.go` — did:web + handle resolver, AIREv1 service entry parser (spec §§5–6)
- `conn.go` — connection abstraction over QUIC, including `DevTLSConfig` for local development
- `operation.go` — per-Operation stream multiplexing (spec §2.4)
- `node.go` — local node runtime: accept loop, dispatch, agent registry
- `conformance_test.go` — round-trips every vector in `aire-spec/vectors/v0.1.json`
- `identity_test.go` — verifies the v0.2 signed-HELLO vector end to end
- `cmd/aire-demo` — two-node demo (streaming + cancel mid-stream)
- `cmd/aire-peers` — federation demo (Node A delegates to Node B over AIRE)

## Relationship to Vega

This library has zero Vega dependencies. AIRE is independent of any specific runtime. [Vega](https://github.com/everydev1618/govega) is the canonical OTP-style runtime that fully exploits AIRE's distribution semantics, but you can use `aire-go` directly without Vega.

## License

Apache 2.0 — see [LICENSE](./LICENSE).
