# aire-go

Reference Go implementation of [AIRE](../aire-spec) — the QUIC-native agent protocol.

> Status: scaffolding. v0.1 implementation in progress.

## Status

This is the canonical Go implementation of the AIRE spec. It tracks the spec and is the reference any other implementation should match for behavior.

## Install

```bash
go get github.com/aire-protocol/aire-go
```

## Demo

```bash
# Two-node demo (coming with v0.1)
go run ./cmd/aire-demo
```

## Layout

- `frame.go` — frame type definitions and wire encoding
- `conn.go` — connection abstraction over QUIC
- `node.go` — local node runtime (registry, dispatch)
- `cmd/aire-demo` — minimal two-node demo

## Relationship to Vega

This library has zero Vega dependencies. AIRE is independent of any specific runtime. [Vega](https://github.com/everydev1618/govega) is the canonical OTP-style runtime that fully exploits AIRE's distribution semantics, but you can use `aire-go` directly without Vega.

## License

Apache 2.0 — see [LICENSE](./LICENSE).
