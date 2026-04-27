# CLAUDE.md

Guidance for Claude Code (and other agents) working in the AIRE Go reference implementation.

## Purpose

This is the canonical Go implementation of the [AIRE protocol](https://github.com/aire-protocol/aire-spec). Other implementations (in any language) match this for behavior against the spec's test vectors.

## Working principles

- **TDD always.** Write tests first, confirm they fail, then implement. Spec test vectors are the source of truth for the codec.
- **The spec leads.** Never invent semantics here and back-port to the spec. If you need a new behavior, propose it in `aire-spec` first.
- **No external runtime dependencies in the import graph.** This library has zero dependencies on Vega or any agent framework, and never will. AIRE is independent of any specific runtime.
- **Correctness > performance.** This is the reference implementation. Optimize once a behavior is correct, never before.
- **Conformance over convenience.** When the spec is silent or ambiguous, file an issue against `aire-spec` rather than guessing.

## Build, test, lint

```bash
go build ./...
go test ./...
go vet ./...
go run ./cmd/aire-demo
```

CI runs build / test / vet / golangci-lint on every push and PR. Always run all tests and the linter locally before opening a PR; fix any issues.

## Package layout

- `frame.go` — frame type definitions, wire encoding/decoding (per spec §2)
- `conn.go` — connection abstraction over QUIC; maps Operations to QUIC streams
- `node.go` — local runtime: accept loop, stream dispatch, agent registry
- `cmd/aire-demo/` — the canonical two-node demo for v0.1
- Future: `handshake.go`, `capability.go`, `identity.go`, `cancel.go`, `budget.go` — one file per major spec section

Keep one Go package at root (`package aire`). Avoid premature subpackaging.

## QUIC

Use [`github.com/quic-go/quic-go`](https://github.com/quic-go/quic-go). Don't roll our own QUIC. Don't add multiple QUIC backends.

## Conformance

Conformance tests load spec test vectors from `aire-spec` and assert byte-for-byte round-trip equality. If a vector fails, the bug is in `aire-go`, not in the spec — the spec is the truth.

## Comments

Default to none. Only comment when the WHY is non-obvious — a hidden invariant, a workaround for a quic-go quirk, a spec-section reference for a subtle decision. Frame names and Go identifiers self-document.

## Errors

Use sentinel errors (`var ErrInvalidFrame = errors.New(...)`) for conditions callers might check. Wrap with `fmt.Errorf("...: %w", err)` to add context. No ad-hoc error types unless they carry structured data.

## Style

Match `gofmt`. Use `go vet` and `golangci-lint run` before committing. Idiomatic Go: small interfaces, accept interfaces / return structs, no init() side effects, no global state outside narrow exceptions.
