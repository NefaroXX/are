# ADR-001: Temporary Wire Protocol — Length-Prefixed JSON is Not the ARE Protocol Specification

## Status

**Accepted** (Gate 3, 2026-09-01)

## Context

Gate 3 required a minimal wire protocol to prove mTLS works end-to-end: client connects, authenticates, sends a request, gets a response. The choices were:

1. **Length-prefixed JSON over TLS TCP** — simple, debuggable, no framework overhead.
2. **HTTP/2** — adds framing complexity (HPACK, stream management, SETTINGS negotiation) without benefit for Gate 3's single-request-per-connection model.
3. **gRPC / protobuf** — adds code generation, schema management, and dependency weight disproportionate to the current scope.

Gate 3 needs exactly one RPC: `GetEnvironmentInfo`. There is no multiplexing, no streaming, no backpressure. The simplest approach wins.

Per PLAN.md Rule 5 ("No Premature Protocol Standardisation"), this format is explicitly **not** the ARE protocol specification. The protocol emerges from real usage at Gate 14 (Protocol Stabilization).

## Decision

The Gate 3 wire format is:

```text
[u32 big-endian length][JSON payload bytes]
```

- **Length prefix:** 4-byte big-endian unsigned integer indicating the byte length of the JSON payload.
- **Payload:** UTF-8 JSON, serialized with serde_json.
- **Maximum payload:** 16 MiB (configurable via `read_message_sized`).
- **Framing module:** duplicated intentionally in `are-daemon/src/framing.rs` and `are-client/src/framing.rs` to preserve the `are-core` zero-I/O constraint. Wire compatibility is verified by integration tests.

The RPC envelope is defined in `are-core/src/info.rs`:

- `RpcRequest` — tagged enum (`#[serde(tag = "type", content = "payload")]`) wrapping typed request payloads.
- `RpcResponse` — struct with `Result<RpcResponsePayload, RpcError>` only. No correlation ID — Gate 3 is single request/response per connection, so correlation is implicit. If multiplexing is added later, a correlation ID will be introduced then (see Gate 14).
- `RpcError` — transport/framing-level errors (distinct from domain-level `CoreError`).

Currently the only RPC variant is `GetEnvironmentInfo`. New request types will be added as enums before Gates 4–7.

## Consequences

### Wire compatibility

Client and daemon framing modules must remain byte-compatible. Integration tests in Gate 3 verify this. A shared test fixture or protocol-level conformance test may be needed if divergence risk grows.

### Not a specification

This format is a temporary implementation detail. It will be revisited at Gate 14 (Protocol Stabilization). Do not depend on it as a stable specification. Third-party integrations should not be built against this wire format.

### Limits

- 16 MiB maximum payload is a deliberate guardrail against memory exhaustion. Configurable per-endpoint if needed.
- No multiplexing or streaming — single request/response per connection for Gate 3. Multiplexing, if needed, will be designed at Gate 14.
- No schema evolution or versioning — JSON serde is forward-compatible by convention, but there is no formal versioning mechanism.

### What is NOT decided

- Whether the final protocol uses JSON, protobuf, or another encoding.
- Whether HTTP/2 or raw TCP framing is used.
- How multiplexing, streaming, or backpressure work.
- Protocol versioning strategy.

All of these are deferred to Gate 14.

## References

- PLAN.md §5 Rule 5: No Premature Protocol Standardisation
- `crates/are-daemon/src/framing.rs` — daemon-side framing implementation
- `crates/are-client/src/framing.rs` — client-side framing implementation
- `crates/are-core/src/info.rs` — RPC envelope types (`RpcRequest`, `RpcResponse`, `RpcError`)
- `crates/are-daemon/tests/gate3_security.rs` — mTLS integration tests
