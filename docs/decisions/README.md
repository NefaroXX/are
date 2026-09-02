# Architecture Decision Records (ADRs)

This directory contains Architecture Decision Records for the ARE project.

## What is an ADR?

An ADR captures a significant architectural decision along with its context and consequences. Each ADR is a lightweight, immutable document — once accepted, it is not revised (though it may be superseded by a new ADR).

## When to Write an ADR

Write an ADR when:

- Choosing between two or more viable approaches with meaningful trade-offs
- Establishing a design constraint or security boundary
- Reversing or superseding a prior decision
- Documenting a gate's security review findings

## ADR Format

Each ADR should include:

1. **Title** — Short, descriptive name
2. **Status** — Proposed, Accepted, Deprecated, Superseded
3. **Context** — What situation necessitated a decision?
4. **Decision** — What was decided and why?
5. **Consequences** — What are the trade-offs?

## Naming Convention

```
NNN-short-title.md
```

Where `NNN` is a zero-padded sequence number (e.g., `001-tls-transport.md`).

## Index

| ADR | Title | Status | Gate |
|-----|-------|--------|------|
| [001](001-wire-protocol-temporary.md) | Temporary Wire Protocol — Length-Prefixed JSON is Not the ARE Protocol Specification | Accepted | 3 |
| [002](002-path-semantics.md) | Path Semantics — Environment-Relative, Not Absolute Host Paths | Accepted | 3.5 |

## Scope

ADRs cover architecture and design decisions only. Implementation details, bug fixes, and feature additions do not require ADRs unless they involve a significant design trade-off.
