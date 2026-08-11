# docker-socket-policy — Agent Guide

## Project Overview
Docker API proxy with per-service policy enforcement via a middleware pipeline. Three equal peer implementations in a monorepo.

## Monorepo Structure
```
go/   — Go implementation (module: github.com/ChainSafe/docker-socket-policy/go)
rs/   — Rust implementation (Cargo.toml)
ts/   — TypeScript implementation (Node 22 ESM)
spec/ — Quint formal specification (source of truth for invariants)
config/ — YAML policy files
deploy/ — Docker Compose + integration tests
```

## Commands
- `make build-all` / `make test-all` / `make lint-all` — all three languages
- `make build-go` / `make test-go` / `make lint-go` — Go only
- `make build-rs` / `make test-rs` / `make lint-rs` — Rust only
- `make build-ts` / `make test-ts` / `make lint-ts` — TypeScript only
- `make verify` — Quint spec simulation
- `make test-integration` — Docker Compose integration tests

## Architecture (same across all 3 languages)
- `policy/` — Policy types + Manager (loads YAML from config dir)
- `middleware/` — Gate trait + Chain: ExecGate, ReadonlyGate, RegistryGate, MountSourceGate, EnvFileGate, CmdGate, ContainerConfigMutator
- `proxy/` — Router (default-deny), Handler (orchestrates chain), Transport (forwards to Docker socket)
- `audit/` — JSON-structured logging

## Key Conventions
- All three languages are equal peers — never privilege one
- Gates return Option<GateResult> (None = allowed, Some = denied with modified_body)
- Transport is abstracted (testable interface/type)
- Graceful shutdown via signal handling
- Zero external deps where possible (Go: yaml.v3, Rust: tokio/hyper/serde/clap, TS: yaml)

## Test Coverage
- Go: 58 unit tests (policy: 9, middleware: 21, proxy: 28)
- Rust: 104 unit tests (policy: 15, middleware: 48, proxy: 41)
- TypeScript: 99 unit tests (policy: 10, middleware: 37, proxy: 26, transport: 3, handler: 6, flags: 13)
- 26 integration tests via deploy/test.sh + docker-compose

## Test Conventions
- Go: stdlib `testing` package, `go test ./...`
- Rust: `#[cfg(test)]` inline modules, `cargo test`
- TypeScript: `node:test` framework, `npm run build && node --test dist/*.test.js`
- Integration: `make test-integration` (26 test cases via Docker Compose)

## Repo Standard Reference

When implementing code or bootstrapping a new ChainSafe open source repo, follow the [ChainSafe Open Source Repository Standard](docs/repo-standard.md). This defines the required file structure, CI/CD, community files, and release pipeline for all ChainSafe public repos. This repo (`docker-socket-policy`) is the living reference implementation of that standard.

## Reproducible Builds

This repo uses [StageX](https://stagex.tools/) source-bootstrapped base images for fully reproducible Docker builds. See [docs/reproducible-builds.md](docs/reproducible-builds.md) for verification steps.

For the authoritative Caution/StageX agent skill, see https://docs.caution.co/guides/build-with-an-ai-agent/
