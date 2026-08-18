# Changelog

## [Unreleased]

## [0.2.8] - 2026-08-18

### Fixed
- Release pipeline: `npm ci` failed in the `release-verify` job because it ran at the repo root instead of `ts/` (no `package-lock.json` there)
- Release pipeline: `release-verify` job never installed Quint, so `make typecheck`/`make verify` crashed
- Release pipeline: `publish-release` job had no git checkout, so `gh release edit` couldn't infer the target repository

## [0.2.7] - 2026-08-18

First published release.

### Added
- Multi-language monorepo with Go, Rust, and TypeScript implementations
- Rust implementation with tokio/hyper runtime (112 unit tests)
- TypeScript implementation with Node 22 ESM (108 unit tests)
- Go implementation moved to `go/` subdirectory (74 unit tests)
- Unified Makefile with `build-all`, `test-all`, `lint-all` targets
- CI pipeline with multi-language matrix (Quint, Go, Rust, TypeScript, integration)
- Release workflow: auto-bumps the patch version on push to `main`, builds and signs (Cosign) Docker images for all three implementations, generates SPDX + CycloneDX SBOMs (syft), and publishes binaries/archives to GitHub Releases
- Agent guide (AGENTS.md) for opencode integration
- Community standard files (LICENSE, CONTRIBUTING, CODE_OF_CONDUCT, SECURITY)
- Formal Quint specification with 9 security invariants
- 26 integration test cases via Docker Compose

### Changed
- Go implementation restructured: single entry point, internal packages, testable Transport interface
- README updated with multi-language comparison table
- Gateway/middleware pipeline standardized across all three languages
