# Changelog

## [Unreleased]

### Added
- Multi-language monorepo with Go, Rust, and TypeScript implementations
- Rust implementation with tokio/hyper runtime (112 unit tests)
- TypeScript implementation with Node 22 ESM (108 unit tests)
- Go implementation moved to `go/` subdirectory (74 unit tests)
- Unified Makefile with `build-all`, `test-all`, `lint-all` targets
- CI pipeline with multi-language matrix (Quint, Go, Rust, TypeScript, integration)
- GoReleaser workflow for automated releases on `v*` tags
- Agent guide (AGENTS.md) for opencode integration
- Community standard files (LICENSE, CONTRIBUTING, CODE_OF_CONDUCT, SECURITY)
- Formal Quint specification with 9 security invariants
- 26 integration test cases via Docker Compose

### Changed
- Go implementation restructured: single entry point, internal packages, testable Transport interface
- README updated with multi-language comparison table
- Gateway/middleware pipeline standardized across all three languages
