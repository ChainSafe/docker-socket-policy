# Contributing to docker-socket-policy

Thank you for your interest! This project uses a multi-language approach — Go, Rust, and TypeScript are equal peer implementations.

## Getting Started

1. Fork the repo
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run the full test suite: `make test-all`
5. Submit a PR

## Development Setup

- **Go 1.22+**, **Rust stable**, **Node.js 22** are required
- Build all: `make build-all`
- Test all: `make test-all`
- Lint all: `make lint-all`

## Architecture

All three languages implement the same architecture:
- `policy/` — Policy types + Manager (loads YAML)
- `middleware/` — Gate trait + Chain (6 gates + 1 mutator)
- `proxy/` — Router (default-deny) + Handler + Transport

Changes should be applied to **all three implementations** unless they are language-specific (e.g., CLI flag parsing).

## Coding Standards

- Follow existing patterns in the language directory
- Tests use the language's standard test framework (no external test deps)
- Go: stdlib `testing`, Rust: `#[cfg(test)]` inline modules, TS: `node:test`
- Gates return `Err/error` (rejected) or `Ok/null` (allowed)
- Transport is abstracted for testability

## Pull Request Process

1. Ensure all tests pass: `make test-all`
2. Update the Quint spec if adding new endpoints or gates
3. Update README.md if changing configuration or behavior
4. PRs require at least one review

## Code of Conduct

All contributors must follow our [Code of Conduct](CODE_OF_CONDUCT.md).
