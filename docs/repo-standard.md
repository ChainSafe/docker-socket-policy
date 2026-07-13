# ChainSafe Open Source Repository Standard

This is the canonical standard for all ChainSafe public repositories. The reference implementation is [docker-socket-policy](https://github.com/ChainSafe/docker-socket-policy). AI agents should use this as a bootstrap checklist when creating new repos.

Sections 1-2 and 4 apply to all projects. Sections 3 and 5 apply where the project ships a service or binary. Section 6 applies to all projects shipping binaries or Docker images.

## 1. Community & Legal

- `LICENSE` — Apache 2.0 (preferred) or MIT / LGPL v3 as ecosystem requires
- `MAINTAINERS.md` — who owns the repo, decision process, contact
- `CONTRIBUTING.md` — how to open issues, submit PRs, coding conventions
- `CODE_OF_CONDUCT.md` — contributor behavior expectations
- `SECURITY.md` — where to report vulnerabilities
- `CHANGELOG.md` — [Keep a Changelog](https://keepachangelog.com/) format

## 2. GitHub Workflows & Templates

- `.github/CODEOWNERS` — auto-assign reviewers per file path
- `.github/dependabot.yml` — automated dependency updates
- `.github/ISSUE_TEMPLATE/bug_report.md`
- `.github/ISSUE_TEMPLATE/feature_request.md`
- `.github/PULL_REQUEST_TEMPLATE.md`
- `.github/workflows/ci.yml` — runs on every PR: lint → test → build
- `.github/workflows/release.yml` — tag `v*` produces GitHub Release + Docker images

## 3. CI & Release Pipeline

- CI runs on every PR (lint + test + build, matrix for multi-lang)
- Caching: language-native (Go build cache, cargo registry, npm cache)
- Release triggered by `v*` tags following SemVer
- Docker images push to `ghcr.io/chainsafe/<repo-name>`, tagged `version` + `latest`
- Security: `.github/dependabot.yml` + optional CodeQL workflow

## 4. Developer Experience

- `README.md` — what, why, how to run, architecture overview
- `Makefile` — `build`/`test`/`lint` targets (+ `-all` for multi-lang)
- `.editorconfig` — cross-editor consistency
- Language-appropriate formatter + linter config
- `AGENTS.md` — agent guide (this file)
- `ARCHITECTURE.md` or `docs/adr/` for non-trivial projects

## 5. Docker & Deployment (if applicable)

- `Dockerfile` — per implementation
- `deploy/docker-compose.yml` — dev + integration test setup
- `deploy/test.sh` — integration test script

## 6. Reproducible Builds & Supply Chain Security

*Applies to all projects shipping binaries or Docker images.*

- Lock files committed and respected in CI (`go.sum`, `Cargo.lock`, `package-lock.json`)
- Toolchain versions pinned (`rust-toolchain.toml`, `.nvmrc`, `go.mod` directive)
- StageX or equivalent source-bootstrapped base images pinned by digest for all Docker builds
- `SOURCE_DATE_EPOCH` set for deterministic timestamp behavior
- Hermetic build steps (`RUN --network=none` after dependency fetch)
- Language-specific deterministic flags (Go: `-trimpath -buildid=`, Rust: `CARGO_INCREMENTAL=0 codegen-units=1`, TS: `npm ci --ignore-scripts`)
- SBOMs generated per release artifact in both SPDX and CycloneDX formats
- Docker images signed with Cosign (keyless via OIDC)
- Two-build `cmp` verification gates releases
- SLSA provenance (Level 1 minimum) for binary artifacts

Build verification steps must be documented in the project README or a dedicated file. See [reproducible-builds reference](docs/reproducible-builds.md) for the full implementation.

## Repo Structure Decision Tree

- **Single impl**: everything at root, single CI job, one Dockerfile
- **Multi-impl monorepo**: subdirectories (`go/`, `rs/`, `ts/`), matrix CI, separate Docker images per language (`<repo>-go`, `<repo>-rs`)
- **Library**: skip Docker/release, add package manager publishing
- **Spec/formal methods**: include `spec/`, add verification CI step

## Versioning

- SemVer (`vMAJOR.MINOR.PATCH`)
- CHANGELOG per Keep a Changelog
- Pre-release tags (e.g. `v1.0.0-rc.1`) publish with `--prerelease`

## Bootstrap Checklist

- [ ] LICENSE, MAINTAINERS.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md, SECURITY.md, CHANGELOG.md
- [ ] README.md with architecture overview and support stance
- [ ] .github/CODEOWNERS, dependabot.yml, issue templates, PR template
- [ ] .github/workflows/ci.yml (lint → test → build, caching)
- [ ] .github/workflows/release.yml (tag v* → artifacts + Docker)
- [ ] CodeQL workflow (recommended)
- [ ] Makefile with build/test/lint targets
- [ ] Language formatter + linter config
- [ ] .editorconfig
- [ ] AGENTS.md
- [ ] ARCHITECTURE.md or docs/adr/ (for non-trivial)
- [ ] Branch protection on main (require CI + PR review)
- [ ] Repository marked as template on GitHub
- [ ] Docker images to ghcr.io/chainsafe/ (if applicable)
- [ ] Toolchain pinning files (`rust-toolchain.toml`, `.nvmrc`)
- [ ] StageX base images pinned by digest
- [ ] Hermetic build Dockerfiles (`RUN --network=none`, `SOURCE_DATE_EPOCH`)
- [ ] SBOM generation in release workflow (SPDX + CycloneDX)
- [ ] Cosign signing step for Docker images
- [ ] Two-build `cmp` CI gate
- [ ] Verification docs (`docs/reproducible-builds.md`)
