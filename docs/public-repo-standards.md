# ChainSafe Public Repo Standards

This document outlines the standards we applied to [docker-socket-policy](https://github.com/ChainSafe/docker-socket-policy) for use as a template across ChainSafe open source repos.

## Required Files

| File | Purpose |
|------|---------|
| `LICENSE` | Apache 2.0 (standard for ChainSafe) — plain text, no modification |
| `README.md` | Project description, architecture, quick start, configuration, badges |
| `CONTRIBUTING.md` | How to contribute, setup, coding standards, PR process |
| `CODE_OF_CONDUCT.md` | Contributor Covenant v2.1 — standard for community behavior |
| `SECURITY.md` | Vulnerability reporting process and contact |
| `CHANGELOG.md` | Unreleased + versioned entries tracking changes |
| `AGENTS.md` | (opencode-specific) Agent guide for AI tooling — optional |
| `.gitignore` | Exclude binaries, dependencies, dist, IDE files |

## GitHub Templates (`.github/`)

| File | Purpose |
|------|---------|
| `ISSUE_TEMPLATE/bug_report.md` | Structured bug report form |
| `ISSUE_TEMPLATE/feature_request.md` | Feature request form |
| `PULL_REQUEST_TEMPLATE.md` | PR checklist for implementations, testing, documentation |

## CI/CD (`.github/workflows/`)

- **`ci.yml`** — Run on push/PR to main: lint, test, build across all relevant languages
- **`release.yml`** — Run on `v*` tag: validate, build, publish artifacts (GoReleaser, Docker)

## CI Best Practices

- Multi-language matrix jobs (one per language)
- Integration tests in CI (Docker Compose)
- Formal verification if applicable (Quint)
- Secrets: `GITHUB_TOKEN` for releases, `secrets.GITHUB_TOKEN` for packages

## README Checklist

- [ ] Badges: CI status, language version, license
- [ ] One-paragraph description of what the project does
- [ ] Key features (bulleted)
- [ ] Architecture diagram or explanation
- [ ] Quick start (build, run, configure, use)
- [ ] Configuration reference (CLI flags, env vars, config files)
- [ ] License section

## What Not to Include in Public Repos

- Internal planning documents (e.g., `MULTILANG_PLAN.md`, rewrite plans)
- IDE/editor configuration (`.vscode/`, `.idea/`, `.opencode/` — optional for opencode)
- Cloned dependencies in repo root
- Compiled binaries
- Internal developer docs not relevant to consumers

## Release Process

1. Tag with `v*` (e.g., `v0.1.0`)
2. CI validates (tests, lint, formal verification)
3. GoReleaser builds binaries + Docker images
4. Draft release created with changelog
5. Publish

## Template Repo

Use [docker-socket-policy](https://github.com/ChainSafe/docker-socket-policy) as a reference for the complete structure.
