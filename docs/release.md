# Release Verification

## Local Gates

- `make ci-verify` — mirrors pull-request CI coverage (Quint TypeScript backend, unit tests, integration tests, reproducible builds).
- `make release-verify` — mirrors release workflow coverage (Quint Rust backend, same test suite) and must pass before tagging.

Run the appropriate target before pushing changes that affect build or policy logic. Expect both commands to take 10–15 minutes because reproducible builds rebuild all artifacts from scratch.