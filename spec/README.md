# docker-socket-policy Formal Specification

This directory contains a [Quint](https://quint-lang.org/) formal specification of the `docker-socket-policy` proxy. It models the proxy as a state machine and verifies security invariants.

## Files

| File | Purpose |
|------|---------|
| `docker_socket_policy.qnt` | Single-file spec: policy types, state machine, endpoint routing table, 9 invariants (6 P0 / 3 P1), 6 attack scenario simulations |

## How to Run

```bash
# Install Quint (requires Node.js)
# See: https://quint-lang.org/docs/install

# Type-check the spec (proves type safety)
quint typecheck spec/docker_socket_policy.qnt

# Random-simulation verification (fast, no Java required)
quint run --max-steps=50 --invariants allInvariants --backend rust \
  spec/docker_socket_policy.qnt

# Random-simulation with TypeScript backend (slower, no binary download)
quint run --max-steps=50 --invariants allInvariants --backend typescript \
  spec/docker_socket_policy.qnt

# Formal model-checking via Apalache (exhaustive, requires Java)
quint verify --max-steps=10 --invariants allInvariants spec/docker_socket_policy.qnt
```

## Verification Coverage

### P0 Security Invariants (Must Never Fail)

| Invariant | What It Checks | Guard / Mutator |
|-----------|---------------|-----------------|
| `noPrivilegedAccess` | No created container has `privileged=true` | ContainerConfigMutator sets `privileged=false` |
| `alwaysHostNetwork` | Every container's network mode matches its policy's configured value (caller cannot override) | ContainerConfigMutator enforces `networkMode` from policy |
| `imagesAlwaysAllowed` | All images match an `allowed_image_prefix` | RegistryGate via `nondet` policy match |
| `validImagesOnly` | No container has invalid image ref (`InvalidTag`, `InvalidDigest`) | `createContainer` guard rejects invalid variants |
| `envOnlyFromFile` | No inline env vars when policy sets `env_file` | EnvFileGate → `envAllowed()` |
| `proxyLives` | Proxy process stays running | Error-handling recovery |

### P1 Security Invariants (Should Never Fail)

| Invariant | What It Checks | Guard |
|-----------|---------------|-------|
| `volumesInWhitelist` | All volume mounts are in the policy whitelist | MountSourceGate → `volumeAllowed()` |
| `flagsInAllowlist` | All CLI flags pass allowlist + denylist | CmdGate → `flagAllowed()` |
| `routingTableComplete` | Every endpoint in the routing table has an explicit action | Explicit `endpointsTable.contains()` check |

### Modeling Notes

Two invariants are structurally tautological within the Quint model — they can't be falsified by any action sequence the simulator generates, so they don't get real coverage from `quint run`/`quint verify`:

- **`proxyLives`** — `proxyRunning` is set once in `init` and every action preserves it (`proxyRunning' = proxyRunning`); nothing in the model ever sets it `false`. The real guarantee ("a panic/error on one request doesn't crash the whole proxy") is enforced by language-specific mechanisms outside the model: Go's stdlib `net/http.Server` recovers per-request panics, Rust's `tokio::spawn` isolates panics per connection task, and TypeScript's request handler wraps `handle()` in a `.catch()`. These are exercised by each implementation's own test suite, not by the Quint simulation.
- **`routingTableComplete`** — checks that `endpointsTable` (a fixed constant) contains a fixed list of literals declared in the same file. It documents the intended routing table but doesn't cross-check it against any of the three Router implementations; that comparison has to be done manually (or via `quint-analyzer`) against `go/internal/proxy/router.go`, `rs/src/proxy.rs`, and `ts/src/proxy.ts`.

### Attack Scenarios Prevented by Invariants

| Scenario | Attacker Action | Prevented By |
|----------|----------------|--------------|
| Privileged Escalation | Request `createContainer(privileged=true)` | `noPrivileged` — guard rejects privileged containers |
| Exec Escape | Request `execContainer("beacon")` | `execContainer` unconditionally returns false |
| Unlisted Image | Request `createContainer("attacker/malware:latest")` | `imagesAlwaysAllowed` — no matching policy |
| Invalid Image Ref | Request `createContainer(InvalidTag/InvalidDigest)` | `validImagesOnly` — `createContainer` guard rejects non-valid |
| Inline Env | Request `createContainer` with `VALIDATOR_KEY=secret` | `envFromFileOnly` — `envFile=true` policy rejects inline env |
| Docker Socket Mount | Request `createContainer` with `/var/run/docker.sock` | `volumesWhitelisted` — `/var/run/docker.sock` not in policy |
| Privileged Flag | Request `createContainer` with `--privileged` flag | `flagsAllowlisted` — `--privileged` is in `deniedFlags` |

## State Machine

```
                    ┌─────────┐
                    │  init   │
                    └────┬────┘
                         │
          readOnlyRequest(_)
                         │
                         ▼
 ┌──────────────────────────────────────────────────────┐
 │                                                      │
 │   createContainer(name, imageRef, ...)               │
 │     │ guards: nondet, imageNameAllowed, flagAllowed, │
 │     │         volumeAllowed, envAllowed, not(priv)   │
 │     │         ValidImage only (invalid rejected)     │
 │     │ mutators: enforcedPrivileged, networkMode,     │
 │     │          effectiveFlags, effectiveVolumes,     │
 │     │          effectiveEnvVars                      │
 │     ▼                                                │
 │   ┌──────────────────────────────────────────────────┐
 │   │  start(name) / unpause(name)                     │
 │   │      ┌─ guard: containerExists                    │
 │   │      │  (paused → Running for unpause)            │
 │   │      └─ effect: state = Running                   │
 │   │                                                   │
 │   │  stop(name) / kill(name)                          │
 │   │      ┌─ guard: containerExists                    │
 │   │      └─ effect: state = Exited                    │
 │   │                                                   │
 │   │  pause(name)                                      │
 │   │      ┌─ guard: containerExists                    │
 │   │      └─ effect: state = Paused                    │
 │   │                                                   │
 │   │  restart(name)                                    │
 │   │      ┌─ guard: containerExists                    │
 │   │      └─ effect: state = Running                   │
 │   │                                                   │
 │   │  wait(name)                                       │
 │   │      ┌─ guard: containerExists                    │
 │   │      └─ effect: no state change (read-only)       │
 │   │                                                   │
 │   │  removeContainer(name)                            │
 │   │      └─ guard: containerExists                    │
 │   │      └─ effect: remove from set                   │
 │   └──────────────────────────────────────────────────┘ │
 │                                                      │
 │   pullImage(image)  ──►  nondet policy match        │
 │                                                      │
 └──────────────────────────────────────────────────────┘
```

## When to Update the Spec

Update the Quint spec whenever:

1. **A new gate is added** to the middleware chain — add a guard in `createContainer` and a new invariant
2. **A new endpoint is added** to the router — add an entry to `endpointsTable` and a check in `allEndpointsMatched`
3. **A policy field is added** — extend the `Policy` type and add a corresponding invariant
4. **A security invariant is identified** — add it to the invariants module

## CI Integration

Quint formal verification runs in CI via `.github/workflows/ci.yml` (quint job), which type-checks the spec and runs random simulation with all invariants:

```yaml
- run: quint typecheck spec/docker_socket_policy.qnt
- run: quint run --max-steps=100 --invariants allInvariants --backend typescript spec/docker_socket_policy.qnt
```

Releases are handled by `.github/workflows/release.yml`, which auto-bumps the patch version on push to `main`, creates a draft release, builds Docker images, generates SPDX + CycloneDX SBOMs with syft, and signs them with Cosign.
