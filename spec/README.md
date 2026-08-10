# docker-socket-policy Formal Specification

This directory contains a [Quint](https://quint-lang.org/) formal specification of the `docker-socket-policy` proxy. It models the proxy as a state machine and verifies security invariants.

## Files

| File | Purpose |
|------|---------|
| `docker_socket_policy.qnt` | Single-file spec: policy types, state machine, endpoint routing table, 7 invariants (P0/P1/system/composite), 6 attack scenario simulations |

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
| `alwaysHostNetwork` | All containers use `network_mode: host` | ContainerConfigMutator enforces `networkMode=host` |
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
