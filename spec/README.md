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
| Unlisted Image | Request `createContainer("attacker/malware:latest")` | `allImagesAllowlisted` — no matching policy |
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
  │   createContainer(name, image, ...)                  │
  │     │ guards: nondet, flagAllowed,                   │
  │     │         volumeAllowed, envAllowed, not(priv)    │
  │     │ mutators: enforcedPrivileged, networkMode,     │
  │     │          effectiveFlags, effectiveVolumes,     │
  │     │          effectiveEnvVars                       │
  │     ▼                                                │
  │   ┌──────────────────────────────────────────┐       │
  │   │  startContainer(name)                    │       │
  │   │      ┌─ guard: containerExists            │       │
  │   │      └─ effect: c.running = true          │       │
  │   │                                          │       │
  │   │  stopContainer(name)                     │       │
  │   │      ┌─ guard: containerExists            │       │
  │   │      └─ effect: c.running = false         │       │
  │   │                                          │       │
  │   │  removeContainer(name)                   │       │
  │   │      ┌─ guard: containerExists            │       │
  │   │      └─ effect: remove from set           │       │
  │   └──────────────────────────────────────────┘       │
  │                                                      │
  │   execContainer(name)  ──►  false  ──► DENIED       │
  │   pullImage(image)      ──►  nondet policy match    │
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

CI is handled via `.github/workflows/release.yml` (GoReleaser). Quint formal verification should be added as a prerequisite step:

```yaml
- name: Verify formal invariants
  uses: quint-lang/action@v1
  with:
    spec: spec/docker_socket_policy.qnt
    max-steps: 100
```
