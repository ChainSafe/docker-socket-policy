# docker-socket-policy Formal Specification

This directory contains a [Quint](https://quint-lang.org/) formal specification of the `docker-socket-policy` proxy. It models the proxy as a state machine and verifies security invariants.

## Files

| File | Purpose |
|------|---------|
| `docker_socket_policy.qnt` | Request-handling spec: policy types, state machine, endpoint routing table, 9 invariants (6 P0 / 3 P1), 6 attack scenario simulations |
| `listener.qnt` | Listening-socket startup: flag/group selection, existing-path checks, single-instance lock, 6 invariants, one `run` test per design-table row. Instances `listener_locked` (Go, Rust) and `listener_unlocked` (TypeScript) |
| `listener-design.md` | Design of the listening socket (dockerd parity) that `listener.qnt` models |
| `router.qnt` | The percent-encoded path deny, container-name extraction and the container-lifecycle branch of the router only, not the full router. The daemon's percent-decoding as a fixed table. One `run` test per table row. Instances `router` (Go, TypeScript, and Rust after #48 and #53), `router_pre48` (Rust's extraction rule before #48) and `router_pre53` (Rust and TypeScript before #53, routing on the raw path) |

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

# Listener model: typecheck, simulate the locked model, run the table tests
quint typecheck spec/listener.qnt
quint run spec/listener.qnt --main=listener_locked --max-steps=30 --invariant allListenerInvariants
quint test spec/listener.qnt --main=listener_locked
quint test spec/listener.qnt --main=listener_unlocked

# Router model: typecheck, run the table tests on all three instances
quint typecheck spec/router.qnt
quint test spec/router.qnt --main=router
quint test spec/router.qnt --main=router_pre48
quint test spec/router.qnt --main=router_pre53

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

### Listener Invariants (`listener.qnt`, checked on `listener_locked`)

| Invariant | What It Checks | Protection in the model |
|-----------|---------------|-------------------------|
| `neverListensOnTcp` | No instance serves unless `--listen-socket` was a Unix path | `start` rejects `fd://3`, `tcp://…`, `http://…` (exit 2) |
| `groupBeforeMode` | The socket never has group bits while its group differs from the selected group | `bind` at `0600`, then `chown`, then `chmod 0660` |
| `neverWorldWritable` | The socket mode never has `o+w` | `chmod` only ever sets `0660` |
| `neverUnlinksNonSocket` | A regular file at the path is never removed | `probe` refuses a non-socket (exit 1) |
| `noLiveTakeover` | A serving instance's socket is still the one at the path | `lock` (`flock` on `<path>.lock`) plus the `connect(2)` probe |
| `groupSelectionMatchesTable` | The selected group and warning match the design's group-selection table | `start` resolves the group moby-style; the table is written out as data |

`allListenerInvariants` is their conjunction. `noLiveTakeover` is shown to fail on `listener_unlocked`:

```bash
quint run spec/listener.qnt --main=listener_unlocked --max-steps=30 --invariant noLiveTakeover   # violation expected
```

### Router path parsing (`router.qnt`)

A path is a list of raw, still percent-encoded segments with the query string removed, so `/containers/` is `["containers", ""]`, `/containers//start` is `["containers", "", "start"]` and `/containers/%2F` is `["containers", "%2F"]`. The first check in `route` denies any path with an encoded segment, for every method (#53). After it, the second segment is a container name unless it is empty or one of `create`, `json`, `exec`. Both properties check every method in `GET`, `POST`, `DELETE` against every path of 1 to 3 segments:

- `lifecycleOnlyTargetsRealNames` holds when each lifecycle allow (`allowKnown` or `allowUnknown`) targets a non-empty, non-reserved name.
- `routerSeesWhatDaemonSees` holds when every request the router does not deny reads the same to the daemon: decoding leaves its path unchanged. The daemon's decoding is the table `DAEMON_DECODING`: `%2F` and `%2f` decode to `["", ""]` (a `/` splits the segment), `%6A%73%6F%6E` to `["json"]`, and `beacon%2Fstart` to `["beacon", "start"]`.

`soundTest` asserts both on `router`.

| Row (`run <row>Test`) | Request | Outcome | Instances |
|-----|---------|---------|-----------|
| `emptyNameDeleteDenied` | `DELETE /containers/` | deny | `router` |
| `emptyNameStartDenied` | `POST /containers//start` | deny | `router` |
| `emptyNameGetAllowed` | `GET /containers/` | allow (passthrough) | all |
| `reservedJsonDeleteDenied` | `DELETE /containers/json` | deny | all |
| `reservedCreateDeleteDenied` | `DELETE /containers/create` | deny | all |
| `reservedExecDeleteDenied` | `DELETE /containers/exec` | deny | all |
| `realNameDeleteAllowed` | `DELETE /containers/mycontainer` | allow (unknown container) | all |
| `reservedInSubpathAllowed` | `GET /containers/mycontainer/json` | allow | all |

Rows for the percent-encoded path deny ([#53](https://github.com/ChainSafe/docker-socket-policy/issues/53)), all on `router`:

| Row (`run <row>Test`) | Request | Outcome | The daemon reads |
|-----|---------|---------|------------------|
| `percentSlashDeleteDenied` | `DELETE /containers/%2F` | deny | `DELETE /containers//` |
| `percentLowerSlashDeleteDenied` | `DELETE /containers/%2f` | deny | `DELETE /containers//` |
| `percentReservedDeleteDenied` | `DELETE /containers/%6A%73%6F%6E` | deny | `DELETE /containers/json` |
| `percentSubpathStartDenied` | `POST /containers/beacon%2Fstart` | deny | `POST /containers/beacon/start` |
| `percentGetDenied` | `GET /containers/%2F` | deny | `GET /containers//` |

Each implementation's router tests use the same row names in comments (added with the #48 and #53 fixes). `router_pre48` runs `pre48UnsoundTest`, which asserts that `lifecycleOnlyTargetsRealNames` fails and that both `emptyName*Denied` requests are allowed as an unknown container ([#48](https://github.com/ChainSafe/docker-socket-policy/issues/48)). `router_pre53` runs `pre53UnsoundTest`, which asserts that `routerSeesWhatDaemonSees` fails, that `DELETE /containers/%2F` is allowed as an unknown container, and that `GET /containers/%2F` is allowed through the passthrough.

### Modeling Notes

Two invariants are structurally tautological within the Quint model — they can't be falsified by any action sequence the simulator generates, so they don't get real coverage from `quint run`/`quint verify`:

- **`proxyLives`** — `proxyRunning` is set once in `init` and every action preserves it (`proxyRunning' = proxyRunning`); nothing in the model ever sets it `false`. The real guarantee ("a panic/error on one request doesn't crash the whole proxy") is enforced by language-specific mechanisms outside the model: Go's stdlib `net/http.Server` recovers per-request panics, Rust's `tokio::spawn` isolates panics per connection task, and TypeScript's request handler wraps `handle()` in a `.catch()`. These are exercised by each implementation's own test suite, not by the Quint simulation.
- **`routingTableComplete`** — checks that `endpointsTable` (a fixed constant) contains a fixed list of literals declared in the same file. It documents the intended routing table but doesn't cross-check it against any of the three Router implementations; that comparison has to be done manually (or via `quint-analyzer`) against `go/internal/proxy/router.go`, `rs/src/proxy.rs`, and `ts/src/proxy.ts`.
- **The model has no caller, by design.** `createContainer` picks a policy from the request's image, and nothing models who sent the request. An invariant such as "a container's `serviceName` equals the caller's service" therefore cannot be stated, and that is deliberate: callers who share a socket cannot be told apart. Several developers may share one account, for example, so the proxy has no identity to check. The trust boundary is the socket itself. Separating trust domains means one proxy instance per domain, each with its own socket group, and the kernel enforces that separation outside this model. See the README's "Trust model" section and [#39](https://github.com/ChainSafe/docker-socket-policy/issues/39).

- **`listener.qnt` checks the design, not the code.** Nothing in the model is derived from the Go, Rust or TypeScript sources. Conformance rests on each implementation's unit and integration tests, which carry the same names as the Quint `run`s (`groupDefaultPresent`, `pathStaleReplaced`, …) so every design-table row can be traced across all four. `raceWithoutLockTest` (in `listener_unlocked`) is the formal record of the TypeScript gap: Node has no `flock`, so two TypeScript instances starting together can orphan one another's socket ([#46](https://github.com/ChainSafe/docker-socket-policy/issues/46)).
- **`lifecycleOnlyTargetsRealNames` is close to a tautology.** `route` only allows by name when `hasContainerName` holds, and `hasContainerName` is nearly the property itself. It is not vacuous: on `router_pre48`, where an empty segment counts as a name, the property fails, and `pre48UnsoundTest` asserts that. Most of the evidence comes from the table rows, whose names the language router tests reuse (added with the #48 fix).
- **`routerSeesWhatDaemonSees` is also close to a tautology on `router`.** The percent check denies exactly the paths with a segment that is a key of `DAEMON_DECODING`, and those are exactly the paths that decoding changes. It is not vacuous: on `router_pre53` the property fails, and `pre53UnsoundTest` asserts that. Setting `router`'s `ALLOW_PERCENT` to `true` makes `soundTest` and four of the five `percent*` rows fail. `percentSubpathStartDenied` still passes then, because the lifecycle branch denies `POST` when the last segment (`beacon%2Fstart`) is not an action. That row pins the outcome but does not discriminate the percent check. `lifecycleOnlyTargetsRealNames` holds on `router_pre53` too: `%2F` is a non-empty, non-reserved segment. That is why #53 needs a property that compares the router's reading with the daemon's.
- **Decoding is a fixed table.** Quint cannot inspect the characters of a string, so the model cannot find a `%` or decode one. `DAEMON_DECODING` lists the encoded tokens in the path universe and the segments the daemon reads them as; a segment is encoded iff it is a key. The implementations check for any `%` in the path. The table covers the shapes that matter: an encoded `/` (upper and lower case) that splits a segment, a fully encoded reserved word, and an encoded `/` inside a name that adds a lifecycle action.
- **The query string is outside the model.** Paths are segment lists with the query string already removed, so the model says nothing about `%` in the query. The implementations never inspect the query string for this rule; encoded queries such as `?filters=%7B…%7D` are routine and must still be forwarded. That is pinned by the language handler tests and the integration tests, not by the model.
- **GET is covered.** The percent check runs before the GET passthrough, and `routerSeesWhatDaemonSees` ranges over `GET` as well as `POST` and `DELETE`. On `router_pre53` the passthrough lets `GET /containers/%2F` through, and the property fails for it too.
- **`router.qnt` is not the full router.** `route` models the percent check, which runs first in all three routers, and the container-lifecycle branch. It leaves out the API-version strip and the checks that the routers run between those two, such as the exec, build and commit denials and `POST /containers/create`. For paths that those checks catch, the model's outcome can differ from what an implementation does:
  - `DELETE /containers/mycontainer/exec` is `allowUnknown` in the model. Rust and TypeScript deny it with their exec checks. Go's exec check matches `exec` only in the name position, so Go sends this path down the lifecycle branch and allows it. This divergence between the languages belongs to the same family as [#24](https://github.com/ChainSafe/docker-socket-policy/issues/24) and [#48](https://github.com/ChainSafe/docker-socket-policy/issues/48). It is outside this model's scope and is tracked with the other routing divergences.
  - `POST /containers/create` is `deny` in the model, but in reality it routes to container create.

  Only the properties and the table rows are claims about the code. `reservedExecDeleteDenied` (`DELETE /containers/exec`) is decided in all three implementations by the exec check, not by the reserved set. Its language tests would therefore not catch `exec` being dropped from the reserved set.
- **HEAD is outside the model.** `METHODS` is `GET`, `POST`, `DELETE`. The real lifecycle branches agree on those three methods only. For `HEAD /containers/x`, Go and TypeScript fall through to the GET/HEAD passthrough and allow it. Rust denies it in the lifecycle branch.
- **Listener fault bias.** `step` crashes an instance on 1 in 10 draws instead of half of all steps, so random runs actually interleave live instances. Every crash stays reachable from every phase, so the reachable state space is unchanged.

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

In practice the job calls `make typecheck`, `make test-spec` and `make verify BACKEND=typescript`, which also cover `listener.qnt` and `router.qnt`.

Releases are handled by `.github/workflows/release.yml`, which auto-bumps the patch version on push to `main`, creates a draft release, builds Docker images, generates SPDX + CycloneDX SBOMs with syft, and signs them with Cosign.
