# docker-socket-policy Formal Specification

This directory contains a [Quint](https://quint-lang.org/) formal specification of the `docker-socket-policy` proxy. It models the proxy as a state machine and verifies security invariants.

## Files

| File | Purpose |
|------|---------|
| `docker_socket_policy.qnt` | Request-handling spec: policy types, state machine, endpoint routing table, 11 invariants (8 P0 / 3 P1), 6 attack scenario simulations. Module `network_endpoints_model` models `NetworkingConfig.EndpointsConfig` under a forced `network_mode` (#87), one `run` test per table row, instances `network_endpoints` (all three after #87) and `network_endpoints_pre87`. Also the create check on `HostConfig` (module `create_model`, #88): the default-deny field rules, `Mounts`, bind options, read-only volumes and case-insensitive field names, with one `run` test per table row. Instances `create` (all three after #88) and `create_pre88` (all three before #88); the state machine uses the `create` rules |
| `listener.qnt` | Listening-socket startup: flag/group selection, existing-path checks, single-instance lock, 6 invariants, one `run` test per design-table row. Instances `listener_locked` (Go, Rust) and `listener_unlocked` (TypeScript) |
| `listener-design.md` | Design of the listening socket (dockerd parity) that `listener.qnt` models |
| `router.qnt` | The percent-encoded path deny, the empty interior segment deny, the dot segment deny, the segment-exact exec deny and `POST /containers/create` route, the segment-exact attach deny, the GET/HEAD-only read passthrough with `/_ping` standing for the read endpoints, container-name extraction and the container-lifecycle branch of the router only, not the full router. The daemon's percent-decoding as a fixed table. One `run` test per table row. Instances `router` (Go, TypeScript, and Rust after #48, #53, #49, #55, #76, #78 and #70), `router_pre48` (Rust's extraction rule before #48), `router_pre53` (Rust and TypeScript before #53, routing on the raw path), `router_pre55` (all three before #55, letting empty interior segments through), `router_readonly` (as `router`, with `--readonly`, #75), `router_pre76` (all three before #76, letting attach through), `router_pre78` (all three before #78, allowing the read endpoints for every method) and `router_pre70` (all three before #70, letting `.` and `..` segments through). Every instance includes the #49 exec and create rule, so the pre instances isolate one earlier rule each rather than being full snapshots. Module `pull_model` models the `POST /images/create` branch: which of the body and the query names the image, and image-name normalisation as a fixed table. Instances `pull` (all three after #83 and #84), `pull_pre83` (all three before #83, reading `fromImage` from the body), `pull_body_ignored` (the first #83 fix, which forwarded a pull's body) and `pull_pre84` (all three before #84, matching the spelling as sent) |

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

# Router model: typecheck, run the table tests on all twelve instances
quint typecheck spec/router.qnt
quint test spec/router.qnt --main=router
quint test spec/router.qnt --main=router_pre48
quint test spec/router.qnt --main=router_pre53
quint test spec/router.qnt --main=router_pre55
quint test spec/router.qnt --main=router_readonly --match='^readonly.*Test$'
quint test spec/router.qnt --main=router_pre76
quint test spec/router.qnt --main=router_pre78
quint test spec/router.qnt --main=router_pre70
quint test spec/router.qnt --main=pull
quint test spec/router.qnt --main=pull_pre83
quint test spec/router.qnt --main=pull_body_ignored
quint test spec/router.qnt --main=pull_pre84

# Network endpoints under a forced network_mode (#87): the table tests on both instances
quint test spec/docker_socket_policy.qnt --main=network_endpoints
quint test spec/docker_socket_policy.qnt --main=network_endpoints_pre87
# Create model (#88): the table tests, and the pre-fix witness
quint test spec/docker_socket_policy.qnt --main=create
quint test spec/docker_socket_policy.qnt --main=create_pre88

# Formal model-checking via Apalache (exhaustive, requires Java)
quint verify --max-steps=10 --invariants allInvariants spec/docker_socket_policy.qnt
```

## Verification Coverage

### P0 Security Invariants (Must Never Fail)

| Invariant | What It Checks | Guard / Mutator |
|-----------|---------------|-----------------|
| `noPrivilegedAccess` | No created container has `privileged=true` | ContainerConfigMutator sets `privileged=false` on every create (#88: also without a `container_config`) |
| `alwaysHostNetwork` | Every container's network mode matches its policy's configured value (caller cannot override) | ContainerConfigMutator enforces `networkMode` from policy |
| `imagesAlwaysAllowed` | All images match an `allowed_image_prefix` | RegistryGate via `nondet` policy match |
| `validImagesOnly` | No container has invalid image ref (`InvalidTag`, `InvalidDigest`) | `createContainer` guard rejects invalid variants |
| `envOnlyFromFile` | No inline env vars when policy sets `env_file` | EnvFileGate → `envAllowed()` |
| `proxyLives` | Proxy process stays running | Error-handling recovery |
| `hostConfigInAllowlist` | Every `HostConfig` field the daemon read is allowed, with an allowed value (#88) | HostConfigGate → `createAllowed()` |
| `hostMountsInWhitelist` | Every host path the daemon mounted is a policy volume, read-only when the volume is, and never propagating (#88) | MountSourceGate → `createAllowed()` |

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

A path is a list of raw, still percent-encoded segments with the query string removed, so `/containers/` is `["containers", ""]`, `/containers//start` is `["containers", "", "start"]` and `/containers/%2F` is `["containers", "%2F"]`. With `READONLY` set, the read-only check runs before all of these and denies every method other than `GET` and `HEAD`, for every path (#75). The percent check, first in `route` after it, denies any path with an encoded segment, for every method (#53). The empty-segment check denies any path with an empty segment before the last one, i.e. `//` in the path, for every method (#55); a single trailing slash, as in `/containers/`, is not interior. Right after it, any path with a segment that is exactly `.` or `..` is denied, for every method (#70); `.hidden`, `...` and `a.b` are names. With `ALLOW_ANY_METHOD_PING` set, `router_pre78` allows `/_ping` for every method between the dot segment check and the exec check, as the routers did before #78. The exec check denies exec, for every method, as `denyExec` (#49): when the first segment is `exec` (the `/exec/<id>/…` namespace), or when the first segment is `containers` and any later segment is exactly `exec`. A segment that only starts with or contains `exec`, such as `exec-runner`, is not matched. The attach check denies attach, for every method (#76): when the first segment is `containers` and any later segment is exactly `attach`; `attach-runner` is a name like any other. The create route then sends `POST` with exactly the segments `["containers", "create"]` to `routeCreate`; a longer path falls through. After these, the second segment is a container name unless it is empty or one of `create`, `json`, `exec`. `HEAD` is routed like `GET` (#55). Every property checks every method in `GET`, `HEAD`, `POST`, `DELETE` against every path of 1 to 3 segments:

- `lifecycleOnlyTargetsRealNames` holds when each lifecycle allow (`allowKnown` or `allowUnknown`) targets a non-empty, non-reserved name.
- `routerSeesWhatDaemonSees` holds when every request the router does not deny reads the same to the daemon: decoding leaves its path unchanged. The daemon's decoding is the table `DAEMON_DECODING`: `%2F` and `%2f` decode to `["", ""]` (a `/` splits the segment), `%6A%73%6F%6E` to `["json"]`, and `beacon%2Fstart` to `["beacon", "start"]`.
- `execNeverAllowed` holds when every path with `exec` in an exec position is denied. The exec positions are written out in the property, not taken from `route`'s `isExecPath`.
- `execPrefixNamesRoute` holds when renaming `exec-runner` to the plain unknown name `mycontainer`, wherever it appears in the path, never changes the outcome.
- `createOnlyExact` holds when `routeCreate` is the outcome for exactly `POST /containers/create`.
- `emptyInteriorDenied` holds when every path with an empty segment before the last one is denied.
- `emptySegmentsHideNoExec` holds when every path that is an exec path once its empty segments are dropped is denied.
- `attachNeverAllowed` holds when every path whose first segment is `containers`, with `attach` at some later segment, is denied. Like `execNeverAllowed`, it writes the positions out instead of calling `isAttachPath`.
- `dotSegmentsDenied` holds when every path with a `.` or `..` segment is denied (#70).
- `dotSegmentsHideNoExec` holds when every path that is an exec or attach path once its dot segments are resolved (`.` dropped; `..` removes the segment before it, if any) is denied. It does not mention `hasDotSegment` or `ALLOW_DOT_SEGMENTS`, so `router_pre70` fails it.
- `readPassthroughOnlyForReads` holds when every request routed to the read passthrough (`allowRead`) is a `GET` or a `HEAD` (#78). It does not mention `ALLOW_ANY_METHOD_PING`, so `router_pre78` fails it.
- `readonlyAllowsOnlyReads` holds when every request whose method is not `GET` or `HEAD` is denied, for every path. It is the read-only claim and holds only with `READONLY = true`; the router's read-only check, which runs before every other check, denies such requests (#75).

On `router`, `soundTest` asserts `lifecycleOnlyTargetsRealNames`, `percentSoundTest` asserts `routerSeesWhatDaemonSees`, `execSoundTest` asserts `execNeverAllowed`, `execPrefixSoundTest` asserts `execPrefixNamesRoute`, `createExactSoundTest` asserts `createOnlyExact`, `emptyInteriorSoundTest` asserts `emptyInteriorDenied`, `emptySegmentsHideNoExecTest` asserts `emptySegmentsHideNoExec`, `attachSoundTest` asserts `attachNeverAllowed`, `readPassthroughSoundTest` asserts `readPassthroughOnlyForReads` and `dotSoundTest` asserts `dotSegmentsDenied` and `dotSegmentsHideNoExec`.

| Row (`run <row>Test`) | Request | Outcome | Instances |
|-----|---------|---------|-----------|
| `emptyNameDeleteDenied` | `DELETE /containers/` | deny | `router` |
| `emptyNameStartDenied` | `POST /containers//start` | deny | `router` |
| `emptyNameGetAllowed` | `GET /containers/` | allow (passthrough) | all |
| `reservedJsonDeleteDenied` | `DELETE /containers/json` | deny | all |
| `reservedCreateDeleteDenied` | `DELETE /containers/create` | deny | all |
| `reservedExecDeleteDenied` | `DELETE /containers/exec` | deny (exec) | all |
| `realNameDeleteAllowed` | `DELETE /containers/mycontainer` | allow (unknown container) | all |
| `reservedInSubpathAllowed` | `GET /containers/mycontainer/json` | allow | all |

Rows for the percent-encoded path deny ([#53](https://github.com/ChainSafe/docker-socket-policy/issues/53)), all on `router`:

| Row (`run <row>Test`) | Request | Outcome | The daemon reads |
|-----|---------|---------|------------------|
| `percentSlashDeleteDenied` | `DELETE /containers/%2F` | deny | `DELETE /containers//` |
| `percentLowerSlashDeleteDenied` | `DELETE /containers/%2f` | deny | `DELETE /containers//` |
| `percentReservedDeleteDenied` | `DELETE /containers/%6A%73%6F%6E` | deny | `DELETE /containers/json` |
| `percentNameStartDenied` | `POST /containers/%2F/start` | deny | `POST /containers///start` |
| `percentSubpathStartDenied` (pin) | `POST /containers/beacon%2Fstart` | deny | `POST /containers/beacon/start` |
| `percentGetDenied` | `GET /containers/%2F` | deny | `GET /containers//` |

Rows for segment-exact exec and create matching ([#49](https://github.com/ChainSafe/docker-socket-policy/issues/49)), all instances. "deny (exec)" is the outcome `denyExec`, which the implementations report as `exec is not allowed`:

| Row (`run <row>Test`) | Request | Outcome |
|-----|---------|---------|
| `execSubpathDeleteDenied` | `DELETE /containers/mycontainer/exec` | deny (exec) |
| `execSubpathPostDenied` | `POST /containers/mycontainer/exec` | deny (exec) |
| `execPrefixNameStartAllowed` | `POST /containers/exec-runner/start` | allow (unknown container) |
| `execPrefixNameDeleteAllowed` | `DELETE /containers/exec-runner` | allow (unknown container) |
| `execPrefixNameGetAllowed` | `GET /containers/exec-runner/json` | allow (read) |
| `execNamespaceGetDenied` | `GET /exec/abc/json` | deny (exec) |
| `execNamespacePostDenied` | `POST /exec/abc/start` | deny (exec) |
| `createSubpathDenied` | `POST /containers/create/extra` | deny (default, not the create route) |

Rows for empty interior segments and HEAD ([#55](https://github.com/ChainSafe/docker-socket-policy/issues/55)):

| Row (`run <row>Test`) | Request | Outcome | Instances |
|-----|---------|---------|-----------|
| `emptyLeadingExecGetDenied` | `GET //exec/abc` | deny | `router` |
| `emptyInteriorGetDenied` | `GET /containers//json` | deny | `router` |
| `headNamedContainerAllowed` | `HEAD /containers/mycontainer` | allow (read) | all |

Rows for the attach deny ([#76](https://github.com/ChainSafe/docker-socket-policy/issues/76)), all on `router`. The model has at most three segments, so `/containers/mycontainer/attach` stands for `/containers/mycontainer/attach/ws`. The implementations deny these with `attach is not allowed`:

| Row (`run <row>Test`) | Request | Outcome |
|-----|---------|---------|
| `attachGetDenied` | `GET /containers/mycontainer/attach` | deny |
| `attachPostDenied` (pin) | `POST /containers/mycontainer/attach` | deny |
| `attachHeadDenied` | `HEAD /containers/mycontainer/attach` | deny |
| `attachNamedContainerDenied` | `GET /containers/attach/ws` | deny (a container literally named `attach`) |

Rows for the read endpoints ([#78](https://github.com/ChainSafe/docker-socket-policy/issues/78)). `/_ping` stands for `/_ping`, `/version`, `/info` and `/events`. The implementations deny the others with the default `endpoint <METHOD> <path> is not allowed`:

| Row (`run <row>Test`) | Request | Outcome | Instances |
|-----|---------|---------|-----------|
| `pingPostDenied` | `POST /_ping` | deny | `router` |
| `pingDeleteDenied` | `DELETE /_ping` | deny | `router` |
| `pingGetAllowed` | `GET /_ping` | allow (read) | all |
| `pingHeadAllowed` | `HEAD /_ping` | allow (read) | all |

Rows for dot segments ([#70](https://github.com/ChainSafe/docker-socket-policy/issues/70)), all on `router`. The model has at most three segments, so the paths are shortened. The implementations deny these with `dot path segment not allowed`:

| Row (`run <row>Test`) | Request | Outcome |
|-----|---------|---------|
| `dotLeadingExecGetDenied` | `GET /./exec/abc` | deny |
| `dotDotExecGetDenied` | `GET /mycontainer/../exec` | deny |
| `dotInContainerPathDenied` | `GET /containers/mycontainer/.` | deny |

Rows for `--readonly` ([#75](https://github.com/ChainSafe/docker-socket-policy/issues/75)), all on `router_readonly`, which also runs `readonlySoundTest` (asserts `readonlyAllowsOnlyReads`). The implementations deny these with `read-only mode: <METHOD> requests are not allowed`:

| Row (`run <row>Test`) | Request | Outcome |
|-----|---------|---------|
| `readonlyLifecycleStopDenied` | `POST /containers/mycontainer/stop` | deny |
| `readonlyDeleteDenied` | `DELETE /containers/mycontainer` | deny |
| `readonlyCreateDenied` | `POST /containers/create` | deny |
| `readonlyGetAllowed` | `GET /containers/json` | allow (read) |
| `readonlyHeadAllowed` | `HEAD /containers/mycontainer` | allow (read) |

The rows marked "all" above run on every `READONLY = false` instance; `router_readonly` runs only its own `readonly*` tests (`--match='^readonly.*Test$'`), since with the flag on the shared write rows are denied.

Each implementation's router tests use the same row names in comments (added with the #48, #53, #49, #55, #76, #78 and #70 fixes). `router_pre48` runs `pre48UnsoundTest`, which asserts that `lifecycleOnlyTargetsRealNames` fails and that both `emptyName*Denied` requests are allowed as an unknown container ([#48](https://github.com/ChainSafe/docker-socket-policy/issues/48)). `router_pre53` runs `pre53UnsoundTest`, which asserts that `routerSeesWhatDaemonSees` fails, that `DELETE /containers/%2F` and `POST /containers/%2F/start` are allowed as an unknown container, and that `GET /containers/%2F` is allowed through the passthrough. `router_pre55` runs `pre55UnsoundTest`, which asserts that `emptyInteriorDenied` fails and that `GET //exec/abc` is allowed through the passthrough: its first segment is empty, not `exec`, so the exec check misses it. `router_pre76` runs `pre76UnsoundTest`, which asserts that `attachNeverAllowed` fails and that `GET /containers/mycontainer/attach` is allowed through the passthrough ([#76](https://github.com/ChainSafe/docker-socket-policy/issues/76)). `router_pre78` runs `pre78UnsoundTest`, which asserts that `readPassthroughOnlyForReads` fails and that `POST /_ping` and `DELETE /_ping` are allowed as reads ([#78](https://github.com/ChainSafe/docker-socket-policy/issues/78)). `router_pre70` runs `pre70UnsoundTest`, which asserts that `dotSegmentsDenied` and `dotSegmentsHideNoExec` fail and that `GET /./exec/abc` is allowed through the passthrough ([#70](https://github.com/ChainSafe/docker-socket-policy/issues/70)).

### Network endpoints under a forced `network_mode` (`docker_socket_policy.qnt`, #87)

`alwaysHostNetwork` covers `HostConfig.NetworkMode` only. The daemon also reads `NetworkingConfig.EndpointsConfig`, and before #87 no implementation touched it: without `--network` the Docker CLI sends `{"default": {}}`, the create succeeded, and the start failed with `network default not found`. The module `network_endpoints_model` models what `NetworkEndpointsGate` and `ContainerConfigMutator` do with `EndpointsConfig` when the policy forces a mode M, as the pure function `handleEndpoints(M, endpoints)`. `EndpointsConfig` is a map from network name to settings (`""` for `{}`, `"a"` for an entry with settings such as `Aliases`); an absent `NetworkingConfig` is the empty map, and `container:x` stands for every `container:<name|id>` mode. A key other than `default` and M is denied with `network "<key>" is not allowed for service <S>; policy forces network_mode <M>`. Otherwise `host`, `none` and `container:x` get an empty `EndpointsConfig`, and `bridge` or a named network gets exactly one entry keyed M, with the settings of the caller's M entry, else of its `default` entry, else `{}`. `daemonStarts` is the daemon's start check as observed on Engine 29.8.2 (API 1.41 to 1.56): every endpoint key must name the container's `NetworkMode`. The properties range over the five modes and all 2187 maps over seven keys and two settings:

- `extraNetworkDenied` holds when every request with a key other than `default` and M is denied (the rule).
- `onlyForcedNetwork` holds when every allowed request names no network but M (the security property: an extra entry would attach the container to a network the policy does not allow).
- `allowedCreatesStart` holds when every allowed request passes `daemonStarts` (the bug).

`network_endpoints` runs `endpointsSoundTest`, which asserts all three, and one test per row. `network_endpoints_pre87` (all three before #87, `ENFORCE_ENDPOINTS = false`) runs `pre87UnsoundTest`, which asserts that all three properties fail, that `{"default": {}}` under `host` is forwarded unchanged and fails `daemonStarts`, and that an extra entry is allowed. The Go, Rust and TypeScript middleware tests use the same row names in comments.

| Row (`run <row>Test`) | Forced mode | Request `EndpointsConfig` | Outcome |
|-----|-----|-----|-----|
| `hostNoEndpoints` | `host` | absent | `{}` |
| `hostDefaultCleared` | `host` | `{"default": {}}` | `{}` |
| `hostOwnCleared` | `host` | `{"host": {Aliases}}` | `{}` |
| `hostExtraDenied` | `host` | `{"default": {}, "other": {}}` | deny |
| `noneNoEndpoints` | `none` | absent | `{}` |
| `noneDefaultCleared` | `none` | `{"default": {}}` | `{}` |
| `noneOwnCleared` | `none` | `{"none": {Aliases}}` | `{}` |
| `noneExtraDenied` | `none` | `{"default": {}, "other": {}}` | deny |
| `containerNoEndpoints` | `container:x` | absent | `{}` |
| `containerDefaultCleared` | `container:x` | `{"default": {}}` | `{}` |
| `containerOwnCleared` | `container:x` | `{"container:x": {Aliases}}` | `{}` |
| `containerExtraDenied` | `container:x` | `{"default": {}, "other": {}}` | deny |
| `bridgeNoEndpoints` | `bridge` | absent | `{"bridge": {}}` |
| `bridgeDefaultRekeyed` | `bridge` | `{"default": {Aliases}}` | `{"bridge": {Aliases}}` |
| `bridgeOwnKept` | `bridge` | `{"bridge": {Aliases}}` | `{"bridge": {Aliases}}` |
| `bridgeExtraDenied` | `bridge` | `{"default": {}, "other": {}}` | deny |
| `namedNoEndpoints` | `mynet` | absent | `{"mynet": {}}` |
| `namedDefaultRekeyed` | `mynet` | `{"default": {Aliases}}` | `{"mynet": {Aliases}}` |
| `namedOwnKept` | `mynet` | `{"mynet": {Aliases}}` | `{"mynet": {Aliases}}` |
| `namedExtraDenied` | `mynet` | `{"default": {}, "other": {}}` | deny |
| `namedOwnOverDefault` | `mynet` | `{"default": {Aliases}, "mynet": {}}` | `{"mynet": {}}` |
### Container create: HostConfig (`create_model` in `docker_socket_policy.qnt`)

The create check of [#88](https://github.com/ChainSafe/docker-socket-policy/issues/88): ContainerConfigMutator, then MountSourceGate and HostConfigGate on the mutated body. `LEGACY_CREATE = true` models all three before #88; `false` all three after. Four properties are checked exhaustively over both model policies (`BEACON`: volumes `/home/beacon` and read-only `/etc/jwt_dir`, a full `container_config`; `TOOLS`: no volumes, no `container_config`) and every single-field, single-bind and single-mount request over the model's atoms, plus every `NetworkingConfig` holding the CLI's `default` entry and one more entry, under `EndpointsConfig` or `endpointsconfig`:

| Property | Claim |
|----------|-------|
| `createChecksEveryField` | The rule: an allowed create has only exactly spelled field names, allowed values after the mutator, and allowed binds and mounts. Close to a tautology on `create`. |
| `daemonSeesOnlyAllowlistedHostConfig` | What the daemon reads (fields under their canonical names) is allowlisted with allowed values, `Privileged` is zero, and every value the policy forces (`NetworkMode`, `SecurityOpt`) is the forced one. Does not mention the gate's rules or the flag. |
| `daemonMountsOnlyWhitelisted` | Every host path the daemon mounts, from `Binds` or `Mounts`, is a policy volume, is not writable when the volume is read-only, and does not propagate. |
| `daemonAttachesOnlyForcedNetwork` | When the policy forces `network_mode`, the daemon attaches no network but the mode (or the CLI's `default`), reading `EndpointsConfig` under any spelling. `NetworkEndpointsGate` (#87, in both instances) reads the exact key only. |

`create` runs `createSoundTest` (all four hold) and the rows below; `create_pre88` runs `pre88UnsoundTest`, which asserts that the three security properties fail and that the #88 reproductions were allowed: a `Mounts` bind of `/`, a `:rw` and a mode-less bind of the read-only volume, `CapAdd`, `PidMode: host`, any bind on a policy with no volumes, `Privileged: true` reaching the daemon on a policy with no `container_config`, a zero-valued `securityopt` clearing a forced `SecurityOpt`, and an `endpointsconfig` entry attaching `evil-net` under a forced `host`. The deny rows run on `create` only.

Rows, with the names the language tables use (the language tables have more rows, one per field):

| Row (`run <row>Test`) | Request | Outcome |
|-----|---------|---------|
| `capAddDenied`, `devicesDenied`, `groupAddDenied`, `unknownFieldDenied` | a non-zero field outside the allowlist | deny |
| `maskedPathsEmptyDenied` | `MaskedPaths: []` | deny |
| `pidModeHostDenied`, `pidModeContainerDenied`, `ipcModeHostDenied` | `host` / `container:<id>` namespace modes | deny |
| `ipcModePrivateAllowed` | `IpcMode: private` | allow |
| `oomScoreAdjNegativeDenied` / `oomScoreAdjPositiveAllowed` | `OomScoreAdj` -1000 / 500 | deny / allow |
| `capDropAllowed`, `memorySwappinessAllowed`, `networkModeAllowed` | any-value fields | allow |
| `zeroValuesAllowed` | denied fields with zero values | allow |
| `securityOptSeccompUnconfinedDenied` / `securityOptNoNewPrivilegesAllowed` | `SecurityOpt` on a policy without `security_options` | deny / allow |
| `securityOptOverwrittenByPolicy` | `SecurityOpt: [seccomp=unconfined]` on `BEACON` | allow; the daemon reads the policy's list |
| `caseVariantPrivilegedDenied`, `caseVariantZeroSecurityOptDenied` | `privileged: true`, `securityopt: null` | deny |
| `networkingConfigVariantDenied` / `networkingConfigVariantBareDenied` | `NetworkingConfig` with `endpointsconfig: {evil-net}` on `BEACON` (forces `host`) / `TOOLS` | deny |
| `privilegedNeutralised`, `privilegedNeutralisedEmptyContainerConfig` | `Privileged: true` on `BEACON` / `TOOLS` | allow; the daemon reads `false` |
| `mountBindRootDenied`, `mountVolumeTypeDenied`, `mountTmpfsWithSourceDenied`, `mountPropagationRsharedDenied`, `mountNoVolumesDenied` | `Mounts` | deny |
| `mountBindReadOnlyVolumeWritableDenied` / `mountBindReadOnlyVolumeReadOnlyAllowed` | bind of `/etc/jwt_dir`, `ReadOnly` false / true | deny / allow |
| `mountBindAllowed`, `mountTmpfsAllowed`, `mountPropagationRprivateAllowed` | `Mounts` | allow |
| `bindReadOnlyVolumeRwDenied`, `bindReadOnlyVolumeNoModeDenied`, `bindReadOnlyVolumeRoRwDenied` | `/etc/jwt_dir:…:rw`, no mode, `ro,rw` | deny |
| `bindReadOnlyVolumeRoAllowed`, `bindReadOnlyVolumeRoZAllowed`, `bindAllowed` | `:ro`, `:ro,Z`, a read-write volume | allow |
| `bindRsharedDenied`, `bindUnlistedDenied`, `bindNoVolumesDenied` | `Binds` | deny |

The state machine imports `create_model(LEGACY_CREATE = false)`: `createContainer` takes the request's `HostConfig`, guards on `createAllowed`, and records what the daemon read; the P0 invariants `hostConfigInAllowlist` and `hostMountsInWhitelist` check it on every step of `make verify`, and `noPrivilegedAccess` now reads `Privileged` from it instead of rejecting privileged requests (the implementations neutralise them).

### Image pull (`router.qnt`, `pull_model`)

`POST /images/create` is modelled on its own, from the point where the router has taken that branch. A request is its body (`none`, `json` or `form`), the `fromImage` the body names, the `fromImage` query parameter, and whether the query carries `fromSrc`; `""` stands for an absent field. The daemon reads the pull parameters with Go's `r.Form`: a form body (`application/x-www-form-urlencoded`) wins over the query, and a JSON body is ignored. With an image it pulls it; with none and `fromSrc` set it imports a tarball under the `repo` and `tag` the caller names. The Docker CLI sends the image fully qualified in the query (`fromImage=docker.io/library/alpine&tag=3.19`) and no body. The table `CANONICAL` maps each spelling to the repository the daemon pulls, which is what the implementations' normalisation returns; the policies' prefixes (`ALLOWED_REPOS`: `alpine`, `chainsafe/lodestar`) are canonical, as the implementations normalise them at load time.

`READ_PULL_FROM_BODY = true` models all three before #83, which read `fromImage` from the JSON body. `NORMALIZE_IMAGES = false` models all three before #84, which matched the spelling as sent against the prefix as written. `ALLOW_PULL_BODY = true` models the first #83 fix, which routed on the query but forwarded the body unchanged, so a form body naming another image overrode the query at the daemon; the final fix denies any pull with a body (`image pull must not have a request body`).

- `pullForwardsOnlyAllowedImages` holds when every forwarded request makes the daemon pull (not import) an image whose canonical form a policy allows. It mentions no flag and reads what the daemon reads: the form body's `fromImage` over the query's.
- `pullWithBodyNeverForwarded` holds when a pull with a body of any kind is denied.
- `cliPullOfAllowedImageForwarded` holds when a pull of an allowed image, sent the Docker CLI way (empty body, image in the query), is forwarded, in every spelling of the image.
- `pullDecidedOnCanonicalImage` holds when two spellings of the same image in the query get the same outcome.

On `pull`, `pullSoundTest` asserts all four. `pull_pre83` runs `pre83UnsoundTest`, which asserts that `pullForwardsOnlyAllowedImages` and `cliPullOfAllowedImageForwarded` fail, that the CLI's pull of `docker.io/library/alpine` is denied, and that a body naming `alpine` forwards a query pull of `attacker/malware` and a `fromSrc` import ([#83](https://github.com/ChainSafe/docker-socket-policy/issues/83)). `pull_body_ignored` runs `bodyIgnoredUnsoundTest`, which asserts that `pullForwardsOnlyAllowedImages` and `pullWithBodyNeverForwarded` fail, that the CLI pull still works, and that a form body naming `attacker/malware` with `fromImage=alpine` in the query is forwarded. `pull_pre84` runs `pre84UnsoundTest`, which asserts that `pullForwardsOnlyAllowedImages` still holds (the old match only added denials), that `cliPullOfAllowedImageForwarded` and `pullDecidedOnCanonicalImage` fail, and that `docker.io/library/alpine` is denied while `alpine` is allowed ([#84](https://github.com/ChainSafe/docker-socket-policy/issues/84)). Setting `pull`'s `READ_PULL_FROM_BODY` to `true` fails `pullSoundTest` and six rows; setting its `NORMALIZE_IMAGES` to `false` fails `pullSoundTest` and three rows; setting its `ALLOW_PULL_BODY` to `true` fails `pullSoundTest` and two rows (`pullFormBodyDenied`, `pullJsonBodyDenied`).

Rows for the image pull ([#83](https://github.com/ChainSafe/docker-socket-policy/issues/83), [#84](https://github.com/ChainSafe/docker-socket-policy/issues/84)). The query is written as the CLI sends it; the implementations deny with the messages shown:

| Row (`run <row>Test`) | Request | Outcome | Instances |
|-----|---------|---------|-----------|
| `pullCliAllowed` | `?fromImage=docker.io/library/alpine`, no body | allow | `pull` |
| `pullCliOrgAllowed` | `?fromImage=docker.io/chainsafe/lodestar`, empty body | allow | `pull` |
| `pullShortNameAllowed` | `?fromImage=alpine`, empty body | allow | `pull` |
| `pullLibraryNameAllowed` | `?fromImage=library/alpine`, empty body | allow | `pull` |
| `pullNoFromImageDenied` | no `fromImage`, empty body | deny (`fromImage query parameter is required for image pull`) | `pull` |
| `pullBodyIgnoredDenied` | `?fromImage=attacker/malware`, JSON body `{"fromImage":"alpine"}` | deny (`image pull must not have a request body`) | `pull` |
| `pullFormBodyDenied` | `?fromImage=alpine`, form body `fromImage=attacker/malware` | deny (`image pull must not have a request body`) | `pull` |
| `pullJsonBodyDenied` | `?fromImage=alpine`, JSON body `{"fromImage":"alpine"}` | deny (`image pull must not have a request body`) | `pull` |
| `pullImportDenied` | `?fromSrc=…`, no body | deny (`image import (fromSrc) is not allowed`) | `pull` |
| `pullImportWithImageDenied` | `?fromImage=alpine&fromSrc=…` | deny (`image import (fromSrc) is not allowed`) | `pull` |
| `pullDisallowedCliDenied` | `?fromImage=docker.io/attacker/malware`, empty body | deny | all `pull*` |
| `pullOtherRegistryDenied` | `?fromImage=localhost:5000/alpine`, empty body | deny | all `pull*` |

The language tables add rows the model cannot express, because its images are atoms: the tag and digest (`tag=` in the query, or in `fromImage`, but not both), the tag pattern, `image_digest_allowed`, the pull of every tag when neither is given, duplicate parameters, and the reference parser itself (registry ports, upper case, the namespace-boundary prefix match).

### Modeling Notes

Two invariants are structurally tautological within the Quint model — they can't be falsified by any action sequence the simulator generates, so they don't get real coverage from `quint run`/`quint verify`:

- **`proxyLives`** — `proxyRunning` is set once in `init` and every action preserves it (`proxyRunning' = proxyRunning`); nothing in the model ever sets it `false`. The real guarantee ("a panic/error on one request doesn't crash the whole proxy") is enforced by language-specific mechanisms outside the model: Go's stdlib `net/http.Server` recovers per-request panics, Rust's `tokio::spawn` isolates panics per connection task, and TypeScript's request handler wraps `handle()` in a `.catch()`. These are exercised by each implementation's own test suite, not by the Quint simulation.
- **`routingTableComplete`** — checks that `endpointsTable` (a fixed constant) contains a fixed list of literals declared in the same file. It documents the intended routing table but doesn't cross-check it against any of the three Router implementations; that comparison has to be done manually (or via `quint-analyzer`) against `go/internal/proxy/router.go`, `rs/src/proxy.rs`, and `ts/src/proxy.ts`.
- **The model has no caller, by design.** `createContainer` picks a policy from the request's image, and nothing models who sent the request. An invariant such as "a container's `serviceName` equals the caller's service" therefore cannot be stated, and that is deliberate: callers who share a socket cannot be told apart. Several developers may share one account, for example, so the proxy has no identity to check. The trust boundary is the socket itself. Separating trust domains means one proxy instance per domain, each with its own socket group, and the kernel enforces that separation outside this model. See the README's "Trust model" section and [#39](https://github.com/ChainSafe/docker-socket-policy/issues/39).

- **`listener.qnt` checks the design, not the code.** Nothing in the model is derived from the Go, Rust or TypeScript sources. Conformance rests on each implementation's unit and integration tests, which carry the same names as the Quint `run`s (`groupDefaultPresent`, `pathStaleReplaced`, …) so every design-table row can be traced across all four. `raceWithoutLockTest` (in `listener_unlocked`) is the formal record of the TypeScript gap: Node has no `flock`, so two TypeScript instances starting together can orphan one another's socket ([#46](https://github.com/ChainSafe/docker-socket-policy/issues/46)).
- **`lifecycleOnlyTargetsRealNames` is close to a tautology.** `route` only allows by name when `hasContainerName` holds, and `hasContainerName` is nearly the property itself. It is not vacuous: on `router_pre48`, where an empty segment counts as a name, the property fails, and `pre48UnsoundTest` asserts that. Most of the evidence comes from the table rows, whose names the language router tests reuse (added with the #48 fix).
- **`routerSeesWhatDaemonSees` is also close to a tautology on `router`.** The percent check denies exactly the paths with a segment that is a key of `DAEMON_DECODING`, and those are exactly the paths that decoding changes. It is not vacuous: on `router_pre53` the property fails, and `pre53UnsoundTest` asserts that. Setting `router`'s `ALLOW_PERCENT` to `true` makes `percentSoundTest` and five of the six `percent*` rows fail. `percentSubpathStartDenied` still passes then, because the lifecycle branch denies `POST` when the last segment (`beacon%2Fstart`) is not an action. That row is a pin: routing on the raw path already denies it, and only Go's decode-first handler before #53 would have allowed it, since the daemon reads `POST /containers/beacon/start`. `percentNameStartDenied` (`POST /containers/%2F/start`) is the discriminating `POST` row. `lifecycleOnlyTargetsRealNames` holds on `router_pre53` too: `%2F` is a non-empty, non-reserved segment. That is why #53 needs a property that compares the router's reading with the daemon's.
- **Decoding is a fixed table.** Quint cannot inspect the characters of a string, so the model cannot find a `%` or decode one. `DAEMON_DECODING` lists the encoded tokens in the path universe and the segments the daemon reads them as; a segment is encoded iff it is a key. The implementations check for any `%` in the path. The table covers the shapes that matter: an encoded `/` (upper and lower case) that splits a segment, a fully encoded reserved word, and an encoded `/` inside a name that adds a lifecycle action.
- **The query string is outside `router_model`.** Paths are segment lists with the query string already removed, so the model says nothing about `%` in the query. `pull_model` reads two query parameters (`fromImage`, `fromSrc`) and a body's `fromImage` as already decoded tokens. The implementations never inspect the query string for this rule; encoded queries such as `?filters=%7B…%7D` are routine and must still be forwarded. That is pinned by the language handler tests and the integration tests, not by the model.
- **GET is covered.** The percent check runs before the GET passthrough, and `routerSeesWhatDaemonSees` ranges over `GET` as well as `POST` and `DELETE`. On `router_pre53` the passthrough lets `GET /containers/%2F` through, and the property fails for it too.
- **No instance models Go before #53.** Go decoded before routing, which is `route(m, decodePath(segs))`. With this table that agrees with the daemon by construction, so `routerSeesWhatDaemonSees` cannot express Go's risk: decoding that differs from the daemon's, such as encoded version segments ([#57](https://github.com/ChainSafe/docker-socket-policy/issues/57)). Go's change is covered by the language handler tests.
- **`router.qnt` is not the full router.** `route` models the read-only check, which runs first in all three routers, the percent check, the empty interior segment check, the dot segment check, the exec check, the attach check, the exact `POST /containers/create` route and the container-lifecycle branch, in that order. It leaves out the API-version strip and the other checks that the routers run before the lifecycle branch, such as auth and the build and commit denials, as well as `POST /images/create` (modelled separately in `pull_model`) and the endpoints after the lifecycle branch. For paths that those checks catch, the model's outcome can differ from what an implementation does: `GET /build` is `allowRead` in the model, for example, while the routers deny it as `build is not allowed`. The `images` rows of #49 (`GET /images/exec` allowed, `POST /images/create/extra` denied) are therefore language-only rows, as are `GET /containers/myexec/json` and `DELETE /containers/executor`: the model's words are atoms, so it cannot express a name that merely contains `exec`. Only the properties and the table rows are claims about the code.
- **Exec and create match whole segments (#49).** Before #49 the routers disagreed: Go matched `exec` only in the name position (`/containers/exec`), so `DELETE /containers/mycontainer/exec` went down the lifecycle branch and was allowed. Rust matched the substring `/exec` anywhere after `/containers/`, and TypeScript anywhere in the path, so Rust and TypeScript denied containers named `exec-runner` or `executor`. Neither Go nor Rust checked the `/exec/…` namespace, so both let `GET /exec/<id>/json` through the GET passthrough. Go also accepted `POST /containers/create/extra` as a container create. In the model the exec check runs before the create route, the lifecycle branch and the GET passthrough, so it denies every method, GET included: exec inspect shows the full command line. `reservedExecDeleteDenied` (`DELETE /containers/exec`) is decided by the exec check, as in all three implementations, and now asserts `denyExec`. `exec` stays in the reserved set, but no row, in the model or in the language tests, would catch it being dropped from there.
- **The #49 properties are not vacuous.** None of them is shown on a separate instance; replacing the rule in `route` makes them fail. With a substring-style rule (a segment that starts with `exec`, modeled as the set `exec`, `exec-runner`), `execPrefixSoundTest` and the three `execPrefixName*Allowed` rows fail. With Go's rule before #49 (`exec` only as the second segment under `containers`), `execSoundTest` and the four `exec*Denied` rows fail. `execSubpathPostDenied` and `execNamespacePostDenied` fail there only because the outcome is the default `deny`, not `denyExec`: the request is still refused, as before #49, but not by the exec check. With Go's prefix match for create, `createExactSoundTest` and `createSubpathDenied` fail. `execNeverAllowed` writes out the exec positions itself instead of calling `isExecPath`, so that a narrower `isExecPath` cannot narrow the property with it.
- **HEAD is routed like GET (#55).** `METHODS` is `GET`, `HEAD`, `POST`, `DELETE`. Before #55 the lifecycle branches disagreed on `HEAD /containers/x`: Go and TypeScript fell through to the GET/HEAD passthrough and allowed it, while Rust denied it. All three now allow it like `GET`, and the model's lifecycle branch allows `GET` and `HEAD` alike.
- **Empty interior segments are denied (#55).** Before #55, `GET //exec/<id>/json` (and `/v1.45//exec/…`) had an empty first segment, so the exec check did not match and the GET passthrough forwarded it. A live daemon answers such paths with a `301` to the clean path, so nothing leaked, but the router had allowed an exec path. `emptyInteriorDenied` states the rule, and on `router` it is close to a tautology, because `route` tests `hasEmptyInterior` directly. `emptySegmentsHideNoExec` states the security claim: a path that is an exec path once its empty segments are dropped, as the daemon's redirect does, is denied for every method. Both fail on `router_pre55`, and setting `router`'s `ALLOW_EMPTY_INTERIOR` to `true` makes `emptyInteriorSoundTest`, `emptySegmentsHideNoExecTest`, `emptyLeadingExecGetDenied` and `emptyInteriorGetDenied` fail. `router_pre48` keeps the rule off: with it on, `POST /containers//start` is denied before it reaches the name branch, and the instance could no longer show the #48 extraction bug. For the same reason, on `router` the empty-segment check now decides `emptyNameStartDenied`; the #48 extraction stays covered there by `emptyNameDeleteDenied` (a trailing slash) and on `router_pre48`. The implementations check for `//` in the path without its query, so `GET /containers/json?filters=a//b` is still forwarded; that is pinned by the TypeScript router test, since Go and Rust route on the path alone.
- **Dot segments are denied, not normalised (#70).** Before #70, `GET /./exec/<id>/json` and `GET /x/../exec/<id>/json` had a first segment of `.` or `x`, so the exec check did not match and the GET passthrough forwarded them; attach and any other path-based deny could be hidden the same way. The daemon answers such paths with a `301` to the clean path, so nothing leaked, but the router had allowed an exec path. The routers now deny any segment that is exactly `.` or `..`, for every method, right after the `//` check. Normalising the path and routing the result was rejected: the proxy would then route one path and forward another, or have to rewrite it. `dotSegmentsDenied` states the rule and on `router` is close to a tautology, since `route` tests `hasDotSegment` directly. `dotSegmentsHideNoExec` states the security claim: a path that is an exec or attach path once its dot segments are resolved is denied for every method. Both fail on `router_pre70`, and setting `router`'s `ALLOW_DOT_SEGMENTS` to `true` makes `dotSoundTest` and the three `dot*Denied` rows fail. An encoded dot (`%2e`) is already denied by the percent check (#53). The implementations check the path without its query, so `GET /containers/json?filters=a/./b` is still forwarded; that is pinned by the TypeScript router test.
- **`--readonly` is a router rule (#75).** Before #75 the flag reached only the middleware chain, and the handler runs the chain only on the create route, so lifecycle `POST`s, `DELETE /containers/{name}` and `POST /images/create` were forwarded in read-only mode. That was handler wiring, not routing, so there is no `pre75` instance: the `READONLY = false` instances are the behaviour without the flag, which before the fix was also the behaviour with it for every route but create. `readonlyAllowsOnlyReads` does not mention `READONLY`, so it is not vacuous: setting `router_readonly`'s `READONLY` to `false` makes `readonlySoundTest` and the three `readonly*Denied` rows fail. `METHODS` has no `PUT`; the implementations' tests cover it.
- **Attach is a router rule; the upgrade refusal is not modelled (#76).** Before #76, `GET /containers/{name}/attach/ws` with `Upgrade: websocket` fell through to the GET passthrough, and Go relayed the daemon's `101`, giving the caller the container's stdin. The router now denies `attach` as a whole segment after `containers`, for every method, right after the exec check. As with `/containers/exec/…`, a container literally named `attach` is denied too (`attachNamedContainerDenied`). `attachNeverAllowed` fails on `router_pre76`, and setting `router`'s `ALLOW_ATTACH` to `true` makes `attachSoundTest` and three of the four `attach*` rows fail; `attachPostDenied` is a pin, since the lifecycle branch already denies `POST` when the last segment is not an action. The handler also refuses every request with an `Upgrade` header, or a `Connection` header listing `upgrade`, with `protocol upgrade not allowed`, before routing. That check is on headers, which the model does not have, so like the query string it is pinned by the language handler tests and the integration tests, not by the model.
- **The read endpoints admit only `GET` and `HEAD`; the `CONNECT` refusal is not modelled (#78).** Before #78 an early clause in all three routers allowed `/_ping`, `/version`, `/info` and any path starting with `/events` for every method, so `POST /_ping` and `DELETE /version` reached the daemon, and `/eventsxyz` matched too. The clause is gone: `GET` and `HEAD` on those paths reach the read passthrough as before, and every other method falls through to the default deny. `readPassthroughOnlyForReads` fails on `router_pre78`, and setting `router`'s `ALLOW_ANY_METHOD_PING` to `true` makes `readPassthroughSoundTest`, `pingPostDenied` and `pingDeleteDenied` fail. The handlers also refuse every `CONNECT` request with `CONNECT is not allowed` before routing, ahead of the upgrade check; `METHODS` has no `CONNECT`, so that is pinned by the language handler tests and the integration tests, not by the model.
- **Network endpoints are a pure function, not part of the state machine (#87).** `createContainer` records the forced `networkMode` but takes no `NetworkingConfig`, and nothing in the state machine models the daemon's start, so the endpoint rule sits in its own module beside it and is checked by `quint test`, not by `make verify`. When the policy does not force `network_mode`, `NetworkingConfig` is forwarded untouched; neither the model nor the implementations check it then. Whether the daemon accepts the settings kept on a re-keyed entry (aliases on the default `bridge` network, for example) is the daemon's decision; the model fixes only the keys. `extraNetworkDenied` and `onlyForcedNetwork` are close to tautologies on `network_endpoints`, since `handleEndpoints` tests the key set directly; `network_endpoints_pre87` shows they are not vacuous. Dropping the extra keys instead of denying would keep `onlyForcedNetwork` and fail `extraNetworkDenied`; that was rejected, because the caller asked for a network the policy does not allow and should be told. A malformed `NetworkingConfig` or `EndpointsConfig` (not a JSON object) is denied by the implementations under a forced mode; the model's maps cannot express it, so the language tests pin it.

- **Image references are tokens, normalisation is a table (#84).** Quint cannot split a string, so `pull_model` cannot parse `[registry/]repository[:tag][@digest]`. `CANONICAL` lists the spellings in the universe and the repository each one names; the implementations compute the same thing with one parser per language, used for the request's image (create `Image` and pull `fromImage`), for the registry gate and for each policy prefix at load time. The parser's rules (the tag is after the last `:` that follows the last `/`; the first component is a registry when it contains `.` or `:` or is `localhost`; `docker.io`, `index.docker.io` and `registry-1.docker.io` are dropped, and so is `library/` before a single-component name; only the registry is lower-cased, and upper case in the path is invalid) are pinned by the same normalisation table in the Go, Rust and TypeScript tests, not by the model. So are the namespace-boundary prefix match (`prefix` or `prefix/…`), which the model reduces to equality, and the tag and digest rules.
- **The create model is a small universe (#88).** Values are atoms (`"null"`, `"zero"`, `"[]"` and a few non-zero ones), a list field holds one entry, and the field names stand for the classes in the README's HostConfig table: `CapAdd`, `Devices`, `GroupAdd` for the must-be-zero fields, `FutureField` for a field the proxy does not know, `CapDrop` and `MemorySwappiness` for the any-value fields, `PidMode` and `IpcMode` for the namespace modes. Case folding is a fixed table (`CASE_FOLD`), as percent-decoding is in `router.qnt`: Quint cannot fold strings. The implementations fold ASCII case plus the Kelvin sign and the long s, as Go's `encoding/json` does, and check the top level of the body, `Mounts` entries and `BindOptions` too; the language tables cover those (`caseVariantLongSDenied`, `caseVariantKelvinDenied`, `topLevel*VariantDenied`, `mountCaseVariantDenied`, `networkingConfigVariantLongSDenied`). The other nested objects need no check: the mutator replaces `RestartPolicy` and `LogConfig` whole when the policy sets them and they are any-value otherwise, and no gate reads `Healthcheck` or an endpoint entry's settings by key. Dropping the `NetworkingConfig` variant check from `createAllowed` makes the two `networkingConfigVariant*` rows and `createSoundTest` fail. Requests are single-field, single-bind or single-mount; a request that combines a canonical field with a variant needs no separate case, because the daemon may keep either value and the property checks every value it may read. Bind parsing (`src:dst:opts`, the escaped colon in Go), the zero-value test on JSON types and the type checks (a `Binds` entry that is not a string) are language-only rows.
- **Mutating the create rules makes the rows fail.** Dropping the case-variant check from `fieldOk` makes `caseVariantZeroSecurityOptDenied` and `createSoundTest` fail (`caseVariantPrivilegedDenied` still passes: `privileged` is not an allowlisted name, so the zero-value rule denies its `true`). Dropping the read-only clause from `mountOk` makes `mountBindReadOnlyVolumeWritableDenied` and `createSoundTest` fail.
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
| Host Root Mount | `createContainer` with `Mounts: [{Type: bind, Source: /}]` | `hostMountsInWhitelist` — `/` is not a policy volume (#88) |
| Read-only Volume Written | `createContainer` with `Binds: [/etc/jwt_dir:/jwtdir:rw]` | `hostMountsInWhitelist` — the volume is `read_write: false` (#88) |
| Capabilities / Host PID | `createContainer` with `CapAdd: [SYS_ADMIN]` or `PidMode: host` | `hostConfigInAllowlist` — default-deny on `HostConfig` (#88) |
| Case-variant Field | `createContainer` with `privileged: true` | `noPrivilegedAccess`, `hostConfigInAllowlist` — the variant is denied (#88) |

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
 │     │         volumeAllowed, envAllowed,             │
 │     │         createAllowed (HostConfig, #88)        │
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
