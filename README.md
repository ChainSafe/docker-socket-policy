# docker-socket-policy

[![CI](https://github.com/ChainSafe/docker-socket-policy/actions/workflows/ci.yml/badge.svg)](https://github.com/ChainSafe/docker-socket-policy/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/ChainSafe/docker-socket-policy)](https://github.com/ChainSafe/docker-socket-policy/releases/latest)
[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8)](https://go.dev)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A validating Docker API proxy that enforces **per-service container policies** through a middleware pipeline. Designed for granting safe, audited Docker access to external contributors, CI/CD pipelines, and automated tooling — without giving them direct Docker daemon access.

Key features:

- **Policy-driven**: Per-service YAML policies, selected by image and container name, control images, volumes, flags, and env vars. The listening socket is the trust boundary: every caller of a socket can use every policy behind it (see [Trust model](#trust-model))
- **Middleware pipeline**: 4 validation gates + 1 config mutator chain
- **Default-deny router**: Only explicitly allowed endpoints pass through
- **Formally verified**: [Quint](https://quint-lang.org/) specification: 9 request-handling invariants, 6 listener invariants, and router properties for `--readonly`, percent-encoded paths, empty segments, dot segments, exec, attach, the read-only passthrough and the container lifecycle
- **Audit logging**: JSON-structured logs for all requests and decisions
- **Three implementations**: [Go](go/), [Rust](rs/), [TypeScript](ts/) — equal peer languages
- **Minimal dependencies**: Zero external deps for Go, crate-based for Rust, npm for TypeScript

## Installation

### Supported Architectures

docker-socket-policy builds and runs on **amd64** (x86-64) and **arm64** (AArch64) Linux architectures:

- **Docker Images**: Multi-arch manifest indexes automatically select the correct architecture when pulling. No platform flag needed:
  ```bash
  docker pull ghcr.io/chainsafe/docker-socket-policy-go:latest
  # Pulls amd64 on x86-64, arm64 on ARM machines
  ```

- **Prebuilt Binaries**: Both amd64 and arm64 variants are published with each release.

See [docs/reproducible-builds.md](docs/reproducible-builds.md) for verification and per-architecture build instructions.

### Docker Images

Signed, SBOM-attested images are published to GHCR for all three implementations:

```bash
docker pull ghcr.io/chainsafe/docker-socket-policy-go:latest
docker pull ghcr.io/chainsafe/docker-socket-policy-rs:latest
docker pull ghcr.io/chainsafe/docker-socket-policy-ts:latest

# Pin to a specific release instead of latest
docker pull ghcr.io/chainsafe/docker-socket-policy-go:v0.2.8
```

Every image is Cosign-signed and ships with SPDX + CycloneDX SBOMs attached to the corresponding [release](https://github.com/ChainSafe/docker-socket-policy/releases/latest). See [docs/reproducible-builds.md](docs/reproducible-builds.md) to verify signatures and reproduce a build byte-for-byte.

### Prebuilt Binaries

Each [release](https://github.com/ChainSafe/docker-socket-policy/releases/latest) attaches binaries for amd64 and arm64 architectures, plus SBOMs for each:

**Go** (statically linked ELF binary):
```bash
# amd64
curl -LO https://github.com/ChainSafe/docker-socket-policy/releases/latest/download/docker-socket-policy-go-linux-amd64
chmod +x docker-socket-policy-go-linux-amd64

# arm64
curl -LO https://github.com/ChainSafe/docker-socket-policy/releases/latest/download/docker-socket-policy-go-linux-arm64
chmod +x docker-socket-policy-go-linux-arm64
```

**Rust** (statically linked ELF binary with musl):
```bash
# amd64
curl -LO https://github.com/ChainSafe/docker-socket-policy/releases/latest/download/docker-socket-policy-rs-linux-amd64
chmod +x docker-socket-policy-rs-linux-amd64

# arm64
curl -LO https://github.com/ChainSafe/docker-socket-policy/releases/latest/download/docker-socket-policy-rs-linux-arm64
chmod +x docker-socket-policy-rs-linux-arm64
```

**TypeScript** (Node 22+ required; archive includes dist/, node_modules/, and package files):
```bash
# Extract and run (platform-independent Node archive)
curl -LO https://github.com/ChainSafe/docker-socket-policy/releases/latest/download/docker-socket-policy-ts-<version>.tar.gz
tar xzf docker-socket-policy-ts-<version>.tar.gz
node dist/index.js
```

To build any implementation from source instead, see [Build All](#build-all) below.

## Architecture

```
Docker CLI → docker-socket-policy (middleware chain) → Docker daemon
                │
                ├── Mutators: modify request (force container config)
                ├── Gates: validate request (image refs, volumes, flags)
                └── Proxy: forward allowed requests to daemon
```

## Language Implementations

All three implementations expose the same API surface, share the same [Quint spec](spec/) and [YAML policies](config/), and pass the same [integration tests](deploy/test.sh).

| Language | Directory | Tests | Stack |
|----------|-----------|-------|-------|
| Go | [go/](go/) | 133 unit + 116 integration + 15 socket | stdlib net/http + yaml.v3 |
| Rust | [rs/](rs/) | 160 unit + 116 integration + 15 socket | tokio, hyper, serde, clap |
| TypeScript | [ts/](ts/) | 330 unit (1 skipped) + 116 integration + 15 socket | Node 22 ESM, built-in http |

### Build All

```bash
# Build all three language implementations
make build-all

# Run all tests (unit + integration)
make test-all

# Lint all three
make lint-all

# Full validation: typecheck + verify + gofmt + vet + test (Go)
make validate
```

### Run

```bash
sudo groupadd --system docker-socket-policy
sudo usermod -aG docker-socket-policy alice

sudo ./docker-socket-policy \
  --listen-socket=/var/run/docker-socket-policy.sock \
  --docker-host=/var/run/docker.sock \
  --config-dir=./config \
  --log-file=/tmp/docker-socket-policy.log
```

Like `docker.sock`, the socket is always created `0660` and owned by the
`docker-socket-policy` group, so members of that group can connect and nobody
else can. Grant or revoke access with group membership alone. If the group
does not exist, the proxy warns and uses its own group instead. See the
Unix socket security boundary note under [CLI flags](#cli-flags) for the
details.

### Configure a Service

Create a YAML policy in the config directory:

```yaml
# config/beacon.yaml
service_name: beacon
container_names:          # optional; see below
  - beacon
allowed_image_prefixes:
  - chainsafe/lodestar
container_config:
  network_mode: host
  restart_policy: unless-stopped
  security_options:
    - no-new-privileges:true
  user: '2001:2001'
  group_add:              # optional; forced as HostConfig.GroupAdd
    - '64190'             # host GID of the jwt group (quote GIDs)
volumes:
  - host_path: /home/beacon
    container_path: /data
    read_write: true
  - host_path: /etc/jwt_dir
    container_path: /jwtdir
    read_write: false   # must be mounted read-only: -v /etc/jwt_dir:/jwtdir:ro
env_file: /home/beacon/beacon.env
allowed_cli_flags:
  - --rcConfig
  - --logLevel
denied_flags:
  - --privileged
  - --volume
  - --cap-add
```

`volumes` is the whole list of host paths a container may mount, through `-v`
(`HostConfig.Binds`) or `--mount type=bind` (`HostConfig.Mounts`). A policy
without `volumes` allows no bind mounts. `read_write: false` (the default when
the key is left out in Go and TypeScript; Rust requires the key) is enforced:
the bind must carry `:ro`, or the mount `ReadOnly: true`, and a bind without a
mode is read-write in Docker, so it is denied. See
[Container create: HostConfig rules](#container-create-hostconfig-rules).

`container_config.group_add` is optional
([#93](https://github.com/ChainSafe/docker-socket-policy/issues/93)). `user`
sets only the primary UID and GID, and the daemon checks a host-mounted file
against the GIDs the process has, so a service that reads a file such as a
`root:jwt 0640` JWT secret needs the host group as a supplementary group. The
mutator overwrites `HostConfig.GroupAdd` with the list, as `user` overwrites
`User`: a caller's own list (`community.docker.docker_container`'s `groups:`,
`docker run --group-add`) is replaced, not denied, and a caller that sends the
same list sees no change. Each entry must be a quoted YAML string holding a
decimal GID that fits in 32 bits or a group name
(`[a-z_][a-z0-9_-]*$?`, at most 32 characters); `0` (in any decimal form) and
`root`, duplicates and anything else fail startup with an error that names the
file. An empty list is the same as leaving the key out. A group name is
resolved by the daemon against the container's `/etc/group` when it starts;
a GID needs no entry there.

`container_names` is optional. It lists the container names the policy
manages, each a valid Docker name (`[a-zA-Z0-9][a-zA-Z0-9_.-]*`; anything else
fails startup). It does two things
([#85](https://github.com/ChainSafe/docker-socket-policy/issues/85),
[#86](https://github.com/ChainSafe/docker-socket-policy/issues/86)):

- **Create selects one policy.** `POST /containers/create?name=N` uses the one
  policy whose `allowed_image_prefixes` match the image and whose
  `container_names` contain `N`; a policy without `container_names` accepts any
  name. No match is denied (`image X not allowed by any policy`, or
  `container name N not allowed for image X by any policy`), and so is more than
  one (`ambiguous policy for image X and name N: a, b`). A create without
  `?name=` can only use a policy without `container_names`
  (`image X requires a container name` otherwise). This is how two services
  built from one image, such as a Lodestar beacon node and validator client,
  get their own users and volumes. An image pull has no container name and
  creates no container, so it is allowed when any policy for the image accepts
  its tag or digest.
- **Lifecycle actions reach only covered containers.** A policy covers its
  `container_names`, or its `service_name` when `container_names` is unset.
  `start`, `stop`, `restart`, `kill`, `wait`, `pause`, `unpause` and `DELETE`
  are forwarded only for a container whose name is covered (see
  [Endpoint Access](#endpoint-access)).

Policies are checked when the proxy starts, and it refuses to start (naming
both files) if two policies use the same `service_name`, or if two policies
could both match one create: their image prefixes share a namespace (equal, or
one is a `/`-prefix of the other) and either one has no `container_names` or
their `container_names` overlap. Two services that share an image therefore
both need `container_names`, with no name in common:

```yaml
# config/beacon.yaml               # config/validator.yaml
service_name: beacon               service_name: validator
container_names: [beacon]          container_names: [validator]
allowed_image_prefixes:            allowed_image_prefixes:
  - chainsafe/lodestar               - chainsafe/lodestar
```

### Use the Proxy

```bash
export DOCKER_HOST=unix:///var/run/docker-socket-policy.sock

# These work (validated against policy)
docker pull chainsafe/lodestar:next
docker run --name beacon chainsafe/lodestar:next --rcConfig /data/config.yml
docker ps
docker logs -f beacon
docker stop beacon
docker rm beacon

# These are denied
docker exec -it beacon bash          # denied: exec not allowed
docker run --privileged alpine sh    # denied: privileged containers blocked
docker pull attacker/malware:latest  # denied: image not in allowlist
docker run --cap-add SYS_ADMIN --pid host chainsafe/lodestar:next      # denied: HostConfig.CapAdd
docker run --mount type=bind,src=/,dst=/host chainsafe/lodestar:next  # denied: mount source not in volumes
```

## Middleware Pipeline

| Middleware | Type | What it checks |
|------------|------|----------------|
| ContainerConfigMutator | Mutator | Forces `network_mode`, `user`, `group_add`, `security_options`, `restart_policy`, `log_driver` from policy, `HostConfig.Privileged: false` on every create, and makes `NetworkingConfig.EndpointsConfig` match a forced `network_mode` |
| RegistryGate | Gate | Validates the normalised image ref against `allowed_image_prefixes`, then `image_tag_pattern` and `image_digest_allowed` |
| MountSourceGate | Gate | Validates `HostConfig.Binds`, `HostConfig.Mounts` and top-level `Volumes` against `volumes`, including bind options and `read_write: false` |
| EnvFileGate | Gate | Strips `Env` field from create body; env must come from locked `env_file` |
| HostConfigGate | Gate | Default-deny on `HostConfig`: a field outside the allowlist must be absent or zero ([#88](https://github.com/ChainSafe/docker-socket-policy/issues/88)) |
| CmdGate | Gate | Validates each CLI flag in `Cmd` array against allowlist + denylist |
| NetworkEndpointsGate | Gate | With a forced `network_mode`, denies `NetworkingConfig.EndpointsConfig` entries for other networks |

When a policy forces `network_mode` M, the endpoint entries in `NetworkingConfig.EndpointsConfig` must agree with it, or the daemon creates the container and then refuses to start it with `network default not found`: without `--network`, the Docker CLI sends an entry for `default` ([#87](https://github.com/ChainSafe/docker-socket-policy/issues/87)). Entries may be keyed `default` or M; any other key is denied with `network "<name>" is not allowed for service <service>; policy forces network_mode <M>`, since it would attach the container to a network the policy does not allow. For `host`, `none` and `container:<id>` the proxy then forwards an empty `EndpointsConfig`; for `bridge` or a named network it forwards exactly one entry, keyed M, with the settings (aliases, for example) of the caller's M entry, else of its `default` entry. A `NetworkingConfig` that is not a JSON object is denied. Without a forced `network_mode`, `NetworkingConfig` is forwarded as sent.

The chain runs only on container create. The mutator runs first, so the gates check the body that is forwarded to the daemon. `--readonly` is not a gate: the router denies every request that is not `GET` or `HEAD`, on every path, before any other check ([#75](https://github.com/ChainSafe/docker-socket-policy/issues/75)). Attach is denied by the router for every method, so a websocket attach (`GET /containers/{name}/attach/ws`) cannot reach a container's stdin, with or without `--readonly` ([#76](https://github.com/ChainSafe/docker-socket-policy/issues/76)).

### Container create: HostConfig rules

`HostConfig` is default-deny ([#88](https://github.com/ChainSafe/docker-socket-policy/issues/88)). Before #88 only the host paths in `HostConfig.Binds` were checked, so `--mount`, a bind mode, `--cap-add`, `--pid host`, `--device` and every other `HostConfig` field reached the daemon unchanged. Now each key is checked against this table, after the mutator has run; any key not listed, including fields the Engine API adds later, must be absent or hold a zero value (`null`, `false`, `0`, `""`, `[]` or `{}`), or the create is denied with 403 `HostConfig.<Key> is not allowed for service <name>`. The body a plain `docker create` or `docker run` sends passes: the CLI sends most fields with zero values.

| `HostConfig` key | Rule |
|------------------|------|
| `Binds` | Host path must be a policy `volumes` entry. Bind options: `ro`, `rw`, `z`, `Z`, `nocopy`, `private`, `rprivate`; `shared`, `rshared`, `slave`, `rslave` and anything else are denied. A `read_write: false` volume needs `ro` (no mode means read-write). |
| `Mounts` | `Type: bind`: `Source` must be a policy `volumes` entry; `ReadOnly: true` for a `read_write: false` volume; `BindOptions.Propagation` empty, `private` or `rprivate`; `BindOptions.ReadOnlyNonRecursive` must be zero. `Type: tmpfs`: allowed, without a `Source`. Every other type (`volume`, `image`, `npipe`, `cluster`) is denied. Other entry keys besides `Target`, `Consistency` and `TmpfsOptions` must be zero. |
| `NetworkMode`, `RestartPolicy`, `LogConfig` | Any value; overwritten when the policy sets `network_mode`, `restart_policy` or `log_driver`. |
| `SecurityOpt` | Each entry must be in the policy's `security_options` or be `no-new-privileges` / `no-new-privileges:true`. Overwritten when the policy sets `security_options`. |
| `GroupAdd` | Absent or zero, unless the policy sets `group_add`: the mutator then overwrites it with that list, and the gate allows exactly that list, in order ([#93](https://github.com/ChainSafe/docker-socket-policy/issues/93)). |
| `Privileged` | Forced to `false` by the mutator on every create, so `true` is neutralised, not denied. |
| `PidMode`, `UTSMode`, `UsernsMode`, `Cgroup` | `""` only. |
| `IpcMode` | `""`, `private`, `shareable` or `none`. |
| `CgroupnsMode` | `""` or `private`. |
| `Isolation` | `""` or `default`. |
| `OomScoreAdj` | `0` or more. |
| `MaskedPaths`, `ReadonlyPaths` | Absent or `null` only: an empty list unmasks `/proc` (`--security-opt systempaths=unconfined`). |
| `CapDrop`, `ReadonlyRootfs`, `Init`, `AutoRemove`, `ConsoleSize`, `ShmSize`, `PortBindings`, `PublishAllPorts`, `Dns`, `DnsOptions`, `DnsSearch`, `ExtraHosts`, `Tmpfs`, `Ulimits`, `Memory`, `MemoryReservation`, `MemorySwap`, `MemorySwappiness`, `NanoCpus`, `CpuShares`, `CpuPeriod`, `CpuQuota`, `CpusetCpus`, `CpusetMems`, `PidsLimit`, `BlkioWeight`, `ContainerIDFile` | Any value. |
| Everything else: `CapAdd`, `Devices`, `DeviceRequests`, `DeviceCgroupRules`, `VolumesFrom`, `Links`, `Sysctls`, `CgroupParent`, `Runtime`, `VolumeDriver`, `OomKillDisable`, `Annotations`, `StorageOpt`, the other resource fields, and unknown keys | Absent or zero. |

The daemon matches JSON field names without regard to case, and the last match wins, so `"privileged": true` would set `Privileged` after the mutator's `"Privileged": false`, and `"securityopt": null` would clear a forced `SecurityOpt`. A key that the daemon would read as a known field but that is not spelled exactly like it (`privileged`, `hostConfig`, `user`, `image`, …) is denied, at the top level of the body, in `HostConfig`, in `Mounts` entries and their `BindOptions`, and in `NetworkingConfig`, whether or not the policy forces `network_mode`: `NetworkEndpointsGate` reads `EndpointsConfig` only, and the daemon would attach the networks under `endpointsconfig` too. Inside `RestartPolicy` and `LogConfig` the spelling does not matter: the mutator replaces the whole object when the policy sets it, and otherwise any value is allowed; no gate reads `Healthcheck` or the settings inside an endpoint entry. The policy's `ports` field is parsed but not enforced; `PortBindings` is not restricted by it.

## Endpoint Access

| HTTP Method | Path | Action |
|-------------|------|--------|
| CONNECT | Any target | **DENIED** (checked first, before routing) |
| Any | Request with an `Upgrade` header, or `Connection: upgrade` | **DENIED** (checked before routing) |
| Not GET/HEAD | Any (with `--readonly`) | **DENIED** (checked first in the router) |
| Any | Path containing `%` | **DENIED** (see below) |
| Any | Path containing `//` | **DENIED** |
| Any | Path with a `.` or `..` segment | **DENIED** |
| POST | `/containers/create` | Validated by middleware chain |
| POST | `/containers/{name}/start\|stop\|restart\|kill\|wait\|pause\|unpause` | Allowed only on a container a policy covers (see below) |
| DELETE | `/containers/{name}` | Allowed only on a container a policy covers (see below) |
| Any | `/containers/…/exec` (an `exec` segment anywhere under `/containers`) | **DENIED** |
| Any | `/exec/*` | **DENIED** |
| Any | `/containers/{name}/attach…` (an `attach` segment anywhere under `/containers`) | **DENIED** |
| POST | `/containers/{name}/rename\|update` | **DENIED** |
| POST | `/images/create` | Pull: `fromImage` and `tag` from the query string get the image checks (see below); a request body or `fromSrc` (import) **DENIED** |
| POST | `/auth` | **DENIED** |
| POST | `/build` | **DENIED** |
| POST | `/commit` | **DENIED** |
| GET/HEAD | Any other path without `%`, `//` or a dot segment, including `/_ping`, `/version`, `/info`, `/events` | Allowed (read-only) |
| Other | Other | **DENIED** |

Any request whose path contains a percent-encoded byte (`%`) is denied with 403 for every method, GET and HEAD included, because the daemon decodes the path before routing. The query string is not inspected, so filters such as `docker ps --filter …` still work. The Go implementation also denies paths that contain raw characters it must re-encode, such as non-ASCII bytes or `{`; the Docker CLI never sends these. A consequence is that networks whose names need percent-encoding (for example a space or `%`) cannot be inspected by name through the proxy; inspecting them by ID still works, and other network operations are denied regardless.

Exec is matched on whole path segments, so containers named like `exec-runner` work normally, and exec inspect (`GET /exec/{id}/json`) is denied too. A path with an empty segment (`//`, as in `//exec/{id}/json`) is denied for every method, so an empty segment cannot hide the exec namespace; a single trailing slash is fine, and `//` in the query string is not inspected. A path with a segment that is exactly `.` or `..` (`/./exec/{id}/json`, `/x/../exec/{id}/json`) is denied the same way, with `dot path segment not allowed`, rather than resolved: the proxy never routes one path and forwards another ([#70](https://github.com/ChainSafe/docker-socket-policy/issues/70)). Names such as `.hidden` or `a.b` are fine, and the query string is not inspected. Absolute-form request targets (`GET http://host/…`) never reach exec: Go and Rust route them on the parsed path, so exec is denied and other paths are routed as usual, while the TypeScript proxy sees the raw target and denies every absolute-form request (its `//` after the scheme is an empty segment). The Docker CLI never sends absolute form.

Attach is matched the same way: an `attach` segment under `/containers` is denied for every method, so `attach-runner` is an ordinary name, while a container literally named `attach` cannot be reached by name. Protocol upgrades are refused outright: any request with an `Upgrade` header, or a `Connection` header that lists `upgrade`, gets 403 `protocol upgrade not allowed` before it is routed, whatever its path ([#76](https://github.com/ChainSafe/docker-socket-policy/issues/76)). Forwarding one would hand the caller a raw stream to the daemon. Every Docker endpoint that upgrades (attach, exec start, the build session) is denied anyway; the refusal keeps any path the router allows from becoming one.

Lifecycle actions and `DELETE` are forwarded only for a container that a loaded policy covers: its name is in some policy's `container_names`, or is the `service_name` of a policy without `container_names` ([#86](https://github.com/ChainSafe/docker-socket-policy/issues/86)). If `{name}` is exactly one policy's covered name, the request is forwarded. Otherwise, because it may be a full or short container ID, or a covered name that only looks like an ID prefix (all lowercase hex), the proxy first asks the daemon `GET /containers/{name}/json` and checks the `Name` it reports. A covered name is forwarded; an uncovered name or a daemon 404 is denied with 403 `container {name} is not managed by any policy`, and any other daemon error with 403 `cannot resolve container {name}: …`. The audit log records the resolved name. Containers outside every policy, such as operator containers for monitoring, cannot be stopped or removed through the proxy. Reads (`GET`) on any container are unchanged. Before #86 these endpoints were forwarded for any container.

`/_ping`, `/version`, `/info` and `/events` are ordinary reads: `GET` and `HEAD` pass, and every other method is denied with `endpoint <METHOD> <path> is not allowed`, `OPTIONS` (a CORS preflight) included ([#78](https://github.com/ChainSafe/docker-socket-policy/issues/78)). `CONNECT` is refused with 403 `CONNECT is not allowed` before anything else, whatever its target or headers; the TypeScript proxy answers it on the raw socket, since Node never hands `CONNECT` to the request handler.

An image pull is routed on its query string, as the Docker Engine API defines it and the Docker CLI sends it: `POST /images/create?fromImage=docker.io%2Flibrary%2Falpine&tag=3.19` and no body ([#83](https://github.com/ChainSafe/docker-socket-policy/issues/83)). A pull with any body is denied (`image pull must not have a request body`), whatever its `Content-Type` or framing: the daemon reads a form body's `fromImage` over the query's, so a body could name an image the router never checked. The image gets the same checks as `Image` on create: its normalised repository must match a policy's prefix, then the tag must match that policy's `image_tag_pattern` and a digest needs `image_digest_allowed` (the CLI sends a digest in `tag`). The proxy denies a pull with no `fromImage` (`fromImage query parameter is required for image pull`), an import (`image import (fromSrc) is not allowed`: it would store any tarball under an allowed name), a tag in both `fromImage` and `tag`, a repeated `fromImage`, `tag` or `fromSrc`, a query the daemon would reject, and a pull with neither tag nor digest, which makes the daemon pull every tag of the repository (`image pull without a tag or digest pulls every tag and is not allowed`; `docker pull alpine` sends `tag=latest`, `docker pull --all-tags` is denied).

Image references are normalised before policy matching, in all three implementations and for both the request and the policy's `allowed_image_prefixes` (at load time) ([#84](https://github.com/ChainSafe/docker-socket-policy/issues/84)). The reference is split the way Docker does: the digest follows `@`, the tag follows the last `:` after the last `/` (so `localhost:5000/team/app:1.2` has tag `1.2`), and the first component is a registry host when it contains `.` or `:` or is `localhost`. Docker Hub's `docker.io/`, `index.docker.io/` and `registry-1.docker.io/` are dropped, and so is `library/` before a single-component name, so `alpine`, `library/alpine` and `docker.io/library/alpine` are the same image, as are `chainsafe/lodestar` and `docker.io/chainsafe/lodestar`. The registry host is compared lower-cased; upper case in the repository path is invalid, as it is for Docker (`invalid image reference "…"`). The prefix match stays on whole path components: `alpine` does not match `alpine-evil`, and `alpine` (Docker Hub) does not match `localhost:5000/alpine`. A prefix that is not a valid repository name, or that carries a tag or digest, fails the policy load.

## Configuration

### CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--listen-socket` | `/var/run/docker-socket-policy.sock` | Unix socket path to listen on (absolute filesystem path only) |
| `--docker-host` | `/var/run/docker.sock` | Docker daemon socket path (Unix socket only) |
| `--config-dir` | `/etc/docker-socket-policy/services` | Policy config directory |
| `--log-file` | `/var/log/docker-socket-policy.log` | Audit log path |
| `--readonly` | `false` | Enable read-only mode: the router denies every request that is not `GET` or `HEAD` |
| `--listen-socket-group` | `docker-socket-policy` | Group owning the socket (default `docker-socket-policy`; `""` = the proxy's own group) |

> **Unix socket security boundary**: the proxy listens on a Unix socket only,
> in all three implementations. Access control is the file permissions and Unix
> group on that socket — a caller is authorised because it can `connect(2)` to
> it. A TCP listener carries no peer identity, so anything able to reach the
> port would be implicitly trusted; there is no `--listen-tcp`.
>
> The same rule applies outbound: all three implementations connect to the
> Docker daemon over Unix sockets exclusively and reject `tcp://` and `http://`
> schemes for `--docker-host`.
>
> The socket works like `docker.sock`. It is always `0660`, whatever the
> ambient umask, and there is no flag to change the mode. `connect(2)` on a
> Unix socket needs **write** permission, so any other mode either locks the
> group out or opens the socket to every local uid. The group is chosen the way
> dockerd chooses the `docker` group:
>
> | `--listen-socket-group` | Group exists | Socket group |
> |---|---|---|
> | not passed | yes | `docker-socket-policy` |
> | not passed | no | the proxy's own group, with the warning `group docker-socket-policy not found, using the proxy's own group <gid>` |
> | `=name` | yes | that group |
> | `=name` | no | none: startup fails, exit 2 |
> | `=gid` | — | that gid, used as-is (no lookup). Digits only, `0-4294967294`; a larger value fails with exit 2 |
> | `=""` | — | the proxy's own group, no warning |
>
> To grant access, create the group once and add callers to it:
>
> ```bash
> groupadd --system docker-socket-policy
> usermod -aG docker-socket-policy alice
> ```
>
> For a container caller, give its user that group (`group_add:`) and
> bind-mount the socket in. To revoke access, remove the group membership. If
> the proxy cannot reach the daemon socket because of its own group
> permissions, requests surface as `403`.
>
> To give the socket a group other than its own, a non-root proxy must be a
> member of that group (`SupplementaryGroups=` / `group_add:`). Otherwise
> startup fails with exit 1 and the message `cannot give <path> to group <gid>:
> the proxy's user must be a member of it`. The proxy does not fall back to
> another group, because a group that exists was chosen on purpose.
>
> The socket is bound at `0600`, then given its group, and only then widened
> to `0660`. It is never reachable by the wrong group, even for a moment.
>
> **One instance per socket path.** At startup the proxy handles what it finds
> at the path as follows:
>
> - A stale socket (`connect(2)` is refused) is removed and replaced.
> - A live socket is refused with `<path> is in use by another process`, exit 1.
>   The proxy leaves that socket untouched.
> - A socket that fails `connect(2)` in any other way (for example `EACCES`)
>   is refused, and the proxy does not remove it.
> - Anything that is not a socket is refused, and the proxy does not remove it.
>
> The Go and Rust implementations also take an exclusive `flock` on
> `<path>.lock` (mode `0600`) before they touch the socket. They hold it for
> the life of the process. A second instance fails with `<path> is in use by
> another instance (lock <path>.lock held)`, exit 1. The kernel releases the
> lock on any exit, including `SIGKILL`, so a crash never leaves a stale lock.
> The `.lock` file stays next to the socket after shutdown. **Do not delete
> it**, especially while the proxy is running: deleting it lets a second
> instance take the socket. A `.lock` left by another uid (for example an
> earlier run as root on a persistent volume) makes startup fail with
> `opening lock …` and a permission-denied error, exit 1; delete that lock file only when
> no instance is running.
>
> *TypeScript exception:* Node has no `flock`, so the TypeScript
> implementation takes no lock and relies on the live-socket check alone. If
> two TypeScript instances start on the same path within the same few
> milliseconds, both can see the old socket as stale. The second one then
> removes the first one's new socket and binds its own, and the first keeps
> running but nothing can reach it. An instance that starts after another is
> already listening is still refused. Node also unlinks its socket path on
> close, so stopping the orphaned instance (the obvious remedy) deletes the
> surviving instance's live socket; restart the survivor afterwards. The same
> holds when a Go or Rust instance is the orphan in a race with TypeScript.
> This gap is tracked in
> [#46](https://github.com/ChainSafe/docker-socket-policy/issues/46).
>
> Group membership decides who can use the proxy, not which policy they get.
> Every caller of one socket can use every policy loaded behind it; see
> [Trust model](#trust-model) for what that means and how to separate callers.

### systemd Service

The proxy always creates its own socket. systemd socket activation
(`fd://`) is not supported, so the proxy never listens on a socket it did not
create. Run it as a plain service:

```bash
sudo groupadd --system docker-socket-policy   # skip if it already exists
sudo useradd --system --no-create-home -g docker-socket-policy docker-socket-policy
sudo usermod -aG docker-socket-policy alice   # grant a caller access
```

**`docker-socket-policy.service`**:
```ini
[Service]
ExecStart=/usr/local/bin/docker-socket-policy \
  --listen-socket=/run/docker-socket-policy/docker-socket-policy.sock \
  --docker-host=/var/run/docker.sock \
  --config-dir=/etc/docker-socket-policy/services \
  --log-file=/var/log/docker-socket-policy/audit.log
User=docker-socket-policy
Group=docker-socket-policy
# Reach the Docker daemon socket.
SupplementaryGroups=docker
# A non-root proxy cannot create files in /var/run; systemd creates this
# directory for it, owned by User=/Group=.
RuntimeDirectory=docker-socket-policy
RuntimeDirectoryMode=0755
LogsDirectory=docker-socket-policy
Restart=on-failure
NoNewPrivileges=true
```

`Group=docker-socket-policy` makes that group the proxy's own group, so it
can give the socket to it. `docker-socket-policy.sock.lock` is created next
to the socket in the same directory. Callers then use
`DOCKER_HOST=unix:///run/docker-socket-policy/docker-socket-policy.sock`.

To use a different group, pass `--listen-socket-group=<name>` and add that
group to `SupplementaryGroups=`. Otherwise startup fails with the
"must be a member of it" error.

## Trust model

**The listening socket is the trust boundary.** The proxy does not identify
callers. Anyone who can `connect(2)` to the socket, which means any member of
its group, can create containers under **every** policy loaded from that
proxy's `--config-dir`.

A policy is a per-service *template*, chosen by the `Image` of the request and,
when policies set `container_names`, by the container name. It fixes what a
container from that image may look like: volumes, network mode, env file, user,
CLI flags, and no other host access (`HostConfig` is default-deny, #88). A
policy says nothing about *who* may ask for it. A caller who names
`chainsafe/lodestar` gets the policy for that image, whichever service the
caller belongs to. Container names are routing, not access control: the caller
picks the name, so a caller who may use the beacon policy may also name a
container `validator` and get the validator policy. Covered names do bound
lifecycle actions: a caller can stop or remove only containers that some
policy behind the socket covers, not every container on the host. This is
intended, not a gap: callers on a
shared socket are all the same caller as far as the kernel can tell (for
example, several developers sharing one account), so no proxy-side check could
tell them apart.

That gives two supported layouts:

- **One trust domain, many services.** Put every policy the callers may use in
  one `--config-dir` behind one socket. The callers' privileges are the union
  of those policies. This is the normal layout when everyone with access is
  equally trusted, such as one team, or one shared account used by several
  developers.
- **Several trust domains on one host.** Run one proxy instance per domain,
  each with its own socket, its own group and a `--config-dir` holding only
  that domain's policies. Membership in one socket's group grants nothing on
  another: the kernel refuses the connection (`EACCES`) before the proxy reads
  a byte. This is the same model as `docker.sock`.

A systemd template unit runs one instance per domain. Create one group per
domain and put each domain's policies in `/etc/docker-socket-policy/<domain>/`:

```bash
sudo groupadd --system dsp-teama
sudo groupadd --system dsp-teamb
sudo usermod -aG dsp-teama alice   # alice can use team A's policies only
```

**`docker-socket-policy@.service`**:
```ini
[Service]
ExecStart=/usr/local/bin/docker-socket-policy \
  --listen-socket=/run/docker-socket-policy-%i/docker-socket-policy.sock \
  --listen-socket-group=dsp-%i \
  --docker-host=/var/run/docker.sock \
  --config-dir=/etc/docker-socket-policy/%i \
  --log-file=/var/log/docker-socket-policy/%i.log
User=docker-socket-policy
Group=dsp-%i
SupplementaryGroups=docker
RuntimeDirectory=docker-socket-policy-%i
RuntimeDirectoryMode=0755
LogsDirectory=docker-socket-policy
Restart=on-failure
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now docker-socket-policy@teama docker-socket-policy@teamb
```

`Group=dsp-%i` makes each domain's group the instance's own group, so the
instance can give its socket to that group. Team A's callers use
`DOCKER_HOST=unix:///run/docker-socket-policy-teama/docker-socket-policy.sock`.
Putting that line in the shared account's shell profile means nobody has to
switch sockets by hand.

The proxy does not authenticate individual people, and its audit log records
requests and decisions, not who sent them. If several developers share one
account, tell them apart at login (for example by SSH key, in the SSH log),
not at the socket.

## Formal Verification

This project includes a [Quint](https://quint-lang.org/) formal specification that models the security invariants as a state machine. Random-simulation verification runs 10,000 sampled traces of up to 100 steps each, checking all 12 invariants on every state transition, among them that every create used the one policy matching its image and name ([#85](https://github.com/ChainSafe/docker-socket-policy/issues/85)). The same file models the create check on `HostConfig` ([#88](https://github.com/ChainSafe/docker-socket-policy/issues/88)): the default-deny field rules, `Mounts`, bind options and read-only volumes, and the case-insensitive field names the daemon accepts; its properties are checked exhaustively over every single-field, single-bind and single-mount request of the model, and instance `create_pre88` shows that they failed before the fix. A second module, `spec/listener.qnt`, models listening-socket startup (group selection, existing-path checks, the single-instance lock) with 6 more invariants. A third module, `spec/router.qnt`, models the router's denies for writes under `--readonly` ([#75](https://github.com/ChainSafe/docker-socket-policy/issues/75)), percent-encoded paths ([#53](https://github.com/ChainSafe/docker-socket-policy/issues/53)), empty interior segments ([#55](https://github.com/ChainSafe/docker-socket-policy/issues/55)), dot segments ([#70](https://github.com/ChainSafe/docker-socket-policy/issues/70)), exec ([#49](https://github.com/ChainSafe/docker-socket-policy/issues/49)) and attach ([#76](https://github.com/ChainSafe/docker-socket-policy/issues/76)), the GET/HEAD-only read passthrough ([#78](https://github.com/ChainSafe/docker-socket-policy/issues/78)), the `POST /containers/create` route, container-name extraction and the container-lifecycle branch with the daemon lookup that limits it to covered containers ([#86](https://github.com/ChainSafe/docker-socket-policy/issues/86)), not the full routing table ([#24](https://github.com/ChainSafe/docker-socket-policy/issues/24), [#48](https://github.com/ChainSafe/docker-socket-policy/issues/48)). Its 13 properties are checked exhaustively over the methods `GET`, `HEAD`, `POST`, `DELETE` and every path of 1 to 3 segments over the model's word set; exec is denied by the router, not by a middleware gate.

The request-handling spec also has a module, `network_endpoints_model`, for the endpoint entries under a forced `network_mode` ([#87](https://github.com/ChainSafe/docker-socket-policy/issues/87)). Its 3 properties (extra networks are denied, an allowed create names no network but the forced one, and every allowed create starts) are checked over five network modes and every endpoint map over seven keys; `network_endpoints_pre87` shows all three failing before the fix.

The CI pipeline runs verification on every push and PR. A violation blocks the build.

```bash
make typecheck            # Quint type-check (proves type safety)
make verify               # Random-simulation verification (default evaluator)
make verify BACKEND=rust  # Same, using the faster Rust backend
make test-spec            # Quint `run` tests for listener.qnt, router.qnt, network_endpoints, the create model and policy selection (one per table row)
make validate             # All checks: typecheck + verify + go vet + go test
```

See `spec/README.md` for details on the invariants, the middleware gate each maps to, and the attack scenarios each prevents.

## License

Apache 2.0
