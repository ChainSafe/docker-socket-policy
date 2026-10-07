# docker-socket-policy

[![CI](https://github.com/ChainSafe/docker-socket-policy/actions/workflows/ci.yml/badge.svg)](https://github.com/ChainSafe/docker-socket-policy/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/ChainSafe/docker-socket-policy)](https://github.com/ChainSafe/docker-socket-policy/releases/latest)
[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8)](https://go.dev)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A validating Docker API proxy that enforces **per-service container policies** through a middleware pipeline. Designed for granting safe, audited Docker access to external contributors, CI/CD pipelines, and automated tooling — without giving them direct Docker daemon access.

Key features:

- **Policy-driven**: Per-service YAML policies, selected by image name, control images, volumes, flags, and env vars. The listening socket is the trust boundary: every caller of a socket can use every policy behind it (see [Trust model](#trust-model))
- **Middleware pipeline**: 6 validation gates + 1 config mutator chain
- **Default-deny router**: Only explicitly allowed endpoints pass through
- **Formally verified**: [Quint](https://quint-lang.org/) specification with 9 security invariants
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
| Go | [go/](go/) | 103 unit + 36 integration | stdlib net/http + yaml.v3 |
| Rust | [rs/](rs/) | 140 unit | tokio, hyper, serde, clap |
| TypeScript | [ts/](ts/) | 157 unit (1 skipped) | Node 22 ESM, built-in http |

### Build All

```bash
# Build all three language implementations
make build-all

# Run all tests (unit + integration)
make test-all

# Lint all three
make lint-all

# Full validation: typecheck + verify + vet + test (Go)
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
allowed_image_prefixes:
  - chainsafe/lodestar
container_config:
  network_mode: host
  restart_policy: unless-stopped
  security_options:
    - no-new-privileges:true
  user: '2001:2001'
volumes:
  - host_path: /home/beacon
    container_path: /data
    read_write: true
env_file: /home/beacon/beacon.env
allowed_cli_flags:
  - --rcConfig
  - --logLevel
denied_flags:
  - --privileged
  - --volume
  - --cap-add
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
```

## Middleware Pipeline

| Middleware | Type | What it checks |
|------------|------|----------------|
| ContainerConfigMutator | Mutator | Forces `network_mode`, `user`, `security_options`, `restart_policy` from policy |
| ExecGate | Gate | Denies `POST /containers/*/exec` and `POST /exec/*/start` |
| ReadonlyGate | Gate | Denies all `POST`, `PUT`, `DELETE`, `PATCH` (optional `--readonly` flag) |
| RegistryGate | Gate | Validates image ref against `allowed_image_prefixes` |
| MountSourceGate | Gate | Validates volume binds against whitelist |
| EnvFileGate | Gate | Strips `Env` field from create body; env must come from locked `env_file` |
| CmdGate | Gate | Validates each CLI flag in `Cmd` array against allowlist + denylist |

## Endpoint Access

| HTTP Method | Path | Action |
|-------------|------|--------|
| POST | `/containers/create` | Validated by middleware chain |
| POST | `/containers/{name}/start\|stop\|restart\|kill\|wait\|pause\|unpause` | Allowed on known containers |
| DELETE | `/containers/{name}` | Allowed on known containers |
| POST | `/containers/{name}/exec` | **DENIED** |
| POST | `/containers/{name}/rename\|update` | **DENIED** |
| POST | `/images/create` | Validated by registry gate |
| POST | `/auth` | **DENIED** |
| POST | `/build` | **DENIED** |
| POST | `/commit` | **DENIED** |
| GET/HEAD | Any | Allowed (read-only) |
| Other | Other | **DENIED** |

Any request whose path contains a percent-encoded byte (`%`) is denied with 403 for every method, GET and HEAD included, because the daemon decodes the path before routing. The query string is not inspected, so filters such as `docker ps --filter …` still work. A consequence is that networks whose names contain a space or `%` cannot be inspected or removed through the proxy.

## Configuration

### CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--listen-socket` | `/var/run/docker-socket-policy.sock` | Unix socket path to listen on (absolute filesystem path only) |
| `--docker-host` | `/var/run/docker.sock` | Docker daemon socket path (Unix socket only) |
| `--config-dir` | `/etc/docker-socket-policy/services` | Policy config directory |
| `--log-file` | `/var/log/docker-socket-policy.log` | Audit log path |
| `--readonly` | `false` | Enable read-only mode |
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

A policy is a per-service *template*, chosen by the `Image` of the request. It
fixes what a container from that image may look like: volumes, network mode,
env file, user, CLI flags. A policy says nothing about *who* may ask for it. A
caller who names `chainsafe/lodestar` gets the policy for that image, whichever
service the caller belongs to. This is intended, not a gap: callers on a
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

This project includes a [Quint](https://quint-lang.org/) formal specification that models the security invariants as a state machine. Random-simulation verification runs 10,000 sampled traces of up to 100 steps each, checking all 9 invariants on every state transition. A second module, `spec/listener.qnt`, models listening-socket startup (group selection, existing-path checks, the single-instance lock) with 6 more invariants. A third module, `spec/router.qnt`, models container-name extraction and the router's container-lifecycle routing branch only, not the full routing table ([#24](https://github.com/ChainSafe/docker-socket-policy/issues/24), [#48](https://github.com/ChainSafe/docker-socket-policy/issues/48)).

The CI pipeline runs verification on every push and PR. A violation blocks the build.

```bash
make typecheck            # Quint type-check (proves type safety)
make verify               # Random-simulation verification (default evaluator)
make verify BACKEND=rust  # Same, using the faster Rust backend
make test-spec            # Quint `run` tests for listener.qnt and router.qnt (one per table row)
make validate             # All checks: typecheck + verify + go vet + go test
```

See `spec/README.md` for details on the invariants, the middleware gate each maps to, and the attack scenarios each prevents.

## License

Apache 2.0
