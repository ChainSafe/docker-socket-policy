# docker-socket-policy

[![CI](https://github.com/ChainSafe/docker-socket-policy/actions/workflows/ci.yml/badge.svg)](https://github.com/ChainSafe/docker-socket-policy/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/ChainSafe/docker-socket-policy)](https://github.com/ChainSafe/docker-socket-policy/releases/latest)
[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8)](https://go.dev)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A validating Docker API proxy that enforces **per-service policies** through a middleware pipeline. Designed for granting safe, audited Docker access to external contributors, CI/CD pipelines, and automated tooling — without giving them direct Docker daemon access.

Key features:

- **Policy-driven**: Per-service YAML policies control images, volumes, flags, and env vars
- **Middleware pipeline**: 6 validation gates + 1 config mutator chain
- **Default-deny router**: Only explicitly allowed endpoints pass through
- **Formally verified**: [Quint](https://quint-lang.org/) specification with 9 security invariants
- **Audit logging**: JSON-structured logs for all requests and decisions
- **Three implementations**: [Go](go/), [Rust](rs/), [TypeScript](ts/) — equal peer languages
- **Minimal dependencies**: Zero external deps for Go, crate-based for Rust, npm for TypeScript

## Installation

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

Each [release](https://github.com/ChainSafe/docker-socket-policy/releases/latest) attaches a Go binary, a Rust binary, and a TypeScript build archive (plus SBOMs for each):

```bash
# Go (statically linked binary)
curl -LO https://github.com/ChainSafe/docker-socket-policy/releases/latest/download/docker-socket-policy-go
chmod +x docker-socket-policy-go

# TypeScript (Node 22+ required; archive includes dist/ and node_modules/)
# Replace <version> with the tag shown on the releases page, e.g. v0.2.8
curl -LO https://github.com/ChainSafe/docker-socket-policy/releases/latest/download/docker-socket-policy-ts-<version>.tar.gz
tar xzf docker-socket-policy-ts-<version>.tar.gz && node dist/index.js
```

The Rust binary is also attached to every release; see the release page for the exact asset name.

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
| Go | [go/](go/) | 74 unit + 26 integration | stdlib net/http + yaml.v3 |
| Rust | [rs/](rs/) | 112 unit | tokio, hyper, serde, clap |
| TypeScript | [ts/](ts/) | 108 unit | Node 22 ESM, built-in http |

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
./docker-socket-policy \
  --listen-socket=/var/run/docker-socket-policy.sock \
  --docker-host=/var/run/docker.sock \
  --config-dir=./config \
  --log-file=/tmp/docker-socket-policy.log
```

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

## Configuration

### CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--listen-socket` | `/var/run/docker-socket-policy.sock` | Unix socket (or `fd://3` for systemd). **Go/Rust only** |
| `--listen-tcp` | `127.0.0.1:2375` | TCP listen address |
| `--docker-host` | `/var/run/docker.sock` | Docker daemon socket path (Unix socket only) |
| `--config-dir` | `/etc/docker-socket-policy/services` | Policy config directory |
| `--log-file` | `/var/log/docker-socket-policy.log` | Audit log path |
| `--readonly` | `false` | Enable read-only mode |

> The TypeScript implementation listens on TCP only (`--listen-tcp`); it does not
> implement `--listen-socket`. All three implementations connect to the Docker
> daemon over a Unix socket only: Go and Rust treat `--docker-host` as a Unix
> socket path, and TypeScript additionally rejects `tcp://`/`http://` schemes
> outright. Connecting to the daemon over TCP would bypass the socket's
> user/group ownership, which is the security boundary.

### Systemd Socket Activation

**`docker-socket-policy.socket`**:
```ini
[Socket]
ListenStream=/var/run/docker-socket-policy.sock
SocketMode=0660
SocketGroup=builders
ListenStream=127.0.0.1:2375
```

**`docker-socket-policy.service`**:
```ini
[Service]
ExecStart=/usr/local/bin/docker-socket-policy \
  --listen-socket=fd://3 \
  --docker-host=/var/run/docker.sock \
  --config-dir=/etc/docker-socket-policy/services \
  --log-file=/var/log/docker-socket-policy.log
User=docker-socket-policy
Restart=on-failure
NoNewPrivileges=true
```

## Formal Verification

This project includes a [Quint](https://quint-lang.org/) formal specification that models the security invariants as a state machine. Random-simulation verification runs 10,000 sampled traces of up to 100 steps each, checking all 9 invariants on every state transition.

The CI pipeline runs verification on every push and PR. A violation blocks the build.

```bash
make typecheck            # Quint type-check (proves type safety)
make verify               # Random-simulation verification (default evaluator)
make verify BACKEND=rust  # Same, using the faster Rust backend
make validate             # All checks: typecheck + verify + go vet + go test
```

See `spec/README.md` for details on the invariants, the middleware gate each maps to, and the attack scenarios each prevents.

## License

Apache 2.0
