# docker-socket-policy

[![CI](https://github.com/ChainSafe/docker-socket-policy/actions/workflows/ci.yml/badge.svg)](https://github.com/ChainSafe/docker-socket-policy/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8)](https://go.dev)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A validating Docker API proxy that enforces **per-service policies** through a middleware pipeline. Designed for granting safe, audited Docker access to external contributors, CI/CD pipelines, and automated tooling — without giving them direct Docker daemon access.

Key features:

- **Policy-driven**: Per-service YAML policies control images, volumes, flags, and env vars
- **Middleware pipeline**: 6 validation gates + 1 config mutator chain
- **Default-deny router**: Only explicitly allowed endpoints pass through
- **Formally verified**: [Quint](https://quint-lang.org/) specification with 8 security invariants
- **Audit logging**: JSON-structured logs for all requests and decisions
- **Zero dependencies**: Single Go binary, no runtime requirements

## Architecture

```
Docker CLI → docker-socket-policy (middleware chain) → Docker daemon
                │
                ├── Mutators: modify request (force container config)
                ├── Gates: validate request (image refs, volumes, flags)
                └── Proxy: forward allowed requests to daemon
```

## Quick Start

### Build

```bash
go build -o docker-socket-policy .

# Validate everything (typecheck, verify, vet, test)
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
| `--listen-socket` | `/var/run/docker-socket-policy.sock` | Unix socket (or `fd://3` for systemd) |
| `--listen-tcp` | `127.0.0.1:2375` | TCP listen address |
| `--docker-host` | `/var/run/docker.sock` | Docker daemon socket path |
| `--config-dir` | `/etc/docker-socket-policy/services` | Policy config directory |
| `--log-file` | `/var/log/docker-socket-policy.log` | Audit log path |
| `--readonly` | `false` | Enable read-only mode |

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

This project includes a [Quint](https://quint-lang.org/) formal specification that models the security invariants as a state machine. Random-simulation verification runs 10,000 traces across 100+ steps each, checking all 8 invariants on every state transition.

The CI pipeline runs verification on every push and PR. A violation blocks the build.

```bash
make typecheck   # Quint type-check (proves type safety)
make verify      # Random-simulation verification (Rust backend, 2,400+ traces/sec)
make validate    # All checks: typecheck + verify + go vet + go test
```

See `spec/README.md` for details on the invariants, the middleware gate each maps to, and the attack scenarios each prevents.

## License

Apache 2.0
