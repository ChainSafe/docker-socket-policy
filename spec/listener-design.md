# Listening socket: dockerd parity, Unix path only

Date: 2026-09-29
Status: approved 2026-09-29
Supersedes: #29, #44 (both resolved by removing `fd://`)

## Goal

Operating the proxy's listening socket should work like operating
`docker.sock`: the socket is always `0660`, owned by a well-known group, and
access is granted or revoked with group membership alone
(`usermod -aG docker-socket-policy alice`). No socket configuration beyond
that.

No code path may listen on anything but a Unix socket file the proxy created
itself.

## Why

- `--listen-tcp` was removed in #35, but `--listen-socket=fd://3` still
  adopts whatever systemd passes, and `ListenStream=127.0.0.1:2375` hands over
  a TCP socket. Keeping TCP out depends on a per-language guard, and #44 showed
  one of those guards rejecting every socket, including valid ones. Removing
  `fd://` removes the whole class instead of hardening it (#29).
- `--listen-socket-mode` exists only to let operators choose a mode, and every
  mode but `0660` is either useless (connect needs write) or dangerous
  (world-writable). dockerd has no such flag.
- Our own compose file already shows `--listen-socket-group` is redundant when
  the proxy runs as `user: uid:gid`: `bind(2)` gives the socket the process's
  group anyway.

## Behaviour

### Flags

| Flag | Change |
|---|---|
| `--listen-socket <path>` | Unchanged, except `fd://…` is now rejected like any other non-path value ("only supports Unix socket paths"). |
| `--listen-socket-mode` | **Removed.** Passing it is an unknown-flag error (exit 2). |
| `--listen-socket-group` | Kept (the name has shipped in v0.2.21). Semantics below. |

### Group selection (mirrors `moby/daemon/listeners/listeners_linux.go`)

Default group name: `docker-socket-policy`.

| `--listen-socket-group` | group resolves | outcome |
|---|---|---|
| not passed | yes | socket group = `docker-socket-policy` |
| not passed | no | warn `group docker-socket-policy not found, using the proxy's own group <gid>`; socket group = process egid; start |
| `=name` or `=gid` | yes | socket group = that group |
| `=name` or `=gid` | no | error, exit 2 |
| `=""` | — | socket group = process egid, no warning |

Resolution is unchanged from #40: Go `os/user.LookupGroup` / numeric,
Rust `getgrnam_r` / numeric, TypeScript parses `/etc/group` / numeric.

The warning is emitted on every container start where the group does not
exist, exactly as dockerd does. Accepted as the cost of parity.

If `chown` to the selected group fails with `EPERM` (a non-root proxy that
is not a member of that group), startup fails, exit 1, with a message naming
the group and saying the proxy's user must be a member of it
(`SupplementaryGroups=` / `group_add:`). It does not fall back: a group that
exists was chosen deliberately.

### Mode

Always `0660`. Creation order stays as #40 established it: `umask(0177)`
around `bind(2)` (socket born `0600`), then `chown`, then `chmod 0660`, so the
socket is never reachable by the wrong group and never at the ambient mode.
The world-writable rejection goes away with the flag, since nothing can
request a mode.

### Single-instance lock (Go, Rust)

Before touching the socket path, Go and Rust open `<path>.lock`
(`O_CREAT|O_RDWR|O_CLOEXEC`, mode `0600`) and take
`flock(LOCK_EX|LOCK_NB)`. The fd is held for the life of the process and
the kernel releases it on any exit, including `SIGKILL`, so a crash never
leaves a stale lock behind. The lock file is **never unlinked**: unlinking
a lock file reopens the same race it exists to close.

- `EWOULDBLOCK` → error `<path> is in use by another instance (lock <path>.lock held)`, exit 1.
- Any other open or lock error → error naming it, exit 1.

This replaces dockerd's pidfile. Unlike a pidfile, it needs no PID check,
so it also works across PID namespaces (two containers sharing a socket
volume).

### Existing path at startup

These checks run after the lock is taken (Go, Rust) and without a lock
(TypeScript):

| What is at the path | outcome |
|---|---|
| nothing | bind |
| a socket, `connect(2)` → `ECONNREFUSED` | stale: unlink, bind (current behaviour) |
| a socket, `connect(2)` succeeds | **new:** error `<path> is in use by another process`, exit 1; the live socket is left untouched |
| a socket, any other `connect(2)` error (e.g. `EACCES`) | **new:** error naming the errno, exit 1; not unlinked |
| not a socket | error, not unlinked (current behaviour) |

The connect check stays in Go and Rust even though they hold the lock.
It still catches an instance that doesn't take the lock: v0.2.21 and
earlier, a TypeScript instance, or an unrelated process.

Verified on main (2026-09-29): a stale `0777` socket is recreated at `0660`
in all three, but a second instance on a live path unlinks the first
instance's socket and takes it over silently.

### TypeScript exception (documented gap)

Node has no `flock`: checked on Node 22, `fs.flock` is undefined and there
is no `fcntl` locking and no `O_EXLOCK` on Linux. TypeScript therefore relies
on the connect check alone. That leaves a check-then-unlink race:

1. A connects: refused, so the socket is stale.
2. B connects: refused, so the socket is stale.
3. A unlinks and binds. A is now live.
4. B unlinks A's live socket and binds. A is left running with nothing able to reach it.

A second instance that starts once the first is already listening is still
refused. The race needs two TypeScript instances starting within the same
few milliseconds on the same path. A Go or Rust instance starting alongside
a TypeScript one is covered only on the Go/Rust side: the TypeScript side
takes no lock.

This is a deliberate departure from the equal-peers rule, recorded in:

- `README.md`: a note beside the socket section saying TypeScript doesn't
  take the single-instance lock, and describing the race.
- A code comment at the TypeScript bind site that points at the follow-up
  issue.
- A follow-up issue, `Type: Enhancement`, TypeScript only: "TypeScript:
  single-instance lock for the listening socket". It describes what closing
  the gap needs:
  - **Preferred:** an in-repo N-API addon (about 30 lines of C) that exposes
    `flock(fd, LOCK_EX|LOCK_NB)`, with no npm dependency. It requires
    `ts/Dockerfile` to compile the addon: drop `--ignore-scripts` for that
    one package, or build it in an explicit step, on `stagex/pallet-nodejs`
    or a StageX C-toolchain stage. `make verify-reproducible-ts` must stay
    bit-for-bit reproducible.
  - **Rejected alternatives** and why: an `fs-ext`-style npm addon (an
    external dependency built by install scripts); calling `flock(1)` from a
    shell (util-linux isn't in the image); an abstract-namespace lock socket
    (Linux only, and scoped to a network namespace, so two containers
    sharing a socket volume would not see each other's lock); a lock-free
    `link`/`rename` protocol (it can still orphan a socket with three
    instances, and a live socket briefly vanishes while it's being put back).
  - **Done when:** the Quint `lockHeld = true` configuration covers
    TypeScript too, and TypeScript passes the same unit and integration
    concurrency tests as Go and Rust.

### Removed

- `fd://3` socket activation: `listenerFromFile` (Go),
  `unix_listener_from_raw_fd` and `SYSTEMD_SOCKET_FD` (Rust), the `fd` listen
  target (TS), the `fd://3` exemption in `unlink_listen_socket` (Rust), and
  their tests.
- `--listen-socket-mode`: `parseSocketMode` / `parse_socket_mode`,
  `DEFAULT_LISTEN_SOCKET_MODE`, world-writable check, and their tests.

## Files

- `go/main.go`, `go/main_test.go`
- `rs/src/main.rs`
- `ts/src/flags.ts`, `ts/src/flags.test.ts`, `ts/src/listen.ts`,
  `ts/src/listen.test.ts`, `ts/src/index.ts`
- `deploy/docker-compose.sock.yml`, `deploy/test-sock.sh`
- `README.md`: flag table, security note, replace "Systemd Socket
  Activation" with a plain `.service` using `Group=` /
  `SupplementaryGroups=` and the `groupadd` / `usermod -aG` workflow
- `.opencode/memory/project.md`
- `spec/listener.qnt` (new), `spec/README.md`, `Makefile`,
  `.github/workflows/ci.yml`

## Formal specification

`spec/docker_socket_policy.qnt` models request handling only. The listener
gets its own module, `spec/listener.qnt`, so the existing model and its
simulation are unchanged.

### Model

- **Configuration:** a nondeterministic `--listen-socket` value drawn from a
  Unix path, `fd://3`, `tcp://0.0.0.0:2375` and `http://…`, plus
  `--listen-socket-group` (not passed, existing group, missing group, `""`).
- **Filesystem at the path:** absent, stale socket, live socket owned by
  another instance, regular file.
- **Instances:** `I1`, `I2`, `I3`. Each moves through
  `lock → probe → unlink → bind(0600) → chown → chmod(0660) → serving`,
  **one step per transition**, so the steps of different instances can
  interleave. An instance can crash at any step: the kernel releases its
  lock, and its socket file stays behind as stale.
- **Constant `lockHeld: bool`:** `true` models Go and Rust; `false` models
  TypeScript, where the lock step does nothing.

### Invariants (checked with `lockHeld = true`)

| Invariant | Statement |
|---|---|
| `neverListensOnTcp` | no instance reaches `serving` unless the configuration was a Unix path |
| `groupBeforeMode` | the socket is never group-accessible while its group differs from the selected group |
| `neverWorldWritable` | the socket's mode never has the `o+w` bit in any state |
| `neverUnlinksNonSocket` | a regular file at the path is never removed |
| `noLiveTakeover` | a serving instance's socket is never unlinked by another instance |
| `groupSelectionMatchesTable` | the selected group matches the group-selection table for every configuration |

`allListenerInvariants` is their conjunction.

### Tests (`quint test`)

- One `run` per row of the group-selection and existing-path tables. Each
  has a matching unit test in Go, Rust and TypeScript with the same name, so
  every row can be traced across all four.
- `raceWithoutLockTest` sets `lockHeld = false` and replays the four-step
  interleaving above, asserting that it ends with I1 serving on a socket
  that is no longer at the path. This is the formal record of the
  TypeScript gap. The follow-up issue turns it into a `lockHeld = true`
  requirement for TypeScript.

### Wiring

- `make typecheck` type-checks both modules.
- `make verify` also runs
  `quint run --invariants allListenerInvariants spec/listener.qnt`, with
  `lockHeld = true`.
- New target `make test-spec` runs `quint test spec/listener.qnt`.
- The CI quint job adds `make test-spec`. CI runs no `quint test` today.
- `spec/README.md`: update the invariant count, add a listener coverage
  table, and add a Modeling Note saying the model checks the design, not
  the code. Conformance of the three implementations rests on their unit
  and integration tests, which share names with the Quint `run`s.

Before relying on `noLiveTakeover`, it must be shown to **fail** with
`lockHeld = false` under `quint run`, so that it demonstrably fails when the
protection is missing. The counterexample trace goes in the PR.

## Testing

Unit, in all three languages, same cases:

- `fd://3` rejected as a non-path value.
- `--listen-socket-mode` rejected as unknown.
- Group table: default missing → own gid + warning; explicit missing → error;
  `""` → own gid, no warning; explicit numeric → that gid.
- Existing path: stale socket replaced at `0660`; live socket refused and
  left in place (same inode, first listener still answers); non-socket
  refused.
- Lock (Go, Rust): a second instance fails with "in use by another
  instance" while the first holds the lock, including when the socket
  file has been deleted by hand. After the first instance is killed with
  `SIGKILL`, a new instance starts, which shows the lock doesn't go stale.
  `<path>.lock` is `0600` and still exists after a clean shutdown.
- Concurrency (Go, Rust): start N=8 instances on the same path at once.
  Exactly one serves, the rest exit 1, and the socket at the path belongs
  to the one that serves. Repeat 50 times. TypeScript is not held to this
  test and the gap is documented; its test is written but skipped, and
  references the follow-up issue.

Integration (`deploy/docker-compose.sock.yml`), run for Go, Rust, TS:

- `proxy-granted` and `proxy-denied` drop both socket flags and rely on
  `user: 65532:<gid>` → exercises the "default group missing" fallback.
  Assertions unchanged: `660`, group `2001`, granted 200 / denied 403.
- New `proxy-default-group`: runs as `65532:65532` with `group_add: [2001]`
  and a bind-mounted `/etc/group` defining `docker-socket-policy:x:2001:`, and
  passes no socket flags → socket must come out `660` group `2001`. This is the
  dockerd-style path.

Every new test is checked to fail without its change. Native check on macOS
and in a Linux container: stale socket, live socket, default-group-present.

## Delivery

One issue (`Type: Enhancement`, `Status: Break Change`), one branch
`feat/dockerd-socket-parity`, one PR titled `feat!:` with a
`BREAKING CHANGE:` footer listing the removed flag and `fd://3`. Closes the new
issue, #29 and #44. PR #43 is independent.

The TypeScript lock follow-up is filed at the same time. The PR links to it
without closing it.
