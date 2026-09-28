// Minimal CLI flag parser supporting both "--name value" and "--name=value"
// forms, matching Go's flag package and Rust's clap behavior.

import { readFileSync } from "node:fs";

export function getFlag(
  args: string[],
  name: string,
  defaultVal: string,
): string {
  const prefix = name + "=";
  for (let i = 0; i < args.length; i++) {
    if (args[i] === name && i + 1 < args.length) return args[i + 1];
    if (args[i].startsWith(prefix)) return args[i].slice(prefix.length);
  }
  return defaultVal;
}

export function hasFlag(args: string[], name: string): boolean {
  const prefix = name + "=";
  return args.includes(name) || args.some((a) => a.startsWith(prefix));
}

// Rejects anything not recognised. Go's flag package and Rust's clap both exit
// non-zero on an unrecognised argument; without this the hand-rolled parser
// above would silently ignore one. That matters most for flags this proxy
// deliberately no longer has: `--listen-tcp=0.0.0.0:2375` must be a loud
// failure, not a no-op that leaves the caller assuming it took effect.
//
// `valueFlags` take an argument (in either `--name value` or `--name=value`
// form); `boolFlags` do not, and must not swallow the following argument.
// Returns an error message, or null when every argument is recognised.
export function validateFlags(
  args: string[],
  valueFlags: string[],
  boolFlags: string[],
): string | null {
  const known = [...valueFlags, ...boolFlags];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    const hasEquals = arg.includes("=");
    const name = hasEquals ? arg.slice(0, arg.indexOf("=")) : arg;

    if (!known.includes(name)) {
      if (arg.startsWith("-")) {
        return `unrecognised flag: ${name}\nsupported flags: ${known.join(", ")}`;
      }
      return `unexpected argument: ${arg}`;
    }
    if (valueFlags.includes(name)) {
      if (hasEquals) continue;
      if (i + 1 >= args.length) return `flag needs an argument: ${name}`;
      i++; // consume the value so it is not mistaken for an argument
    }
  }
  return null;
}

// Raw fd systemd passes for the first socket under socket activation
// (sd_listen_fds convention: fds start at 3).
export const SYSTEMD_SOCKET_FD = 3;

// Where the proxy should listen. The proxy listens on a Unix socket only:
// filesystem ownership on that socket is the access-control boundary, and a
// TCP listener would carry no peer identity at all.
export type ListenTarget =
  | { kind: "fd"; fd: number }
  | { kind: "path"; path: string }
  | { kind: "error"; message: string };

// Parses --listen-socket. "fd://3" selects systemd socket activation (the
// socket is already bound; we adopt the fd). Any other value is a filesystem
// path. Mirrors bindUnixListener in Go and bind_unix_listener in Rust.
export function parseListenSocket(input: string): ListenTarget {
  if (input === `fd://${SYSTEMD_SOCKET_FD}`) {
    return { kind: "fd", fd: SYSTEMD_SOCKET_FD };
  }
  if (input.startsWith("fd://")) {
    return {
      kind: "error",
      message: `--listen-socket only supports fd://${SYSTEMD_SOCKET_FD} for socket activation, got: ${input}`,
    };
  }
  if (
    input.startsWith("tcp://") ||
    input.startsWith("http://") ||
    input.startsWith("https://") ||
    input.startsWith("unix://")
  ) {
    return {
      kind: "error",
      message: `--listen-socket only supports Unix socket paths, got: ${input}`,
    };
  }
  if (input.startsWith("@") || input.startsWith("\0")) {
    return {
      kind: "error",
      message:
        `--listen-socket must be a filesystem path; abstract sockets have no permissions ` +
        `and would be reachable by any process, got: ${input}`,
    };
  }
  if (input.length > 0 && !input.startsWith("/")) {
    return {
      kind: "error",
      message: `--listen-socket must be an absolute path, got: ${input}`,
    };
  }
  if (input.length === 0) {
    return { kind: "error", message: "--listen-socket must not be empty" };
  }
  return { kind: "path", path: input };
}

// Mode applied to the listening socket when --listen-socket-mode is omitted.
// connect(2) on an AF_UNIX socket requires write permission, so 0o660 is what
// actually grants the owning group access.
export const DEFAULT_LISTEN_SOCKET_MODE = 0o660;

// Set around bind(2) so the socket is created at 0600 and is never briefly
// reachable by group or world. bind() applies 0777 & ~umask, and
// 0777 & ~0177 === 0600. Correcting with chmod afterwards would leave a window
// in which the socket is already listening at the ambient mode.
export const BIND_UMASK = 0o177;

export type SocketMode = { mode: number } | { error: string };

// Parses an octal mode and rejects anything world-writable. A world-writable
// socket is connectable by every local uid, which removes the boundary
// entirely, so there is deliberately no opt-out.
export function parseSocketMode(input: string): SocketMode {
  if (input.length === 0) {
    return { error: "--listen-socket-mode must not be empty" };
  }
  if (!/^[0-7]+$/.test(input)) {
    return { error: `--listen-socket-mode ${JSON.stringify(input)}: not an octal mode` };
  }
  const mode = parseInt(input, 8);
  if (mode > 0o777) {
    return { error: `--listen-socket-mode ${JSON.stringify(input)}: must be within 0777` };
  }
  if (mode & 0o002) {
    return {
      error:
        `--listen-socket-mode ${JSON.stringify(input)} is world-writable: every local user ` +
        `could connect to the proxy, which disables the access-control boundary`,
    };
  }
  return { mode };
}

export type GroupId = { gid: number } | { error: string };

// Maps --listen-socket-group to a gid. A numeric value is used as-is so a
// deployment without the group defined can still be configured.
//
// Node exposes no getgrnam equivalent, so a name is resolved by reading
// /etc/group. That covers the container case this proxy targets but not
// NSS-backed directories (LDAP, SSSD) — pass a numeric gid for those. Go uses
// os/user.LookupGroup and Rust uses getgrnam_r, both of which do consult NSS.
export function resolveGroup(input: string, groupFile = "/etc/group"): GroupId {
  if (/^\d+$/.test(input)) {
    return { gid: parseInt(input, 10) };
  }
  let contents: string;
  try {
    contents = readFileSync(groupFile, "utf8");
  } catch (err) {
    const e = err as NodeJS.ErrnoException;
    return {
      error: `--listen-socket-group ${JSON.stringify(input)}: cannot read ${groupFile}: ${e.message}`,
    };
  }
  for (const line of contents.split("\n")) {
    // name:password:gid:members
    const parts = line.split(":");
    if (parts.length >= 3 && parts[0] === input) {
      const gid = parseInt(parts[2], 10);
      if (Number.isNaN(gid)) {
        return {
          error: `--listen-socket-group ${JSON.stringify(input)}: gid ${JSON.stringify(parts[2])} is not numeric`,
        };
      }
      return { gid };
    }
  }
  return {
    error:
      `--listen-socket-group ${JSON.stringify(input)}: no such group in ${groupFile} ` +
      `(Node cannot query NSS; pass a numeric gid if the group is not in ${groupFile})`,
  };
}

// Validates a Docker daemon address supplied via --docker-host. Only Unix
// socket paths are accepted: connecting to the daemon over TCP would bypass
// the Linux user/group ownership on the socket, which is the security model
// of this proxy. Returns an error message when the value is unusable.
export function parseSocketPath(input: string): string | null {
  if (
    input.startsWith("tcp://") ||
    input.startsWith("http://") ||
    input.startsWith("https://") ||
    input.startsWith("unix://")
  ) {
    return `--docker-host only supports Unix socket paths, got: ${input}`;
  }
  if (input.length === 0) {
    return "--docker-host must not be empty";
  }
  return null;
}
