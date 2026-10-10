// Minimal CLI flag parser supporting both "--name value" and "--name=value"
// forms, matching Go's flag package and Rust's clap behavior.

import { readFileSync } from "node:fs";

export function getFlag(args: string[], name: string, defaultVal: string): string {
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

// The flags the proxy accepts, for validateFlags.
export const VALUE_FLAGS = ["--listen-socket", "--docker-host", "--config-dir", "--log-file", "--listen-socket-group"];
export const BOOL_FLAGS = ["--readonly"];

// Rejects anything not recognised. Go's flag package and Rust's clap both exit
// non-zero on an unrecognised argument; without this the hand-rolled parser
// above would silently ignore one. That matters most for flags this proxy
// deliberately no longer has: `--listen-tcp=0.0.0.0:2375` must be a loud
// failure, not a no-op that leaves the caller assuming it took effect.
//
// `valueFlags` take an argument (in either `--name value` or `--name=value`
// form); `boolFlags` do not, and must not swallow the following argument.
// Returns an error message, or null when every argument is recognised.
export function validateFlags(args: string[], valueFlags: string[], boolFlags: string[]): string | null {
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

// Where the proxy should listen. The proxy listens on a Unix socket only:
// filesystem ownership on that socket is the access-control boundary, and a
// TCP listener would carry no peer identity at all.
export type ListenTarget = { kind: "path"; path: string } | { kind: "error"; message: string };

// Parses --listen-socket, which must be an absolute filesystem path. Mirrors
// validateListenSocket in Go and validate_listen_socket in Rust.
export function parseListenSocket(input: string): ListenTarget {
  if (
    input.startsWith("fd://") ||
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

// Mode applied to the listening socket. connect(2) on an AF_UNIX socket
// requires write permission, so 0o660 is what actually grants the owning group
// access.
export const SOCKET_MODE = 0o660;

// Set around bind(2) so the socket is created at 0600 and is never briefly
// reachable by group or world. bind() applies 0777 & ~umask, and
// 0777 & ~0177 === 0600. Correcting with chmod afterwards would leave a window
// in which the socket is already listening at the ambient mode.
export const BIND_UMASK = 0o177;

export type GroupId = { gid: number } | { error: string };

// The group the socket is given when --listen-socket-group is not passed.
export const DEFAULT_SOCKET_GROUP = "docker-socket-policy";

// Picks the socket's group the way dockerd does
// (moby/daemon/listeners/listeners_linux.go). An undefined flag means the flag
// was not passed: the default group is used if it exists, and otherwise the
// proxy falls back to its own group with a warning. An explicit group that
// does not resolve is an error. An explicit "" selects the proxy's own group.
export function selectSocketGroup(
  flag: string | undefined,
  lookup: (name: string) => GroupId,
  egid: number,
): { gid: number; warning?: string } | { error: string } {
  if (flag === undefined) {
    const found = lookup(DEFAULT_SOCKET_GROUP);
    if ("error" in found) {
      return {
        gid: egid,
        warning: `group ${DEFAULT_SOCKET_GROUP} not found, using the proxy's own group ${egid}`,
      };
    }
    return { gid: found.gid };
  }
  if (flag === "") {
    return { gid: egid };
  }
  return lookup(flag);
}

const MAX_SOCKET_GID = 4294967294;

// Maps --listen-socket-group to a gid. A numeric value is used as-is so a
// deployment without the group defined can still be configured.
//
// Node exposes no getgrnam equivalent, so a name is resolved by reading
// /etc/group. That covers the container case this proxy targets but not
// NSS-backed directories (LDAP, SSSD) — pass a numeric gid for those. Go uses
// os/user.LookupGroup and Rust uses getgrnam_r, both of which do consult NSS.
export function resolveGroup(input: string, groupFile = "/etc/group"): GroupId {
  if (/^\d+$/.test(input)) {
    // 4294967295 is chown's "don't change" sentinel. BigInt keeps a long
    // digit string exact, where parseInt would round it.
    if (BigInt(input) > BigInt(MAX_SOCKET_GID)) {
      return {
        error: `--listen-socket-group ${JSON.stringify(input)}: gid out of range (0-${MAX_SOCKET_GID})`,
      };
    }
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
