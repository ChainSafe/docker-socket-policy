// Minimal CLI flag parser supporting both "--name value" and "--name=value"
// forms, matching Go's flag package and Rust's clap behavior.

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
