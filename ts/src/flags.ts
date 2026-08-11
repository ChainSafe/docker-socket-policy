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

// Parses a "host:port" listen address (the form Go's net.Listen and Rust's
// bind accept) into the (host, port) pair that Node's http.Server.listen
// requires. A bare port string defaults to binding all interfaces.
export function parseHostPort(
  input: string,
  defaultHost = "0.0.0.0",
): { host: string; port: number } {
  const colon = input.lastIndexOf(":");
  if (colon === -1) {
    return { host: defaultHost, port: parseInt(input, 10) };
  }
  return { host: input.slice(0, colon), port: parseInt(input.slice(colon + 1), 10) };
}