import { createServer } from "node:http";
import { lstatSync, unlinkSync } from "node:fs";
import { AuditLogger } from "./audit.js";
import { Chain } from "./middleware.js";
import { Manager } from "./policy.js";
import { Router } from "./proxy.js";
import { Handler } from "./handler.js";
import { Transport } from "./transport.js";
import {
  getFlag,
  hasFlag,
  parseListenSocket,
  parseSocketPath,
  validateFlags,
} from "./flags.js";

const args = process.argv.slice(2);

const VALUE_FLAGS = ["--listen-socket", "--docker-host", "--config-dir", "--log-file"];
const BOOL_FLAGS = ["--readonly"];

const flagError = validateFlags(args, VALUE_FLAGS, BOOL_FLAGS);
if (flagError) {
  console.error(flagError);
  process.exit(2);
}

const dockerHost = getFlag(args, "--docker-host", "/var/run/docker.sock");
const socketPathError = parseSocketPath(dockerHost);
if (socketPathError) {
  console.error(socketPathError);
  process.exit(2);
}
const listenSocket = getFlag(args, "--listen-socket", "/var/run/docker-socket-policy.sock");
const listenTarget = parseListenSocket(listenSocket);
if (listenTarget.kind === "error") {
  console.error(listenTarget.message);
  process.exit(2);
}
const configDir = getFlag(args, "--config-dir", "/etc/docker-socket-policy/services");
const logFile = getFlag(args, "--log-file", "/var/log/docker-socket-policy.log");
const readonly = hasFlag(args, "--readonly");

console.log(`loading policies from ${configDir}...`);

const policyManager = new Manager(configDir);
console.log(`loaded ${policyManager.list().length} policies`);

const router = new Router(policyManager);
const chain = new Chain(readonly);
const audit = new AuditLogger(logFile);
const transport = new Transport(dockerHost);
const handler = new Handler(router, chain, audit, transport);

const server = createServer((req, res) => {
  handler.handle(req, res).catch((err) => {
    console.error("handler error:", err);
    res.writeHead(500);
    res.end("internal server error");
  });
});

// A bind failure leaves the process with no listener at all, so it is fatal.
// This handler is scoped to the bind: net.Server also emits "error" for accept
// failures (EMFILE and friends), and exiting on those would let any caller kill
// the proxy — Go retries them and Rust backs off, so exiting would be a
// TypeScript-only availability regression.
const onBindError = (err: NodeJS.ErrnoException) => {
  console.error(`failed to bind ${listenSocket}: ${err.message}`);
  process.exit(1);
};
server.once("error", onBindError);
server.once("listening", () => {
  server.off("error", onBindError);
  server.on("error", (err) => console.error(`server error: ${err.message}`));
});

if (listenTarget.kind === "fd") {
  // systemd socket activation: the socket is already bound and listening,
  // so we adopt the fd rather than binding a path ourselves.
  const fd = listenTarget.fd;
  server.listen({ fd }, () => {
    // Node hands back whatever the fd actually is. A unit with
    // ListenStream=127.0.0.1:2375 yields a TCP server, which would silently
    // reinstate the TCP listener this proxy does not have. address() returns
    // a string for a Unix socket and an object for TCP.
    if (typeof server.address() !== "string") {
      console.error(
        `fd ${fd} is not a Unix socket: set ListenStream to a filesystem path ` +
          `in the .socket unit`,
      );
      process.exit(1);
    }
    console.log(`listening on socket-activated fd ${fd}`);
  });
} else {
  // Remove a stale socket left by a previous run, but only a socket: blindly
  // unlinking would let a mistyped path silently delete an operator's file.
  const path = listenTarget.path;
  try {
    if (!lstatSync(path).isSocket()) {
      console.error(`refusing to remove ${path}: not a socket`);
      process.exit(1);
    }
    unlinkSync(path);
  } catch (err) {
    const e = err as NodeJS.ErrnoException;
    if (e.code !== "ENOENT") {
      console.error(`failed to remove stale socket ${path}: ${e.message}`);
      process.exit(1);
    }
  }
  server.listen(path, () => {
    console.log(`listening on unix socket ${path}`);
  });
}

function shutdown(signal: string) {
  console.log(`received ${signal}, shutting down...`);
  server.close(() => {
    console.log("server closed");
    process.exit(0);
  });
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
