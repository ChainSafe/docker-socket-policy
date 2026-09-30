import { createServer } from "node:http";
import { lstatSync, unlinkSync } from "node:fs";
import { AuditLogger } from "./audit.js";
import { Chain } from "./middleware.js";
import { Manager } from "./policy.js";
import { Router } from "./proxy.js";
import { Handler } from "./handler.js";
import { Transport } from "./transport.js";
import { createShutdown } from "./shutdown.js";
import { listenOnSocket } from "./listen.js";
import {
  BOOL_FLAGS,
  getFlag,
  hasFlag,
  parseListenSocket,
  parseSocketPath,
  resolveGroup,
  SOCKET_MODE,
  validateFlags,
  VALUE_FLAGS,
} from "./flags.js";

const args = process.argv.slice(2);

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
const groupFlag = getFlag(args, "--listen-socket-group", "");
let socketGid: number | undefined;
if (groupFlag !== "") {
  const resolved = resolveGroup(groupFlag);
  if ("error" in resolved) {
    console.error(resolved.error);
    process.exit(2);
  }
  socketGid = resolved.gid;
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
listenOnSocket(server, path, socketGid).then(
  () => {
    console.log(
      `listening on unix socket ${path} (mode ${SOCKET_MODE.toString(8).padStart(4, "0")})`,
    );
  },
  (err: NodeJS.ErrnoException) => {
    console.error(`failed to listen on ${path}: ${err.message}`);
    process.exit(1);
  },
);

const shutdown = createShutdown(server);

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
