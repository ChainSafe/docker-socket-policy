import { createServer } from "node:http";
import { unlinkSync } from "node:fs";
import { AuditLogger } from "./audit.js";
import { Chain } from "./middleware.js";
import { Manager } from "./policy.js";
import { Router } from "./proxy.js";
import { Handler } from "./handler.js";
import { Transport } from "./transport.js";
import { getFlag, hasFlag, parseListenSocket, parseSocketPath } from "./flags.js";

const args = process.argv.slice(2);

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

// A bind failure leaves the process with no listener at all, so it is fatal
// rather than merely logged.
server.on("error", (err) => {
  console.error(`failed to bind ${listenSocket}: ${err.message}`);
  process.exit(1);
});

if (listenTarget.kind === "fd") {
  // systemd socket activation: the socket is already bound and listening,
  // so we adopt the fd rather than binding a path ourselves.
  server.listen({ fd: listenTarget.fd }, () => {
    console.log(`listening on socket-activated fd ${listenTarget.fd}`);
  });
} else {
  // Remove a stale socket file left by a previous run before binding,
  // matching the Go and Rust implementations.
  try {
    unlinkSync(listenTarget.path);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
  }
  server.listen(listenTarget.path, () => {
    console.log(`listening on unix socket ${listenTarget.path}`);
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
