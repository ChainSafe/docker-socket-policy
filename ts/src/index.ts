import { createServer } from "node:http";
import { AuditLogger } from "./audit.js";
import { Chain } from "./middleware.js";
import { Manager } from "./policy.js";
import { Router } from "./proxy.js";
import { Handler } from "./handler.js";
import { Transport } from "./transport.js";
import { getFlag, hasFlag, parseHostPort, parseSocketPath } from "./flags.js";

const args = process.argv.slice(2);

const dockerHost = getFlag(args, "--docker-host", "/var/run/docker.sock");
const socketPathError = parseSocketPath(dockerHost);
if (socketPathError) {
  console.error(socketPathError);
  process.exit(2);
}
const listenTCP = getFlag(args, "--listen-tcp", "127.0.0.1:2375");
const { host: listenHost, port: listenPort } = parseHostPort(listenTCP, "127.0.0.1");
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

server.listen(listenPort, listenHost, () => {
  console.log(`listening on ${listenHost}:${listenPort}`);
});

function shutdown(signal: string) {
  console.log(`received ${signal}, shutting down...`);
  server.close(() => {
    console.log("server closed");
    process.exit(0);
  });
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
