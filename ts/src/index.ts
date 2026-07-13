import { createServer } from "node:http";
import { AuditLogger } from "./audit.js";
import { Chain } from "./middleware.js";
import { Manager } from "./policy.js";
import { Router } from "./proxy.js";
import { Handler } from "./handler.js";
import { Transport } from "./transport.js";

const args = process.argv.slice(2);

function getFlag(name: string, defaultVal: string): string {
  const idx = args.indexOf(name);
  return idx !== -1 && idx + 1 < args.length ? args[idx + 1] : defaultVal;
}

function hasFlag(name: string): boolean {
  return args.includes(name);
}

const listenTCP = getFlag("--listen-tcp", "127.0.0.1:2375");
const configDir = getFlag("--config-dir", "/etc/docker-socket-policy/services");
const logFile = getFlag("--log-file", "/var/log/docker-socket-policy.log");
const readonly = hasFlag("--readonly");

console.log(`loading policies from ${configDir}...`);

const policyManager = new Manager(configDir);
console.log(`loaded ${policyManager.list().length} policies`);

const router = new Router(policyManager);
const chain = new Chain(readonly);
const audit = new AuditLogger(logFile);
const transport = new Transport();
const handler = new Handler(router, chain, audit, transport);

const server = createServer((req, res) => {
  handler.handle(req, res).catch((err) => {
    console.error("handler error:", err);
    res.writeHead(500);
    res.end("internal server error");
  });
});

server.listen(listenTCP, () => {
  console.log(`listening on ${listenTCP}`);
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
