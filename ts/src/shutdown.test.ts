import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  Agent,
  createServer,
  request as httpRequest,
  type Server,
} from "node:http";
import { connect } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createShutdown } from "./shutdown.js";

// sun_path is capped at 104 bytes on macOS, so keep the socket path short.
function tempSocket(): { path: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "dsp-"));
  return {
    path: join(dir, "s.sock"),
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

interface Harness {
  server: Server;
  path: string;
  exited: Promise<number>;
  shutdown: (signal: string) => void;
  logs: string[];
  cleanup: () => void;
}

async function harness(
  handler: (req: unknown, res: import("node:http").ServerResponse) => void,
  timeoutMs = 30_000,
): Promise<Harness> {
  const { path, cleanup } = tempSocket();
  const server = createServer((req, res) => handler(req, res));
  // Keep this short so an unreleased keep-alive socket shows up as a failure
  // rather than being masked by Node's 5s default.
  server.keepAliveTimeout = 2_000;

  await new Promise<void>((resolve) => server.listen(path, resolve));

  const logs: string[] = [];
  let settle: (code: number) => void;
  const exited = new Promise<number>((resolve) => {
    settle = resolve;
  });

  const shutdown = createShutdown(server, {
    timeoutMs,
    log: (m) => logs.push(m),
    error: (m) => logs.push(m),
    exit: (code) => settle(code),
  });

  return { server, path, exited, shutdown, logs, cleanup };
}

function withTimeout<T>(p: Promise<T>, ms: number, msg: string): Promise<T> {
  return Promise.race([
    p,
    new Promise<T>((_, reject) =>
      setTimeout(() => reject(new Error(msg)), ms).unref(),
    ),
  ]);
}

/** Opens a connection and sends a request, returning the raw reply. */
function request(path: string, target: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const sock = connect(path, () => {
      sock.write(`GET ${target} HTTP/1.1\r\nHost: localhost\r\n\r\n`);
    });
    let buf = "";
    sock.on("data", (d) => {
      buf += d.toString();
    });
    sock.on("end", () => resolve(buf));
    sock.on("error", reject);
  });
}

describe("createShutdown", () => {
  it("exits promptly when idle", async () => {
    const h = await harness((_req, res) => res.end("ok"));
    h.shutdown("SIGTERM");

    const code = await withTimeout(h.exited, 5_000, "shutdown did not complete");
    assert.equal(code, 0);
    h.cleanup();
  });

  // Node >= 19 releases idle keep-alive connections inside server.close(), so
  // this passes without any help from createShutdown. It is kept as a guard on
  // that platform behaviour: the Go and Rust implementations have to do this
  // explicitly, and if Node ever regressed (or the runtime were downgraded to
  // 18) shutdown would silently start stalling for keepAliveTimeout.
  it("does not stall on an idle keep-alive connection", async () => {
    const h = await harness((_req, res) => res.end("ok"));

    // Complete a real request over a keep-alive agent. The response ends but
    // the socket stays parked in the agent's pool — exactly the state a Docker
    // client leaves behind between API calls.
    const agent = new Agent({ keepAlive: true });
    await new Promise<void>((resolve, reject) => {
      const req = httpRequest(
        { socketPath: h.path, path: "/first", agent },
        (res) => {
          res.resume();
          res.on("end", () => resolve());
        },
      );
      req.on("error", reject);
      req.end();
    });

    const started = Date.now();
    h.shutdown("SIGTERM");
    const code = await withTimeout(
      h.exited,
      5_000,
      "idle keep-alive connection held shutdown open",
    );

    const elapsed = Date.now() - started;
    assert.equal(code, 0);
    assert.ok(
      elapsed < 1_500,
      `shutdown took ${elapsed}ms; keepAliveTimeout is 2000ms, so the idle ` +
        `connection was waited out rather than released. Node >= 19 should ` +
        `release it inside server.close()`,
    );
    agent.destroy();
    h.cleanup();
  });

  it("lets an in-flight request finish before exiting", async () => {
    let respond: (() => void) | undefined;
    const h = await harness((_req, res) => {
      respond = () => res.end("done");
    });

    const inFlight = request(h.path, "/slow");
    // Wait until the handler is actually running.
    while (!respond) await new Promise((r) => setTimeout(r, 10));

    h.shutdown("SIGTERM");
    // The request has not been answered yet; shutdown must not have exited.
    await new Promise((r) => setTimeout(r, 200));
    respond();

    const reply = await withTimeout(inFlight, 5_000, "in-flight request aborted");
    assert.ok(reply.includes("done"), `expected the response body, got: ${reply}`);

    const code = await withTimeout(h.exited, 5_000, "shutdown never completed");
    assert.equal(code, 0);
    h.cleanup();
  });

  it("forces close and exits non-zero when the deadline passes", async () => {
    // A handler that never responds: without a deadline this would hang forever.
    const h = await harness(() => {}, 300);
    request(h.path, "/hang").catch(() => {});
    await new Promise((r) => setTimeout(r, 100));

    h.shutdown("SIGTERM");
    const code = await withTimeout(h.exited, 5_000, "deadline never fired");

    assert.equal(code, 1, "expected a non-zero exit when draining times out");
    assert.ok(
      h.logs.some((l) => l.includes("deadline exceeded")),
      `expected a deadline log, got: ${JSON.stringify(h.logs)}`,
    );
    h.cleanup();
  });

  it("ignores a repeated signal", async () => {
    const h = await harness((_req, res) => res.end("ok"));

    h.shutdown("SIGTERM");
    h.shutdown("SIGTERM");
    h.shutdown("SIGINT");

    await withTimeout(h.exited, 5_000, "shutdown did not complete");
    const received = h.logs.filter((l) => l.includes("shutting down"));
    assert.equal(received.length, 1, `expected one shutdown log, got: ${JSON.stringify(h.logs)}`);
    h.cleanup();
  });
});
