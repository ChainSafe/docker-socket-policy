import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Readable } from "node:stream";
import type { IncomingMessage, ServerResponse } from "node:http";
import { Handler } from "./handler.js";
import { Chain } from "./middleware.js";
import { Router } from "./proxy.js";
import { Manager } from "./policy.js";
import { AuditLogger } from "./audit.js";
import { Transport } from "./transport.js";

class FakeTransport extends Transport {
  lastBody?: Buffer;
  lastRequest?: IncomingMessage;
  override async forward(req: IncomingMessage, _res: ServerResponse, body?: Buffer): Promise<void> {
    this.lastRequest = req;
    this.lastBody = body;
  }
}

interface RecorderRes {
  statusCode: number;
  body: string;
  headers: Record<string, string | number | undefined>;
}

function makeResponse(): { res: ServerResponse; recorder: RecorderRes } {
  const recorder: RecorderRes = { statusCode: 200, body: "", headers: {} };
  const res = {
    writeHead: (code: number, headers?: Record<string, string | number | undefined>) => {
      recorder.statusCode = code;
      if (headers) recorder.headers = headers;
    },
    end: (chunk?: string) => {
      if (chunk) recorder.body = String(chunk);
    },
  } as unknown as ServerResponse;
  return { res, recorder };
}

function makeRequest(method: string, url: string, body?: string): IncomingMessage {
  const stream = Readable.from(body ? [Buffer.from(body)] : []);
  (stream as IncomingMessage).method = method;
  (stream as IncomingMessage).url = url;
  (stream as IncomingMessage).headers = body
    ? { "content-length": String(Buffer.byteLength(body)) }
    : {};
  return stream as IncomingMessage;
}

function makeEnv(configFiles: Record<string, string>) {
  const dir = mkdtempSync(join(tmpdir(), "handler-test-"));
  for (const [name, content] of Object.entries(configFiles)) {
    writeFileSync(join(dir, name), content);
  }
  return dir;
}

function newHandler(dir: string) {
  const manager = new Manager(dir);
  const router = new Router(manager);
  const chain = new Chain(false);
  const audit = new AuditLogger(join(dir, "audit.log"));
  const transport = new FakeTransport();
  return { handler: new Handler(router, chain, audit, transport), transport };
}

const defaultConfig = {
  "default.yaml": "service_name: default\nallowed_image_prefixes:\n  - scratch\n",
};

const beaconConfig = {
  "beacon.yaml":
    "service_name: beacon\nallowed_image_prefixes:\n  - chainsafe/lodestar\ncontainer_config:\n  network_mode: host\n",
};

describe("Handler", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "handler-test-"));
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("denies a routed-denied endpoint with 403", async () => {
    const dir = makeEnv(defaultConfig);
    const { handler } = newHandler(dir);
    const { res, recorder } = makeResponse();
    await handler.handle(makeRequest("POST", "/build"), res);
    assert.equal(recorder.statusCode, 403);
    assert.ok(recorder.body.includes("build"));
  });

  it("forwards a valid container create with the modified body", async () => {
    const dir = makeEnv(beaconConfig);
    const { handler, transport } = newHandler(dir);
    const { res, recorder } = makeResponse();
    await handler.handle(
      makeRequest("POST", "/containers/create", JSON.stringify({ Image: "chainsafe/lodestar:next" })),
      res,
    );
    assert.notEqual(recorder.statusCode, 403);
    assert.ok(transport.lastRequest, "expected request to be forwarded");
    assert.ok(transport.lastBody, "expected a modified body");
    const forwarded = JSON.parse(transport.lastBody!.toString("utf-8"));
    const hostConfig = forwarded["HostConfig"] as Record<string, unknown>;
    assert.equal(hostConfig["NetworkMode"], "host");
  });

  it("denies a container create that fails the gate chain with 403", async () => {
    const dir = makeEnv(defaultConfig);
    const { handler, transport } = newHandler(dir);
    const { res, recorder } = makeResponse();
    await handler.handle(
      makeRequest("POST", "/containers/create", JSON.stringify({ Image: "ubuntu:latest" })),
      res,
    );
    assert.equal(recorder.statusCode, 403);
    assert.equal(transport.lastRequest, undefined);
  });

  it("denies container create with empty body", async () => {
    const dir = makeEnv(defaultConfig);
    const { handler } = newHandler(dir);
    const { res, recorder } = makeResponse();
    await handler.handle(makeRequest("POST", "/containers/create"), res);
    assert.equal(recorder.statusCode, 403);
  });

  it("passes through non-JSON body on read-only endpoint", async () => {
    const dir = makeEnv(defaultConfig);
    const { handler, transport } = newHandler(dir);
    const { res, recorder } = makeResponse();
    await handler.handle(makeRequest("GET", "/_ping", "not json at all"), res);
    assert.notEqual(recorder.statusCode, 400);
    assert.ok(transport.lastRequest, "expected request to be forwarded");
  });

  it("preserves headers on forwarded create", async () => {
    const dir = makeEnv(beaconConfig);
    const { handler, transport } = newHandler(dir);
    const { res } = makeResponse();
    const body = JSON.stringify({ Image: "chainsafe/lodestar:next" });
    await handler.handle(makeRequest("POST", "/containers/create", body), res);
    assert.ok(transport.lastRequest, "expected request to be forwarded");
    assert.ok(transport.lastBody, "expected a modified body");
    assert.equal(Number(transport.lastRequest.headers["content-length"]), Buffer.byteLength(body));
    const forwarded = JSON.parse(transport.lastBody!.toString("utf-8"));
    const hostConfig = forwarded["HostConfig"] as Record<string, unknown>;
    assert.equal(hostConfig["NetworkMode"], "host");
  });
});