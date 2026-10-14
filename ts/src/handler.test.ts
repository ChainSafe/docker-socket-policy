import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Readable, type Duplex } from "node:stream";
import { createServer, request, type IncomingMessage, type ServerResponse } from "node:http";
import { connect, type AddressInfo } from "node:net";
import { Handler } from "./handler.js";
import { Chain } from "./middleware.js";
import { Router } from "./proxy.js";
import { Manager } from "./policy.js";
import { AuditLogger } from "./audit.js";
import { Transport, type DaemonResponse } from "./transport.js";

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

function makeRequest(
  method: string,
  url: string,
  body?: string,
  headers: Record<string, string> = {},
): IncomingMessage {
  const stream = Readable.from(body ? [Buffer.from(body)] : []);
  (stream as IncomingMessage).method = method;
  (stream as IncomingMessage).url = url;
  (stream as IncomingMessage).headers = {
    ...(body ? { "content-length": String(Buffer.byteLength(body)) } : {}),
    ...headers,
  };
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
  const chain = new Chain();
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

// #83: a pull with a body is never forwarded. The daemon reads a form body's
// fromImage over the query's, so an allowed image in the query and another in
// the body would pull the body's. Any body is denied, whatever its
// Content-Type.
describe("Handler image pull with a body (#83)", () => {
  it("denies a pull that has a body", async () => {
    const dir = makeEnv({ "probe.yaml": "service_name: probe\nallowed_image_prefixes:\n  - alpine\n" });
    try {
      const cases: [string, string][] = [
        ["application/x-www-form-urlencoded", "fromImage=busybox&tag=latest"],
        ["application/json", '{"fromImage":"alpine"}'],
        ["text/plain", "x"],
      ];
      for (const [contentType, body] of cases) {
        const { handler, transport } = newHandler(dir);
        const { res, recorder } = makeResponse();
        await handler.handle(
          makeRequest("POST", "/v1.56/images/create?fromImage=alpine&tag=3.19", body, {
            "content-type": contentType,
          }),
          res,
        );
        assert.equal(recorder.statusCode, 403, contentType);
        assert.equal(recorder.body, "image pull must not have a request body", contentType);
        assert.equal(transport.lastRequest, undefined, contentType);
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

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

  // #75: --readonly is enforced in the router, so a delete never reaches the
  // daemon. Before #75 the flag only reached the chain, which runs on create.
  it("denies a delete in read-only mode without forwarding it", async () => {
    const dir = makeEnv(defaultConfig);
    const router = new Router(new Manager(dir)).withReadonly(true);
    const transport = new FakeTransport();
    const handler = new Handler(router, new Chain(), new AuditLogger(join(dir, "audit.log")), transport);
    const { res, recorder } = makeResponse();
    await handler.handle(makeRequest("DELETE", "/containers/mycontainer"), res);
    assert.equal(recorder.statusCode, 403);
    assert.equal(recorder.body, "read-only mode: DELETE requests are not allowed");
    assert.equal(transport.lastRequest, undefined);
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
    await handler.handle(makeRequest("POST", "/containers/create", JSON.stringify({ Image: "ubuntu:latest" })), res);
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

  // #53: TS routed on the raw name and forwarded it; the daemon decodes it to
  // "foo bar" and acts on that container.
  it("denies a percent-encoded container name with 403", async () => {
    const dir = makeEnv(defaultConfig);
    const { handler, transport } = newHandler(dir);
    const { res, recorder } = makeResponse();
    await handler.handle(makeRequest("DELETE", "/containers/foo%20bar"), res);
    assert.equal(recorder.statusCode, 403);
    assert.ok(recorder.body.includes("percent-encoded"), `deny reason = ${JSON.stringify(recorder.body)}`);
    assert.equal(transport.lastRequest, undefined);
  });

  // #53: the daemon reads %2F as a request about "/".
  it("denies a percent-encoded slash with 403", async () => {
    const dir = makeEnv(defaultConfig);
    const { handler, transport } = newHandler(dir);
    const { res, recorder } = makeResponse();
    await handler.handle(makeRequest("DELETE", "/containers/%2F"), res);
    assert.equal(recorder.statusCode, 403);
    assert.ok(recorder.body.includes("percent-encoded"), `deny reason = ${JSON.stringify(recorder.body)}`);
    assert.equal(transport.lastRequest, undefined);
  });

  // #53: the rule looks at the path only; an encoded query string is routine
  // (docker ps --filter) and must reach the daemon unchanged.
  it("forwards a percent-encoded query string unchanged", async () => {
    const dir = makeEnv(defaultConfig);
    const { handler, transport } = newHandler(dir);
    const { res, recorder } = makeResponse();
    const url = "/containers/json?filters=%7B%22status%22%3A%5B%22running%22%5D%7D";
    await handler.handle(makeRequest("GET", url), res);
    assert.notEqual(recorder.statusCode, 403);
    assert.ok(transport.lastRequest, "expected request to be forwarded");
    assert.equal(transport.lastRequest.url, url);
  });

  // #55: the audit uri is the raw request target, query and escapes included,
  // for allowed and denied requests alike.
  it("logs the raw request target as the audit uri", async () => {
    const dir = makeEnv(defaultConfig);
    const { handler } = newHandler(dir);
    const targets = [
      { method: "GET", target: "/containers/json?all=1", decision: "ALLOW" },
      { method: "DELETE", target: "/containers/a%2Fb?force=1", decision: "DENY" },
    ];
    for (const { method, target } of targets) {
      await handler.handle(makeRequest(method, target), makeResponse().res);
    }
    const lines = readFileSync(join(dir, "audit.log"), "utf-8").trim().split("\n");
    assert.equal(lines.length, targets.length);
    targets.forEach(({ method, target, decision }, i) => {
      const entry = JSON.parse(lines[i]!) as { uri: string; decision: string };
      assert.equal(entry.decision, decision, `${method} ${target}`);
      assert.equal(entry.uri, target, `${method} ${target}`);
    });
  });

  // #76: any protocol upgrade is refused before the body is read and before
  // routing, so the transport never sees it. Before #76 a websocket attach
  // went through the GET passthrough to the daemon.
  it("refuses a protocol upgrade", async () => {
    const dir = makeEnv(defaultConfig);
    const { handler, transport } = newHandler(dir);
    const refused = "protocol upgrade not allowed";
    const cases: [string, string, Record<string, string>][] = [
      ["websocket", "/containers/json", { upgrade: "websocket", connection: "Upgrade" }],
      ["connection token only", "/_ping", { connection: "keep-alive, Upgrade" }],
      ["upgrade header only", "/_ping", { upgrade: "h2c" }],
    ];
    const mismatches: string[] = [];
    for (const [name, target, headers] of cases) {
      const { res, recorder } = makeResponse();
      await handler.handle(makeRequest("GET", target, undefined, headers), res);
      if (recorder.statusCode !== 403 || recorder.body !== refused) {
        mismatches.push(`${name}: got ${recorder.statusCode} ${JSON.stringify(recorder.body)}`);
      }
      if (transport.lastRequest) mismatches.push(`${name}: forwarded`);
      transport.lastRequest = undefined;
    }
    await handler.handle(makeRequest("GET", "/containers/json"), makeResponse().res);
    if (!transport.lastRequest) mismatches.push("plain GET /containers/json: not forwarded");

    const first = JSON.parse(readFileSync(join(dir, "audit.log"), "utf-8").split("\n")[0]!) as Record<string, string>;
    if (
      first.method !== "GET" ||
      first.uri !== "/containers/json" ||
      first.decision !== "DENY" ||
      first.reason !== refused
    ) {
      mismatches.push(`audit entry: ${JSON.stringify(first)}`);
    }
    assert.deepEqual(mismatches, []);
  });

  // #76, TS-only: Node's http.Server routes a request with Upgrade and
  // Connection: Upgrade to the "upgrade" event when it has a listener. The
  // proxy registers none, so the request reaches the handler, which refuses it.
  it("refuses a protocol upgrade through a real http.Server", async () => {
    const dir = makeEnv(defaultConfig);
    const { handler, transport } = newHandler(dir);
    const server = createServer((req, res) => void handler.handle(req, res));
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { port } = server.address() as AddressInfo;
    try {
      const got = await new Promise<string>((resolve, reject) => {
        const req = request(
          {
            host: "127.0.0.1",
            port,
            path: "/containers/mycontainer/attach/ws?stdin=1&stream=1",
            headers: { Upgrade: "websocket", Connection: "Upgrade" },
          },
          (res) => {
            let body = "";
            res.on("data", (c: Buffer) => (body += c.toString()));
            res.on("end", () => resolve(`${res.statusCode} ${body}`));
          },
        );
        req.on("upgrade", (res) => resolve(`upgraded ${res.statusCode}`));
        req.on("error", reject);
        req.setTimeout(2000, () => req.destroy(new Error("no response within 2s")));
        req.end();
      });
      assert.equal(got, "403 protocol upgrade not allowed");
      assert.equal(transport.lastRequest, undefined);
    } finally {
      server.closeAllConnections();
      await new Promise((resolve) => server.close(resolve));
    }
  });

  // #78: CONNECT is refused before the upgrade check and before routing, so
  // the transport never sees it, in origin form and in authority form. Before
  // #78 CONNECT /_ping matched the early read-endpoint allow and was forwarded.
  it("refuses CONNECT", async () => {
    const dir = makeEnv(defaultConfig);
    const { handler, transport } = newHandler(dir);
    const refused = "CONNECT is not allowed";
    const cases: [string, string, Record<string, string>][] = [
      ["origin form", "/_ping", {}],
      ["authority form", "localhost:80", {}],
      ["with Upgrade", "/_ping", { upgrade: "websocket", connection: "Upgrade" }],
    ];
    const mismatches: string[] = [];
    for (const [name, target, headers] of cases) {
      const { res, recorder } = makeResponse();
      await handler.handle(makeRequest("CONNECT", target, undefined, headers), res);
      if (recorder.statusCode !== 403 || recorder.body !== refused) {
        mismatches.push(`${name}: got ${recorder.statusCode} ${JSON.stringify(recorder.body)}`);
      }
      if (transport.lastRequest) mismatches.push(`${name}: forwarded`);
      transport.lastRequest = undefined;
    }

    const lines = readFileSync(join(dir, "audit.log"), "utf-8").trim().split("\n");
    ["/_ping", "localhost:80", "/_ping"].forEach((uri, i) => {
      const entry = JSON.parse(lines[i] ?? "{}") as Record<string, string>;
      if (entry.method !== "CONNECT" || entry.uri !== uri || entry.decision !== "DENY" || entry.reason !== refused) {
        mismatches.push(`audit entry ${i}: ${lines[i]}`);
      }
    });
    assert.deepEqual(mismatches, []);
  });

  // #78, TS-only: Node never passes CONNECT to the request handler. With no
  // "connect" listener it destroys the socket, so the caller got no response
  // and nothing was audited. The proxy wires Handler.refuseConnect to it.
  it("refuses CONNECT through a real http.Server", async () => {
    const dir = makeEnv(defaultConfig);
    const { handler, transport } = newHandler(dir);
    const server = createServer((req, res) => void handler.handle(req, res));
    server.on("connect", (req: IncomingMessage, socket: Duplex) => handler.refuseConnect(req, socket));
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { port } = server.address() as AddressInfo;
    const send = (target: string) =>
      new Promise<string>((resolve, reject) => {
        const sock = connect(port, "127.0.0.1");
        let got = "";
        sock.on("data", (c: Buffer) => (got += c.toString()));
        sock.on("close", () => resolve(got));
        sock.on("error", reject);
        sock.setTimeout(2000, () => sock.destroy(new Error("no response within 2s")));
        sock.write(`CONNECT ${target} HTTP/1.1\r\nHost: localhost:80\r\n\r\n`);
      });
    try {
      const mismatches: string[] = [];
      for (const target of ["localhost:80", "/_ping"]) {
        const got = await send(target);
        if (!got.startsWith("HTTP/1.1 403 Forbidden\r\n") || !got.endsWith("\r\n\r\nCONNECT is not allowed")) {
          mismatches.push(`${target}: got ${JSON.stringify(got)}`);
        }
      }
      if (transport.lastRequest) mismatches.push("forwarded");
      const log = readFileSync(join(dir, "audit.log"), { encoding: "utf-8", flag: "a+" });
      const lines = log.trim().split("\n");
      ["localhost:80", "/_ping"].forEach((uri, i) => {
        const entry = JSON.parse(lines[i] || "{}") as Record<string, string>;
        if (
          entry.method !== "CONNECT" ||
          entry.uri !== uri ||
          entry.decision !== "DENY" ||
          entry.reason !== "CONNECT is not allowed"
        ) {
          mismatches.push(`audit entry ${i}: ${lines[i]}`);
        }
      });
      assert.deepEqual(mismatches, []);
    } finally {
      server.closeAllConnections();
      await new Promise((resolve) => server.close(resolve));
    }
  });
});

// #83: the handler hands the request target, query included, to the router.
// A pull sent the Docker CLI way, empty body and image in the query, is
// forwarded, and a disallowed one is not.
describe("Handler image pull (#83)", () => {
  it("routes a pull on its query string", async () => {
    const dir = makeEnv({ "probe.yaml": "service_name: probe\nallowed_image_prefixes:\n  - alpine\n" });
    try {
      let { handler, transport } = newHandler(dir);
      let { res, recorder } = makeResponse();
      await handler.handle(
        makeRequest("POST", "/v1.56/images/create?fromImage=docker.io%2Flibrary%2Falpine&tag=3.19"),
        res,
      );
      assert.equal(recorder.statusCode, 200);
      assert.equal(transport.lastRequest?.url, "/v1.56/images/create?fromImage=docker.io%2Flibrary%2Falpine&tag=3.19");

      ({ handler, transport } = newHandler(dir));
      ({ res, recorder } = makeResponse());
      await handler.handle(makeRequest("POST", "/v1.56/images/create?fromImage=busybox&tag=latest"), res);
      assert.equal(recorder.statusCode, 403);
      assert.equal(recorder.body, "image busybox not allowed by any policy");
      assert.equal(transport.lastRequest, undefined);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

const BEACON_ID = "4f6e1d2c9a7b8c3d4e5f60718293a4b5c6d7e8f9012345678901234567890abc";
const MONITORING_ID = "9d8c7b6a5f4e3d2c1b0a99887766554433221100ffeeddccbbaa998877665544";

// Answers GET /containers/{id}/json from a table of id -> container name, as
// the daemon does, and records every request.
class DaemonTransport extends Transport {
  requests: string[] = [];
  lastBody?: Buffer;
  status?: number;
  names = new Map<string, string>([
    ["beacon", "beacon"],
    [BEACON_ID, "beacon"],
    [BEACON_ID.slice(0, 12), "beacon"],
    ["dsp-monitoring", "dsp-monitoring"],
    [MONITORING_ID, "dsp-monitoring"],
    [MONITORING_ID.slice(0, 12), "dsp-monitoring"],
  ]);

  override async get(path: string): Promise<DaemonResponse> {
    this.requests.push(`GET ${path}`);
    if (this.status !== undefined) return { statusCode: this.status, body: Buffer.from("boom") };
    const id = path.slice("/containers/".length, -"/json".length);
    const name = this.names.get(id);
    if (name === undefined) return { statusCode: 404, body: Buffer.from("no such container") };
    return { statusCode: 200, body: Buffer.from(JSON.stringify({ Id: "4f6e1d2c9a7b", Name: `/${name}` })) };
  }

  override async forward(req: IncomingMessage, res: ServerResponse, body?: Buffer): Promise<void> {
    this.requests.push(`${req.method} ${(req.url ?? "").split("?")[0]}`);
    this.lastBody = body;
    res.writeHead(204);
    res.end();
  }
}

function newDaemonHandler(files: Record<string, string>) {
  const dir = makeEnv(files);
  const transport = new DaemonTransport();
  const handler = new Handler(
    new Router(new Manager(dir)),
    new Chain(),
    new AuditLogger(join(dir, "audit.log")),
    transport,
  );
  return { handler, transport, dir };
}

describe("Handler container coverage", () => {
  const notManaged = (id: string) => `container ${id} is not managed by any policy`;
  const inspect = (id: string) => [`GET /containers/${id}/json`];
  const beaconShort = BEACON_ID.slice(0, 12);
  const monShort = MONITORING_ID.slice(0, 12);

  // The handler half of #86: a lifecycle action or DELETE is forwarded only
  // if its target is a container a policy covers. A name, full ID or short ID
  // is resolved with GET /containers/{id}/json. Before #86 every row was
  // forwarded.
  it("forwards lifecycle actions only for covered containers", async () => {
    const cases: [string, string, string, number, string, string[]][] = [
      ["covered name", "POST", "/v1.45/containers/beacon/stop?t=1", 204, "", []],
      ["covered full ID", "POST", `/containers/${BEACON_ID}/kill`, 204, "", inspect(BEACON_ID)],
      ["covered short ID", "DELETE", `/containers/${beaconShort}?force=1`, 204, "", inspect(beaconShort)],
      // uncoveredNameStopDeniedTest: an operator container.
      [
        "uncovered name",
        "POST",
        "/containers/dsp-monitoring/stop",
        403,
        notManaged("dsp-monitoring"),
        inspect("dsp-monitoring"),
      ],
      [
        "uncovered full ID",
        "POST",
        `/containers/${MONITORING_ID}/kill`,
        403,
        notManaged(MONITORING_ID),
        inspect(MONITORING_ID),
      ],
      ["uncovered short ID", "DELETE", `/containers/${monShort}`, 403, notManaged(monShort), inspect(monShort)],
      // realNameDeleteDeniedTest: the daemon answers 404.
      ["unknown name", "DELETE", "/containers/mycontainer", 403, notManaged("mycontainer"), inspect("mycontainer")],
      // execPrefixNameStartDeniedTest
      [
        "unknown exec-prefixed name",
        "POST",
        "/containers/exec-runner/start",
        403,
        notManaged("exec-runner"),
        inspect("exec-runner"),
      ],
    ];
    const mismatches: string[] = [];
    for (const [name, method, target, status, body, inspects] of cases) {
      const { handler, transport } = newDaemonHandler(beaconConfig);
      const { res, recorder } = makeResponse();
      await handler.handle(makeRequest(method, target), res);
      if (recorder.statusCode !== status || (body !== "" && recorder.body !== body)) {
        mismatches.push(`${name}: got ${recorder.statusCode} ${recorder.body}, want ${status} ${body}`);
      }
      const want = [...inspects];
      if (status !== 403) want.push(`${method} ${target.split("?")[0]}`);
      if (JSON.stringify(transport.requests) !== JSON.stringify(want)) {
        mismatches.push(`${name}: daemon saw ${JSON.stringify(transport.requests)}, want ${JSON.stringify(want)}`);
      }
    }
    assert.deepEqual(mismatches, []);
  });

  // A daemon error other than 404 fails closed with its own message (#86).
  it("fails closed when the daemon cannot resolve a container", async () => {
    const { handler, transport } = newDaemonHandler(beaconConfig);
    transport.status = 500;
    const { res, recorder } = makeResponse();
    await handler.handle(makeRequest("POST", `/containers/${beaconShort}/stop`), res);
    assert.equal(recorder.statusCode, 403);
    assert.equal(recorder.body, `cannot resolve container ${beaconShort}: daemon returned 500`);
    assert.deepEqual(transport.requests, inspect(beaconShort));
  });

  // The resolved name is audited with the request (#86).
  it("audits the resolved name", async () => {
    const { handler, dir } = newDaemonHandler(beaconConfig);
    await handler.handle(makeRequest("POST", `/containers/${beaconShort}/start`), makeResponse().res);
    await handler.handle(makeRequest("POST", `/containers/${monShort}/start`), makeResponse().res);
    const lines = readFileSync(join(dir, "audit.log"), "utf-8")
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l) as { decision: string; reason: string });
    assert.equal(lines.length, 2);
    assert.equal(lines[0]!.decision, "ALLOW");
    assert.equal(lines[0]!.reason, `container ${beaconShort} resolved to beacon`);
    assert.equal(lines[1]!.decision, "DENY");
    assert.equal(lines[1]!.reason, `container ${monShort} is not managed by any policy (resolved to dsp-monitoring)`);
  });

  // The #85 reproduction through the handler: two policies for one image
  // force different users, and each create named for one of them gets that
  // policy's user, every time.
  it("applies the policy selected by the create name", async () => {
    const { handler, transport } = newDaemonHandler({
      "a.yaml":
        'service_name: svc-a\ncontainer_names: [svc-a]\nallowed_image_prefixes: [alpine]\ncontainer_config: { user: "1111:1111" }\n',
      "b.yaml":
        'service_name: svc-b\ncontainer_names: [svc-b]\nallowed_image_prefixes: [alpine]\ncontainer_config: { user: "2222:2222" }\n',
    });
    const body = JSON.stringify({ Image: "alpine:3.20", Cmd: ["true"] });
    for (let i = 0; i < 50; i++) {
      for (const [name, user] of [
        ["svc-a", "1111:1111"],
        ["svc-b", "2222:2222"],
      ] as const) {
        transport.lastBody = undefined;
        const { res, recorder } = makeResponse();
        await handler.handle(makeRequest("POST", `/v1.45/containers/create?name=${name}`, body), res);
        assert.equal(recorder.statusCode, 204, `iteration ${i} ${name}: ${recorder.body}`);
        const fwd = JSON.parse(transport.lastBody!.toString("utf-8")) as { User?: string };
        assert.equal(fwd.User, user, `iteration ${i}: create ?name=${name}`);
      }
    }
    const { res, recorder } = makeResponse();
    await handler.handle(makeRequest("POST", "/containers/create", JSON.stringify({ Image: "alpine:3.20" })), res);
    assert.equal(recorder.statusCode, 403);
    assert.equal(recorder.body, "image alpine:3.20 requires a container name");
  });
});
