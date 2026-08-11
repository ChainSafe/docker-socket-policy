import { describe, it } from "node:test";
import assert from "node:assert/strict";
import type { IncomingMessage, ServerResponse } from "node:http";
import { Transport, isPermissionDenied } from "./transport.js";

describe("Transport", () => {
  it("constructs with default socket path", () => {
    const t = new Transport();
    assert.ok(t instanceof Transport);
  });

  it("constructs with custom socket path", () => {
    const t = new Transport("/tmp/test-docker.sock");
    assert.ok(t instanceof Transport);
  });

  it("fails to forward to non-existent socket", async () => {
    const t = new Transport("/nonexistent/docker.sock");
    const req = { url: "/_ping", method: "GET", headers: {} } as IncomingMessage;
    const res = { writeHead() {}, end() {} } as unknown as ServerResponse;
    await assert.rejects(t.forward(req, res), { name: "Error" });
  });
});

describe("isPermissionDenied", () => {
  const err = (code: string) => {
    const e = new Error(code) as NodeJS.ErrnoException;
    e.code = code;
    return e;
  };

  it("returns true for EACCES and EPERM", () => {
    assert.equal(isPermissionDenied(err("EACCES")), true);
    assert.equal(isPermissionDenied(err("EPERM")), true);
  });

  it("returns false for other socket error codes", () => {
    assert.equal(isPermissionDenied(err("ENOENT")), false);
    assert.equal(isPermissionDenied(err("ECONNREFUSED")), false);
    assert.equal(isPermissionDenied(err("ECONNRESET")), false);
  });
});
