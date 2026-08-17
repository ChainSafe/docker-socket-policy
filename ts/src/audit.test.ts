import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLogger } from "./audit.js";

describe("AuditLogger", () => {
  it("writes a well-formed ALLOW entry", () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const path = join(dir, "audit.log");
    const logger = new AuditLogger(path);
    logger.allow("GET", "/_ping");

    const lines = readFileSync(path, "utf8").trim().split("\n");
    assert.equal(lines.length, 1);
    const entry = JSON.parse(lines[0]);
    assert.equal(entry.decision, "ALLOW");
    assert.equal(entry.method, "GET");
    assert.equal(entry.uri, "/_ping");
    assert.equal(entry.reason, "");
    assert.ok(entry.request_id);
    assert.ok(entry.timestamp);
    rmSync(dir, { recursive: true, force: true });
  });

  it("writes a well-formed DENY entry with reason", () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const path = join(dir, "audit.log");
    const logger = new AuditLogger(path);
    logger.deny("POST", "/containers/create", "exec denied by policy");

    const lines = readFileSync(path, "utf8").trim().split("\n");
    assert.equal(lines.length, 1);
    const entry = JSON.parse(lines[0]);
    assert.equal(entry.decision, "DENY");
    assert.equal(entry.method, "POST");
    assert.equal(entry.uri, "/containers/create");
    assert.equal(entry.reason, "exec denied by policy");
    rmSync(dir, { recursive: true, force: true });
  });

  it("appends one JSON line per event", () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const path = join(dir, "audit.log");
    const logger = new AuditLogger(path);
    for (let i = 0; i < 5; i++) {
      logger.allow("GET", "/version");
    }

    const lines = readFileSync(path, "utf8").trim().split("\n");
    assert.equal(lines.length, 5);
    for (const line of lines) {
      const entry = JSON.parse(line);
      assert.equal(entry.decision, "ALLOW");
    }
    rmSync(dir, { recursive: true, force: true });
  });

  it("never throws when the log file cannot be written", () => {
    const logger = new AuditLogger("/nonexistent-dir/audit.log");
    assert.doesNotThrow(() => logger.allow("GET", "/_ping"));
  });
});