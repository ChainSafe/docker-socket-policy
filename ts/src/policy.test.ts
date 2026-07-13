import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Manager } from "./policy.js";

describe("Manager", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "policy-test-"));
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("loads policies from YAML files", () => {
    writeFileSync(
      join(tmpDir, "test.yaml"),
      "service_name: test-service\nallowed_image_prefixes:\n  - nginx\n",
    );
    const m = new Manager(tmpDir);
    assert.equal(m.list().length, 1);
    assert.ok(m.list().includes("test-service"));
  });

  it("ignores non-YAML files", () => {
    writeFileSync(join(tmpDir, "test.txt"), "hello");
    writeFileSync(join(tmpDir, "test.yaml"), "service_name: svc\nallowed_image_prefixes:\n  - alpine\n");
    const m = new Manager(tmpDir);
    assert.equal(m.list().length, 1);
  });

  it("loads .yml extension", () => {
    writeFileSync(
      join(tmpDir, "test.yml"),
      "service_name: my-service\nallowed_image_prefixes:\n  - busybox\n",
    );
    const m = new Manager(tmpDir);
    assert.equal(m.list().length, 1);
  });

  it("throws on missing service_name", () => {
    writeFileSync(join(tmpDir, "bad.yaml"), "allowed_image_prefixes:\n  - foo\n");
    assert.throws(() => new Manager(tmpDir), /service_name/);
  });

  it("throws on missing allowed_image_prefixes", () => {
    writeFileSync(join(tmpDir, "bad.yaml"), "service_name: svc\n");
    assert.throws(() => new Manager(tmpDir), /allowed_image_prefixes/);
  });

  it("get returns policy by service name", () => {
    writeFileSync(
      join(tmpDir, "svc.yaml"),
      "service_name: my-svc\nallowed_image_prefixes:\n  - nginx\n",
    );
    const m = new Manager(tmpDir);
    const p = m.get("my-svc");
    assert.ok(p);
    assert.equal(p?.service_name, "my-svc");
    assert.deepEqual(p?.allowed_image_prefixes, ["nginx"]);
  });

  it("get returns undefined for unknown service", () => {
    writeFileSync(
      join(tmpDir, "svc.yaml"),
      "service_name: known\nallowed_image_prefixes:\n  - nginx\n",
    );
    const m = new Manager(tmpDir);
    assert.equal(m.get("unknown"), undefined);
  });

  it("getByImage matches exact prefix", () => {
    writeFileSync(
      join(tmpDir, "svc.yaml"),
      "service_name: nginx-svc\nallowed_image_prefixes:\n  - nginx\n",
    );
    const m = new Manager(tmpDir);
    const p = m.getByImage("nginx:latest");
    assert.ok(p);
    assert.equal(p?.service_name, "nginx-svc");
  });

  it("getByImage matches prefix with slash", () => {
    writeFileSync(
      join(tmpDir, "svc.yaml"),
      "service_name: my-org\nallowed_image_prefixes:\n  - myorg\n",
    );
    const m = new Manager(tmpDir);
    const p = m.getByImage("myorg/web-app:v1");
    assert.ok(p);
    assert.equal(p?.service_name, "my-org");
  });

  it("getByImage returns undefined when no prefix matches", () => {
    writeFileSync(
      join(tmpDir, "svc.yaml"),
      "service_name: svc\nallowed_image_prefixes:\n  - nginx\n",
    );
    const m = new Manager(tmpDir);
    assert.equal(m.getByImage("redis:latest"), undefined);
  });
});
