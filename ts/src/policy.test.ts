import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Manager, parseImageRef, type ImageRef } from "./policy.js";

describe("Manager", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "policy-test-"));
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("loads policies from YAML files", () => {
    writeFileSync(join(tmpDir, "test.yaml"), "service_name: test-service\nallowed_image_prefixes:\n  - nginx\n");
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
    writeFileSync(join(tmpDir, "test.yml"), "service_name: my-service\nallowed_image_prefixes:\n  - busybox\n");
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
    writeFileSync(join(tmpDir, "svc.yaml"), "service_name: my-svc\nallowed_image_prefixes:\n  - nginx\n");
    const m = new Manager(tmpDir);
    const p = m.get("my-svc");
    assert.ok(p);
    assert.equal(p?.service_name, "my-svc");
    assert.deepEqual(p?.allowed_image_prefixes, ["nginx"]);
  });

  it("get returns undefined for unknown service", () => {
    writeFileSync(join(tmpDir, "svc.yaml"), "service_name: known\nallowed_image_prefixes:\n  - nginx\n");
    const m = new Manager(tmpDir);
    assert.equal(m.get("unknown"), undefined);
  });

  it("getByImage matches exact prefix", () => {
    writeFileSync(join(tmpDir, "svc.yaml"), "service_name: nginx-svc\nallowed_image_prefixes:\n  - nginx\n");
    const m = new Manager(tmpDir);
    const p = m.getByImage("nginx:latest");
    assert.ok(p);
    assert.equal(p?.service_name, "nginx-svc");
  });

  it("getByImage matches prefix with slash", () => {
    writeFileSync(join(tmpDir, "svc.yaml"), "service_name: my-org\nallowed_image_prefixes:\n  - myorg\n");
    const m = new Manager(tmpDir);
    const p = m.getByImage("myorg/web-app:v1");
    assert.ok(p);
    assert.equal(p?.service_name, "my-org");
  });

  it("getByImage returns undefined when no prefix matches", () => {
    writeFileSync(join(tmpDir, "svc.yaml"), "service_name: svc\nallowed_image_prefixes:\n  - nginx\n");
    const m = new Manager(tmpDir);
    assert.equal(m.getByImage("redis:latest"), undefined);
  });
});

// The #84 normalisation table, on the parser itself. The same rows run in Go
// and Rust.
describe("parseImageRef (#84)", () => {
  it("normalises references the way Docker does", () => {
    const digest = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    const cases: [string, ImageRef | null][] = [
      ["alpine", { name: "alpine", tag: "", digest: "" }],
      ["library/alpine", { name: "alpine", tag: "", digest: "" }],
      ["docker.io/library/alpine", { name: "alpine", tag: "", digest: "" }],
      ["index.docker.io/library/alpine:3.19", { name: "alpine", tag: "3.19", digest: "" }],
      ["registry-1.docker.io/library/alpine", { name: "alpine", tag: "", digest: "" }],
      ["docker.io/chainsafe/lodestar:v1", { name: "chainsafe/lodestar", tag: "v1", digest: "" }],
      [`ghcr.io/chainsafe/lodestar@${digest}`, { name: "ghcr.io/chainsafe/lodestar", tag: "", digest }],
      ["localhost:5000/x/y:2", { name: "localhost:5000/x/y", tag: "2", digest: "" }],
      ["registry.example.com:443/a", { name: "registry.example.com:443/a", tag: "", digest: "" }],
      ["REGISTRY.Example.com:443/a:V1", { name: "registry.example.com:443/a", tag: "V1", digest: "" }],
      ["docker.io/library/a/b", { name: "library/a/b", tag: "", digest: "" }],
      ["ghcr.io/library/alpine", { name: "ghcr.io/library/alpine", tag: "", digest: "" }],
      ["localhost/x", { name: "localhost/x", tag: "", digest: "" }],
      ["localhost", { name: "localhost", tag: "", digest: "" }],
      [`alpine:3.19@${digest}`, { name: "alpine", tag: "3.19", digest }],
      ["Alpine", null],
      ["chainsafe/Lodestar", null],
      ["alpine:", null],
      ["alpine@", null],
      ["", null],
      ["a//b", null],
      ["/alpine", null],
      ["alpine/", null],
      ["-alpine", null],
      ["alpine:a/b", null],
      ["a:b/c", null],
      ["alpine:t$g", null],
    ];
    const mismatches: string[] = [];
    for (const [input, want] of cases) {
      let got: ImageRef | string;
      try {
        got = parseImageRef(input);
      } catch (err) {
        got = (err as Error).message;
      }
      const ok =
        want === null ? got === `invalid image reference "${input}"` : JSON.stringify(got) === JSON.stringify(want);
      if (!ok) mismatches.push(`${JSON.stringify(input)}: got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
    }
    assert.deepEqual(mismatches, []);
  });

  // Prefixes are normalised at load time, and a prefix with a tag or an
  // invalid one fails the load (#84).
  it("normalises policy prefixes at load time", () => {
    const dir = mkdtempSync(join(tmpdir(), "policy-prefix-test-"));
    try {
      writeFileSync(
        join(dir, "a.yaml"),
        "service_name: a\nallowed_image_prefixes:\n  - docker.io/library/alpine\n  - GHCR.io/team\n",
      );
      assert.deepEqual(new Manager(dir).get("a")?.allowed_image_prefixes, ["alpine", "ghcr.io/team"]);
      for (const bad of ["alpine:3.19", "Alpine"]) {
        writeFileSync(join(dir, "a.yaml"), `service_name: a\nallowed_image_prefixes:\n  - "${bad}"\n`);
        assert.throws(() => new Manager(dir), /invalid allowed_image_prefixes entry/, bad);
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
