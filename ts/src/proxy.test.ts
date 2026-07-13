import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Manager } from "./policy.js";
import { Action, Router } from "./proxy.js";

function createManager(dir: string) {
  writeFileSync(
    join(dir, "nginx.yaml"),
    "service_name: nginx-svc\nallowed_image_prefixes:\n  - nginx\n",
  );
  writeFileSync(
    join(dir, "redis.yaml"),
    "service_name: redis-svc\nallowed_image_prefixes:\n  - redis\ncontainer_config:\n  network_mode: bridge\nvolumes:\n  - host_path: /data\n    container_path: /data\n    read_write: true\n",
  );
  return new Manager(dir);
}

describe("Router", () => {
  let tmpDir: string;
  let manager: Manager;
  let router: Router;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "proxy-test-"));
    manager = createManager(tmpDir);
    router = new Router(manager);
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("allows GET /_ping", () => {
    const r = router.route("GET", "/_ping");
    assert.equal(r.action, Action.Allow);
  });

  it("allows GET /version", () => {
    const r = router.route("GET", "/version");
    assert.equal(r.action, Action.Allow);
  });

  it("allows GET /info", () => {
    const r = router.route("GET", "/info");
    assert.equal(r.action, Action.Allow);
  });

  it("allows GET /events", () => {
    const r = router.route("GET", "/events");
    assert.equal(r.action, Action.Allow);
  });

  it("denies /auth", () => {
    const r = router.route("POST", "/auth");
    assert.equal(r.action, Action.Deny);
    assert.ok(r.denyMsg?.includes("auth"));
  });

  it("denies /exec", () => {
    const r = router.route("POST", "/containers/foo/exec");
    assert.equal(r.action, Action.Deny);
    assert.ok(r.denyMsg?.includes("exec"));
  });

  it("denies /build", () => {
    const r = router.route("POST", "/build");
    assert.equal(r.action, Action.Deny);
    assert.ok(r.denyMsg?.includes("build"));
  });

  it("denies /commit", () => {
    const r = router.route("POST", "/commit");
    assert.equal(r.action, Action.Deny);
    assert.ok(r.denyMsg?.includes("commit"));
  });

  it("routes POST /containers/create to CreateContainer", () => {
    const r = router.route("POST", "/containers/create", { Image: "nginx:latest" });
    assert.equal(r.action, Action.CreateContainer);
    assert.equal(r.service, "nginx-svc");
    assert.ok(r.policy);
  });

  it("denies POST /containers/create with empty body", () => {
    const r = router.route("POST", "/containers/create", {});
    assert.equal(r.action, Action.Deny);
    assert.ok(r.denyMsg?.includes("empty"));
  });

  it("denies POST /containers/create with no body", () => {
    const r = router.route("POST", "/containers/create");
    assert.equal(r.action, Action.Deny);
  });

  it("denies POST /containers/create with unknown image", () => {
    const r = router.route("POST", "/containers/create", { Image: "unknown:latest" });
    assert.equal(r.action, Action.Deny);
  });

  it("allows POST /containers/:name/start for known service", () => {
    const r = router.route("POST", "/containers/nginx-svc/start");
    assert.equal(r.action, Action.Allow);
    assert.equal(r.service, "nginx-svc");
  });

  it("allows POST /containers/:name/start for unknown container", () => {
    const r = router.route("POST", "/containers/my-arbitrary/start");
    assert.equal(r.action, Action.Allow);
    assert.equal(r.container, "my-arbitrary");
  });

  it("allows DELETE /containers/:name for known service", () => {
    const r = router.route("DELETE", "/containers/redis-svc");
    assert.equal(r.action, Action.Allow);
    assert.equal(r.service, "redis-svc");
  });

  it("denies POST /containers/:name/rename", () => {
    const r = router.route("POST", "/containers/foo/rename");
    assert.equal(r.action, Action.Deny);
    assert.ok(r.denyMsg?.includes("rename"));
  });

  it("denies POST /containers/:name/update", () => {
    const r = router.route("POST", "/containers/foo/update");
    assert.equal(r.action, Action.Deny);
    assert.ok(r.denyMsg?.includes("update"));
  });

  it("allows GET /containers/:name", () => {
    const r = router.route("GET", "/containers/foo");
    assert.equal(r.action, Action.Allow);
  });

  it("allows GET /containers/json", () => {
    const r = router.route("GET", "/containers/json");
    assert.equal(r.action, Action.Allow);
  });

  it("allows POST /images/create for allowed image", () => {
    const r = router.route("POST", "/images/create", { fromImage: "nginx:latest" });
    assert.equal(r.action, Action.Allow);
  });

  it("denies POST /images/create for unknown image", () => {
    const r = router.route("POST", "/images/create", { fromImage: "unknown:latest" });
    assert.equal(r.action, Action.Deny);
  });

  it("denies POST /images/create with empty body", () => {
    const r = router.route("POST", "/images/create", {});
    assert.equal(r.action, Action.Deny);
  });

  it("allows GET passthrough for unknown paths", () => {
    const r = router.route("GET", "/containers/foo/logs");
    assert.equal(r.action, Action.Allow);
  });

  it("strips API version prefix", () => {
    const r = router.route("GET", "/v1.41/_ping");
    assert.equal(r.action, Action.Allow);
  });

  it("denies unknown POST endpoint", () => {
    const r = router.route("POST", "/some/unknown/path");
    assert.equal(r.action, Action.Deny);
  });

  it("strips query string from path", () => {
    const r = router.route("POST", "/containers/nginx-svc/start?foo=bar");
    assert.equal(r.action, Action.Allow);
    assert.equal(r.service, "nginx-svc");
  });
});
