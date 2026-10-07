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

  // Cross-language parity guard for #24. /containers/<x> is ambiguous: <x> is
  // usually a container name, but Docker also has reserved endpoints at that
  // position. Treating one as a container name routes the request down the
  // lifecycle path, where an unknown container is allowed through — Go allowed
  // DELETE /containers/json for exactly that reason.
  it("does not treat reserved path segments as container names", () => {
    const cases: [string, string, Action][] = [
      // Reserved: must not be mistaken for a container to remove.
      // reservedJsonDeleteDeniedTest
      ["DELETE", "/containers/json", Action.Deny],
      // reservedCreateDeleteDeniedTest
      ["DELETE", "/containers/create", Action.Deny],
      // reservedExecDeleteDeniedTest: denied by the exec check, before the lifecycle branch.
      ["DELETE", "/containers/exec", Action.Deny],
      // Listing stays allowed, via the GET/HEAD passthrough.
      ["GET", "/containers/json", Action.Allow],
      // A real container name is still routed as a container.
      // realNameDeleteAllowedTest
      ["DELETE", "/containers/mycontainer", Action.Allow],
      ["GET", "/containers/mycontainer", Action.Allow],
      // Reserved words are only reserved in the name position.
      // reservedInSubpathAllowedTest
      ["GET", "/containers/mycontainer/json", Action.Allow],
    ];
    for (const [method, path, want] of cases) {
      const r = router.route(method, path);
      assert.equal(r.action, want, `route(${method} ${path})`);
    }
  });

  // Cross-language parity guard for #48. An empty segment in the name position
  // (/containers/, /containers//start) is not a container name. Treating it as
  // one routes the request down the lifecycle path, where an unknown container
  // is allowed through. Rows mirror the emptyName* runs in spec/router.qnt.
  it("does not treat an empty path segment as a container name", () => {
    const cases: [string, string, Action][] = [
      // emptyNameDeleteDeniedTest
      ["DELETE", "/containers/", Action.Deny],
      // emptyNameStartDeniedTest
      ["POST", "/containers//start", Action.Deny],
      // emptyNameGetAllowedTest
      ["GET", "/containers/", Action.Allow],
    ];
    for (const [method, path, want] of cases) {
      const r = router.route(method, path);
      assert.equal(r.action, want, `route(${method} ${path})`);
    }
  });

  // Cross-language parity guard for #52. The Docker CLI prefixes every request
  // with a dotted API version (/v1.43/containers/create). The router must
  // strip the prefix and route the rest exactly like the unversioned path.
  // stripAPIVersion only stripped undotted prefixes (/v1/...), so dotted paths
  // fell through to the default deny.
  it("routes dotted API-version paths like the unversioned ones", () => {
    const cases: [string, string, Record<string, unknown> | undefined, Action][] = [
      // #52: dotted version, container lifecycle delete.
      ["DELETE", "/v1.43/containers/foo", undefined, Action.Allow],
      // #52: dotted version, container lifecycle start.
      ["POST", "/v1.43/containers/beacon/start", undefined, Action.Allow],
      // #52: dotted version, create with a policy-allowed image.
      ["POST", "/v1.43/containers/create", { Image: "nginx:latest" }, Action.CreateContainer],
      // #52: undotted control — stripped correctly everywhere already.
      ["POST", "/v1/containers/beacon/start", undefined, Action.Allow],
      // #52: the reserved segment survives the strip (#24 parity).
      ["DELETE", "/v1.43/containers/json", undefined, Action.Deny],
      // #52 no-overreach: /version is an endpoint, not a version prefix.
      ["GET", "/version", undefined, Action.Allow],
      // #52 no-overreach: /volumes must not be mistaken for a version prefix.
      ["DELETE", "/volumes/x", undefined, Action.Deny],
    ];
    for (const [method, path, body, want] of cases) {
      const r = router.route(method, path, body);
      assert.equal(r.action, want, `route(${method} ${path})`);
    }
  });
});
