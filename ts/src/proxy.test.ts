import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Manager } from "./policy.js";
import { Action, Router } from "./proxy.js";

function createManager(dir: string) {
  writeFileSync(join(dir, "nginx.yaml"), "service_name: nginx-svc\nallowed_image_prefixes:\n  - nginx\n");
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
    const cases: [string, string, Action, string?][] = [
      // Reserved: must not be mistaken for a container to remove.
      // reservedJsonDeleteDeniedTest
      ["DELETE", "/containers/json", Action.Deny],
      // reservedCreateDeleteDeniedTest
      ["DELETE", "/containers/create", Action.Deny],
      // reservedExecDeleteDeniedTest: denied by the exec check, before the lifecycle branch.
      ["DELETE", "/containers/exec", Action.Deny, "exec is not allowed"],
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
    const mismatches: string[] = [];
    for (const [method, path, want, wantMsg] of cases) {
      const r = router.route(method, path);
      if (r.action !== want || (wantMsg !== undefined && r.denyMsg !== wantMsg)) {
        mismatches.push(
          `${method} ${path}: got ${Action[r.action]}/${r.denyMsg ?? "-"}, want ${Action[want]}/${wantMsg ?? "-"}`,
        );
      }
    }
    assert.deepEqual(mismatches, []);
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
    const mismatches: string[] = [];
    for (const [method, path, want] of cases) {
      const r = router.route(method, path);
      if (r.action !== want) {
        mismatches.push(`${method} ${path}: got ${Action[r.action]}/${r.denyMsg ?? "-"}, want ${Action[want]}`);
      }
    }
    assert.deepEqual(mismatches, []);
  });

  // Cross-language parity guard for #52 and #57. The Docker CLI prefixes every
  // request with a dotted API version (/v1.43/containers/create), and the
  // router must strip the prefix and route the rest exactly like the
  // unversioned path. The table pins one canonical prefix rule,
  // ^/v\d+(\.\d+)?/ with ASCII digits, in all three languages (#52, #57).
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
      // #57: undotted version, container lifecycle delete.
      ["DELETE", "/v1/containers/foo", undefined, Action.Allow],
      // #57: multi-digit major version.
      ["DELETE", "/v10.0/containers/foo", undefined, Action.Allow],
      // #57: /volumes/ is not a version; the daemon routes this as a volume removal.
      ["DELETE", "/volumes/containers/foo", undefined, Action.Deny],
      // #57: /version/ is not a version prefix.
      ["DELETE", "/version/containers/foo", undefined, Action.Deny],
      // #57: two dots is not an API version.
      ["DELETE", "/v1.2.3/containers/foo", undefined, Action.Deny],
      // #57: no digits after v.
      ["DELETE", "/vabc/containers/foo", undefined, Action.Deny],
      // #57: bare v.
      ["DELETE", "/v/containers/foo", undefined, Action.Deny],
      // #57: dot without a minor version.
      ["DELETE", "/v1./containers/foo", undefined, Action.Deny],
      // #57: strip once; the remaining /v1.43/containers/foo matches no route.
      ["DELETE", "/v1/v1.43/containers/foo", undefined, Action.Deny],
      // #57: a non-ASCII digit (U+0661 ARABIC-INDIC DIGIT ONE) is not a version digit.
      ["DELETE", "/v\u0661/containers/foo", undefined, Action.Deny],
      // #57 sanity row, cannot fail: GET /version is allowed as a read-only request.
      ["GET", "/version", undefined, Action.Allow],
    ];
    const mismatches: string[] = [];
    for (const [method, path, body, want] of cases) {
      const r = router.route(method, path, body);
      if (r.action !== want) {
        mismatches.push(`${method} ${path}: got ${Action[r.action]}/${r.denyMsg ?? "-"}, want ${Action[want]}`);
      }
    }
    assert.deepEqual(mismatches, []);
  });

  // Cross-language parity guard for #53. The daemon percent-decodes the path
  // before it routes, so any % in the path lets the proxy and the daemon read
  // the same request differently. A path containing % is denied for every
  // method. Rows mirror the percent* runs in spec/router.qnt.
  it("denies percent-encoded paths", () => {
    const cases: [string, string, Action][] = [
      // percentSlashDeleteDeniedTest (#53)
      ["DELETE", "/containers/%2F", Action.Deny],
      // percentLowerSlashDeleteDeniedTest (#53)
      ["DELETE", "/containers/%2f", Action.Deny],
      // percentReservedDeleteDeniedTest (#53): %6A%73%6F%6E decodes to json.
      ["DELETE", "/containers/%6A%73%6F%6E", Action.Deny],
      // percentSubpathStartDeniedTest (#53): a pin; raw routing already denies it.
      // It discriminates only in Go's handler before #53, which decoded first;
      // the foo%20bar handler test covers that.
      ["POST", "/containers/beacon%2Fstart", Action.Deny],
      // percentNameStartDeniedTest (#53)
      ["POST", "/containers/%2F/start", Action.Deny],
      // percentGetDeniedTest (#53)
      ["GET", "/containers/%2F", Action.Deny],
      // #53, language-only: the rule covers every method, HEAD included.
      ["HEAD", "/containers/%2F", Action.Deny],
      // #53: the check runs on the versioned path too.
      ["DELETE", "/v1.45/containers/foo%25", Action.Deny],
      // #53: an encoded version prefix is not stripped.
      ["DELETE", "/v%31/containers/foo", Action.Deny],
      // #53: network names that need escaping are denied, GET included.
      ["GET", "/networks/a%20b", Action.Deny],
      // #53 control: a plain name is still routed as a container.
      ["DELETE", "/containers/foo", Action.Allow],
      // #53, TS-only: only the TS router receives the query string (Go and Rust
      // route URL.EscapedPath() / uri.path()). A % in the query is not checked.
      ["GET", "/containers/json?filters=%7B%7D", Action.Allow],
      // Non-GET, so the GET passthrough cannot hide a check placed before the split.
      ["DELETE", "/containers/foo?force=%31", Action.Allow],
    ];
    const mismatches: string[] = [];
    for (const [method, path, want] of cases) {
      const r = router.route(method, path);
      if (r.action !== want || (want === Action.Deny && !r.denyMsg?.includes("percent-encoded"))) {
        const wantMsg = want === Action.Deny ? "*percent-encoded*" : "-";
        mismatches.push(
          `${method} ${path}: got ${Action[r.action]}/${r.denyMsg ?? "-"}, want ${Action[want]}/${wantMsg}`,
        );
      }
    }
    assert.deepEqual(mismatches, []);
  });

  // Cross-language parity guard for #49. Exec and create are matched on whole
  // path segments. Exec is denied for every method when the first segment is
  // exec, or when the first segment is containers and a later segment is
  // exactly exec; a name that only contains exec routes normally.
  // POST /containers/create and POST /images/create match only with exactly
  // two segments. Rows mirror the exec* and create* runs in spec/router.qnt.
  it("matches exec and create endpoints on whole path segments", () => {
    const createBody = { Image: "nginx:latest" };
    const exec = "exec is not allowed";
    const cases: [string, string, Record<string, unknown> | undefined, Action, string | undefined][] = [
      // execSubpathDeleteDeniedTest (#49)
      ["DELETE", "/containers/mycontainer/exec", undefined, Action.Deny, exec],
      // execSubpathPostDeniedTest (#49)
      ["POST", "/containers/mycontainer/exec", undefined, Action.Deny, exec],
      // execPrefixNameStartAllowedTest (#49): an unknown container.
      ["POST", "/containers/exec-runner/start", undefined, Action.Allow, undefined],
      // execPrefixNameDeleteAllowedTest (#49): an unknown container.
      ["DELETE", "/containers/exec-runner", undefined, Action.Allow, undefined],
      // execPrefixNameGetAllowedTest (#49)
      ["GET", "/containers/exec-runner/json", undefined, Action.Allow, undefined],
      // execNamespaceGetDeniedTest (#49): exec inspect leaks command lines.
      ["GET", "/exec/abc/json", undefined, Action.Deny, exec],
      // execNamespacePostDeniedTest (#49)
      ["POST", "/exec/abc/start", undefined, Action.Deny, exec],
      // createSubpathDeniedTest (#49): an allowed image, so only the path decides.
      ["POST", "/containers/create/extra", createBody, Action.Deny, undefined],
      // Exec is matched under containers or exec only (#49, language-only).
      ["GET", "/images/exec", undefined, Action.Allow, undefined],
      // An allowed image, so only the path decides (#49, language-only).
      ["POST", "/images/create/extra?fromImage=nginx&tag=latest", undefined, Action.Deny, undefined],
      // A name ending in exec is a plain name (#49, language-only).
      ["GET", "/containers/myexec/json", undefined, Action.Allow, undefined],
      // A name starting with exec is a plain name (#49, language-only).
      ["DELETE", "/containers/executor", undefined, Action.Allow, undefined],
      // The reserved name, decided by the exec check (#49, language-only).
      ["GET", "/containers/exec/json", undefined, Action.Deny, exec],
      // A top-level name starting with exec is not the exec namespace (#49, language-only).
      ["GET", "/executor", undefined, Action.Allow, undefined],
    ];
    const mismatches: string[] = [];
    for (const [method, path, body, want, wantMsg] of cases) {
      const r = router.route(method, path, body);
      // Exact match: the default deny for POST /containers/x/exec ends in
      // "exec is not allowed" too, so a substring check passes vacuously.
      if (r.action !== want || (wantMsg !== undefined && r.denyMsg !== wantMsg)) {
        mismatches.push(
          `${method} ${path}: got ${Action[r.action]}/${r.denyMsg ?? "-"}, want ${Action[want]}/${wantMsg ?? "-"}`,
        );
      }
    }
    assert.deepEqual(mismatches, []);
  });

  // Cross-language parity guard for #55. A path with an empty interior segment
  // (// anywhere in the path) is denied for every method, after the percent
  // check and before the API-version strip; a single trailing slash is not
  // interior. HEAD on a named container is routed like GET. Rows mirror the
  // emptyLeadingExecGetDenied, emptyInteriorGetDenied and
  // headNamedContainerAllowed runs in spec/router.qnt.
  it("denies empty interior segments and routes HEAD like GET", () => {
    const empty = "empty path segment not allowed";
    const percent = "percent-encoded path not allowed";
    const exec = "exec is not allowed";
    const cases: [string, string, Action, string | undefined][] = [
      // emptyLeadingExecGetDeniedTest (#55): the leading empty segment hid the exec namespace.
      ["GET", "//exec/abc/json", Action.Deny, empty],
      // #55: the empty segment after the version prefix hides the exec namespace too.
      ["GET", "/v1.45//exec/abc/json", Action.Deny, empty],
      // #55: the check runs before the version strip.
      ["GET", "//v1.45/exec/abc/json", Action.Deny, empty],
      // emptyInteriorGetDeniedTest (#55)
      ["GET", "/containers//json", Action.Deny, empty],
      // #55: emptyNameStartDeniedTest (#48) is now decided by the empty segment check.
      ["POST", "/containers//start", Action.Deny, empty],
      // #55: an empty name followed by a trailing slash.
      ["DELETE", "/containers//", Action.Deny, empty],
      // #55: the read-only endpoints are not exempt.
      ["GET", "//_ping", Action.Deny, empty],
      // #55: the percent check runs first.
      ["GET", "//containers/%2F", Action.Deny, percent],
      // #55 control: a single trailing slash is not an empty interior segment.
      ["GET", "/containers/", Action.Allow, undefined],
      // #55 control: the root path.
      ["GET", "/", Action.Allow, undefined],
      // headNamedContainerAllowedTest (#55)
      ["HEAD", "/containers/mycontainer", Action.Allow, undefined],
      // #55: HEAD on a container subpath.
      ["HEAD", "/containers/mycontainer/json", Action.Allow, undefined],
      // #55: the exec check still denies HEAD.
      ["HEAD", "/containers/mycontainer/exec", Action.Deny, exec],
      // #55, TS-only: only the TS router receives the query string (Go and Rust
      // route URL.EscapedPath() / uri.path()). A // in the query is not checked.
      ["GET", "/containers/json?filters=a//b", Action.Allow, undefined],
      // #55, TS-only: the TS router receives the raw request target, so an
      // absolute-form target reaches it as-is. Its "//" after the scheme denies
      // it; before #55 the first segment "http:" hid exec inspect (v0.3.1-v0.3.3).
      ["GET", "http://docker/exec/abc/json", Action.Deny, empty],
    ];
    const mismatches: string[] = [];
    for (const [method, path, want, wantMsg] of cases) {
      const r = router.route(method, path);
      if (r.action !== want || r.denyMsg !== wantMsg) {
        mismatches.push(
          `${method} ${path}: got ${Action[r.action]}/${r.denyMsg ?? "-"}, want ${Action[want]}/${wantMsg ?? "-"}`,
        );
      }
    }
    assert.deepEqual(mismatches, []);
  });

  // Cross-language parity guard for #75. With --readonly, every request whose
  // method is not GET or HEAD is denied first in the router, for every path.
  // Before #75 the flag only reached the middleware chain, which runs on the
  // create route alone, so lifecycle POSTs, DELETE /containers/{name} and
  // image pulls were forwarded. Rows mirror the readonly* runs in
  // spec/router.qnt.
  it("denies every write in read-only mode", () => {
    writeFileSync(
      join(tmpDir, "beacon.yaml"),
      "service_name: beacon\nallowed_image_prefixes:\n  - chainsafe/lodestar\n",
    );
    const m = new Manager(tmpDir);
    const ro = new Router(m).withReadonly(true);
    const post = "read-only mode: POST requests are not allowed";
    const createBody = { Image: "chainsafe/lodestar:latest" };
    const cases: [string, string, Record<string, unknown> | undefined, Action, string | undefined][] = [
      // readonlyGetAllowedTest (#75)
      ["GET", "/containers/json", undefined, Action.Allow, undefined],
      // readonlyHeadAllowedTest (#75)
      ["HEAD", "/containers/mycontainer", undefined, Action.Allow, undefined],
      // #75: the read-only endpoints stay allowed.
      ["GET", "/_ping", undefined, Action.Allow, undefined],
      // readonlyLifecycleStopDeniedTest (#75)
      ["POST", "/containers/mycontainer/stop", undefined, Action.Deny, post],
      // #75: the other lifecycle actions too.
      ["POST", "/containers/mycontainer/start", undefined, Action.Deny, post],
      // readonlyDeleteDeniedTest (#75)
      ["DELETE", "/containers/mycontainer", undefined, Action.Deny, "read-only mode: DELETE requests are not allowed"],
      // #75: an image pull of an allowed image.
      ["POST", "/images/create?fromImage=chainsafe%2Flodestar&tag=latest", undefined, Action.Deny, post],
      // readonlyCreateDeniedTest (#75): an allowed image, so only the flag decides.
      ["POST", "/containers/create", createBody, Action.Deny, post],
      // #75: methods outside the spec's universe.
      [
        "PUT",
        "/containers/mycontainer/archive",
        undefined,
        Action.Deny,
        "read-only mode: PUT requests are not allowed",
      ],
      // #75: the check runs before the API-version strip.
      ["POST", "/v1.45/containers/mycontainer/stop", undefined, Action.Deny, post],
    ];
    const mismatches: string[] = [];
    for (const [method, path, body, want, wantMsg] of cases) {
      const r = ro.route(method, path, body);
      if (r.action !== want || r.denyMsg !== wantMsg) {
        mismatches.push(
          `${method} ${path}: got ${Action[r.action]}/${r.denyMsg ?? "-"}, want ${Action[want]}/${wantMsg ?? "-"}`,
        );
      }
    }
    // #75: the flag gates the rule; without it a lifecycle POST is routed as before.
    const off = new Router(m).route("POST", "/containers/mycontainer/stop");
    if (off.denyMsg === post) {
      mismatches.push("POST /containers/mycontainer/stop without --readonly: got the read-only deny");
    }
    assert.deepEqual(mismatches, []);
  });

  // Cross-language parity guard for #76. attach as a whole segment after
  // /containers/{name} is denied for every method, right after the exec
  // check. Before #76 GET .../attach/ws fell through to the GET passthrough.
  // Rows mirror the attach* runs in spec/router.qnt.
  it("denies attach for every method", () => {
    const attach = "attach is not allowed";
    const cases: [string, string, Action, string | undefined][] = [
      // attachGetDeniedTest (#76): the websocket attach endpoint.
      ["GET", "/containers/mycontainer/attach/ws", Action.Deny, attach],
      // #76, TS-only: the TS router receives the raw target, query included.
      ["GET", "/containers/mycontainer/attach/ws?stdin=1&stream=1", Action.Deny, attach],
      // attachPostDeniedTest (#76)
      ["POST", "/containers/mycontainer/attach", Action.Deny, attach],
      // attachHeadDeniedTest (#76)
      ["HEAD", "/containers/mycontainer/attach", Action.Deny, attach],
      // #76: the check runs after the API-version strip.
      ["GET", "/v1.45/containers/mycontainer/attach/ws", Action.Deny, attach],
      // #76: every method.
      ["DELETE", "/containers/mycontainer/attach", Action.Deny, attach],
      // #76 control: attach-runner is a name like any other.
      ["GET", "/containers/attach-runner/json", Action.Allow, undefined],
      // #76 control: other container reads stay allowed.
      ["GET", "/containers/mycontainer/logs", Action.Allow, undefined],
      ["GET", "/containers/json", Action.Allow, undefined],
    ];
    const mismatches: string[] = [];
    for (const [method, path, want, wantMsg] of cases) {
      const r = router.route(method, path);
      if (r.action !== want || r.denyMsg !== wantMsg) {
        mismatches.push(
          `${method} ${path}: got ${Action[r.action]}/${r.denyMsg ?? "-"}, want ${Action[want]}/${wantMsg ?? "-"}`,
        );
      }
    }
    assert.deepEqual(mismatches, []);
  });

  // Cross-language parity guard for #78. /_ping, /version, /info and /events
  // admit only GET and HEAD, through the read passthrough; every other method
  // gets the default deny. Before #78 an early clause allowed them for every
  // method, and /events as a prefix also matched /eventsxyz. Rows mirror the
  // ping* runs in spec/router.qnt.
  it("allows only GET and HEAD on the read endpoints", () => {
    const cases: [string, string, Action, string | undefined][] = [
      // pingPostDeniedTest (#78)
      ["POST", "/_ping", Action.Deny, "endpoint POST /_ping is not allowed"],
      // pingDeleteDeniedTest (#78)
      ["DELETE", "/_ping", Action.Deny, "endpoint DELETE /_ping is not allowed"],
      // #78: every read endpoint, every non-read method.
      ["DELETE", "/version", Action.Deny, "endpoint DELETE /version is not allowed"],
      ["PUT", "/info", Action.Deny, "endpoint PUT /info is not allowed"],
      ["POST", "/events", Action.Deny, "endpoint POST /events is not allowed"],
      ["CONNECT", "/_ping", Action.Deny, "endpoint CONNECT /_ping is not allowed"],
      // #78: the daemon's CORS preflight, denied on purpose.
      ["OPTIONS", "/_ping", Action.Deny, "endpoint OPTIONS /_ping is not allowed"],
      ["PATCH", "/_ping", Action.Deny, "endpoint PATCH /_ping is not allowed"],
      // A lowercase method is an extension method, not CONNECT: the router denies it.
      ["connect", "/_ping", Action.Deny, "endpoint connect /_ping is not allowed"],
      // #78: the old /events prefix match.
      ["POST", "/eventsxyz", Action.Deny, "endpoint POST /eventsxyz is not allowed"],
      // #78: the check runs after the API-version strip.
      ["POST", "/v1.45/_ping", Action.Deny, "endpoint POST /_ping is not allowed"],
      // pingGetAllowedTest (#78)
      ["GET", "/_ping", Action.Allow, undefined],
      // pingHeadAllowedTest (#78)
      ["HEAD", "/_ping", Action.Allow, undefined],
      ["GET", "/version", Action.Allow, undefined],
      ["HEAD", "/version", Action.Allow, undefined],
      ["GET", "/info", Action.Allow, undefined],
      ["HEAD", "/info", Action.Allow, undefined],
      ["GET", "/events", Action.Allow, undefined],
      ["HEAD", "/events", Action.Allow, undefined],
      ["GET", "/v1.45/_ping", Action.Allow, undefined],
      // #78 pin: a read on an unknown path stays on the passthrough.
      ["GET", "/eventsxyz", Action.Allow, undefined],
      // #78, TS-only: the TS router receives the raw target, query included.
      ["POST", "/events?since=1", Action.Deny, "endpoint POST /events is not allowed"],
    ];
    const mismatches: string[] = [];
    for (const [method, path, want, wantMsg] of cases) {
      const r = router.route(method, path);
      if (r.action !== want || r.denyMsg !== wantMsg) {
        mismatches.push(
          `${method} ${path}: got ${Action[r.action]}/${r.denyMsg ?? "-"}, want ${Action[want]}/${wantMsg ?? "-"}`,
        );
      }
    }
    assert.deepEqual(mismatches, []);
  });

  // Cross-language parity guard for #70. A path with a segment that is
  // exactly . or .. is denied for every method, right after the // check and
  // before the API-version strip. Before #70 GET /./exec/<id>/json had a
  // first segment of ".", so the exec check missed it and the GET passthrough
  // forwarded it. Rows mirror the dot* runs in spec/router.qnt.
  it("denies dot path segments", () => {
    const dot = "dot path segment not allowed";
    const cases: [string, string, Action, string | undefined][] = [
      // dotLeadingExecGetDeniedTest (#70): the leading . hid the exec namespace.
      ["GET", "/./exec/abc/json", Action.Deny, dot],
      // dotDotExecGetDeniedTest (#70)
      ["GET", "/x/../exec/abc/json", Action.Deny, dot],
      // dotInContainerPathDeniedTest (#70)
      ["GET", "/containers/x/./exec", Action.Deny, dot],
      // #70: .. climbing out of the container path.
      ["GET", "/containers/x/../../exec/abc/json", Action.Deny, dot],
      // #70: the check runs before the version strip.
      ["GET", "/v1.45/./_ping", Action.Deny, dot],
      // #70: every method.
      ["DELETE", "/containers/..", Action.Deny, dot],
      ["POST", "/containers/x/./start", Action.Deny, dot],
      // #70: the dot hid the attach deny too.
      ["GET", "/containers/./x/attach/ws", Action.Deny, dot],
      // #70 control: names with dots are names.
      ["GET", "/containers/.hidden/json", Action.Allow, undefined],
      ["GET", "/containers/a.b/json", Action.Allow, undefined],
      ["GET", "/containers/.../json", Action.Allow, undefined],
      // #70: the // check runs first.
      ["GET", "//./_ping", Action.Deny, "empty path segment not allowed"],
      // #70: an encoded dot is denied by the percent check (#53).
      ["GET", "/containers/%2e/json", Action.Deny, "percent-encoded path not allowed"],
      // #70, TS-only: the TS router receives the raw target; the query is not inspected.
      ["GET", "/containers/json?filters=a/./b", Action.Allow, undefined],
    ];
    const mismatches: string[] = [];
    for (const [method, path, want, wantMsg] of cases) {
      const r = router.route(method, path);
      if (r.action !== want || r.denyMsg !== wantMsg) {
        mismatches.push(
          `${method} ${path}: got ${Action[r.action]}/${r.denyMsg ?? "-"}, want ${Action[want]}/${wantMsg ?? "-"}`,
        );
      }
    }
    assert.deepEqual(mismatches, []);
  });
});

const TEST_DIGEST = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

// The policy set for the #83 and #84 tables. beacon's prefixes are written in
// spellings that normalisation must reduce at load time:
// docker.io/chainsafe/lodestar is chainsafe/lodestar, and the registry host
// Registry.Example.com:443 is lower-cased.
function createPullManager(dir: string): Manager {
  writeFileSync(
    join(dir, "probe.yaml"),
    "service_name: probe\nallowed_image_prefixes:\n  - alpine\nimage_digest_allowed: true\n",
  );
  writeFileSync(
    join(dir, "beacon.yaml"),
    "service_name: beacon\nallowed_image_prefixes:\n  - docker.io/chainsafe/lodestar\n  - ghcr.io/chainsafe/lodestar\n  - localhost:5000/x\n  - Registry.Example.com:443/a\nimage_tag_pattern: '^(v[0-9]+|[0-9]+)$'\n",
  );
  return new Manager(dir);
}

describe("Router image pull and normalisation (#83, #84)", () => {
  let tmpDir: string;
  let router: Router;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "proxy-pull-test-"));
    router = new Router(createPullManager(tmpDir));
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  // Cross-language parity guard for #83 and #84. POST /images/create is
  // routed on its query string, the way the Docker CLI sends it: fromImage
  // (fully qualified, URL-encoded) and tag, with an empty body. The body is
  // ignored, fromSrc (import) is denied, and the image gets the create checks:
  // a policy prefix on the normalised repository, then that policy's tag
  // pattern and digest rule. Rows mirror the pull* runs in spec/router.qnt;
  // the rest are language-only.
  it("routes POST /images/create on the query string", () => {
    const alpineBody = { fromImage: "alpine" };
    const notAllowed = (image: string) => `image ${image} not allowed by any policy`;
    const required = "fromImage query parameter is required for image pull";
    const fromSrc = "image import (fromSrc) is not allowed";
    const bodyMsg = "image pull must not have a request body";
    const encDigest = encodeURIComponent(TEST_DIGEST);
    const cases: [string, Record<string, unknown> | undefined, Action, string, string][] = [
      // pullCliAllowedTest (#83): the issue's reproduction, as the CLI sends it.
      ["/v1.56/images/create?fromImage=docker.io%2Flibrary%2Falpine&tag=3.19", undefined, Action.Allow, "probe", ""],
      // pullShortNameAllowedTest (#84)
      ["/images/create?fromImage=alpine&tag=3.19", undefined, Action.Allow, "probe", ""],
      // pullLibraryNameAllowedTest (#84)
      ["/images/create?fromImage=library%2Falpine&tag=latest", undefined, Action.Allow, "probe", ""],
      // pullCliOrgAllowedTest (#84): the prefix is written docker.io/chainsafe/lodestar.
      ["/images/create?fromImage=docker.io%2Fchainsafe%2Flodestar&tag=v1", undefined, Action.Allow, "beacon", ""],
      // #84: the tag in fromImage, on another Docker Hub host name.
      ["/images/create?fromImage=index.docker.io%2Flibrary%2Falpine%3A3.19", undefined, Action.Allow, "probe", ""],
      // #83: the CLI sends a digest in tag.
      [`/images/create?fromImage=alpine&tag=${encDigest}`, undefined, Action.Allow, "probe", ""],
      // #83: a digest in fromImage.
      [`/images/create?fromImage=alpine%40${encDigest}`, undefined, Action.Allow, "probe", ""],
      // #83: image_digest_allowed is false for beacon.
      [
        `/images/create?fromImage=ghcr.io%2Fchainsafe%2Flodestar&tag=${encDigest}`,
        undefined,
        Action.Deny,
        "",
        "image digests not allowed for service beacon",
      ],
      // #84: a registry port is not a tag.
      ["/images/create?fromImage=localhost%3A5000%2Fx%2Fy&tag=2", undefined, Action.Allow, "beacon", ""],
      // #84: the registry host is compared lower-cased.
      ["/images/create?fromImage=REGISTRY.example.com%3A443%2Fa&tag=1", undefined, Action.Allow, "beacon", ""],
      // #83: the tag pattern applies to pulls.
      [
        "/images/create?fromImage=chainsafe%2Flodestar&tag=latest",
        undefined,
        Action.Deny,
        "",
        'image tag "latest" does not match pattern "^(v[0-9]+|[0-9]+)$"',
      ],
      // pullDisallowedCliDeniedTest (#83)
      [
        "/images/create?fromImage=docker.io%2Fattacker%2Fmalware&tag=latest",
        undefined,
        Action.Deny,
        "",
        notAllowed("docker.io/attacker/malware"),
      ],
      // pullOtherRegistryDeniedTest (#84): another registry is not Docker Hub's alpine.
      [
        "/images/create?fromImage=localhost%3A5000%2Falpine&tag=1",
        undefined,
        Action.Deny,
        "",
        notAllowed("localhost:5000/alpine"),
      ],
      // #84: the prefix match stays on namespace boundaries.
      ["/images/create?fromImage=alpine-evil&tag=1", undefined, Action.Deny, "", notAllowed("alpine-evil")],
      // pullNoFromImageDeniedTest (#83)
      ["/images/create", undefined, Action.Deny, "", required],
      // #83: the old contract, fromImage in a JSON body: a pull has no body.
      ["/images/create", { fromImage: "alpine:3.19" }, Action.Deny, "", bodyMsg],
      // pullBodyIgnoredDeniedTest (#83): the daemon would pull the query's image.
      ["/images/create?fromImage=attacker%2Fmalware&tag=latest", alpineBody, Action.Deny, "", bodyMsg],
      // pullJsonBodyDeniedTest (#83): any body is denied, even one that agrees.
      ["/images/create?fromImage=alpine&tag=3.19", alpineBody, Action.Deny, "", bodyMsg],
      // pullImportDeniedTest (#83): the daemon would import the tarball as alpine:latest.
      [
        "/images/create?fromSrc=http%3A%2F%2Fexample.com%2Fx.tar&repo=alpine&tag=latest",
        undefined,
        Action.Deny,
        "",
        fromSrc,
      ],
      // pullImportWithImageDeniedTest (#83)
      ["/images/create?fromImage=alpine&tag=latest&fromSrc=-", undefined, Action.Deny, "", fromSrc],
      // #83: a tag in fromImage and in tag is ambiguous.
      [
        "/images/create?fromImage=alpine%3A3.19&tag=3.20",
        undefined,
        Action.Deny,
        "",
        "fromImage alpine:3.19 already has a tag or digest; the tag query parameter is ambiguous",
      ],
      // #83: no tag and no digest pulls every tag.
      [
        "/images/create?fromImage=alpine",
        undefined,
        Action.Deny,
        "",
        "image pull without a tag or digest pulls every tag and is not allowed",
      ],
      // #84: upper case in the repository path is invalid.
      ["/images/create?fromImage=Alpine&tag=latest", undefined, Action.Deny, "", 'invalid image reference "Alpine"'],
      // #83: a repeated parameter could be read two ways.
      [
        "/images/create?fromImage=alpine&fromImage=attacker%2Fmalware&tag=1",
        undefined,
        Action.Deny,
        "",
        "duplicate fromImage query parameter",
      ],
      // #83: the daemon rejects a malformed query; so does the proxy.
      ["/images/create?fromImage=alpine%zz&tag=1", undefined, Action.Deny, "", "invalid query string"],
      // #53 still holds: the percent check reads the path, not the query.
      ["/images/%63reate?fromImage=alpine&tag=1", undefined, Action.Deny, "", "percent-encoded path not allowed"],
    ];
    const mismatches: string[] = [];
    for (const [path, body, want, service, wantMsg] of cases) {
      const r = router.route("POST", path, body);
      if (r.action !== want || (r.service ?? "") !== service || (r.denyMsg ?? "") !== wantMsg) {
        mismatches.push(
          `POST ${path}: got ${Action[r.action]}/${r.service ?? ""}/${r.denyMsg ?? ""}, want ${Action[want]}/${service}/${wantMsg}`,
        );
      }
    }
    assert.deepEqual(mismatches, []);
  });

  // The normalisation table for #84, on the create route: each spelling
  // selects the policy its normalised repository matches, and a path with
  // upper case is invalid. The same table runs in Go and Rust.
  it("normalises image references before policy matching", () => {
    const notAllowed = (image: string) => `image ${image} not allowed by any policy`;
    const cases: [string, Action, string, string][] = [
      ["alpine", Action.CreateContainer, "probe", ""],
      ["library/alpine", Action.CreateContainer, "probe", ""],
      ["docker.io/library/alpine", Action.CreateContainer, "probe", ""],
      ["docker.io/alpine", Action.CreateContainer, "probe", ""],
      ["index.docker.io/library/alpine:3.19", Action.CreateContainer, "probe", ""],
      ["docker.io/chainsafe/lodestar:v1", Action.CreateContainer, "beacon", ""],
      ["chainsafe/lodestar:v1", Action.CreateContainer, "beacon", ""],
      ["registry-1.docker.io/chainsafe/lodestar:v1", Action.CreateContainer, "beacon", ""],
      [`ghcr.io/chainsafe/lodestar@${TEST_DIGEST}`, Action.CreateContainer, "beacon", ""],
      ["localhost:5000/x/y:2", Action.CreateContainer, "beacon", ""],
      ["registry.example.com:443/a", Action.CreateContainer, "beacon", ""],
      ["Alpine:latest", Action.Deny, "", 'invalid image reference "Alpine:latest"'],
      ["chainsafe/Lodestar:v1", Action.Deny, "", 'invalid image reference "chainsafe/Lodestar:v1"'],
      ["alpine-evil", Action.Deny, "", notAllowed("alpine-evil")],
      ["ghcr.io/library/alpine", Action.Deny, "", notAllowed("ghcr.io/library/alpine")],
      ["ghcr.io/chainsafe/lodestar-evil", Action.Deny, "", notAllowed("ghcr.io/chainsafe/lodestar-evil")],
      ["localhost:5000/xy:1", Action.Deny, "", notAllowed("localhost:5000/xy:1")],
    ];
    const mismatches: string[] = [];
    for (const [image, want, service, wantMsg] of cases) {
      const r = router.route("POST", "/containers/create", { Image: image });
      if (r.action !== want || (r.service ?? "") !== service || (r.denyMsg ?? "") !== wantMsg) {
        mismatches.push(
          `create ${image}: got ${Action[r.action]}/${r.service ?? ""}/${r.denyMsg ?? ""}, want ${Action[want]}/${service}/${wantMsg}`,
        );
      }
    }
    assert.deepEqual(mismatches, []);
  });
});
