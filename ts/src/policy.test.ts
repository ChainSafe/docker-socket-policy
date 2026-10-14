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

describe("Manager container names", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "policy-names-"));
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  // The cross-language parity guard for the #85 load-time checks. Two
  // policies conflict when their image prefixes share a namespace and one has
  // no container_names or their container_names intersect. Before #85 every
  // row loaded, and a duplicate service_name silently replaced the first file.
  it("validates policies at load time", () => {
    const cases: [string, Record<string, string>, string][] = [
      [
        "same prefix, no container_names",
        {
          "a.yaml": "service_name: a\nallowed_image_prefixes: [alpine]\n",
          "b.yaml": "service_name: b\nallowed_image_prefixes: [alpine]\n",
        },
        'conflicting policies "a" (a.yaml) and "b" (b.yaml): image prefixes "alpine" and "alpine" overlap and "a" has no container_names',
      ],
      [
        "one side has no container_names",
        {
          "a.yaml": "service_name: a\ncontainer_names: [x]\nallowed_image_prefixes: [chainsafe/lodestar]\n",
          "b.yaml": "service_name: b\nallowed_image_prefixes: [chainsafe]\n",
        },
        'conflicting policies "a" (a.yaml) and "b" (b.yaml): image prefixes "chainsafe/lodestar" and "chainsafe" overlap and "b" has no container_names',
      ],
      [
        "shared container name",
        {
          "a.yaml": "service_name: a\ncontainer_names: [x, y]\nallowed_image_prefixes: [chainsafe/lodestar]\n",
          "b.yaml": "service_name: b\ncontainer_names: [z, y]\nallowed_image_prefixes: [chainsafe/lodestar]\n",
        },
        'conflicting policies "a" (a.yaml) and "b" (b.yaml): image prefixes "chainsafe/lodestar" and "chainsafe/lodestar" overlap and both accept container name "y"',
      ],
      [
        "disjoint container names",
        {
          "a.yaml": "service_name: a\ncontainer_names: [beacon]\nallowed_image_prefixes: [chainsafe/lodestar]\n",
          "b.yaml": "service_name: b\ncontainer_names: [validator]\nallowed_image_prefixes: [chainsafe/lodestar]\n",
        },
        "",
      ],
      [
        "sibling prefixes do not overlap",
        {
          "a.yaml": "service_name: a\nallowed_image_prefixes: [chainsafe/lodestar]\n",
          "b.yaml": "service_name: b\nallowed_image_prefixes: [chainsafe/lodestar-backup]\n",
        },
        "",
      ],
      [
        "duplicate service_name",
        {
          "a.yaml": "service_name: svc\nallowed_image_prefixes: [alpine]\n",
          "b.yaml": "service_name: svc\nallowed_image_prefixes: [busybox]\n",
        },
        'policies in a.yaml and b.yaml both use service_name "svc"',
      ],
      [
        "invalid container name",
        { "a.yaml": "service_name: a\ncontainer_names: [-bad]\nallowed_image_prefixes: [alpine]\n" },
        'invalid container name "-bad" in container_names',
      ],
      [
        "container name with a slash",
        { "a.yaml": "service_name: a\ncontainer_names: [a/b]\nallowed_image_prefixes: [alpine]\n" },
        'invalid container name "a/b" in container_names',
      ],
      [
        "empty container_names",
        { "a.yaml": "service_name: a\ncontainer_names: []\nallowed_image_prefixes: [alpine]\n" },
        "container_names must not be empty",
      ],
      // container_config.group_add (#93).
      [
        "group_add GIDs and names",
        {
          "a.yaml":
            "service_name: a\nallowed_image_prefixes: [alpine]\ncontainer_config:\n  group_add: ['64190', '4294967295', jwt, _x-1, 'samba$', abcdefghijklmnopqrstuvwxyz012345]\n",
        },
        "",
      ],
      [
        "group_add empty",
        { "a.yaml": "service_name: a\nallowed_image_prefixes: [alpine]\ncontainer_config:\n  group_add: []\n" },
        "",
      ],
      [
        "group_add 0",
        {
          "a.yaml":
            "service_name: a\nallowed_image_prefixes: [alpine]\ncontainer_config:\n  group_add: ['64190', '0']\n",
        },
        'policy file a.yaml: group_add entry "0" is the root group, which is not allowed',
      ],
      [
        "group_add 00",
        { "a.yaml": "service_name: a\nallowed_image_prefixes: [alpine]\ncontainer_config:\n  group_add: ['00']\n" },
        'policy file a.yaml: group_add entry "00" is the root group, which is not allowed',
      ],
      [
        "group_add root",
        { "a.yaml": "service_name: a\nallowed_image_prefixes: [alpine]\ncontainer_config:\n  group_add: [root]\n" },
        'policy file a.yaml: group_add entry "root" is the root group, which is not allowed',
      ],
      [
        "group_add duplicate",
        {
          "a.yaml":
            "service_name: a\nallowed_image_prefixes: [alpine]\ncontainer_config:\n  group_add: ['64190', jwt, '64190']\n",
        },
        'policy file a.yaml: duplicate group_add entry "64190"',
      ],
      [
        "group_add duplicate GID with leading zero",
        {
          "a.yaml":
            "service_name: a\nallowed_image_prefixes: [alpine]\ncontainer_config:\n  group_add: ['64190', '064190']\n",
        },
        'policy file a.yaml: duplicate group_add entry "064190"',
      ],
      [
        "group_add GID too large",
        {
          "a.yaml":
            "service_name: a\nallowed_image_prefixes: [alpine]\ncontainer_config:\n  group_add: ['4294967296']\n",
        },
        'policy file a.yaml: invalid group_add entry "4294967296"',
      ],
      [
        "group_add upper-case name",
        { "a.yaml": "service_name: a\nallowed_image_prefixes: [alpine]\ncontainer_config:\n  group_add: [Jwt]\n" },
        'policy file a.yaml: invalid group_add entry "Jwt"',
      ],
      [
        "group_add name with a space",
        { "a.yaml": "service_name: a\nallowed_image_prefixes: [alpine]\ncontainer_config:\n  group_add: ['a b']\n" },
        'policy file a.yaml: invalid group_add entry "a b"',
      ],
      [
        "group_add name starting with a dash",
        { "a.yaml": "service_name: a\nallowed_image_prefixes: [alpine]\ncontainer_config:\n  group_add: ['-x']\n" },
        'policy file a.yaml: invalid group_add entry "-x"',
      ],
      [
        "group_add name of 33 characters",
        {
          "a.yaml":
            "service_name: a\nallowed_image_prefixes: [alpine]\ncontainer_config:\n  group_add: [abcdefghijklmnopqrstuvwxyz0123456]\n",
        },
        'policy file a.yaml: invalid group_add entry "abcdefghijklmnopqrstuvwxyz0123456"',
      ],
      [
        "group_add empty string",
        { "a.yaml": "service_name: a\nallowed_image_prefixes: [alpine]\ncontainer_config:\n  group_add: ['']\n" },
        'policy file a.yaml: invalid group_add entry ""',
      ],
      [
        "group_add unquoted number",
        { "a.yaml": "service_name: a\nallowed_image_prefixes: [alpine]\ncontainer_config:\n  group_add: [64190]\n" },
        "group_add entries must be strings",
      ],
    ];
    const mismatches: string[] = [];
    for (const [name, files, want] of cases) {
      const dir = mkdtempSync(join(tmpDir, "case-"));
      for (const [file, content] of Object.entries(files)) writeFileSync(join(dir, file), content);
      let err: string | undefined;
      try {
        new Manager(dir);
      } catch (e) {
        err = (e as Error).message;
      }
      if (want === "" && err !== undefined) mismatches.push(`${name}: ${err}`);
      if (want !== "" && err === undefined) mismatches.push(`${name}: loaded, want error ${want}`);
      if (want !== "" && err !== undefined && !err.includes(want))
        mismatches.push(`${name}: error ${err}, want ${want}`);
    }
    assert.deepEqual(mismatches, []);
  });

  // An empty group_add is the same as an unset one (#93).
  it("treats an empty group_add as unset", () => {
    writeFileSync(
      join(tmpDir, "a.yaml"),
      "service_name: a\nallowed_image_prefixes: [alpine]\ncontainer_config:\n  group_add: []\n",
    );
    const m = new Manager(tmpDir);
    assert.equal(m.get("a")!.container_config!.group_add, undefined);
  });

  // #85 selection: the one policy matching the image and accepting the name,
  // the nameless create, and ambiguity.
  it("selects the create policy by image and name", () => {
    const beacon = {
      service_name: "beacon",
      container_names: ["beacon"],
      allowed_image_prefixes: ["chainsafe/lodestar"],
    };
    const validator = {
      service_name: "validator",
      container_names: ["validator"],
      allowed_image_prefixes: ["chainsafe/lodestar"],
    };
    let m = Manager.fromPolicies([validator, beacon, { service_name: "any", allowed_image_prefixes: ["chainsafe"] }]);
    for (let i = 0; i < 50; i++) {
      for (const name of ["beacon", "validator"]) {
        assert.deepEqual(m.selectForCreate("chainsafe/lodestar:v1", name), {
          error: `ambiguous policy for image chainsafe/lodestar:v1 and name ${name}: any, ${name}`,
        });
      }
    }
    const nameless = m.selectForCreate("chainsafe/lodestar:v1", "");
    assert.ok("policy" in nameless && nameless.policy.service_name === "any");

    m = Manager.fromPolicies([validator, beacon]);
    for (let i = 0; i < 50; i++) {
      for (const name of ["beacon", "validator"]) {
        const got = m.selectForCreate("chainsafe/lodestar:v1", name);
        assert.ok("policy" in got && got.policy.service_name === name, `iteration ${i}: ${JSON.stringify(got)}`);
      }
    }
  });

  it("reports the policies covering a name", () => {
    const m = Manager.fromPolicies([
      { service_name: "beacon", allowed_image_prefixes: ["chainsafe/lodestar"] },
      { service_name: "vc", container_names: ["validator"], allowed_image_prefixes: ["chainsafe/lodestar"] },
    ]);
    for (const [name, want] of [
      ["beacon", 1],
      ["validator", 1],
      ["vc", 0],
      ["other", 0],
    ] as const) {
      assert.equal(m.covering(name).length, want, `covering(${name})`);
    }
  });
});
