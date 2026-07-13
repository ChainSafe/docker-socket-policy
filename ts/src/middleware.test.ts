import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  Chain,
  ExecGate,
  ReadonlyGate,
  RegistryGate,
  MountSourceGate,
  EnvFileGate,
  CmdGate,
  ContainerConfigMutator,
} from "./middleware.js";
import type { Policy } from "./policy.js";

function makePolicy(overrides: Partial<Policy> = {}): Policy {
  return {
    service_name: "test-svc",
    allowed_image_prefixes: ["nginx"],
    ...overrides,
  };
}

describe("ExecGate", () => {
  const gate = new ExecGate();

  it("denies paths containing /exec", () => {
    const result = gate.check("POST", "/containers/foo/exec", makePolicy(), {});
    assert.notEqual(result, null);
    assert.ok(result?.includes("shell escape"));
  });

  it("allows non-exec paths", () => {
    assert.equal(gate.check("POST", "/containers/create", makePolicy(), {}), null);
  });
});

describe("ReadonlyGate", () => {
  const gate = new ReadonlyGate();

  for (const method of ["POST", "PUT", "DELETE", "PATCH"]) {
    it(`denies ${method} requests`, () => {
      const result = gate.check(method, "/containers/create", makePolicy(), {});
      assert.notEqual(result, null);
      assert.ok(result?.includes("read-only"));
    });
  }

  it("allows GET requests", () => {
    assert.equal(gate.check("GET", "/containers/json", makePolicy(), {}), null);
  });
});

describe("RegistryGate", () => {
  const gate = new RegistryGate();

  it("allows image matching allowed prefix", () => {
    assert.equal(gate.check("POST", "/containers/create", makePolicy(), { Image: "nginx:latest" }), null);
  });

  it("allows image matching prefix with org", () => {
    assert.equal(gate.check("POST", "/containers/create", makePolicy({ allowed_image_prefixes: ["myorg"] }), { Image: "myorg/app:v1" }), null);
  });

  it("denies image not in allowed prefixes", () => {
    const result = gate.check("POST", "/containers/create", makePolicy(), { Image: "redis:7" });
    assert.notEqual(result, null);
    assert.ok(result?.includes("not in allowed prefixes"));
  });

  it("returns null when no Image in body", () => {
    assert.equal(gate.check("POST", "/containers/create", makePolicy(), {}), null);
  });

  it("allows image with tag matching pattern", () => {
    const policy = makePolicy({ image_tag_pattern: "^v?[0-9]+\\.[0-9]+\\.[0-9]+$" });
    assert.equal(gate.check("POST", "/containers/create", policy, { Image: "nginx:v1.2.3" }), null);
  });

  it("denies image with tag not matching pattern", () => {
    const policy = makePolicy({ image_tag_pattern: "^v?[0-9]+\\.[0-9]+\\.[0-9]+$" });
    const result = gate.check("POST", "/containers/create", policy, { Image: "nginx:latest" });
    assert.notEqual(result, null);
    assert.ok(result?.includes("does not match pattern"));
  });

  it("allows digest when image_digest_allowed is true", () => {
    const policy = makePolicy({ image_digest_allowed: true });
    assert.equal(
      gate.check("POST", "/containers/create", policy, {
        Image: "nginx@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
      }),
      null,
    );
  });

  it("denies digest when image_digest_allowed is false", () => {
    const policy = makePolicy({ image_digest_allowed: false });
    const result = gate.check("POST", "/containers/create", policy, {
      Image: "nginx@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
    });
    assert.notEqual(result, null);
    assert.ok(result?.includes("digests not allowed"));
  });

  it("denies invalid digest format", () => {
    const policy = makePolicy({ image_digest_allowed: true });
    const result = gate.check("POST", "/containers/create", policy, {
      Image: "nginx@sha256:xyz",
    });
    assert.notEqual(result, null);
    assert.ok(result?.includes("invalid digest format"));
  });

  it("denies tag longer than 128 characters", () => {
    const policy = makePolicy({});
    const longTag = "a".repeat(129);
    const result = gate.check("POST", "/containers/create", policy, { Image: `nginx:${longTag}` });
    assert.notEqual(result, null);
    assert.ok(result?.includes("exceeds 128"));
  });
});

describe("MountSourceGate", () => {
  const gate = new MountSourceGate();

  it("allows mounts in whitelist", () => {
    const policy = makePolicy({
      volumes: [{ host_path: "/data", container_path: "/data", read_write: true }],
    });
    const body = { HostConfig: { Binds: ["/data:/data"] } };
    assert.equal(gate.check("POST", "/containers/create", policy, body), null);
  });

  it("denies mounts not in whitelist", () => {
    const policy = makePolicy({
      volumes: [{ host_path: "/data", container_path: "/data", read_write: true }],
    });
    const body = { HostConfig: { Binds: ["/other:/other"] } };
    const result = gate.check("POST", "/containers/create", policy, body);
    assert.notEqual(result, null);
    assert.ok(result?.includes("not in the whitelist"));
  });

  it("returns null when no volumes in policy", () => {
    assert.equal(gate.check("POST", "/containers/create", makePolicy(), { HostConfig: { Binds: ["/data:/data"] } }), null);
  });

  it("returns null when no Binds", () => {
    assert.equal(gate.check("POST", "/containers/create", makePolicy({ volumes: [{ host_path: "/data", container_path: "/data", read_write: true }] }), {}), null);
  });

  it("allows top-level Volumes in whitelist", () => {
    const policy = makePolicy({
      volumes: [{ host_path: "/data", container_path: "/data", read_write: true }],
    });
    assert.equal(gate.check("POST", "/containers/create", policy, { Volumes: { "/data": {} } }), null);
  });

  it("denies top-level Volumes not in whitelist", () => {
    const policy = makePolicy({
      volumes: [{ host_path: "/data", container_path: "/data", read_write: true }],
    });
    const result = gate.check("POST", "/containers/create", policy, { Volumes: { "/other": {} } });
    assert.notEqual(result, null);
    assert.ok(result?.includes("not in the whitelist"));
  });
});

describe("EnvFileGate", () => {
  const gate = new EnvFileGate();

  it("returns null when no env_file in policy", () => {
    assert.equal(gate.check("POST", "/containers/create", makePolicy(), { Env: ["FOO=bar"] }), null);
  });

  it("denies inline env when env_file is set", () => {
    const policy = makePolicy({ env_file: "/app/.env" });
    const result = gate.check("POST", "/containers/create", policy, { Env: ["FOO=bar"] });
    assert.notEqual(result, null);
    assert.ok(result?.includes("env_file"));
  });

  it("returns null when env_file is set but no Env in body", () => {
    const policy = makePolicy({ env_file: "/app/.env" });
    assert.equal(gate.check("POST", "/containers/create", policy, {}), null);
  });

  it("denies inline env in HostConfig when env_file is set", () => {
    const policy = makePolicy({ env_file: "/app/.env" });
    const result = gate.check("POST", "/containers/create", policy, { HostConfig: { Env: ["FOO=bar"] } });
    assert.notEqual(result, null);
    assert.ok(result?.includes("HostConfig"));
    assert.ok(result?.includes("env_file"));
  });
});

describe("CmdGate", () => {
  const gate = new CmdGate();

  it("returns null when no Cmd", () => {
    assert.equal(gate.check("POST", "/containers/create", makePolicy(), {}), null);
  });

  it("allows safe Cmd arguments without flags", () => {
    const policy = makePolicy({ allowed_cli_flags: ["--port"] });
    assert.equal(gate.check("POST", "/containers/create", policy, { Cmd: ["node", "app.js"] }), null);
  });

  it("denies Cmd with denied flag", () => {
    const policy = makePolicy({ allowed_cli_flags: ["--port"], denied_flags: ["--debug"] });
    const result = gate.check("POST", "/containers/create", policy, { Cmd: ["--debug=true"] });
    assert.notEqual(result, null);
    assert.ok(result?.includes("denied"));
  });

  it("denies Cmd with flag not in allowlist", () => {
    const policy = makePolicy({ allowed_cli_flags: ["--port"] });
    const result = gate.check("POST", "/containers/create", policy, { Cmd: ["--unknown=val"] });
    assert.notEqual(result, null);
    assert.ok(result?.includes("not in the allowlist"));
  });

  it("allows flag value matching pattern in --flag=value form", () => {
    const policy = makePolicy({
      allowed_cli_flags: ["--port"],
      flag_rules: [{ flag: "--port", value_pattern: "^[0-9]+$" }],
    });
    assert.equal(gate.check("POST", "/containers/create", policy, { Cmd: ["--port=8080"] }), null);
  });

  it("allows flag value matching pattern in --flag value form", () => {
    const policy = makePolicy({
      allowed_cli_flags: ["--port"],
      flag_rules: [{ flag: "--port", value_pattern: "^[0-9]+$" }],
    });
    assert.equal(gate.check("POST", "/containers/create", policy, { Cmd: ["--port", "8080"] }), null);
  });

  it("denies flag value not matching pattern", () => {
    const policy = makePolicy({
      allowed_cli_flags: ["--port"],
      flag_rules: [{ flag: "--port", value_pattern: "^[0-9]+$" }],
    });
    const result = gate.check("POST", "/containers/create", policy, { Cmd: ["--port=abc"] });
    assert.notEqual(result, null);
    assert.ok(result?.includes("does not match pattern"));
  });
});

describe("ContainerConfigMutator", () => {
  it("sets network mode", () => {
    const policy = makePolicy({ container_config: { network_mode: "host" } });
    const body: Record<string, unknown> = {};
    new ContainerConfigMutator().mutate(policy, body);
    assert.equal((body["HostConfig"] as Record<string, unknown>)["NetworkMode"], "host");
  });

  it("sets restart policy", () => {
    const policy = makePolicy({ container_config: { restart_policy: "always" } });
    const body: Record<string, unknown> = {};
    new ContainerConfigMutator().mutate(policy, body);
    assert.deepEqual((body["HostConfig"] as Record<string, unknown>)["RestartPolicy"], { Name: "always" });
  });

  it("forces Privileged to false when container_config is set", () => {
    const policy = makePolicy({ container_config: { network_mode: "bridge" } });
    const body: Record<string, unknown> = {};
    new ContainerConfigMutator().mutate(policy, body);
    assert.equal((body["HostConfig"] as Record<string, unknown>)["Privileged"], false);
  });

  it("sets security options", () => {
    const policy = makePolicy({ container_config: { security_options: ["no-new-privileges"] } });
    const body: Record<string, unknown> = {};
    new ContainerConfigMutator().mutate(policy, body);
    assert.deepEqual((body["HostConfig"] as Record<string, unknown>)["SecurityOpt"], ["no-new-privileges"]);
  });
});

describe("Chain", () => {
  it("allows valid create container request", () => {
    const chain = new Chain(false);
    const policy = makePolicy({ allowed_cli_flags: ["--port"] });
    const body: Record<string, unknown> = { Image: "nginx:latest" };
    const result = chain.execute("POST", "/containers/create", policy, body);
    assert.ok(result.allowed);
    assert.ok(result.modifiedBody);
  });

  it("denies exec request", () => {
    const chain = new Chain(false);
    const result = chain.execute("POST", "/containers/foo/exec", makePolicy(), {});
    assert.equal(result.allowed, false);
    assert.ok(result.reason.includes("exec"));
  });

  it("denies readonly mode write request", () => {
    const chain = new Chain(true);
    const result = chain.execute("POST", "/containers/create", makePolicy(), { Image: "nginx:latest" });
    assert.equal(result.allowed, false);
    assert.ok(result.reason.includes("read-only"));
  });
});
