import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { Chain, RegistryGate, MountSourceGate, EnvFileGate, CmdGate, ContainerConfigMutator } from "./middleware.js";
import type { Policy } from "./policy.js";

function makePolicy(overrides: Partial<Policy> = {}): Policy {
  return {
    service_name: "test-svc",
    allowed_image_prefixes: ["nginx"],
    ...overrides,
  };
}

describe("RegistryGate", () => {
  const gate = new RegistryGate();

  it("allows image matching allowed prefix", () => {
    assert.equal(gate.check("POST", "/containers/create", makePolicy(), { Image: "nginx:latest" }), null);
  });

  it("allows image matching prefix with org", () => {
    assert.equal(
      gate.check("POST", "/containers/create", makePolicy({ allowed_image_prefixes: ["myorg"] }), {
        Image: "myorg/app:v1",
      }),
      null,
    );
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
    assert.equal(
      gate.check("POST", "/containers/create", makePolicy(), { HostConfig: { Binds: ["/data:/data"] } }),
      null,
    );
  });

  it("returns null when no Binds", () => {
    assert.equal(
      gate.check(
        "POST",
        "/containers/create",
        makePolicy({ volumes: [{ host_path: "/data", container_path: "/data", read_write: true }] }),
        {},
      ),
      null,
    );
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
    const chain = new Chain();
    const policy = makePolicy({ allowed_cli_flags: ["--port"] });
    const body: Record<string, unknown> = { Image: "nginx:latest" };
    const result = chain.execute("POST", "/containers/create", policy, body);
    assert.ok(result.allowed);
    assert.ok(result.modifiedBody);
  });

  // When the policy forces network_mode, the endpoint entries in
  // NetworkingConfig.EndpointsConfig are made consistent with it (#87). Before
  // #87 they went through as sent, so the Docker CLI's {"default": {}} made the
  // start fail with "network default not found", and an extra entry attached
  // the container to a network the policy does not allow. Rows mirror the runs
  // in the network_endpoints module of spec/docker_socket_policy.qnt; mynet
  // stands for a named network and container:beacon for container:x.
  it("makes NetworkingConfig endpoints consistent with a forced network_mode", () => {
    const aliases = { Aliases: ["a"] };
    const ec = (entries: Record<string, unknown>) => ({ EndpointsConfig: entries });
    const extra = (mode: string) =>
      `network "other" is not allowed for service test-svc; policy forces network_mode ${mode}`;
    const malformed = "NetworkingConfig.EndpointsConfig must be a JSON object; policy forces network_mode host";
    const both = ec({ default: {}, other: {} });
    // [row, forced mode ("" = none), NetworkingConfig sent (undefined = absent),
    //  NetworkingConfig forwarded when allowed, deny reason when denied]
    const cases: [string, string, unknown, unknown, string | undefined][] = [
      ["hostNoEndpoints", "host", undefined, ec({}), undefined],
      ["hostDefaultCleared", "host", ec({ default: {} }), ec({}), undefined],
      ["hostOwnCleared", "host", ec({ host: aliases }), ec({}), undefined],
      ["hostExtraDenied", "host", both, undefined, extra("host")],
      ["noneNoEndpoints", "none", undefined, ec({}), undefined],
      ["noneDefaultCleared", "none", ec({ default: {} }), ec({}), undefined],
      ["noneOwnCleared", "none", ec({ none: aliases }), ec({}), undefined],
      ["noneExtraDenied", "none", both, undefined, extra("none")],
      ["containerNoEndpoints", "container:beacon", undefined, ec({}), undefined],
      ["containerDefaultCleared", "container:beacon", ec({ default: {} }), ec({}), undefined],
      ["containerOwnCleared", "container:beacon", ec({ "container:beacon": aliases }), ec({}), undefined],
      ["containerExtraDenied", "container:beacon", both, undefined, extra("container:beacon")],
      ["bridgeNoEndpoints", "bridge", undefined, ec({ bridge: {} }), undefined],
      ["bridgeDefaultRekeyed", "bridge", ec({ default: aliases }), ec({ bridge: aliases }), undefined],
      ["bridgeOwnKept", "bridge", ec({ bridge: aliases }), ec({ bridge: aliases }), undefined],
      ["bridgeExtraDenied", "bridge", both, undefined, extra("bridge")],
      ["namedNoEndpoints", "mynet", undefined, ec({ mynet: {} }), undefined],
      ["namedDefaultRekeyed", "mynet", ec({ default: aliases }), ec({ mynet: aliases }), undefined],
      ["namedOwnKept", "mynet", ec({ mynet: aliases }), ec({ mynet: aliases }), undefined],
      ["namedExtraDenied", "mynet", both, undefined, extra("mynet")],
      ["namedOwnOverDefault", "mynet", ec({ default: aliases, mynet: {} }), ec({ mynet: {} }), undefined],
      // #87: a null NetworkingConfig or EndpointsConfig counts as absent.
      ["#87 null NetworkingConfig", "host", null, ec({}), undefined],
      ["#87 null EndpointsConfig", "bridge", { EndpointsConfig: null }, ec({ bridge: {} }), undefined],
      // #87: a NetworkingConfig or EndpointsConfig that is not an object is denied.
      ["#87 EndpointsConfig array", "host", { EndpointsConfig: [] }, undefined, malformed],
      ["#87 NetworkingConfig string", "host", "default", undefined, malformed],
      // #87 control: without a forced network_mode, NetworkingConfig is untouched.
      ["#87 no forced mode", "", both, both, undefined],
    ];
    const mismatches: string[] = [];
    for (const [row, mode, req, want, deny] of cases) {
      const policy = makePolicy({
        container_config: { network_mode: mode || undefined, restart_policy: "unless-stopped" },
      });
      const body: Record<string, unknown> = { Image: "nginx:latest" };
      if (req !== undefined) body["NetworkingConfig"] = JSON.parse(JSON.stringify(req));
      const result = new Chain().execute("POST", "/containers/create", policy, body);
      if (deny !== undefined) {
        if (result.allowed || !result.reason.includes(deny)) {
          mismatches.push(`${row}: got allowed=${result.allowed} ${result.reason}, want deny ${deny}`);
        }
        continue;
      }
      if (!result.allowed) {
        mismatches.push(`${row}: got deny ${result.reason}, want ${JSON.stringify(want)}`);
        continue;
      }
      const out = JSON.parse(result.modifiedBody!.toString()) as Record<string, unknown>;
      try {
        assert.deepStrictEqual(out["NetworkingConfig"], want);
      } catch {
        mismatches.push(`${row}: got ${JSON.stringify(out["NetworkingConfig"])}, want ${JSON.stringify(want)}`);
      }
    }
    assert.deepEqual(mismatches, []);
  });
});

// Pins the registry gate's reference parser (#84): a registry port is not a
// tag, Docker Hub spellings match the normalised prefix, and the tag pattern
// sees only the tag. The policy's prefixes are normalised, as the manager
// stores them. Same rows in Go and Rust.
describe("RegistryGate reference parsing (#84)", () => {
  it("parses registry ports, Docker Hub spellings and tags", () => {
    const gate = new RegistryGate();
    const policy = makePolicy({
      allowed_image_prefixes: ["chainsafe/lodestar", "localhost:5000/team", "registry.example.com:443/a"],
      image_tag_pattern: "^(v[0-9]+|[0-9.]+)$",
    });
    const cases: [string, string | null][] = [
      ["localhost:5000/team/app:1.2", null],
      ["localhost:5000/team/app", null],
      ["docker.io/chainsafe/lodestar:v1", null],
      ["registry.example.com:443/a", null],
      ["Registry.Example.com:443/a:2", null],
      ["localhost:5000/team/app:latest", 'image tag "latest" does not match pattern "^(v[0-9]+|[0-9.]+)$"'],
      ["localhost:5000/other:1", 'image "localhost:5000/other" is not in allowed prefixes'],
      ["chainsafe/Lodestar:v1", 'invalid image reference "chainsafe/Lodestar:v1"'],
    ];
    const mismatches: string[] = [];
    for (const [image, wantErr] of cases) {
      const got = gate.check("POST", "/containers/create", policy, { Image: image });
      const ok = wantErr === null ? got === null : got !== null && got.includes(wantErr);
      if (!ok) mismatches.push(`${image}: got ${got}, want ${wantErr}`);
    }
    assert.deepEqual(mismatches, []);
  });
});
