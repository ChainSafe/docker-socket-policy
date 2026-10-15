import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  Chain,
  RegistryGate,
  MountSourceGate,
  EnvFileGate,
  CmdGate,
  ContainerConfigMutator,
  HostConfigGate,
} from "./middleware.js";
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

  it("denies binds when no volumes in policy", () => {
    // A policy with no volumes allows no binds (#88); before #88 the gate
    // returned early and let every bind through.
    const result = gate.check("POST", "/containers/create", makePolicy(), { HostConfig: { Binds: ["/data:/data"] } });
    assert.ok(result?.includes("not in the whitelist"));
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

// HostConfig default-deny, Mounts and bind-mode rows (#88). The same rows, by
// name, are in go/internal/middleware/hostconfig_test.go and
// rs/src/middleware.rs.
//
// Policies: "std" has volumes /data (read_write) and /ro (read-only) and
// forces network_mode host; "secopt" is "std" plus security_options
// [no-new-privileges:true]; "bare" has no volumes and no container_config;
// "groups" is "std" plus group_add ["64190", "jwt"] (#93).
// want is "" for an allowed create, or a substring of the deny reason. fwd,
// when set, lists HostConfig fields the forwarded body must hold.
interface HostConfigRow {
  name: string;
  policy: string;
  body: string;
  want: string;
  fwd: string;
}

function hostConfigRowPolicy(name: string): Policy {
  const p: Policy = { service_name: "svc", allowed_image_prefixes: ["chainsafe/lodestar"] };
  if (name === "bare") return p;
  p.volumes = [
    { host_path: "/data", container_path: "/data", read_write: true },
    { host_path: "/ro", container_path: "/ro", read_write: false },
  ];
  p.container_config = { network_mode: "host" };
  if (name === "secopt") p.container_config.security_options = ["no-new-privileges:true"];
  if (name === "groups") p.container_config.group_add = ["64190", "jwt"];
  return p;
}

const hostConfigRows: HostConfigRow[] = [
  {
    name: "capAddDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"CapAdd":["SYS_ADMIN"]}}`,
    want: "HostConfig.CapAdd is not allowed for service svc",
    fwd: String.raw``,
  },
  {
    name: "devicesDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Devices":[{"PathOnHost":"/dev/sda","PathInContainer":"/dev/sda","CgroupPermissions":"rwm"}]}}`,
    want: "HostConfig.Devices is not allowed for service svc",
    fwd: String.raw``,
  },
  {
    name: "deviceRequestsDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"DeviceRequests":[{"Driver":"","Count":-1,"Capabilities":[["gpu"]]}]}}`,
    want: "HostConfig.DeviceRequests is not allowed for service svc",
    fwd: String.raw``,
  },
  {
    name: "deviceCgroupRulesDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"DeviceCgroupRules":["b 8:* rmw"]}}`,
    want: "HostConfig.DeviceCgroupRules is not allowed for service svc",
    fwd: String.raw``,
  },
  {
    name: "groupAddDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"GroupAdd":["docker"]}}`,
    want: "HostConfig.GroupAdd is not allowed for service svc",
    fwd: String.raw``,
  },
  {
    name: "groupAddPolicyListWithoutGroupAddDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"GroupAdd":["64190","jwt"]}}`,
    want: "HostConfig.GroupAdd is not allowed for service svc",
    fwd: String.raw``,
  },
  {
    name: "groupAddForced",
    policy: "groups",
    body: String.raw`{"Image":"chainsafe/lodestar:v1"}`,
    want: "",
    fwd: String.raw`{"GroupAdd":["64190","jwt"]}`,
  },
  {
    name: "groupAddForcedNullHostConfig",
    policy: "groups",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":null}`,
    want: "",
    fwd: String.raw`{"GroupAdd":["64190","jwt"]}`,
  },
  {
    name: "groupAddCallerReplaced",
    policy: "groups",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"GroupAdd":["docker","0"]}}`,
    want: "",
    fwd: String.raw`{"GroupAdd":["64190","jwt"]}`,
  },
  {
    name: "groupAddCallerNullReplaced",
    policy: "groups",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"GroupAdd":null}}`,
    want: "",
    fwd: String.raw`{"GroupAdd":["64190","jwt"]}`,
  },
  {
    name: "groupAddSameListUnchanged",
    policy: "groups",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"GroupAdd":["64190","jwt"]}}`,
    want: "",
    fwd: String.raw`{"GroupAdd":["64190","jwt"]}`,
  },
  {
    name: "groupAddCaseVariantDenied",
    policy: "groups",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"groupadd":["0"]}}`,
    want: "HostConfig.groupadd is not allowed for service svc",
    fwd: String.raw``,
  },
  {
    name: "groupAddNonObjectHostConfigDenied",
    policy: "groups",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":["GroupAdd"]}`,
    want: "HostConfig must be an object for service svc",
    fwd: String.raw``,
  },

  {
    name: "volumesFromDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"VolumesFrom":["other"]}}`,
    want: "HostConfig.VolumesFrom is not allowed for service svc",
    fwd: String.raw``,
  },
  {
    name: "linksDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Links":["other:alias"]}}`,
    want: "HostConfig.Links is not allowed for service svc",
    fwd: String.raw``,
  },
  {
    name: "sysctlsDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Sysctls":{"kernel.shm_rmid_forced":"1"}}}`,
    want: "HostConfig.Sysctls is not allowed for service svc",
    fwd: String.raw``,
  },
  {
    name: "cgroupParentDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"CgroupParent":"/"}}`,
    want: "HostConfig.CgroupParent is not allowed for service svc",
    fwd: String.raw``,
  },
  {
    name: "runtimeDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Runtime":"other"}}`,
    want: "HostConfig.Runtime is not allowed for service svc",
    fwd: String.raw``,
  },
  {
    name: "volumeDriverDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"VolumeDriver":"local"}}`,
    want: "HostConfig.VolumeDriver is not allowed for service svc",
    fwd: String.raw``,
  },
  {
    name: "oomKillDisableDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"OomKillDisable":true}}`,
    want: "HostConfig.OomKillDisable is not allowed for service svc",
    fwd: String.raw``,
  },
  {
    name: "annotationsDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Annotations":{"a":"b"}}}`,
    want: "HostConfig.Annotations is not allowed for service svc",
    fwd: String.raw``,
  },
  {
    name: "storageOptDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"StorageOpt":{"size":"1G"}}}`,
    want: "HostConfig.StorageOpt is not allowed for service svc",
    fwd: String.raw``,
  },
  {
    name: "blkioDeviceReadBpsDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"BlkioDeviceReadBps":[{"Path":"/dev/sda","Rate":1}]}}`,
    want: "HostConfig.BlkioDeviceReadBps is not allowed for service svc",
    fwd: String.raw``,
  },
  {
    name: "cpuRealtimeRuntimeDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"CpuRealtimeRuntime":1000}}`,
    want: "HostConfig.CpuRealtimeRuntime is not allowed for service svc",
    fwd: String.raw``,
  },
  {
    name: "unknownFieldDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"FutureField":true}}`,
    want: "HostConfig.FutureField is not allowed for service svc",
    fwd: String.raw``,
  },
  {
    name: "maskedPathsEmptyDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"MaskedPaths":[]}}`,
    want: "HostConfig.MaskedPaths is not allowed for service svc",
    fwd: String.raw``,
  },
  {
    name: "readonlyPathsEmptyDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"ReadonlyPaths":[]}}`,
    want: "HostConfig.ReadonlyPaths is not allowed for service svc",
    fwd: String.raw``,
  },
  {
    name: "maskedPathsListDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"MaskedPaths":["/proc/kcore"]}}`,
    want: "HostConfig.MaskedPaths is not allowed for service svc",
    fwd: String.raw``,
  },
  {
    name: "zeroValuesAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"CapAdd":null,"Devices":[],"GroupAdd":null,"Sysctls":{},"CgroupParent":"","OomKillDisable":false,"Runtime":"","VolumeDriver":"","FutureField":0,"MaskedPaths":null,"ReadonlyPaths":null,"PidMode":"","IpcMode":"","SecurityOpt":null,"OomScoreAdj":0,"Privileged":false}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "pidModeHostDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"PidMode":"host"}}`,
    want: 'HostConfig.PidMode value "host" is not allowed for service svc',
    fwd: String.raw``,
  },
  {
    name: "pidModeContainerDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"PidMode":"container:abc"}}`,
    want: 'HostConfig.PidMode value "container:abc" is not allowed',
    fwd: String.raw``,
  },
  {
    name: "ipcModeHostDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"IpcMode":"host"}}`,
    want: 'HostConfig.IpcMode value "host" is not allowed',
    fwd: String.raw``,
  },
  {
    name: "ipcModeContainerDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"IpcMode":"container:abc"}}`,
    want: 'HostConfig.IpcMode value "container:abc" is not allowed',
    fwd: String.raw``,
  },
  {
    name: "utsModeHostDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"UTSMode":"host"}}`,
    want: 'HostConfig.UTSMode value "host" is not allowed',
    fwd: String.raw``,
  },
  {
    name: "usernsModeHostDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"UsernsMode":"host"}}`,
    want: 'HostConfig.UsernsMode value "host" is not allowed',
    fwd: String.raw``,
  },
  {
    name: "cgroupnsModeHostDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"CgroupnsMode":"host"}}`,
    want: 'HostConfig.CgroupnsMode value "host" is not allowed',
    fwd: String.raw``,
  },
  {
    name: "cgroupContainerDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Cgroup":"container:abc"}}`,
    want: 'HostConfig.Cgroup value "container:abc" is not allowed',
    fwd: String.raw``,
  },
  {
    name: "isolationHypervDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Isolation":"hyperv"}}`,
    want: 'HostConfig.Isolation value "hyperv" is not allowed',
    fwd: String.raw``,
  },
  {
    name: "ipcModePrivateAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"IpcMode":"private"}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "ipcModeShareableAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"IpcMode":"shareable"}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "ipcModeNoneAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"IpcMode":"none"}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "cgroupnsModePrivateAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"CgroupnsMode":"private"}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "isolationDefaultAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Isolation":"default"}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "oomScoreAdjNegativeDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"OomScoreAdj":-1000}}`,
    want: "HostConfig.OomScoreAdj value -1000 is not allowed",
    fwd: String.raw``,
  },
  {
    name: "oomScoreAdjPositiveAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"OomScoreAdj":500}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "securityOptSeccompUnconfinedDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"SecurityOpt":["seccomp=unconfined"]}}`,
    want: 'HostConfig.SecurityOpt entry "seccomp=unconfined" is not allowed',
    fwd: String.raw``,
  },
  {
    name: "securityOptApparmorUnconfinedDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"SecurityOpt":["apparmor=unconfined"]}}`,
    want: 'HostConfig.SecurityOpt entry "apparmor=unconfined" is not allowed',
    fwd: String.raw``,
  },
  {
    name: "securityOptLabelDisableDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"SecurityOpt":["label=disable"]}}`,
    want: 'HostConfig.SecurityOpt entry "label=disable" is not allowed',
    fwd: String.raw``,
  },
  {
    name: "securityOptNoNewPrivilegesFalseDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"SecurityOpt":["no-new-privileges:false"]}}`,
    want: 'HostConfig.SecurityOpt entry "no-new-privileges:false" is not allowed',
    fwd: String.raw``,
  },
  {
    name: "securityOptNoNewPrivilegesAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"SecurityOpt":["no-new-privileges"]}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "securityOptNoNewPrivilegesTrueAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"SecurityOpt":["no-new-privileges:true"]}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "securityOptOverwrittenByPolicy",
    policy: "secopt",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"SecurityOpt":["seccomp=unconfined"]}}`,
    want: "",
    fwd: String.raw`{"SecurityOpt":["no-new-privileges:true"]}`,
  },
  {
    name: "caseVariantPrivilegedDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"privileged":true}}`,
    want: "HostConfig.privileged is not allowed for service svc (the daemon reads it as HostConfig.Privileged)",
    fwd: String.raw``,
  },
  {
    name: "caseVariantZeroSecurityOptDenied",
    policy: "secopt",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"securityopt":null}}`,
    want: "HostConfig.securityopt is not allowed",
    fwd: String.raw``,
  },
  {
    name: "caseVariantBindsDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"binds":["/:/host"]}}`,
    want: "HostConfig.binds is not allowed",
    fwd: String.raw``,
  },
  {
    name: "caseVariantLongSDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"\u017fecurityOpt":["seccomp=unconfined"]}}`,
    want: "(the daemon reads it as HostConfig.SecurityOpt)",
    fwd: String.raw``,
  },
  {
    name: "caseVariantKelvinDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Lin\u212as":["other:alias"]}}`,
    want: "(the daemon reads it as HostConfig.Links)",
    fwd: String.raw``,
  },
  {
    name: "topLevelHostConfigVariantDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","hostConfig":{"Privileged":true}}`,
    want: "hostConfig is not allowed for service svc (the daemon reads it as HostConfig)",
    fwd: String.raw``,
  },
  {
    name: "topLevelUserVariantDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","user":"root"}`,
    want: "user is not allowed for service svc (the daemon reads it as User)",
    fwd: String.raw``,
  },
  {
    name: "topLevelImageVariantDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","image":"alpine:3.20"}`,
    want: "image is not allowed for service svc (the daemon reads it as Image)",
    fwd: String.raw``,
  },
  {
    name: "networkingConfigVariantDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","NetworkingConfig":{"EndpointsConfig":{"default":{}},"endpointsconfig":{"evil-net":{}}}}`,
    want: "NetworkingConfig.endpointsconfig is not allowed for service svc (the daemon reads it as NetworkingConfig.EndpointsConfig)",
    fwd: String.raw``,
  },
  {
    name: "networkingConfigVariantBareDenied",
    policy: "bare",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","NetworkingConfig":{"EndpointsConfig":{"default":{}},"endpointsconfig":{"evil-net":{}}}}`,
    want: "NetworkingConfig.endpointsconfig is not allowed for service svc",
    fwd: String.raw``,
  },
  {
    name: "networkingConfigVariantLongSDenied",
    policy: "bare",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","NetworkingConfig":{"Endpoint\u017fConfig":{"evil-net":{}}}}`,
    want: "(the daemon reads it as NetworkingConfig.EndpointsConfig)",
    fwd: String.raw``,
  },
  {
    name: "networkingConfigUnforcedAllowed",
    policy: "bare",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","NetworkingConfig":{"EndpointsConfig":{"default":{},"other":{}}}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "hostConfigNotObjectDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":"x"}`,
    want: "HostConfig must be an object",
    fwd: String.raw``,
  },
  {
    name: "capDropAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"CapDrop":["ALL"]}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "readonlyRootfsAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"ReadonlyRootfs":true}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "initAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Init":true}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "autoRemoveAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"AutoRemove":true}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "consoleSizeAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"ConsoleSize":[24,80]}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "shmSizeAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"ShmSize":67108864}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "portBindingsAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"PortBindings":{"8080/tcp":[{"HostIp":"127.0.0.1","HostPort":"8080"}]}}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "publishAllPortsAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"PublishAllPorts":true}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "dnsAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Dns":["1.1.1.1"]}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "dnsOptionsAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"DnsOptions":["ndots:1"]}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "dnsSearchAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"DnsSearch":["example.com"]}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "extraHostsAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"ExtraHosts":["host:10.0.0.1"]}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "tmpfsAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Tmpfs":{"/run":"rw,noexec"}}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "ulimitsAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Ulimits":[{"Name":"nofile","Soft":1024,"Hard":2048}]}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "memoryAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Memory":268435456}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "memoryReservationAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"MemoryReservation":134217728}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "memorySwapAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"MemorySwap":-1}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "memorySwappinessAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"MemorySwappiness":-1}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "nanoCpusAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"NanoCpus":500000000}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "cpuSharesAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"CpuShares":512}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "cpuPeriodAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"CpuPeriod":100000}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "cpuQuotaAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"CpuQuota":50000}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "cpusetCpusAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"CpusetCpus":"0-1"}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "cpusetMemsAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"CpusetMems":"0"}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "pidsLimitAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"PidsLimit":100}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "blkioWeightAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"BlkioWeight":10}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "containerIdFileAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"ContainerIDFile":"/tmp/cid"}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "networkModeAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"NetworkMode":"bridge"}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "restartPolicyAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"RestartPolicy":{"Name":"always","MaximumRetryCount":0}}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "logConfigAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"LogConfig":{"Type":"json-file","Config":{"max-size":"10m"}}}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "privilegedNeutralised",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Privileged":true}}`,
    want: "",
    fwd: String.raw`{"Privileged":false}`,
  },
  {
    name: "privilegedNeutralisedEmptyContainerConfig",
    policy: "bare",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Privileged":true}}`,
    want: "",
    fwd: String.raw`{"Privileged":false}`,
  },
  {
    name: "emptyContainerConfigForcesPrivilegedFalse",
    policy: "bare",
    body: String.raw`{"Image":"chainsafe/lodestar:v1"}`,
    want: "",
    fwd: String.raw`{"Privileged":false}`,
  },
  {
    name: "mountBindRootDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"bind","Source":"/","Target":"/host"}]}}`,
    want: 'mount source "/" is not in the whitelist for service svc',
    fwd: String.raw``,
  },
  {
    name: "mountBindAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"bind","Source":"/data","Target":"/data"}]}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "mountBindReadOnlyVolumeWritableDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"bind","Source":"/ro","Target":"/ro"}]}}`,
    want: 'mount of "/ro" must be read-only (ReadOnly: true) for service svc',
    fwd: String.raw``,
  },
  {
    name: "mountBindReadOnlyVolumeReadOnlyFalseDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"bind","Source":"/ro","Target":"/ro","ReadOnly":false}]}}`,
    want: 'mount of "/ro" must be read-only',
    fwd: String.raw``,
  },
  {
    name: "mountBindReadOnlyVolumeReadOnlyAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"bind","Source":"/ro","Target":"/ro","ReadOnly":true}]}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "mountVolumeTypeDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"volume","Source":"myvol","Target":"/v"}]}}`,
    want: 'mount type "volume" is not allowed for service svc',
    fwd: String.raw``,
  },
  {
    name: "mountImageTypeDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"image","Source":"alpine:3.20","Target":"/i"}]}}`,
    want: 'mount type "image" is not allowed',
    fwd: String.raw``,
  },
  {
    name: "mountNpipeTypeDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"npipe","Source":"//./pipe/docker_engine","Target":"/p"}]}}`,
    want: 'mount type "npipe" is not allowed',
    fwd: String.raw``,
  },
  {
    name: "mountMissingTypeDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Source":"/data","Target":"/data"}]}}`,
    want: 'mount type "" is not allowed',
    fwd: String.raw``,
  },
  {
    name: "mountTmpfsAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"tmpfs","Target":"/run","TmpfsOptions":{"SizeBytes":1048576}}]}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "mountTmpfsWithSourceDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"tmpfs","Source":"/","Target":"/run"}]}}`,
    want: "tmpfs mount must not have a Source",
    fwd: String.raw``,
  },
  {
    name: "mountPropagationRsharedDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"bind","Source":"/data","Target":"/data","BindOptions":{"Propagation":"rshared"}}]}}`,
    want: 'mount propagation "rshared" is not allowed',
    fwd: String.raw``,
  },
  {
    name: "mountPropagationSlaveDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"bind","Source":"/data","Target":"/data","BindOptions":{"Propagation":"slave"}}]}}`,
    want: 'mount propagation "slave" is not allowed',
    fwd: String.raw``,
  },
  {
    name: "mountPropagationRprivateAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"bind","Source":"/data","Target":"/data","BindOptions":{"Propagation":"rprivate"}}]}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "mountCreateMountpointAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"bind","Source":"/data","Target":"/data","BindOptions":{"CreateMountpoint":true}}]}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "mountReadOnlyNonRecursiveDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"bind","Source":"/ro","Target":"/ro","ReadOnly":true,"BindOptions":{"ReadOnlyNonRecursive":true}}]}}`,
    want: "HostConfig.Mounts.BindOptions.ReadOnlyNonRecursive is not allowed",
    fwd: String.raw``,
  },
  {
    name: "mountVolumeOptionsDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"bind","Source":"/data","Target":"/data","VolumeOptions":{"NoCopy":true}}]}}`,
    want: "HostConfig.Mounts.VolumeOptions is not allowed",
    fwd: String.raw``,
  },
  {
    name: "mountCaseVariantDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"tmpfs","Target":"/x","type":"bind","source":"/"}]}}`,
    want: "HostConfig.Mounts.source is not allowed",
    fwd: String.raw``,
  },
  {
    name: "mountNoVolumesDenied",
    policy: "bare",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"bind","Source":"/data","Target":"/data"}]}}`,
    want: 'mount source "/data" is not in the whitelist',
    fwd: String.raw``,
  },
  {
    name: "mountsNotListDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":{}}}`,
    want: "HostConfig.Mounts must be a list",
    fwd: String.raw``,
  },
  {
    name: "bindAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Binds":["/data:/data"]}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "bindReadOnlyVolumeRwDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Binds":["/ro:/ro:rw"]}}`,
    want: 'volume mount "/ro" must be read-only (:ro) for service svc',
    fwd: String.raw``,
  },
  {
    name: "bindReadOnlyVolumeNoModeDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Binds":["/ro:/ro"]}}`,
    want: 'volume mount "/ro" must be read-only (:ro)',
    fwd: String.raw``,
  },
  {
    name: "bindReadOnlyVolumeRoAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Binds":["/ro:/ro:ro"]}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "bindReadOnlyVolumeRoZAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Binds":["/ro:/ro:ro,Z"]}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "bindReadOnlyVolumeRoRwDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Binds":["/ro:/ro:ro,rw"]}}`,
    want: 'volume mount "/ro" must be read-only (:ro)',
    fwd: String.raw``,
  },
  {
    name: "bindRsharedDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Binds":["/data:/data:rshared"]}}`,
    want: 'bind option "rshared" on volume mount "/data" is not allowed for service svc',
    fwd: String.raw``,
  },
  {
    name: "bindRslaveDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Binds":["/data:/data:rw,rslave"]}}`,
    want: 'bind option "rslave" on volume mount "/data" is not allowed',
    fwd: String.raw``,
  },
  {
    name: "bindConsistencyModeDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Binds":["/data:/data:cached"]}}`,
    want: 'bind option "cached" on volume mount "/data" is not allowed',
    fwd: String.raw``,
  },
  {
    name: "bindRprivateAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Binds":["/data:/data:rw,rprivate"]}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "bindPrivateZAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Binds":["/data:/data:z,private"]}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "bindNocopyAllowed",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Binds":["/data:/data:nocopy"]}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "bindUnlistedDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Binds":["/etc:/etc:ro"]}}`,
    want: 'volume mount "/etc" is not in the whitelist for service svc',
    fwd: String.raw``,
  },
  {
    name: "bindNoVolumesDenied",
    policy: "bare",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Binds":["/data:/data"]}}`,
    want: 'volume mount "/data" is not in the whitelist',
    fwd: String.raw``,
  },
  {
    name: "bindNotStringDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Binds":[1]}}`,
    want: "HostConfig.Binds must be a list of strings",
    fwd: String.raw``,
  },
  {
    name: "bindTooManyPartsDenied",
    policy: "std",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","HostConfig":{"Binds":["/data:/data:ro:x"]}}`,
    want: 'bind "/data:/data:ro:x" is not a valid bind',
    fwd: String.raw``,
  },
  {
    name: "topLevelVolumesNoVolumesDenied",
    policy: "bare",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","Volumes":{"/data":{}}}`,
    want: 'volume "/data" is not in the whitelist',
    fwd: String.raw``,
  },
  {
    name: "topLevelVolumesEmptyAllowed",
    policy: "bare",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","Volumes":{}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "dockerCliCreateBodyAllowed",
    policy: "std",
    body: String.raw`{"Hostname":"","Domainname":"","User":"","AttachStdin":false,"AttachStdout":true,"AttachStderr":true,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":null,"Cmd":["true"],"Image":"chainsafe/lodestar:v1","Volumes":{},"WorkingDir":"","Entrypoint":null,"Labels":{},"HostConfig":{"Binds":null,"ContainerIDFile":"","LogConfig":{"Type":"","Config":{}},"NetworkMode":"default","PortBindings":{},"RestartPolicy":{"Name":"no","MaximumRetryCount":0},"AutoRemove":false,"VolumeDriver":"","VolumesFrom":null,"ConsoleSize":[0,0],"CapAdd":null,"CapDrop":null,"CgroupnsMode":"","Dns":null,"DnsOptions":[],"DnsSearch":[],"ExtraHosts":null,"GroupAdd":null,"IpcMode":"","Cgroup":"","Links":null,"OomScoreAdj":0,"PidMode":"","Privileged":false,"PublishAllPorts":false,"ReadonlyRootfs":false,"SecurityOpt":null,"UTSMode":"","UsernsMode":"","ShmSize":0,"Isolation":"","CpuShares":0,"Memory":0,"NanoCpus":0,"CgroupParent":"","BlkioWeight":0,"BlkioWeightDevice":[],"BlkioDeviceReadBps":[],"BlkioDeviceWriteBps":[],"BlkioDeviceReadIOps":[],"BlkioDeviceWriteIOps":[],"CpuPeriod":0,"CpuQuota":0,"CpuRealtimePeriod":0,"CpuRealtimeRuntime":0,"CpusetCpus":"","CpusetMems":"","Devices":[],"DeviceCgroupRules":null,"DeviceRequests":null,"MemoryReservation":0,"MemorySwap":0,"MemorySwappiness":-1,"OomKillDisable":false,"PidsLimit":0,"Ulimits":null,"CpuCount":0,"CpuPercent":0,"IOMaximumIOps":0,"IOMaximumBandwidth":0,"MaskedPaths":null,"ReadonlyPaths":null},"NetworkingConfig":{"EndpointsConfig":{"default":{"IPAMConfig":null,"Links":null,"Aliases":null,"DriverOpts":null,"GwPriority":0,"NetworkID":"","EndpointID":"","Gateway":"","IPAddress":"","MacAddress":"","IPPrefixLen":0,"IPv6Gateway":"","GlobalIPv6Address":"","GlobalIPv6PrefixLen":0,"DNSNames":null}}}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "dockerCliCreateBodyBareAllowed",
    policy: "bare",
    body: String.raw`{"Hostname":"","Domainname":"","User":"","AttachStdin":false,"AttachStdout":true,"AttachStderr":true,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":null,"Cmd":["true"],"Image":"chainsafe/lodestar:v1","Volumes":{},"WorkingDir":"","Entrypoint":null,"Labels":{},"HostConfig":{"Binds":null,"ContainerIDFile":"","LogConfig":{"Type":"","Config":{}},"NetworkMode":"default","PortBindings":{},"RestartPolicy":{"Name":"no","MaximumRetryCount":0},"AutoRemove":false,"VolumeDriver":"","VolumesFrom":null,"ConsoleSize":[0,0],"CapAdd":null,"CapDrop":null,"CgroupnsMode":"","Dns":null,"DnsOptions":[],"DnsSearch":[],"ExtraHosts":null,"GroupAdd":null,"IpcMode":"","Cgroup":"","Links":null,"OomScoreAdj":0,"PidMode":"","Privileged":false,"PublishAllPorts":false,"ReadonlyRootfs":false,"SecurityOpt":null,"UTSMode":"","UsernsMode":"","ShmSize":0,"Isolation":"","CpuShares":0,"Memory":0,"NanoCpus":0,"CgroupParent":"","BlkioWeight":0,"BlkioWeightDevice":[],"BlkioDeviceReadBps":[],"BlkioDeviceWriteBps":[],"BlkioDeviceReadIOps":[],"BlkioDeviceWriteIOps":[],"CpuPeriod":0,"CpuQuota":0,"CpuRealtimePeriod":0,"CpuRealtimeRuntime":0,"CpusetCpus":"","CpusetMems":"","Devices":[],"DeviceCgroupRules":null,"DeviceRequests":null,"MemoryReservation":0,"MemorySwap":0,"MemorySwappiness":-1,"OomKillDisable":false,"PidsLimit":0,"Ulimits":null,"CpuCount":0,"CpuPercent":0,"IOMaximumIOps":0,"IOMaximumBandwidth":0,"MaskedPaths":null,"ReadonlyPaths":null},"NetworkingConfig":{"EndpointsConfig":{"default":{"IPAMConfig":null,"Links":null,"Aliases":null,"DriverOpts":null,"GwPriority":0,"NetworkID":"","EndpointID":"","Gateway":"","IPAddress":"","MacAddress":"","IPPrefixLen":0,"IPv6Gateway":"","GlobalIPv6Address":"","GlobalIPv6PrefixLen":0,"DNSNames":null}}}}`,
    want: "",
    fwd: String.raw``,
  },
  {
    name: "ansibleCreateBodyAllowed",
    policy: "secopt",
    body: String.raw`{"Image":"chainsafe/lodestar:v1","Cmd":["beacon"],"Env":[],"Labels":{"app":"beacon"},"HostConfig":{"Binds":["/data:/data:rw","/ro:/ro:ro"],"NetworkMode":"host","RestartPolicy":{"Name":"unless-stopped","MaximumRetryCount":0},"LogConfig":{"Type":"json-file","Config":{"max-size":"100m"}},"SecurityOpt":["no-new-privileges:true"],"Init":false,"AutoRemove":false,"Privileged":false,"ReadonlyRootfs":false,"CapDrop":["ALL"],"Memory":0}}`,
    want: "",
    fwd: String.raw``,
  },
];

// HostConfigGate alone, on the "groups" policy (#93): as if the mutator
// stopped forcing the list. Only the policy's list, exactly, or a zero value
// passes. The same rows, by name, are in
// go/internal/middleware/hostconfig_test.go and rs/src/middleware.rs.
const groupAddGateRows: [string, string, string][] = [
  ["groupAddGateForcedListAllowed", String.raw`{"HostConfig":{"GroupAdd":["64190","jwt"]}}`, ""],
  ["groupAddGateEmptyAllowed", String.raw`{"HostConfig":{"GroupAdd":[]}}`, ""],
  ["groupAddGateNullAllowed", String.raw`{"HostConfig":{"GroupAdd":null}}`, ""],
  [
    "groupAddGateOtherListDenied",
    String.raw`{"HostConfig":{"GroupAdd":["docker"]}}`,
    "HostConfig.GroupAdd is not allowed for service svc",
  ],
  [
    "groupAddGateReorderedDenied",
    String.raw`{"HostConfig":{"GroupAdd":["jwt","64190"]}}`,
    "HostConfig.GroupAdd is not allowed for service svc",
  ],
  [
    "groupAddGateSubsetDenied",
    String.raw`{"HostConfig":{"GroupAdd":["64190"]}}`,
    "HostConfig.GroupAdd is not allowed for service svc",
  ],
  [
    "groupAddGateSupersetDenied",
    String.raw`{"HostConfig":{"GroupAdd":["64190","jwt","0"]}}`,
    "HostConfig.GroupAdd is not allowed for service svc",
  ],
  [
    "groupAddGateNumberDenied",
    String.raw`{"HostConfig":{"GroupAdd":[64190,"jwt"]}}`,
    "HostConfig.GroupAdd is not allowed for service svc",
  ],
  [
    "groupAddGateStringDenied",
    String.raw`{"HostConfig":{"GroupAdd":"64190"}}`,
    "HostConfig.GroupAdd is not allowed for service svc",
  ],
];

describe("GroupAdd gate rows (#93)", () => {
  for (const [name, body, want] of groupAddGateRows) {
    it(name, () => {
      const reason = new HostConfigGate().check(
        "POST",
        "/containers/create",
        hostConfigRowPolicy("groups"),
        JSON.parse(body) as Record<string, unknown>,
      );
      if (want === "") {
        assert.equal(reason, null);
      } else {
        assert.ok(reason !== null && reason.includes(want), "expected deny with " + want + ", got: " + reason);
      }
    });
  }
});

describe("HostConfig rows (#88)", () => {
  for (const row of hostConfigRows) {
    it(row.name, () => {
      const body = JSON.parse(row.body) as Record<string, unknown>;
      const result = new Chain().execute("POST", "/containers/create", hostConfigRowPolicy(row.policy), body);
      if (row.want !== "") {
        assert.equal(result.allowed, false, `expected deny with ${row.want}`);
        assert.ok(result.reason.includes(row.want), `expected deny with ${row.want}, got: ${result.reason}`);
        return;
      }
      assert.ok(result.allowed, `expected allow, got: ${result.reason}`);
      if (row.fwd === "") return;
      const want = JSON.parse(row.fwd) as Record<string, unknown>;
      const forwarded = JSON.parse(result.modifiedBody!.toString("utf-8")) as Record<string, unknown>;
      const hc = forwarded["HostConfig"] as Record<string, unknown>;
      for (const [k, v] of Object.entries(want)) {
        assert.deepEqual(hc[k], v, `forwarded HostConfig.${k}`);
      }
    });
  }
});
