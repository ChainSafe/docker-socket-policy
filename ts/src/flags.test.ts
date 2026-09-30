import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  BOOL_FLAGS,
  DEFAULT_SOCKET_GROUP,
  getFlag,
  type GroupId,
  selectSocketGroup,
  hasFlag,
  parseListenSocket,
  parseSocketPath,
  resolveGroup,
  validateFlags,
  VALUE_FLAGS,
} from "./flags.js";

describe("flags", () => {
  describe("getFlag", () => {
    it("reads --name value (space form)", () => {
      assert.equal(getFlag(["--config-dir", "/x"], "--config-dir", "d"), "/x");
    });

    it("reads --name=value (equals form)", () => {
      assert.equal(getFlag(["--config-dir=/x"], "--config-dir", "d"), "/x");
    });

    it("prefers first occurrence", () => {
      assert.equal(
        getFlag(["--config-dir=/a", "--config-dir", "/b"], "--config-dir", "d"),
        "/a",
      );
    });

    it("returns default when absent", () => {
      assert.equal(getFlag([], "--config-dir", "d"), "d");
      assert.equal(getFlag(["--other"], "--config-dir", "d"), "d");
    });

    it("returns default when --name is last arg with no value", () => {
      assert.equal(getFlag(["--config-dir"], "--config-dir", "d"), "d");
    });

    it("does not match a different flag's value", () => {
      assert.equal(
        getFlag(["--listen-socket", "/run/dsp.sock"], "--config-dir", "d"),
        "d",
      );
    });

    it("handles --name=value where value contains equals", () => {
      assert.equal(
        getFlag(["--log-file=/a=/b"], "--log-file", "d"),
        "/a=/b",
      );
    });
  });

  describe("hasFlag", () => {
    it("detects --name (space form)", () => {
      assert.equal(hasFlag(["--readonly"], "--readonly"), true);
    });

    it("detects --name=value (equals form)", () => {
      assert.equal(hasFlag(["--readonly=true"], "--readonly"), true);
    });

    it("returns false when absent", () => {
      assert.equal(hasFlag([], "--readonly"), false);
      assert.equal(hasFlag(["--other"], "--readonly"), false);
    });
  });

  describe("validateFlags", () => {
    const VALUE = ["--listen-socket", "--docker-host", "--config-dir", "--log-file"];
    const BOOL = ["--readonly"];
    const check = (args: string[]) => validateFlags(args, VALUE, BOOL);

    it("accepts known flags in both space and equals form", () => {
      assert.equal(check(["--config-dir", "/x", "--log-file=/y"]), null);
      assert.equal(check([]), null);
    });

    it("accepts a boolean flag without swallowing the next argument", () => {
      // --readonly takes no value, so --config-dir must still be parsed.
      assert.equal(check(["--readonly", "--config-dir", "/x"]), null);
    });

    it("rejects --listen-tcp, which this proxy no longer has", () => {
      // The whole point: silently ignoring it would leave a caller believing
      // the proxy is listening on TCP when it is not.
      assert.match(check(["--listen-tcp=0.0.0.0:2375"]) ?? "", /unrecognised flag: --listen-tcp/);
      assert.match(check(["--listen-tcp", "0.0.0.0:2375"]) ?? "", /unrecognised flag: --listen-tcp/);
    });

    it("rejects unknown and misspelled flags", () => {
      assert.match(check(["--bogus"]) ?? "", /unrecognised flag: --bogus/);
      assert.match(check(["--read-only"]) ?? "", /unrecognised flag: --read-only/);
      assert.match(check(["-readonly"]) ?? "", /unrecognised flag: -readonly/);
    });

    it("rejects stray positional arguments", () => {
      assert.match(check(["oops"]) ?? "", /unexpected argument: oops/);
      assert.match(check(["--readonly", "oops"]) ?? "", /unexpected argument: oops/);
    });

    it("rejects a value flag with no value", () => {
      assert.match(check(["--config-dir"]) ?? "", /flag needs an argument: --config-dir/);
    });

    it("does not mistake a flag-like value for a flag", () => {
      // "--config-dir --readonly" consumes --readonly as the value; odd, but
      // it matches Go's flag package, and the point is that it is not an error.
      assert.equal(check(["--config-dir", "--readonly"]), null);
    });

    // The socket mode is fixed. A deployment still passing the flag must fail
    // at startup rather than silently get a different mode than it asked for.
    it("rejects --listen-socket-mode, which this proxy no longer has", () => {
      assert.match(
        validateFlags(["--listen-socket-mode=0660"], VALUE_FLAGS, BOOL_FLAGS) ?? "",
        /unrecognised flag: --listen-socket-mode/,
      );
    });
  });

  describe("parseListenSocket", () => {
    it("accepts a plain unix socket path", () => {
      assert.deepEqual(parseListenSocket("/var/run/docker-socket-policy.sock"), {
        kind: "path",
        path: "/var/run/docker-socket-policy.sock",
      });
    });

    // Socket activation was removed; fd:// is just another scheme now.
    it("rejects fd:// addresses, including fd://3", () => {
      for (const input of ["fd://3", "fd://4", "fd://0", "fd://", "fd://abc"]) {
        const result = parseListenSocket(input);
        assert.ok(result.kind === "error", `expected ${input} to be rejected`);
        assert.match(result.message, /only supports Unix socket paths/);
      }
    });

    it("rejects a host:port left over from --listen-tcp", () => {
      // The likeliest migration mistake: dropping the scheme but keeping the
      // address. Accepting it would create a file named "0.0.0.0:2375" and
      // report success while being unreachable.
      const result = parseListenSocket("0.0.0.0:2375");
      assert.ok(result.kind === "error");
      assert.match(result.message, /absolute path/);
    });

    it("rejects abstract-namespace sockets, which have no permissions", () => {
      for (const input of ["@dsp", "\0dsp"]) {
        const result = parseListenSocket(input);
        assert.ok(result.kind === "error", `expected ${input} to be rejected`);
        assert.match(result.message, /abstract sockets have no permissions/);
      }
    });

    it("rejects relative paths", () => {
      const result = parseListenSocket("dsp.sock");
      assert.ok(result.kind === "error");
      assert.match(result.message, /absolute path/);
    });

    it("rejects TCP and HTTP listen addresses", () => {
      for (const input of [
        "tcp://0.0.0.0:2375",
        "http://0.0.0.0:2375",
        "https://0.0.0.0:2375",
        "unix:///var/run/docker-socket-policy.sock",
      ]) {
        const result = parseListenSocket(input);
        assert.equal(result.kind, "error", `expected ${input} to be rejected`);
        assert.match(result.kind === "error" ? result.message : "", /Unix socket paths/);
      }
    });

    it("rejects empty values", () => {
      const result = parseListenSocket("");
      assert.equal(result.kind, "error");
      assert.match(result.kind === "error" ? result.message : "", /must not be empty/);
    });
  });

  describe("parseSocketPath", () => {
    it("accepts a plain unix socket path", () => {
      assert.equal(parseSocketPath("/var/run/docker.sock"), null);
      assert.equal(parseSocketPath("/sock/docker.sock"), null);
    });

    it("rejects TCP and HTTP daemon addresses", () => {
      assert.match(parseSocketPath("tcp://dind:2375") ?? "", /Unix socket paths/);
      assert.match(parseSocketPath("http://dind:2375") ?? "", /Unix socket paths/);
      assert.match(parseSocketPath("https://dind:2375") ?? "", /Unix socket paths/);
      assert.match(parseSocketPath("unix:///var/run/docker.sock") ?? "", /Unix socket paths/);
    });

    it("rejects empty values", () => {
      assert.match(parseSocketPath("") ?? "", /must not be empty/);
    });
  });
});

describe("resolveGroup", () => {
  function groupFile(contents: string): string {
    const p = join(mkdtempSync(join(tmpdir(), "grp-")), "group");
    writeFileSync(p, contents);
    return p;
  }

  it("takes a numeric value as a gid without consulting the group file", () => {
    assert.deepEqual(resolveGroup("2001", "/nonexistent"), { gid: 2001 });
  });

  it("resolves a name from the group file", () => {
    const f = groupFile("root:x:0:\ndocker:x:999:alice,bob\n");
    assert.deepEqual(resolveGroup("docker", f), { gid: 999 });
  });

  it("reports an unknown group", () => {
    const f = groupFile("root:x:0:\n");
    const got = resolveGroup("nope", f);
    assert.ok("error" in got);
    assert.match(got.error, /no such group/);
  });

  it("reports a non-numeric gid field", () => {
    const f = groupFile("broken:x:notanumber:\n");
    const got = resolveGroup("broken", f);
    assert.ok("error" in got);
    assert.match(got.error, /not numeric/);
  });

  it("reports an unreadable group file", () => {
    const got = resolveGroup("docker", "/nonexistent-group-file");
    assert.ok("error" in got);
    assert.match(got.error, /cannot read/);
  });
});

describe("resolveGroup rejects out-of-range gid", () => {
  // 4294967295 is chown's "don't change" sentinel; larger values do not fit
  // a gid_t at all.
  it("accepts 4294967294 and rejects anything above it", () => {
    assert.deepEqual(resolveGroup("4294967294", "/nonexistent"), { gid: 4294967294 });
    for (const v of ["4294967295", "4294967296", "12345678901234567890"]) {
      assert.deepEqual(resolveGroup(v, "/nonexistent"), {
        error: `--listen-socket-group ${JSON.stringify(v)}: gid out of range (0-4294967294)`,
      });
    }
  });
});

// One case per row of the group-selection table in spec/listener-design.md;
// the test names match the Quint runs.
describe("selectSocketGroup", () => {
  const egid = 65532;
  const known =
    (groups: Record<string, number>) =>
    (name: string): GroupId =>
      name in groups
        ? { gid: groups[name] }
        : { error: `--listen-socket-group ${JSON.stringify(name)}: unknown group` };
  const both = known({ "docker-socket-policy": 2001, ops: 3001 });

  it("groupDefaultPresent: flag absent, default group exists", () => {
    assert.deepEqual(selectSocketGroup(undefined, both, egid), { gid: 2001 });
  });

  it("groupDefaultMissingWarns: flag absent, default group missing", () => {
    assert.deepEqual(selectSocketGroup(undefined, known({}), egid), {
      gid: egid,
      warning: "group docker-socket-policy not found, using the proxy's own group 65532",
    });
  });

  it("groupExplicitPresent: explicit group exists", () => {
    assert.deepEqual(selectSocketGroup("ops", both, egid), { gid: 3001 });
  });

  it("groupExplicitMissingFails: explicit group missing", () => {
    const got = selectSocketGroup("nope", both, egid);
    assert.ok("error" in got, `want an error, got ${JSON.stringify(got)}`);
  });

  it("groupEmptyUsesOwn: explicit empty uses the proxy's own group", () => {
    assert.deepEqual(selectSocketGroup("", both, egid), { gid: egid });
  });

  it("uses the default group name", () => {
    assert.equal(DEFAULT_SOCKET_GROUP, "docker-socket-policy");
  });
});

// An explicit empty value means "the proxy's own group" and must not be
// confused with the flag being absent, which means the default group. This is
// the expression index.ts uses.
describe("--listen-socket-group empty vs absent", () => {
  const groupFlag = (args: string[]) =>
    hasFlag(args, "--listen-socket-group")
      ? getFlag(args, "--listen-socket-group", "")
      : undefined;

  it("absent", () => {
    assert.equal(groupFlag([]), undefined);
  });

  it("equals empty", () => {
    assert.equal(groupFlag(["--listen-socket-group="]), "");
  });

  it("separate empty", () => {
    assert.equal(groupFlag(["--listen-socket-group", ""]), "");
  });

  it("named", () => {
    assert.equal(groupFlag(["--listen-socket-group=ops"]), "ops");
  });
});
