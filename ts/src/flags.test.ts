import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  getFlag,
  hasFlag,
  parseListenSocket,
  parseSocketPath,
  validateFlags,
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
  });

  describe("parseListenSocket", () => {
    it("accepts a plain unix socket path", () => {
      assert.deepEqual(parseListenSocket("/var/run/docker-socket-policy.sock"), {
        kind: "path",
        path: "/var/run/docker-socket-policy.sock",
      });
    });

    it("accepts fd://3 for systemd socket activation", () => {
      assert.deepEqual(parseListenSocket("fd://3"), { kind: "fd", fd: 3 });
    });

    it("rejects socket activation on any fd other than 3", () => {
      for (const input of ["fd://4", "fd://0", "fd://", "fd://3x", "fd://abc"]) {
        const result = parseListenSocket(input);
        assert.ok(result.kind === "error", `expected ${input} to be rejected`);
        assert.match(result.message, /only supports fd:\/\/3/);
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