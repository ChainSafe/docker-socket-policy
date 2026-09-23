import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { getFlag, hasFlag, parseListenSocket, parseSocketPath } from "./flags.js";

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
      const result = parseListenSocket("fd://4");
      assert.equal(result.kind, "error");
      assert.match(result.kind === "error" ? result.message : "", /only supports fd:\/\/3/);
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