import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { getFlag, hasFlag, parseHostPort, parseSocketPath } from "./flags.js";

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
        getFlag(["--listen-tcp", "0.0.0.0:2375"], "--config-dir", "d"),
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

  describe("parseHostPort", () => {
    it("parses host:port", () => {
      assert.deepEqual(parseHostPort("0.0.0.0:2375"), { host: "0.0.0.0", port: 2375 });
      assert.deepEqual(parseHostPort("127.0.0.1:2375"), { host: "127.0.0.1", port: 2375 });
    });

    it("defaults to all interfaces for a bare port", () => {
      assert.deepEqual(parseHostPort("2375"), { host: "0.0.0.0", port: 2375 });
    });

    it("accepts a custom default host for bare port", () => {
      assert.deepEqual(parseHostPort("2375", "127.0.0.1"), { host: "127.0.0.1", port: 2375 });
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