import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { listenOnSocket } from "./listen.js";

// sun_path is capped at 104 bytes on macOS, so keep the path short.
function tempSocket(): { path: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "lsn-"));
  return {
    path: join(dir, "s.sock"),
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

function modeOf(path: string): number {
  return statSync(path).mode & 0o777;
}

describe("listenOnSocket", () => {
  // Regression test for #40: the mode used to be whatever the umask left
  // behind, which is 0755 by default. connect(2) requires write permission, so
  // the documented group grant silently did not work.
  it("applies mode 0660", async () => {
    const { path, cleanup } = tempSocket();
    const server = createServer(() => {});
    await listenOnSocket(server, path);

    assert.equal(modeOf(path), 0o660, `socket mode was ${modeOf(path).toString(8)}, want 660`);

    await new Promise((r) => server.close(r));
    cleanup();
  });

  // The ambient umask must not influence the result: that was the whole bug.
  it("ignores the ambient umask", async () => {
    const previous = process.umask(0);
    const { path, cleanup } = tempSocket();
    const server = createServer(() => {});
    try {
      await listenOnSocket(server, path);
    } finally {
      process.umask(previous);
    }

    assert.equal(
      modeOf(path),
      0o660,
      `socket mode was ${modeOf(path).toString(8)} under umask 0, want 660`,
    );
    assert.equal(
      modeOf(path) & 0o002,
      0,
      "socket is world-writable: any local uid could connect",
    );

    await new Promise((r) => server.close(r));
    cleanup();
  });

  it("restores the previous umask", async () => {
    const { path, cleanup } = tempSocket();
    const before = process.umask();
    const server = createServer(() => {});
    await listenOnSocket(server, path);

    assert.equal(process.umask(), before, "umask was not restored after bind");

    await new Promise((r) => server.close(r));
    cleanup();
  });

  it("rejects, and restores the umask, when the bind fails", async () => {
    const before = process.umask();
    const server = createServer(() => {});

    await assert.rejects(
      () => listenOnSocket(server, "/nonexistent-dir-xyz/s.sock"),
      /ENOENT|EACCES/,
    );
    assert.equal(process.umask(), before, "umask was not restored after a failed bind");
  });

  it("is actually connectable at the mode it sets", async () => {
    const { path, cleanup } = tempSocket();
    const server = createServer((_req, res) => res.end("ok"));
    await listenOnSocket(server, path);

    const { connect } = await import("node:net");
    const reply = await new Promise<string>((resolve, reject) => {
      const sock = connect(path, () => {
        sock.write("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
      });
      let buf = "";
      sock.on("data", (d) => {
        buf += d.toString();
      });
      sock.on("error", reject);
      setTimeout(() => {
        sock.destroy();
        resolve(buf);
      }, 300).unref();
    });
    assert.match(reply, /200 OK/);

    await new Promise((r) => server.close(r));
    cleanup();
  });
});
