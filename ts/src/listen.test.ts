import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import {
  chmodSync,
  chownSync,
  existsSync,
  lstatSync,
  mkdtempSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { connect, createServer as createNetServer, type Server } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { listenOnSocket, openListener, prepareSocketPath } from "./listen.js";

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

// Leaves a socket file at path with nothing listening on it, as an unclean
// shutdown would: connect(2) to it is refused. Node unlinks a Unix socket when
// its server closes, so bind at a sibling path and rename the socket into
// place first; close then unlinks the (now absent) sibling path only.
async function seedStaleSocket(path: string): Promise<void> {
  const seed = path + ".seed";
  const server = createNetServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(seed, () => resolve());
  });
  renameSync(seed, path);
  await new Promise((r) => server.close(r));
}

function inode(path: string): number {
  return lstatSync(path).ino;
}

function closeServer(server: Server): Promise<void> {
  return new Promise((r) => server.close(() => r()));
}

// One case per row of the existing-path table in spec/listener-design.md; the
// test names match the Quint runs.
describe("prepareSocketPath", () => {
  it("pathAbsentBinds", async () => {
    const { path, cleanup } = tempSocket();
    try {
      await prepareSocketPath(path);
    } finally {
      cleanup();
    }
  });

  it("pathStaleReplaced", async () => {
    const { path, cleanup } = tempSocket();
    try {
      await seedStaleSocket(path);
      assert.ok(lstatSync(path).isSocket(), "seeding did not leave a socket behind");
      await prepareSocketPath(path);
      assert.equal(existsSync(path), false, "stale socket still present after prepare");
    } finally {
      cleanup();
    }
  });

  it("pathLiveRefused", async () => {
    const { path, cleanup } = tempSocket();
    const server = createNetServer();
    try {
      await new Promise<void>((resolve) => server.listen(path, () => resolve()));
      const before = inode(path);

      await assert.rejects(prepareSocketPath(path), {
        message: `${path} is in use by another process`,
      });
      assert.equal(inode(path), before, "live socket inode changed: it was replaced");

      const accepted = new Promise<void>((resolve) =>
        server.once("connection", (c) => {
          c.destroy();
          resolve();
        }),
      );
      await new Promise<void>((resolve, reject) => {
        const c = connect(path, () => {
          c.destroy();
          resolve();
        });
        c.once("error", reject);
      });
      await accepted;
    } finally {
      await closeServer(server);
      cleanup();
    }
  });

  // connect(2) needs write permission on the socket, so a 0000 socket yields
  // EACCES: neither live nor provably stale, so it is left alone.
  it(
    "pathConnectErrorRefused",
    { skip: process.geteuid?.() === 0 ? "root ignores socket permissions" : false },
    async () => {
      const { path, cleanup } = tempSocket();
      try {
        await seedStaleSocket(path);
        chmodSync(path, 0);
        await assert.rejects(prepareSocketPath(path), {
          message: `refusing to remove ${path}: connect EACCES ${path}`,
        });
        assert.ok(lstatSync(path).isSocket(), "socket was removed");
      } finally {
        cleanup();
      }
    },
  );

  it("pathNotSocketRefused", async () => {
    const { path, cleanup } = tempSocket();
    try {
      writeFileSync(path, "data");
      await assert.rejects(prepareSocketPath(path), {
        message: `refusing to remove ${path}: not a socket`,
      });
      assert.equal(existsSync(path), true, "regular file was removed");
    } finally {
      cleanup();
    }
  });
});

// A non-root proxy that is not a member of the selected group cannot chown the
// socket to it. The error must say what to fix rather than surface a bare EPERM.
describe("listenOnSocket chown EPERM", () => {
  const skip =
    process.geteuid?.() === 0
      ? "root can chown to any group"
      : process.getgroups?.().includes(0)
        ? "process is a member of gid 0, so chown to it succeeds"
        : false;

  it("names the group", { skip }, async () => {
    const { path, cleanup } = tempSocket();
    // BSD semantics (macOS) give a new file its directory's group, which is
    // gid 0 under /tmp, and chown to the current group is always allowed.
    // Give the directory our own group so the socket starts out not in gid 0.
    chownSync(join(path, ".."), -1, process.getegid!());
    const server = createServer(() => {});
    try {
      await assert.rejects(listenOnSocket(server, path, 0), {
        message:
          `cannot give ${path} to group 0: the proxy's user must be a member of it ` +
          `(SupplementaryGroups= / group_add:)`,
      });
      assert.equal(server.listening, false, "server left listening after chown failed");
    } finally {
      cleanup();
    }
  });
});

describe("openListener", () => {
  it("replaces a stale socket and applies mode 0660", async () => {
    const { path, cleanup } = tempSocket();
    const server = createServer(() => {});
    try {
      await seedStaleSocket(path);
      chmodSync(path, 0o777);
      await openListener(server, path, process.getegid!());
      assert.equal(modeOf(path), 0o660);
    } finally {
      await closeServer(server);
      cleanup();
    }
  });

  // Node has no flock, so TypeScript takes no single-instance lock and relies
  // on the connect probe alone, which races (spec/listener-design.md,
  // "TypeScript exception"). This is the Go/Rust concurrency test unchanged:
  // un-skipping it is the whole test for the follow-up.
  it("openListener concurrent (#46)", { skip: "no flock in Node — #46" }, async () => {
    const { path: base, cleanup } = tempSocket();
    const dir = join(base, "..");
    const racers = 8;
    try {
      for (let i = 0; i < 50; i++) {
        const path = join(dir, `c${i}.sock`);
        const servers = Array.from({ length: racers }, () => createNetServer());
        try {
          const results = await Promise.allSettled(
            servers.map((s) => openListener(s, path, process.getegid!())),
          );

          const winners = results.flatMap((r, j) => (r.status === "fulfilled" ? [j] : []));
          assert.equal(
            winners.length,
            1,
            `iteration ${i}: ${winners.length} openListener calls succeeded, want 1`,
          );
          for (const r of results) {
            if (r.status === "rejected") {
              assert.match(
                (r.reason as Error).message,
                /is in use by another/,
                `iteration ${i}: loser error, want an in-use error`,
              );
            }
          }

          const winner = servers[winners[0]];
          const accepted = new Promise<void>((resolve) =>
            winner.once("connection", (c) => {
              c.destroy();
              resolve();
            }),
          );
          await new Promise<void>((resolve, reject) => {
            const c = connect(path, () => {
              c.destroy();
              resolve();
            });
            c.once("error", reject);
          });
          await accepted;
        } finally {
          await Promise.all(servers.filter((s) => s.listening).map(closeServer));
        }
      }
    } finally {
      cleanup();
    }
  });
});
