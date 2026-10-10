import type { Server } from "node:net";
import { chmodSync, chownSync, lstatSync, unlinkSync } from "node:fs";
import { connect } from "node:net";
import { BIND_UMASK, SOCKET_MODE } from "./flags.js";

/**
 * Binds `server` to a Unix socket path with mode SOCKET_MODE and an optional
 * group.
 *
 * Extracted from index.ts so it can be tested: the mode of the listening
 * socket is invisible to the integration suite, which only observes HTTP
 * status codes.
 *
 * The mode is set rather than inherited from the ambient umask. Left to the
 * umask the socket is 0755 by default — connect(2) needs write permission, so
 * the documented "add the caller to the socket's group" grant does not work —
 * and 0777 under umask 0, which lets any local uid drive the Docker API.
 *
 * The umask is narrowed around bind(2) rather than the mode being corrected
 * afterwards, because a chmod after bind leaves a window in which the socket is
 * already listening at the ambient mode. The window here is at 0600 instead,
 * which is more restrictive than any mode we would set.
 *
 * main always passes the gid chosen by selectSocketGroup; an undefined gid
 * skips the chown and exists only for tests.
 */
export function listenOnSocket(server: Server, path: string, gid?: number): Promise<void> {
  return new Promise((resolve, reject) => {
    // umask is process-global. This runs during startup, before any request is
    // served, so nothing else is creating files in the window.
    const previousUmask = process.umask(BIND_UMASK);

    const onError = (err: Error) => {
      process.umask(previousUmask);
      reject(err);
    };
    server.once("error", onError);

    server.listen(path, () => {
      process.umask(previousUmask);
      server.off("error", onError);
      try {
        // Set the group before widening the mode, so the socket is never
        // reachable by the wrong group.
        if (gid !== undefined) {
          try {
            chownSync(path, -1, gid);
          } catch (err) {
            if ((err as NodeJS.ErrnoException).code === "EPERM") {
              throw new Error(
                `cannot give ${path} to group ${gid}: the proxy's user must be a member of it ` +
                  `(SupplementaryGroups= / group_add:)`,
              );
            }
            throw err;
          }
        }
        chmodSync(path, SOCKET_MODE);
      } catch (err) {
        server.close();
        reject(err);
        return;
      }
      resolve();
    });
  });
}

// Bounds the connect(2) that tells a live socket from a stale one.
const PROBE_TIMEOUT_MS = 1000;

/**
 * Clears the socket path for bind, following the existing-path table in
 * spec/listener-design.md. Only a socket that refuses connections is removed.
 * A live one belongs to another process, and replacing it would cut that
 * process off silently. Anything that is not a socket is refused: blindly
 * unlinking would let a mistyped path silently delete an operator's file.
 */
export async function prepareSocketPath(path: string): Promise<void> {
  let isSocket: boolean;
  try {
    isSocket = lstatSync(path).isSocket();
  } catch (err) {
    const e = err as NodeJS.ErrnoException;
    if (e.code === "ENOENT") return;
    throw new Error(`checking ${path}: ${e.message}`);
  }
  if (!isSocket) {
    throw new Error(`refusing to remove ${path}: not a socket`);
  }

  await new Promise<void>((resolve, reject) => {
    const probe = connect(path);
    const timer = setTimeout(() => {
      probe.destroy();
      reject(new Error(`${path} is in use by another process`));
    }, PROBE_TIMEOUT_MS);
    probe.once("connect", () => {
      clearTimeout(timer);
      probe.destroy();
      reject(new Error(`${path} is in use by another process`));
    });
    probe.once("error", (err: NodeJS.ErrnoException) => {
      clearTimeout(timer);
      probe.destroy();
      if (err.code === "ECONNREFUSED") {
        resolve();
      } else {
        reject(new Error(`refusing to remove ${path}: ${err.message}`));
      }
    });
  });

  try {
    unlinkSync(path);
  } catch (err) {
    throw new Error(`removing stale socket ${path}: ${(err as Error).message}`);
  }
}

/**
 * Clears the socket path and binds it.
 *
 * Unlike Go and Rust, this takes no single-instance lock: Node has no flock
 * (#46, spec/listener-design.md §TypeScript exception). Two instances starting
 * together can both see a stale socket refuse the probe, and the later one then
 * unlinks the earlier one's freshly bound, live socket and takes the path over.
 */
export async function openListener(server: Server, path: string, gid: number): Promise<void> {
  await prepareSocketPath(path);
  await listenOnSocket(server, path, gid);
}
