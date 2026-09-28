import type { Server } from "node:http";
import { chmodSync, chownSync } from "node:fs";
import { BIND_UMASK } from "./flags.js";

/**
 * Binds `server` to a Unix socket path with an explicit mode and group.
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
 */
export function listenOnSocket(
  server: Server,
  path: string,
  mode: number,
  gid?: number,
): Promise<void> {
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
          chownSync(path, -1, gid);
        }
        chmodSync(path, mode);
      } catch (err) {
        reject(err);
        return;
      }
      resolve();
    });
  });
}
