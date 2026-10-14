import type { IncomingMessage, OutgoingHttpHeaders, ServerResponse } from "node:http";
import { request } from "node:http";

const DEFAULT_SOCKET_PATH = "/var/run/docker.sock";

// Reports whether a socket connection failure is a permission denial. The
// group-restricted Unix socket is the security boundary, so EACCES/EPERM
// surfaces as 403 — indistinguishable from a middleware policy denial.
export function isPermissionDenied(err: NodeJS.ErrnoException): boolean {
  return err.code === "EACCES" || err.code === "EPERM";
}

export interface DaemonResponse {
  statusCode: number;
  body: Buffer;
}

// Bounds the response read by get().
const MAX_GET_BODY = 4 << 20;

export class Transport {
  constructor(private socketPath: string = DEFAULT_SOCKET_PATH) {}

  // Sends GET path to the daemon and returns its response, for the proxy's
  // own lookups (#86). Nothing from the caller's request is forwarded.
  get(path: string): Promise<DaemonResponse> {
    return new Promise((resolve, reject) => {
      const dockerReq = request(
        { socketPath: this.socketPath, path, method: "GET", headers: { Host: "docker" } },
        (dockerRes) => {
          const chunks: Buffer[] = [];
          let size = 0;
          dockerRes.on("data", (chunk: Buffer) => {
            size += chunk.length;
            if (size > MAX_GET_BODY) {
              dockerRes.destroy();
              reject(new Error("response too large"));
              return;
            }
            chunks.push(chunk);
          });
          dockerRes.on("end", () => resolve({ statusCode: dockerRes.statusCode ?? 500, body: Buffer.concat(chunks) }));
          dockerRes.on("error", reject);
        },
      );
      dockerReq.on("error", reject);
      dockerReq.end();
    });
  }

  forward(req: IncomingMessage, res: ServerResponse, body?: Buffer): Promise<void> {
    return new Promise((resolve, reject) => {
      const headers: OutgoingHttpHeaders = { ...req.headers, Host: "docker" };
      // When forwarding a (possibly mutated) body, Content-Length must reflect
      // the bytes actually written, not the original request's header —
      // otherwise the daemon truncates the JSON ("unexpected EOF").
      if (body && body.length > 0) {
        headers["content-length"] = body.length;
      }
      const dockerReq = request(
        {
          socketPath: this.socketPath,
          path: req.url,
          method: req.method,
          headers,
        },
        (dockerRes) => {
          res.writeHead(dockerRes.statusCode ?? 500, dockerRes.headers);
          dockerRes.pipe(res);
          dockerRes.on("end", resolve);
        },
      );

      dockerReq.on("error", (err: NodeJS.ErrnoException) => {
        if (isPermissionDenied(err)) {
          res.writeHead(403, { "content-type": "text/plain" });
          res.end("permission denied on Docker socket");
          resolve();
          return;
        }
        reject(err);
      });

      if (body && body.length > 0) {
        dockerReq.write(body);
      }

      dockerReq.end();
    });
  }
}
