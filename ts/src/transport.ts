import type { IncomingMessage, OutgoingHttpHeaders, ServerResponse } from "node:http";
import { request } from "node:http";

const DEFAULT_SOCKET_PATH = "/var/run/docker.sock";

// Reports whether a socket connection failure is a permission denial. The
// group-restricted Unix socket is the security boundary, so EACCES/EPERM
// surfaces as 403 — indistinguishable from a middleware policy denial.
export function isPermissionDenied(err: NodeJS.ErrnoException): boolean {
  return err.code === "EACCES" || err.code === "EPERM";
}

export class Transport {
  constructor(private socketPath: string = DEFAULT_SOCKET_PATH) {}

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
