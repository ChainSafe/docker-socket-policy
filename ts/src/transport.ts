import type { IncomingMessage, OutgoingHttpHeaders, ServerResponse } from "node:http";
import { request } from "node:http";

const DEFAULT_SOCKET_PATH = "/var/run/docker.sock";

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

      dockerReq.on("error", reject);

      if (body && body.length > 0) {
        dockerReq.write(body);
      }

      dockerReq.end();
    });
  }
}
