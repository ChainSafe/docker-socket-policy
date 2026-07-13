import type { IncomingMessage, ServerResponse } from "node:http";
import { request } from "node:http";

const DEFAULT_SOCKET_PATH = "/var/run/docker.sock";

export class Transport {
  constructor(private socketPath: string = DEFAULT_SOCKET_PATH) {}

  forward(req: IncomingMessage, res: ServerResponse, body?: Buffer): Promise<void> {
    return new Promise((resolve, reject) => {
      const dockerReq = request(
        {
          socketPath: this.socketPath,
          path: req.url,
          method: req.method,
          headers: {
            ...req.headers,
            Host: "docker",
          },
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
