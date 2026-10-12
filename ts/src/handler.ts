import { randomBytes } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { Duplex } from "node:stream";
import { AuditLogger } from "./audit.js";
import { Chain } from "./middleware.js";
import { Action, Router } from "./proxy.js";
import { Transport } from "./transport.js";

export class Handler {
  constructor(
    private router: Router,
    private chain: Chain,
    private audit: AuditLogger,
    private transport: Transport,
  ) {}

  async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const requestId = randomBytes(8).toString("hex");
    const method = req.method ?? "GET";
    const path = req.url ?? "/";

    // Refuse CONNECT before anything else, whatever its target or headers
    // (#78). Node's http.Server never delivers CONNECT here; refuseConnect
    // answers it on the server's "connect" event.
    if (method === "CONNECT") {
      console.warn(`[${requestId}] DENIED ${method} ${path}: ${CONNECT_REFUSED}`);
      this.audit.deny(method, path, CONNECT_REFUSED);
      res.writeHead(403);
      res.end(CONNECT_REFUSED);
      return;
    }

    // Refuse protocol upgrades next: forwarding one would
    // hand the caller a raw stream to the daemon (#76). The server registers
    // no "upgrade" listener, so Node delivers these requests here.
    if (isUpgradeRequest(req)) {
      const msg = "protocol upgrade not allowed";
      console.warn(`[${requestId}] DENIED ${method} ${path}: ${msg}`);
      this.audit.deny(method, path, msg);
      res.writeHead(403);
      res.end(msg);
      return;
    }

    const bodyBytes = await readBody(req);
    let bodyJSON: Record<string, unknown> | undefined;

    if (bodyBytes.length > 0) {
      try {
        bodyJSON = JSON.parse(bodyBytes.toString("utf-8"));
      } catch {
        // Non-JSON body — pass through for read-only endpoints
      }
    }

    const route = this.router.route(method, path, bodyJSON);

    if (route.action === Action.Deny) {
      const msg = route.denyMsg ?? "denied";
      console.warn(`[${requestId}] DENIED ${method} ${path}: ${msg}`);
      this.audit.deny(method, path, msg);
      res.writeHead(403);
      res.end(msg);
      return;
    }

    if (route.action === Action.CreateContainer && route.policy && route.body) {
      const result = this.chain.execute(method, path, route.policy, route.body);
      if (!result.allowed) {
        console.warn(`[${requestId}] DENIED ${method} ${path}: ${result.reason}`);
        this.audit.deny(method, path, result.reason);
        res.writeHead(403);
        res.end(result.reason);
        return;
      }

      console.log(`[${requestId}] ALLOWED ${method} ${path}`);
      this.audit.allow(method, path);
      await this.transport.forward(req, res, result.modifiedBody);
      return;
    }

    console.log(`[${requestId}] ALLOWED ${method} ${path}`);
    this.audit.allow(method, path);
    await this.transport.forward(req, res, bodyBytes.length > 0 ? bodyBytes : undefined);
  }

  // Answers a CONNECT request with 403 on the raw socket (#78). Node emits
  // CONNECT as the server's "connect" event, never as a request, and without
  // a listener it destroys the socket, so the caller got no response and
  // nothing was audited.
  refuseConnect(req: IncomingMessage, socket: Duplex): void {
    socket.on("error", () => {});
    const method = req.method ?? "CONNECT";
    const target = req.url ?? "";
    console.warn(`[${randomBytes(8).toString("hex")}] DENIED ${method} ${target}: ${CONNECT_REFUSED}`);
    this.audit.deny(method, target, CONNECT_REFUSED);
    const resp =
      "HTTP/1.1 403 Forbidden\r\n" +
      "Content-Type: text/plain; charset=utf-8\r\n" +
      `Content-Length: ${Buffer.byteLength(CONNECT_REFUSED)}\r\n` +
      "Connection: close\r\n\r\n" +
      CONNECT_REFUSED;
    socket.end(resp, () => socket.destroy());
  }
}

const CONNECT_REFUSED = "CONNECT is not allowed";

// An Upgrade header, or a Connection header that lists the upgrade token.
function isUpgradeRequest(req: IncomingMessage): boolean {
  if (req.headers.upgrade !== undefined) return true;
  const connection = req.headers.connection ?? "";
  return connection.split(",").some((tok) => tok.trim().toLowerCase() === "upgrade");
}

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks)));
  });
}
