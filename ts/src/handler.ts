import { randomBytes } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
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
}

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks)));
  });
}
