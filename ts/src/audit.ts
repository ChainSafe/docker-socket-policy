import { appendFileSync } from "node:fs";
import { randomBytes } from "node:crypto";

export class AuditLogger {
  constructor(private path: string) {}

  allow(method: string, uri: string) {
    this.log("ALLOW", method, uri, "");
  }

  deny(method: string, uri: string, reason: string) {
    this.log("DENY", method, uri, reason);
  }

  private log(decision: string, method: string, uri: string, reason: string) {
    const entry = {
      timestamp: new Date().toISOString(),
      request_id: randomBytes(8).toString("hex"),
      decision,
      method,
      uri,
      reason,
    };
    try {
      appendFileSync(this.path, JSON.stringify(entry) + "\n");
    } catch {
      // Silently fail — audit should never crash the proxy
    }
  }
}
