import type { ImageRef, Policy } from "./policy.js";
import { Manager, checkImageTag, parseImageRef } from "./policy.js";

export enum Action {
  Deny,
  Allow,
  CreateContainer,
}

export interface RouteResult {
  action: Action;
  service?: string;
  policy?: Policy;
  body?: Record<string, unknown>;
  container?: string;
  image?: string;
  denyMsg?: string;
}

export class Router {
  private readonlyMode = false;

  constructor(private manager: Manager) {}

  // Sets read-only mode (--readonly) and returns the router.
  withReadonly(readonly: boolean): this {
    this.readonlyMode = readonly;
    return this;
  }

  // Routes a request. path is the raw request target: the path, still
  // percent-encoded, and the query string, if any. hasBody reports a
  // non-empty raw body of any Content-Type (by default, a parsed JSON body);
  // body is that body parsed as JSON, if it was.
  route(method: string, path: string, body?: Record<string, unknown>, hasBody = body !== undefined): RouteResult {
    // Read-only mode denies every write, for every path (#75).
    if (this.readonlyMode && method !== "GET" && method !== "HEAD") {
      return { action: Action.Deny, denyMsg: `read-only mode: ${method} requests are not allowed` };
    }
    const qmIdx = path.indexOf("?");
    const cleanPath = qmIdx !== -1 ? path.slice(0, qmIdx) : path;
    const query = qmIdx !== -1 ? path.slice(qmIdx + 1) : "";
    // The daemon decodes the path before routing, so deny any escape (#53).
    if (cleanPath.includes("%")) return { action: Action.Deny, denyMsg: "percent-encoded path not allowed" };
    // An empty interior segment can hide a denied prefix such as /exec (#55).
    if (cleanPath.includes("//")) return { action: Action.Deny, denyMsg: "empty path segment not allowed" };
    // A . or .. segment can hide a denied prefix the same way (#70).
    if (hasDotSegment(cleanPath)) return { action: Action.Deny, denyMsg: "dot path segment not allowed" };
    path = stripAPIVersion(cleanPath);

    // Denied endpoints
    if (path.startsWith("/auth")) return { action: Action.Deny, denyMsg: "auth endpoint is not allowed" };
    if (isExecPath(path)) return { action: Action.Deny, denyMsg: "exec is not allowed" };
    if (isAttachPath(path)) return { action: Action.Deny, denyMsg: "attach is not allowed" };
    if (path.startsWith("/build")) return { action: Action.Deny, denyMsg: "build is not allowed" };
    if (path.startsWith("/commit")) return { action: Action.Deny, denyMsg: "commit is not allowed" };

    // Container create
    if (method === "POST" && path === "/containers/create") {
      return this.routeCreate(body);
    }

    // Container lifecycle
    const containerName = extractContainerName(path);
    if (containerName) {
      if (path.endsWith("/start") && method === "POST") return this.routeByName(containerName);
      if (path.endsWith("/stop") && method === "POST") return this.routeByName(containerName);
      if (path.endsWith("/restart") && method === "POST") return this.routeByName(containerName);
      if (path.endsWith("/kill") && method === "POST") return this.routeByName(containerName);
      if (path.endsWith("/wait") && method === "POST") return this.routeByName(containerName);
      if (path.endsWith("/pause") && method === "POST") return this.routeByName(containerName);
      if (path.endsWith("/unpause") && method === "POST") return this.routeByName(containerName);
      if (path.endsWith("/rename") && method === "POST")
        return { action: Action.Deny, denyMsg: "rename is not allowed" };
      if (path.endsWith("/update") && method === "POST")
        return { action: Action.Deny, denyMsg: "update is not allowed" };
      if (method === "DELETE") return this.routeByName(containerName);
      if (method === "GET") return { action: Action.Allow };
    }

    // Image pull
    if (method === "POST" && path === "/images/create") {
      return this.routeImagePull(query, hasBody);
    }

    // Default GET/HEAD passthrough
    if (method === "GET" || method === "HEAD") {
      return { action: Action.Allow };
    }

    return { action: Action.Deny, denyMsg: `endpoint ${method} ${path} is not allowed` };
  }

  private routeCreate(body?: Record<string, unknown>): RouteResult {
    if (!body || !Object.keys(body).length) {
      return { action: Action.Deny, denyMsg: "empty request body" };
    }

    const image = body["Image"] as string | undefined;
    if (!image) {
      return { action: Action.Deny, denyMsg: "image field is required" };
    }
    try {
      parseImageRef(image);
    } catch (err) {
      return { action: Action.Deny, denyMsg: (err as Error).message };
    }

    const policy = this.manager.getByImage(image);
    if (!policy) {
      return { action: Action.Deny, denyMsg: `image ${image} not allowed by any policy` };
    }

    return { action: Action.CreateContainer, service: policy.service_name, policy, body, image };
  }

  private routeByName(name: string): RouteResult {
    const policy = this.manager.get(name);
    if (policy) {
      return { action: Action.Allow, service: policy.service_name, policy };
    }
    return { action: Action.Allow, container: name };
  }

  // Image pull (#83). The Docker CLI sends fromImage and tag in the query
  // string and no body. The image then
  // gets the create checks: a policy prefix on the normalised repository
  // (#84), and that policy's tag and digest rules.
  private routeImagePull(rawQuery: string, hasBody: boolean): RouteResult {
    const deny = (denyMsg: string): RouteResult => ({ action: Action.Deny, denyMsg });
    // The daemon reads a form body's fromImage over the query's, so a body
    // could name any image: a pull has no body, whatever its Content-Type.
    if (hasBody) return deny("image pull must not have a request body");
    const params = parseQuery(rawQuery);
    if (!params) return deny("invalid query string");
    for (const key of ["fromImage", "tag", "fromSrc"]) {
      if (params.filter(([k]) => k === key).length > 1) return deny(`duplicate ${key} query parameter`);
    }
    const get = (key: string) => params.find(([k]) => k === key)?.[1];
    if (get("fromSrc") !== undefined) return deny("image import (fromSrc) is not allowed");
    const fromImage = get("fromImage") ?? "";
    if (!fromImage) return deny("fromImage query parameter is required for image pull");
    let ref: ImageRef;
    try {
      ref = parseImageRef(fromImage);
      const tag = get("tag") ?? "";
      if (tag) {
        if (ref.tag || ref.digest) {
          return deny(`fromImage ${fromImage} already has a tag or digest; the tag query parameter is ambiguous`);
        }
        // The CLI sends a digest in tag; a tag never contains ':'.
        ref = parseImageRef(fromImage + (tag.includes(":") ? "@" : ":") + tag);
      }
    } catch (err) {
      return deny((err as Error).message);
    }
    // With neither, the daemon pulls every tag of the repository.
    if (!ref.tag && !ref.digest) return deny("image pull without a tag or digest pulls every tag and is not allowed");
    const policy = this.manager.getByImage(ref.name);
    if (!policy) return deny(`image ${fromImage} not allowed by any policy`);
    const reason = checkImageTag(policy, ref);
    if (reason !== null) return deny(reason);
    return { action: Action.Allow, service: policy.service_name, image: fromImage };
  }
}

// Parses a query string as Go's url.ParseQuery does, which is what the daemon
// uses: & separates pairs, + is a space, and a ; or a bad % escape fails the
// whole query (undefined).
function parseQuery(raw: string): [string, string][] | undefined {
  const out: [string, string][] = [];
  for (const part of raw.split("&")) {
    if (part.includes(";")) return undefined;
    if (!part) continue;
    const eq = part.indexOf("=");
    const k = queryUnescape(eq === -1 ? part : part.slice(0, eq));
    const v = queryUnescape(eq === -1 ? "" : part.slice(eq + 1));
    if (k === undefined || v === undefined) return undefined;
    out.push([k, v]);
  }
  return out;
}

function queryUnescape(s: string): string | undefined {
  const bytes: number[] = [];
  for (let i = 0; i < s.length;) {
    const c = s[i];
    if (c === "%") {
      const hex = s.slice(i + 1, i + 3);
      if (!/^[0-9A-Fa-f]{2}$/.test(hex)) return undefined;
      bytes.push(parseInt(hex, 16));
      i += 3;
    } else if (c === "+") {
      bytes.push(0x20);
      i += 1;
    } else {
      const cp = s.codePointAt(i)!;
      const ch = String.fromCodePoint(cp);
      bytes.push(...Buffer.from(ch, "utf-8"));
      i += ch.length;
    }
  }
  return Buffer.from(bytes).toString("utf-8");
}

function stripAPIVersion(path: string): string {
  // Accepts /v<major> and /v<major>.<minor> (the Docker CLI sends /v1.43/) (#52).
  const match = path.match(/^\/v\d+(\.\d+)?\//);
  return match ? path.slice(match[0].length - 1) : path;
}

// A segment that is exactly . or ..; names such as .hidden or a.b are not
// dot segments (#70).
function hasDotSegment(path: string): boolean {
  return path.split("/").some((s) => s === "." || s === "..");
}

// Exec is matched on whole segments, so a name like exec-runner is not exec (#49).
function isExecPath(path: string): boolean {
  const [first, ...rest] = path.replace(/^\//, "").split("/");
  return first === "exec" || (first === "containers" && rest.includes("exec"));
}

// Attach is matched on whole segments after /containers, so a name like
// attach-runner is not attach (#76).
function isAttachPath(path: string): boolean {
  const [first, ...rest] = path.replace(/^\//, "").split("/");
  return first === "containers" && rest.includes("attach");
}

function extractContainerName(path: string): string | undefined {
  const parts = path.replace(/^\//, "").split("/");
  if (parts[0] === "containers" && parts[1] && !["create", "json", "exec"].includes(parts[1])) {
    return parts[1];
  }
  return undefined;
}
