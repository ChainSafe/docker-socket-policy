import type { ImageRef, Policy } from "./policy.js";
import { Manager, checkImageTag, parseImageRef, validContainerName } from "./policy.js";

export enum Action {
  Deny,
  Allow,
  CreateContainer,
  // A lifecycle action or DELETE on a container that is not directly a
  // covered name. The handler asks the daemon which container it is and
  // allows the request only if its name is covered (#86).
  ResolveContainer,
}

export interface RouteResult {
  action: Action;
  service?: string;
  policy?: Policy;
  body?: Record<string, unknown>;
  container?: string;
  // The daemon's name for `container`, set when the handler resolved it (#86).
  resolvedName?: string;
  image?: string;
  denyMsg?: string;
}

export class Router {
  private readonlyMode = false;

  constructor(readonly manager: Manager) {}

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
      return this.routeCreate(body, query);
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

  private routeCreate(body: Record<string, unknown> | undefined, query: string): RouteResult {
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

    const parsed = createName(query);
    if ("error" in parsed) {
      return { action: Action.Deny, denyMsg: parsed.error };
    }
    const name = parsed.name;

    const selected = this.manager.selectForCreate(image, name);
    if ("error" in selected) {
      return { action: Action.Deny, denyMsg: selected.error };
    }
    const policy = selected.policy;
    return {
      action: Action.CreateContainer,
      service: policy.service_name,
      policy,
      body,
      image,
      ...(name ? { container: name } : {}),
    };
  }

  // Allows a lifecycle action or DELETE on a name that exactly one policy
  // covers. Anything else, including a name that could also be an ID prefix,
  // needs the daemon to say which container it is (#86).
  private routeByName(name: string): RouteResult {
    const covering = this.manager.covering(name);
    if (covering.length === 1 && !couldBeId(name)) {
      return { action: Action.Allow, service: covering[0].service_name, policy: covering[0], container: name };
    }
    return { action: Action.ResolveContainer, container: name };
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
    // Several policies may allow the image once container_names tells their
    // creates apart (#85). A pull creates no container, so any of them may
    // accept the tag or digest; with none, the first one's reason is given.
    const matching = this.manager.matchingImage(ref.name);
    if (matching.length === 0) return deny(`image ${fromImage} not allowed by any policy`);
    let firstReason: string | undefined;
    for (const policy of matching) {
      const reason = checkImageTag(policy, ref);
      if (reason === null) return { action: Action.Allow, service: policy.service_name, image: fromImage };
      firstReason ??= reason;
    }
    return deny(firstReason!);
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

// The ?name= of a create, without the one leading slash the daemon also
// strips, or "" when there is none. The query is parsed as the daemon parses
// it, as the image pull does (#83). error is the deny message for a query the
// daemon would reject or an invalid name (#85).
function createName(query: string): { name: string } | { error: string } {
  const params = parseQuery(query);
  if (!params) return { error: "invalid query string" };
  // The daemon takes the first of a repeated name (r.Form.Get). Deny it rather
  // than pick, as the pull does for its parameters.
  if (params.filter(([k]) => k === "name").length > 1) return { error: "duplicate name query parameter" };
  let name = params.find(([k]) => k === "name")?.[1] ?? "";
  if (name.startsWith("/")) name = name.slice(1);
  if (name !== "" && !validContainerName(name)) return { error: "invalid container name" };
  return { name };
}

// A name of lowercase hex digits only. The daemon looks up an ID, then a name,
// then an ID prefix, so if no container has this name it would act on the
// container whose ID starts with it (#86).
function couldBeId(name: string): boolean {
  return /^[0-9a-f]+$/.test(name);
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
