import type { Policy } from "./policy.js";
import { Manager } from "./policy.js";

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

  route(method: string, path: string, body?: Record<string, unknown>): RouteResult {
    // Read-only mode denies every write, for every path (#75).
    if (this.readonlyMode && method !== "GET" && method !== "HEAD") {
      return { action: Action.Deny, denyMsg: `read-only mode: ${method} requests are not allowed` };
    }
    const qmIdx = path.indexOf("?");
    const cleanPath = qmIdx !== -1 ? path.slice(0, qmIdx) : path;
    // The daemon decodes the path before routing, so deny any escape (#53).
    if (cleanPath.includes("%")) return { action: Action.Deny, denyMsg: "percent-encoded path not allowed" };
    // An empty interior segment can hide a denied prefix such as /exec (#55).
    if (cleanPath.includes("//")) return { action: Action.Deny, denyMsg: "empty path segment not allowed" };
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
      return this.routeImagePull(body);
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

  private routeImagePull(body?: Record<string, unknown>): RouteResult {
    if (!body || !Object.keys(body).length) {
      return { action: Action.Deny, denyMsg: "empty request body" };
    }

    const fromImage = body["fromImage"] as string | undefined;
    if (!fromImage) {
      return { action: Action.Deny, denyMsg: "fromImage field is required for image pull" };
    }

    const policy = this.manager.getByImage(fromImage);
    if (!policy) {
      return { action: Action.Deny, denyMsg: `image ${fromImage} not allowed by any policy` };
    }

    return { action: Action.Allow, image: fromImage };
  }
}

function stripAPIVersion(path: string): string {
  // Accepts /v<major> and /v<major>.<minor> (the Docker CLI sends /v1.43/) (#52).
  const match = path.match(/^\/v\d+(\.\d+)?\//);
  return match ? path.slice(match[0].length - 1) : path;
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
