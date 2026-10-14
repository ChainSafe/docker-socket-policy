import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { parse } from "yaml";

export interface Policy {
  service_name: string;
  user_id?: string;
  group_id?: string;
  allowed_image_prefixes: string[];
  image_tag_pattern?: string;
  image_digest_allowed?: boolean;
  container_config?: ContainerConfig;
  volumes?: Volume[];
  ports?: string[];
  env_file?: string;
  allowed_cli_flags?: string[];
  flag_rules?: FlagRule[];
  denied_flags?: string[];
}

export interface ContainerConfig {
  network_mode?: string;
  restart_policy?: string;
  security_options?: string[];
  user?: string;
  log_driver?: string;
  log_options?: Record<string, string>;
}

export interface Volume {
  host_path: string;
  container_path: string;
  read_write: boolean;
}

export interface FlagRule {
  flag: string;
  value_pattern: string;
}

export class Manager {
  private policiesByName = new Map<string, Policy>();

  constructor(configDir: string) {
    let entries: string[];
    try {
      entries = readdirSync(configDir);
    } catch (err: any) {
      if (err.code === "ENOENT") {
        console.warn(`warn: config dir ${configDir} not found, starting with empty policy set`);
        entries = [];
      } else {
        throw err;
      }
    }

    for (const entry of entries) {
      if (!entry.endsWith(".yaml") && !entry.endsWith(".yml")) continue;

      const filePath = join(configDir, entry);
      const data = readFileSync(filePath, "utf-8");
      const policy = parse(data) as Policy;

      if (!policy.service_name) {
        throw new Error(`policy file ${entry} missing required field 'service_name'`);
      }
      if (!policy.allowed_image_prefixes?.length) {
        throw new Error(`policy file ${entry} missing required field 'allowed_image_prefixes'`);
      }
      // Prefixes are compared in normalised form (#84).
      policy.allowed_image_prefixes = policy.allowed_image_prefixes.map((prefix) => {
        try {
          return normalizeImagePrefix(prefix);
        } catch {
          throw new Error(`policy file ${entry} has an invalid allowed_image_prefixes entry "${prefix}"`);
        }
      });

      this.policiesByName.set(policy.service_name, policy);
    }
  }

  get(serviceName: string): Policy | undefined {
    return this.policiesByName.get(serviceName);
  }

  // The policy whose prefixes match the reference's normalised repository
  // (#84). An invalid reference matches nothing.
  getByImage(imageRef: string): Policy | undefined {
    let name: string;
    try {
      name = parseImageRef(imageRef).name;
    } catch {
      return undefined;
    }
    for (const policy of this.policiesByName.values()) {
      if (matchesImagePrefix(name, policy.allowed_image_prefixes)) return policy;
    }
    return undefined;
  }

  list(): string[] {
    return [...this.policiesByName.keys()];
  }
}

// A parsed image reference (#84). `name` is the normalised repository: the
// registry host, lower-cased, and the path; Docker Hub's host is dropped, and
// so is `library/` before a single-component name, so `alpine`,
// `library/alpine` and `docker.io/library/alpine` are all `alpine`. `tag` and
// `digest` are empty when absent.
export interface ImageRef {
  name: string;
  tag: string;
  digest: string;
}

const DEFAULT_REGISTRIES = new Set(["docker.io", "index.docker.io", "registry-1.docker.io"]);
const DOMAIN_RE =
  /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*(?::[0-9]+)?$/;
const PATH_COMPONENT_RE = /^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$/;
const TAG_RE = /^[A-Za-z0-9_][A-Za-z0-9_.-]*$/;
const SHA256_DIGEST_RE = /^sha256:[a-f0-9]{64}$/;

// Parses `[registry/]repository[:tag][@digest]` the way Docker does (#84).
// The digest follows the first `@`; the tag follows the last `:` after the
// last `/`, so a registry port is not a tag. The first path component is a
// registry host when it contains `.` or `:` or is `localhost`. Only the host
// is lower-cased: upper case in the path is invalid. The digest is checked by
// checkImageTag, not here. Throws on an invalid reference.
export function parseImageRef(reference: string): ImageRef {
  const invalid = () => new Error(`invalid image reference "${reference}"`);
  let rest = reference;
  let digest = "";
  const at = reference.indexOf("@");
  if (at !== -1) {
    digest = reference.slice(at + 1);
    rest = reference.slice(0, at);
    if (!digest) throw invalid();
  }
  const afterSlash = rest.lastIndexOf("/") + 1;
  const colon = rest.slice(afterSlash).lastIndexOf(":");
  let name = rest;
  let tag = "";
  if (colon !== -1) {
    tag = rest.slice(afterSlash + colon + 1);
    name = rest.slice(0, afterSlash + colon);
    if (!TAG_RE.test(tag)) throw invalid();
  }
  const normalized = normalizeName(name);
  if (normalized === undefined) throw invalid();
  return { name: normalized, tag, digest };
}

function normalizeName(name: string): string | undefined {
  let domain: string | undefined;
  let path = name;
  const slash = name.indexOf("/");
  if (slash !== -1) {
    const first = name.slice(0, slash);
    if (first.includes(".") || first.includes(":") || first === "localhost") {
      domain = first.toLowerCase();
      path = name.slice(slash + 1);
    }
  }
  if (domain !== undefined && !DOMAIN_RE.test(domain)) return undefined;
  if (!path.split("/").every((c) => PATH_COMPONENT_RE.test(c))) return undefined;
  if (domain !== undefined && DEFAULT_REGISTRIES.has(domain)) domain = undefined;
  let full: string;
  if (domain !== undefined) {
    full = `${domain}/${path}`;
  } else if (path.startsWith("library/") && !path.slice("library/".length).includes("/")) {
    full = path.slice("library/".length);
  } else {
    full = path;
  }
  return full.length > 255 ? undefined : full;
}

// Normalises a policy prefix at load time (#84). A prefix names a repository
// or a namespace, so a tag or digest makes it invalid. Throws when invalid.
export function normalizeImagePrefix(prefix: string): string {
  const r = parseImageRef(prefix);
  if (r.tag || r.digest) throw new Error(`image prefix "${prefix}" has a tag or digest`);
  return r.name;
}

// Matches a normalised repository against normalised prefixes on namespace
// boundaries ("prefix" or "prefix/..."), never a bare substring.
export function matchesImagePrefix(name: string, prefixes: string[]): boolean {
  return prefixes.some((p) => name === p || name.startsWith(p + "/"));
}

// Applies a policy's digest and tag rules to a parsed reference: the digest
// must be allowed and well-formed, the tag must match image_tag_pattern.
// Shared by the registry gate (create) and the router (pull, #83). Returns
// the deny reason, or null.
export function checkImageTag(policy: Policy, r: ImageRef): string | null {
  if (r.digest) {
    if (r.digest.length > 128) return "image tag/digest exceeds 128 characters";
    if (!policy.image_digest_allowed) return `image digests not allowed for service ${policy.service_name}`;
    if (!SHA256_DIGEST_RE.test(r.digest)) return `invalid digest format: ${r.digest}`;
  }
  if (r.tag) {
    if (r.tag.length > 128) return "image tag/digest exceeds 128 characters";
    if (policy.image_tag_pattern && !new RegExp(policy.image_tag_pattern).test(r.tag)) {
      return `image tag "${r.tag}" does not match pattern "${policy.image_tag_pattern}"`;
    }
  }
  return null;
}
