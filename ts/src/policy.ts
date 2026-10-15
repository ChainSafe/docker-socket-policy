import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { parse } from "yaml";

export interface Policy {
  service_name: string;
  container_names?: string[];
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
  // Forced as HostConfig.GroupAdd (#93). An empty list is unset.
  group_add?: string[];
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

const GROUP_GID = /^[0-9]+$/;
const GROUP_NAME = /^[a-z_][a-z0-9_-]*\$?$/;

// Validates container_config.group_add (#93): each entry is a YAML string
// holding a decimal GID that fits in 32 bits or a group name of at most 32
// characters; the root group (0 in any decimal form, or root) and duplicates
// (by GID value for numbers) are refused. Only strings are taken: the YAML
// parser reads an unquoted 0x10 as 16, where Go and Rust would read "0x10".
function checkGroupAdd(file: string, groups: unknown): void {
  if (!Array.isArray(groups)) throw new Error(`policy file ${file}: group_add must be a list`);
  const q = JSON.stringify;
  const seen = new Set<string>();
  for (const g of groups) {
    if (typeof g !== "string") {
      throw new Error(`policy file ${file}: group_add entries must be strings (quote GIDs: '64190')`);
    }
    let key: string;
    if (GROUP_GID.test(g)) {
      const gid = BigInt(g);
      if (gid > 0xffffffffn) {
        throw new Error(`policy file ${file}: invalid group_add entry ${q(g)} (want a decimal GID or a group name)`);
      }
      if (gid === 0n) {
        throw new Error(`policy file ${file}: group_add entry ${q(g)} is the root group, which is not allowed`);
      }
      key = `gid:${gid}`;
    } else if (g.length <= 32 && GROUP_NAME.test(g)) {
      if (g === "root") {
        throw new Error(`policy file ${file}: group_add entry ${q(g)} is the root group, which is not allowed`);
      }
      key = `name:${g}`;
    } else {
      throw new Error(`policy file ${file}: invalid group_add entry ${q(g)} (want a decimal GID or a group name)`);
    }
    if (seen.has(key)) throw new Error(`policy file ${file}: duplicate group_add entry ${q(g)}`);
    seen.add(key);
  }
}

// A Docker container name without the optional leading slash (#85).
const VALID_CONTAINER_NAME = /^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/;

export function validContainerName(name: string): boolean {
  return VALID_CONTAINER_NAME.test(name);
}

// The container names a policy manages: its container_names, or its
// service_name when container_names is unset (#85, #86). Lifecycle actions and
// DELETE are forwarded only for covered names.
export function coveredNames(p: Policy): string[] {
  return p.container_names ?? [p.service_name];
}

// Whether a create named `name` may use the policy: a policy without
// container_names accepts any name, including none (#85).
export function acceptsName(p: Policy, name: string): boolean {
  return p.container_names === undefined || p.container_names === null || p.container_names.includes(name);
}

export class Manager {
  private policiesByName = new Map<string, Policy>();
  // Sorted by service_name, so selection never depends on load order (#85).
  private ordered: Policy[] = [];

  // Builds a manager without load-time validation, as Go's
  // NewManagerFromPolicies and Rust's Manager::from_map do. Tests use it to
  // reach states that the constructor refuses, such as ambiguity.
  static fromPolicies(policies: Policy[]): Manager {
    const m = new Manager(undefined);
    for (const p of policies) m.policiesByName.set(p.service_name, p);
    m.sortPolicies();
    return m;
  }

  constructor(configDir: string | undefined) {
    if (configDir === undefined) return;
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

    const fileOf = new Map<string, string>();
    for (const entry of [...entries].sort()) {
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
      if (policy.container_names === null) delete policy.container_names;
      if (policy.container_names !== undefined) {
        if (!Array.isArray(policy.container_names) || policy.container_names.length === 0) {
          throw new Error(`policy file ${entry}: container_names must not be empty`);
        }
        const bad = policy.container_names.find((n) => typeof n !== "string" || !validContainerName(n));
        if (bad !== undefined) {
          throw new Error(`policy file ${entry}: invalid container name ${JSON.stringify(bad)} in container_names`);
        }
      }
      const cc = policy.container_config;
      if (cc && cc.group_add !== undefined && cc.group_add !== null) {
        checkGroupAdd(entry, cc.group_add);
        // An empty group_add is the same as an unset one.
        if (cc.group_add.length === 0) delete cc.group_add;
      } else if (cc) {
        delete cc.group_add;
      }
      // A second file with the same service_name used to replace the first
      // silently (#85).
      const prev = fileOf.get(policy.service_name);
      if (prev !== undefined) {
        throw new Error(
          `policies in ${prev} and ${entry} both use service_name ${JSON.stringify(policy.service_name)}`,
        );
      }
      fileOf.set(policy.service_name, entry);
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

    this.sortPolicies();
    this.checkConflicts(fileOf);
  }

  private sortPolicies(): void {
    this.ordered = [...this.policiesByName.values()].sort((a, b) =>
      a.service_name < b.service_name ? -1 : a.service_name > b.service_name ? 1 : 0,
    );
  }

  // Fails when two policies could both be selected for one create: their
  // image prefixes share a namespace, and one of them accepts any name or
  // their container_names intersect (#85).
  private checkConflicts(fileOf: Map<string, string>): void {
    const q = JSON.stringify;
    for (let i = 0; i < this.ordered.length; i++) {
      for (const b of this.ordered.slice(i + 1)) {
        const a = this.ordered[i];
        const pair = overlappingPrefixes(a.allowed_image_prefixes, b.allowed_image_prefixes);
        if (!pair) continue;
        let reason: string;
        if (a.container_names === undefined) {
          reason = `${q(a.service_name)} has no container_names`;
        } else if (b.container_names === undefined) {
          reason = `${q(b.service_name)} has no container_names`;
        } else {
          const shared = a.container_names.filter((n) => b.container_names!.includes(n)).sort();
          if (shared.length === 0) continue;
          reason = `both accept container name ${q(shared[0])}`;
        }
        throw new Error(
          `conflicting policies ${q(a.service_name)} (${fileOf.get(a.service_name)}) and ${q(b.service_name)} ` +
            `(${fileOf.get(b.service_name)}): image prefixes ${q(pair[0])} and ${q(pair[1])} overlap and ${reason}`,
        );
      }
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
    return this.matchingImage(name)[0];
  }

  // The policies, sorted by service_name, whose prefixes match a normalised
  // repository name (#85).
  matchingImage(name: string): Policy[] {
    return this.ordered.filter((p) => matchesImagePrefix(name, p.allowed_image_prefixes));
  }

  // The one policy whose image prefixes match the normalised repository of
  // imageRef and which accepts the container name ("" for a create without
  // ?name=). No match, or more than one, is an error whose text is the deny
  // message (#85).
  selectForCreate(imageRef: string, name: string): { policy: Policy } | { error: string } {
    let imageName: string;
    try {
      imageName = parseImageRef(imageRef).name;
    } catch (err) {
      return { error: (err as Error).message };
    }
    const matching = this.matchingImage(imageName);
    const candidates = matching.filter((p) => acceptsName(p, name));
    if (matching.length === 0) return { error: `image ${imageRef} not allowed by any policy` };
    if (candidates.length === 0 && name === "") return { error: `image ${imageRef} requires a container name` };
    if (candidates.length === 0) {
      return { error: `container name ${name} not allowed for image ${imageRef} by any policy` };
    }
    if (candidates.length > 1) {
      return {
        error: `ambiguous policy for image ${imageRef} and name ${name}: ${candidates.map((p) => p.service_name).join(", ")}`,
      };
    }
    return { policy: candidates[0] };
  }

  // The policies, sorted by service_name, whose covered names include name
  // (#86).
  covering(name: string): Policy[] {
    return this.ordered.filter((p) => coveredNames(p).includes(name));
  }

  list(): string[] {
    return this.ordered.map((p) => p.service_name);
  }
}

// The first pair of prefixes where one equals the other or is a namespace (/)
// prefix of it.
function overlappingPrefixes(as: string[], bs: string[]): [string, string] | undefined {
  for (const a of as) {
    for (const b of bs) {
      if (a === b || a.startsWith(b + "/") || b.startsWith(a + "/")) return [a, b];
    }
  }
  return undefined;
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
