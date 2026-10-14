import type { ImageRef, Policy } from "./policy.js";
import { checkImageTag, matchesImagePrefix, parseImageRef } from "./policy.js";

export interface Gate {
  check(method: string, path: string, policy: Policy, body: Record<string, unknown>): string | null;
}

export interface Mutator {
  mutate(policy: Policy, body: Record<string, unknown>): void;
}

export class Chain {
  private gates: Gate[];
  private mutators: Mutator[];

  constructor() {
    this.gates = [];
    this.mutators = [new ContainerConfigMutator()];

    this.gates.push(new RegistryGate());
    this.gates.push(new MountSourceGate());
    this.gates.push(new EnvFileGate());
    this.gates.push(new HostConfigGate());
    this.gates.push(new CmdGate());
    this.gates.push(new NetworkEndpointsGate());
  }

  execute(
    method: string,
    path: string,
    policy: Policy,
    body: Record<string, unknown>,
  ): { allowed: boolean; reason: string; modifiedBody?: Buffer } {
    for (const m of this.mutators) {
      m.mutate(policy, body);
    }

    for (const g of this.gates) {
      const err = g.check(method, path, policy, body);
      if (err !== null) {
        return { allowed: false, reason: `validation failed: ${err}` };
      }
    }

    return { allowed: true, reason: "container create allowed", modifiedBody: Buffer.from(JSON.stringify(body)) };
  }
}

const SAFE_CHARSET = /^[A-Za-z0-9._=:/,\-]{1,256}$/;

export class RegistryGate implements Gate {
  check(_method: string, _path: string, policy: Policy, body: Record<string, unknown>): string | null {
    const image = body["Image"] as string | undefined;
    if (!image) return null;

    // The same parser as the router, so a registry port is not a tag (#84).
    let ref: ImageRef;
    try {
      ref = parseImageRef(image);
    } catch (err) {
      return (err as Error).message;
    }
    if (!matchesImagePrefix(ref.name, policy.allowed_image_prefixes)) {
      return `image "${ref.name}" is not in allowed prefixes`;
    }
    return checkImageTag(policy, ref);
  }
}

type JsonObject = Record<string, unknown>;

function isObject(v: unknown): v is JsonObject {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

// Keys in byte order, so that the first deny is the same one Go and Rust report.
function sortedKeys(obj: JsonObject): string[] {
  return Object.keys(obj).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

// null, false, 0, "", [] and {}.
function isZeroValue(v: unknown): boolean {
  if (v === null || v === undefined || v === false || v === 0 || v === "") return true;
  if (Array.isArray(v)) return v.length === 0;
  if (isObject(v)) return Object.keys(v).length === 0;
  return false;
}

// Folds a key the way the daemon's JSON decoder matches field names: ASCII
// case, plus the Kelvin sign (U+212A) as k and the long s (U+017F) as s.
function foldKey(s: string): string {
  let out = "";
  for (const c of s) {
    if (c >= "A" && c <= "Z") out += c.toLowerCase();
    else if (c === "K") out += "k";
    else if (c === "ſ") out += "s";
    else out += c;
  }
  return out;
}

// Denies a key that the daemon would read as one of fields but that is not
// spelled exactly like it.
function checkFieldCase(prefix: string, obj: JsonObject, fields: readonly string[], policy: Policy): string | null {
  for (const key of sortedKeys(obj)) {
    const folded = foldKey(key);
    for (const f of fields) {
      if (key !== f && folded === foldKey(f)) {
        return `${prefix}${key} is not allowed for service ${policy.service_name} (the daemon reads it as ${prefix}${f})`;
      }
    }
  }
  return null;
}

// Go's %q / Rust's {:?} for the strings in deny messages.
function quote(s: string): string {
  return JSON.stringify(s);
}

// The bind options allowed in a Binds entry. The propagation modes shared,
// rshared, slave and rslave are not among them.
const BIND_MODES = new Set(["ro", "rw", "z", "Z", "nocopy", "private", "rprivate"]);

const MOUNT_FIELDS = [
  "Type",
  "Source",
  "Target",
  "ReadOnly",
  "Consistency",
  "BindOptions",
  "VolumeOptions",
  "ImageOptions",
  "TmpfsOptions",
  "ClusterOptions",
] as const;

// May hold any value in a Mounts entry; Type, Source, ReadOnly and
// BindOptions have their own rules, and every other key must be zero.
const MOUNT_ANY_VALUE = new Set(["Target", "Consistency", "TmpfsOptions"]);

const BIND_OPTION_FIELDS = [
  "Propagation",
  "NonRecursive",
  "CreateMountpoint",
  "ReadOnlyNonRecursive",
  "ReadOnlyForceRecursive",
] as const;

// May hold any value in BindOptions; Propagation has its own rule, and every
// other key, ReadOnlyNonRecursive included, must be zero.
const BIND_OPTION_ANY_VALUE = new Set(["NonRecursive", "CreateMountpoint", "ReadOnlyForceRecursive"]);

function findVolume(hostPath: string, policy: Policy) {
  return policy.volumes?.find((v) => v.host_path === hostPath);
}

function checkBinds(raw: unknown, policy: Policy): string | null {
  if (raw === undefined || raw === null) return null;
  const notList = `HostConfig.Binds must be a list of strings for service ${policy.service_name}`;
  if (!Array.isArray(raw)) return notList;
  for (const bind of raw) {
    if (typeof bind !== "string") return notList;
    const parts = bind.split(":");
    if (bind === "" || parts.length > 3) {
      return `bind ${quote(bind)} is not a valid bind for service ${policy.service_name}`;
    }
    const hostPath = parts[0];
    const vol = findVolume(hostPath, policy);
    if (!vol) {
      return `volume mount ${quote(hostPath)} is not in the whitelist for service ${policy.service_name}`;
    }
    const opts = parts.length === 3 && parts[2] !== "" ? parts[2].split(",") : [];
    for (const o of opts) {
      if (!BIND_MODES.has(o)) {
        return `bind option ${quote(o)} on volume mount ${quote(hostPath)} is not allowed for service ${policy.service_name}`;
      }
    }
    if (!vol.read_write && (!opts.includes("ro") || opts.includes("rw"))) {
      return `volume mount ${quote(hostPath)} must be read-only (:ro) for service ${policy.service_name}`;
    }
  }
  return null;
}

function checkMounts(raw: unknown, policy: Policy): string | null {
  if (raw === undefined || raw === null) return null;
  if (!Array.isArray(raw)) return `HostConfig.Mounts must be a list for service ${policy.service_name}`;
  for (const m of raw) {
    if (!isObject(m)) return `HostConfig.Mounts entry must be an object for service ${policy.service_name}`;
    const err = checkMount(m, policy);
    if (err !== null) return err;
  }
  return null;
}

function checkMount(mount: JsonObject, policy: Policy): string | null {
  const caseErr = checkFieldCase("HostConfig.Mounts.", mount, MOUNT_FIELDS, policy);
  if (caseErr !== null) return caseErr;
  for (const key of sortedKeys(mount)) {
    if (key === "Type" || key === "Source" || key === "ReadOnly" || MOUNT_ANY_VALUE.has(key)) continue;
    if (key === "BindOptions") {
      const err = checkBindOptions(mount[key], policy);
      if (err !== null) return err;
      continue;
    }
    if (!isZeroValue(mount[key])) {
      return `HostConfig.Mounts.${key} is not allowed for service ${policy.service_name}`;
    }
  }

  const mountType = typeof mount["Type"] === "string" ? mount["Type"] : "";
  const source = typeof mount["Source"] === "string" ? mount["Source"] : "";
  if (mountType === "tmpfs") {
    if (!isZeroValue(mount["Source"])) {
      return `tmpfs mount must not have a Source for service ${policy.service_name}`;
    }
    return null;
  }
  if (mountType === "bind") {
    const vol = findVolume(source, policy);
    if (!vol) {
      return `mount source ${quote(source)} is not in the whitelist for service ${policy.service_name}`;
    }
    if (!vol.read_write && mount["ReadOnly"] !== true) {
      return `mount of ${quote(source)} must be read-only (ReadOnly: true) for service ${policy.service_name}`;
    }
    return null;
  }
  return `mount type ${quote(mountType)} is not allowed for service ${policy.service_name}`;
}

function checkBindOptions(raw: unknown, policy: Policy): string | null {
  if (raw === undefined || raw === null) return null;
  if (!isObject(raw)) return `HostConfig.Mounts.BindOptions must be an object for service ${policy.service_name}`;
  const caseErr = checkFieldCase("HostConfig.Mounts.BindOptions.", raw, BIND_OPTION_FIELDS, policy);
  if (caseErr !== null) return caseErr;
  for (const key of sortedKeys(raw)) {
    const value = raw[key];
    if (key === "Propagation") {
      if (value === null) continue;
      if (typeof value !== "string") {
        return `mount propagation ${JSON.stringify(value)} is not allowed for service ${policy.service_name}`;
      }
      if (value !== "" && value !== "private" && value !== "rprivate") {
        return `mount propagation ${quote(value)} is not allowed for service ${policy.service_name}`;
      }
      continue;
    }
    if (BIND_OPTION_ANY_VALUE.has(key)) continue;
    if (!isZeroValue(value)) {
      return `HostConfig.Mounts.BindOptions.${key} is not allowed for service ${policy.service_name}`;
    }
  }
  return null;
}

// MountSourceGate checks every host path a create request mounts against the
// policy's volumes: HostConfig.Binds, HostConfig.Mounts and the top-level
// Volumes keys. A policy with no volumes allows no binds. A volume with
// read_write: false must be mounted read-only (#88).
export class MountSourceGate implements Gate {
  check(_method: string, _path: string, policy: Policy, body: Record<string, unknown>): string | null {
    const hostConfig = body["HostConfig"];
    if (isObject(hostConfig)) {
      const err = checkBinds(hostConfig["Binds"], policy) ?? checkMounts(hostConfig["Mounts"], policy);
      if (err !== null) return err;
    }

    const topVolumes = body["Volumes"];
    if (isObject(topVolumes)) {
      for (const hostPath of sortedKeys(topVolumes)) {
        if (!findVolume(hostPath, policy)) {
          return `volume ${quote(hostPath)} is not in the whitelist for service ${policy.service_name}`;
        }
      }
    }

    return null;
  }
}

// Every HostConfig field of the Docker Engine API (v1.44 and later, including
// the embedded Resources fields), plus a few removed ones. Used only to catch
// case variants of field names.
const HOST_CONFIG_FIELDS = [
  "Binds",
  "ContainerIDFile",
  "LogConfig",
  "NetworkMode",
  "PortBindings",
  "RestartPolicy",
  "AutoRemove",
  "VolumeDriver",
  "VolumesFrom",
  "Mounts",
  "ConsoleSize",
  "Annotations",
  "CapAdd",
  "CapDrop",
  "CgroupnsMode",
  "Dns",
  "DnsOptions",
  "DnsSearch",
  "ExtraHosts",
  "GroupAdd",
  "IpcMode",
  "Cgroup",
  "Links",
  "OomScoreAdj",
  "PidMode",
  "Privileged",
  "PublishAllPorts",
  "ReadonlyRootfs",
  "SecurityOpt",
  "StorageOpt",
  "Tmpfs",
  "UTSMode",
  "UsernsMode",
  "ShmSize",
  "Sysctls",
  "Runtime",
  "Isolation",
  "MaskedPaths",
  "ReadonlyPaths",
  "Init",
  "Capabilities",
  "CpuShares",
  "Memory",
  "CgroupParent",
  "BlkioWeight",
  "BlkioWeightDevice",
  "BlkioDeviceReadBps",
  "BlkioDeviceWriteBps",
  "BlkioDeviceReadIOps",
  "BlkioDeviceWriteIOps",
  "CpuPeriod",
  "CpuQuota",
  "CpuRealtimePeriod",
  "CpuRealtimeRuntime",
  "CpusetCpus",
  "CpusetMems",
  "Devices",
  "DeviceCgroupRules",
  "DeviceRequests",
  "KernelMemory",
  "KernelMemoryTCP",
  "MemoryReservation",
  "MemorySwap",
  "MemorySwappiness",
  "NanoCpus",
  "OomKillDisable",
  "PidsLimit",
  "Ulimits",
  "CpuCount",
  "CpuPercent",
  "IOMaximumIOps",
  "IOMaximumBandwidth",
] as const;

// Every top-level field of the create body (the container Config, HostConfig
// and NetworkingConfig), used to catch case variants.
const CREATE_BODY_FIELDS = [
  "Hostname",
  "Domainname",
  "User",
  "AttachStdin",
  "AttachStdout",
  "AttachStderr",
  "ExposedPorts",
  "Tty",
  "OpenStdin",
  "StdinOnce",
  "Env",
  "Cmd",
  "Healthcheck",
  "ArgsEscaped",
  "Image",
  "Volumes",
  "WorkingDir",
  "Entrypoint",
  "NetworkDisabled",
  "MacAddress",
  "OnBuild",
  "Labels",
  "StopSignal",
  "StopTimeout",
  "Shell",
  "HostConfig",
  "NetworkingConfig",
] as const;

// Every field of NetworkingConfig.
const NETWORKING_CONFIG_FIELDS = ["EndpointsConfig"] as const;

// May hold any value. NetworkMode, RestartPolicy and LogConfig are
// overwritten by the mutator when the policy sets them.
const HOST_CONFIG_ANY_VALUE = new Set([
  "NetworkMode",
  "RestartPolicy",
  "LogConfig",
  "CapDrop",
  "ReadonlyRootfs",
  "Init",
  "AutoRemove",
  "ConsoleSize",
  "ShmSize",
  "PortBindings",
  "PublishAllPorts",
  "Dns",
  "DnsOptions",
  "DnsSearch",
  "ExtraHosts",
  "Tmpfs",
  "Ulimits",
  "Memory",
  "MemoryReservation",
  "MemorySwap",
  "MemorySwappiness",
  "NanoCpus",
  "CpuShares",
  "CpuPeriod",
  "CpuQuota",
  "CpusetCpus",
  "CpusetMems",
  "PidsLimit",
  "BlkioWeight",
  "ContainerIDFile",
]);

// The values a namespace field may take besides "". "host" and
// "container:<id>" are denied.
const HOST_CONFIG_MODES = new Map<string, readonly string[]>([
  ["PidMode", []],
  ["IpcMode", ["private", "shareable", "none"]],
  ["UTSMode", []],
  ["UsernsMode", []],
  ["CgroupnsMode", ["private"]],
  ["Cgroup", []],
  ["Isolation", ["default"]],
]);

const NO_NEW_PRIVILEGES = new Set(["no-new-privileges", "no-new-privileges:true"]);

function checkSecurityOpt(value: unknown, policy: Policy): string | null {
  if (value === null) return null;
  if (!Array.isArray(value)) return `HostConfig.SecurityOpt must be a list for service ${policy.service_name}`;
  for (const e of value) {
    if (typeof e !== "string") {
      return `HostConfig.SecurityOpt entry ${JSON.stringify(e)} is not allowed for service ${policy.service_name}`;
    }
    if (NO_NEW_PRIVILEGES.has(e) || policy.container_config?.security_options?.includes(e)) continue;
    return `HostConfig.SecurityOpt entry ${quote(e)} is not allowed for service ${policy.service_name}`;
  }
  return null;
}

// HostConfigGate is the default-deny check on HostConfig (#88). It runs after
// ContainerConfigMutator, on the body that is forwarded, so values the policy
// forces (Privileged, NetworkMode, SecurityOpt, ...) are what it sees.
//
// A key in HOST_CONFIG_ANY_VALUE may hold any value. SecurityOpt, OomScoreAdj
// and the namespace modes have their own rules. Binds and Mounts are checked
// by MountSourceGate. Every other key, known or not, must be absent or hold a
// zero value (null, false, 0, "", [] or {}); MaskedPaths and ReadonlyPaths
// must be absent or null, because an empty list unmasks /proc.
//
// The daemon matches JSON keys without regard to case, and the last match
// wins, so "privileged": true would set Privileged and "securityopt": null
// would clear a forced SecurityOpt. A key that folds to a known field name but
// is not spelled exactly like it is denied, here and at the top level.
export class HostConfigGate implements Gate {
  check(_method: string, _path: string, policy: Policy, body: Record<string, unknown>): string | null {
    const topErr = checkFieldCase("", body, CREATE_BODY_FIELDS, policy);
    if (topErr !== null) return topErr;
    // NetworkEndpointsGate and the mutator read NetworkingConfig.EndpointsConfig
    // by its exact name; the daemon would also read "endpointsconfig".
    const nc = body["NetworkingConfig"];
    if (isObject(nc)) {
      const ncErr = checkFieldCase("NetworkingConfig.", nc, NETWORKING_CONFIG_FIELDS, policy);
      if (ncErr !== null) return ncErr;
    }

    const hc = body["HostConfig"];
    if (hc === undefined || hc === null) return null;
    if (!isObject(hc)) return `HostConfig must be an object for service ${policy.service_name}`;
    const caseErr = checkFieldCase("HostConfig.", hc, HOST_CONFIG_FIELDS, policy);
    if (caseErr !== null) return caseErr;

    for (const key of sortedKeys(hc)) {
      const value = hc[key];
      // Binds and Mounts: MountSourceGate.
      if (key === "Binds" || key === "Mounts" || HOST_CONFIG_ANY_VALUE.has(key)) continue;
      if (key === "MaskedPaths" || key === "ReadonlyPaths") {
        if (value !== null) return `HostConfig.${key} is not allowed for service ${policy.service_name}`;
        continue;
      }
      if (key === "SecurityOpt") {
        const err = checkSecurityOpt(value, policy);
        if (err !== null) return err;
        continue;
      }
      if (key === "OomScoreAdj") {
        if (value !== null && !(typeof value === "number" && value >= 0)) {
          return `HostConfig.OomScoreAdj value ${JSON.stringify(value)} is not allowed for service ${policy.service_name}`;
        }
        continue;
      }
      const modes = HOST_CONFIG_MODES.get(key);
      if (modes !== undefined) {
        if (value === null || value === "" || (typeof value === "string" && modes.includes(value))) continue;
        const shown = typeof value === "string" ? quote(value) : JSON.stringify(value);
        return `HostConfig.${key} value ${shown} is not allowed for service ${policy.service_name}`;
      }
      if (!isZeroValue(value)) return `HostConfig.${key} is not allowed for service ${policy.service_name}`;
    }
    return null;
  }
}

export class EnvFileGate implements Gate {
  check(_method: string, _path: string, policy: Policy, body: Record<string, unknown>): string | null {
    if (!policy.env_file) return null;

    const env = body["Env"] as unknown[] | undefined;
    if (env?.length) {
      return `inline environment variables are not allowed for service ${policy.service_name}; use env_file: ${policy.env_file}`;
    }

    const hostConfig = body["HostConfig"] as Record<string, unknown> | undefined;
    if (hostConfig) {
      const hcEnv = hostConfig["Env"] as unknown[] | undefined;
      if (hcEnv?.length) {
        return `inline environment variables in HostConfig are not allowed for service ${policy.service_name}; use env_file: ${policy.env_file}`;
      }
    }

    return null;
  }
}

export class CmdGate implements Gate {
  check(_method: string, _path: string, policy: Policy, body: Record<string, unknown>): string | null {
    const cmd = body["Cmd"] as string[] | undefined;
    if (!cmd?.length) return null;

    for (let i = 0; i < cmd.length; i++) {
      const arg = cmd[i];
      if (!SAFE_CHARSET.test(arg)) {
        return `Cmd argument "${arg}" contains invalid characters`;
      }
      if (!arg.startsWith("-")) continue;

      const flag = arg.split("=")[0];

      if (policy.denied_flags?.includes(flag)) {
        return `flag "${flag}" is denied for service ${policy.service_name}`;
      }
      if (!policy.allowed_cli_flags?.includes(flag)) {
        return `flag "${flag}" is not in the allowlist for service ${policy.service_name}`;
      }

      let value = "";
      const eqIdx = arg.indexOf("=");
      if (eqIdx !== -1) {
        value = arg.slice(eqIdx + 1);
      } else if (i + 1 < cmd.length && !cmd[i + 1].startsWith("-")) {
        value = cmd[i + 1];
        i++;
      }

      if (value && policy.flag_rules) {
        for (const rule of policy.flag_rules) {
          if (rule.flag === flag) {
            if (!new RegExp(rule.value_pattern).test(value)) {
              return `flag ${flag} value "${value}" does not match pattern "${rule.value_pattern}"`;
            }
            break;
          }
        }
      }
    }

    return null;
  }
}

/** NetworkingConfig.EndpointsConfig of a create body: null when absent or null, "malformed" when not an object. */
function endpointsConfig(body: Record<string, unknown>): Record<string, unknown> | null | "malformed" {
  const nc = body["NetworkingConfig"];
  if (nc === undefined || nc === null) return null;
  if (!isObject(nc)) return "malformed";
  const eps = nc["EndpointsConfig"];
  if (eps === undefined || eps === null) return null;
  return isObject(eps) ? eps : "malformed";
}

/** A network mode in which the container joins no network of its own. */
function detachedNetworkMode(mode: string): boolean {
  return mode === "host" || mode === "none" || mode.startsWith("container:");
}

/**
 * When the policy forces network_mode M, every key in
 * NetworkingConfig.EndpointsConfig must be "default" or M (#87). Any other key
 * would attach the container to a network the policy does not allow.
 * ContainerConfigMutator leaves such a request unchanged, so this gate sees
 * what the caller sent.
 */
export class NetworkEndpointsGate implements Gate {
  check(_method: string, _path: string, policy: Policy, body: Record<string, unknown>): string | null {
    const mode = policy.container_config?.network_mode;
    if (!mode) return null;
    const eps = endpointsConfig(body);
    if (eps === null) return null;
    if (eps === "malformed") {
      return `NetworkingConfig.EndpointsConfig must be a JSON object; policy forces network_mode ${mode}`;
    }
    const extra = Object.keys(eps)
      .sort()
      .find((k) => k !== "default" && k !== mode);
    if (extra !== undefined) {
      return `network "${extra}" is not allowed for service ${policy.service_name}; policy forces network_mode ${mode}`;
    }
    return null;
  }
}

/**
 * Make NetworkingConfig.EndpointsConfig consistent with the forced network
 * mode (#87): no entries for host, none and container:<id>; otherwise exactly
 * one entry keyed by the mode, with the settings of the caller's entry for the
 * mode, else of its "default" entry, else {}. A request that
 * NetworkEndpointsGate denies is left unchanged.
 */
function forceEndpoints(mode: string, body: Record<string, unknown>): void {
  const sent = endpointsConfig(body);
  if (sent === "malformed") return;
  const eps = sent ?? {};
  if (Object.keys(eps).some((k) => k !== "default" && k !== mode)) return;
  const forced: Record<string, unknown> = {};
  if (!detachedNetworkMode(mode)) {
    forced[mode] = Object.hasOwn(eps, mode) ? eps[mode] : Object.hasOwn(eps, "default") ? eps["default"] : {};
  }
  const nc = isObject(body["NetworkingConfig"]) ? body["NetworkingConfig"] : {};
  nc["EndpointsConfig"] = forced;
  body["NetworkingConfig"] = nc;
}

// ContainerConfigMutator overwrites the fields the policy's container_config
// sets. It forces HostConfig.Privileged to false on every create, even without
// a container_config (#88). A HostConfig that is not an object is left alone
// for HostConfigGate to deny.
export class ContainerConfigMutator implements Mutator {
  mutate(policy: Policy, body: Record<string, unknown>): void {
    const existing = body["HostConfig"];
    if (existing !== undefined && existing !== null && !isObject(existing)) return;
    const hostConfig: JsonObject = isObject(existing) ? existing : {};
    body["HostConfig"] = hostConfig;
    hostConfig["Privileged"] = false;

    const cc = policy.container_config;
    if (!cc) return;

    if (cc.network_mode) hostConfig["NetworkMode"] = cc.network_mode;
    if (cc.restart_policy) hostConfig["RestartPolicy"] = { Name: cc.restart_policy };
    if (cc.security_options?.length) hostConfig["SecurityOpt"] = cc.security_options;
    if (cc.user) body["User"] = cc.user;
    if (cc.log_driver) {
      hostConfig["LogConfig"] = { Type: cc.log_driver, Config: cc.log_options ?? {} };
    }
    if (cc.network_mode) forceEndpoints(cc.network_mode, body);
  }
}
