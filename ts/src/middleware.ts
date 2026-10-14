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

export class MountSourceGate implements Gate {
  check(_method: string, _path: string, policy: Policy, body: Record<string, unknown>): string | null {
    const volumes = policy.volumes;
    if (!volumes?.length) return null;

    const hostConfig = body["HostConfig"] as Record<string, unknown> | undefined;
    if (hostConfig) {
      const binds = hostConfig["Binds"] as string[] | undefined;
      if (binds) {
        for (const bind of binds) {
          const hostPath = bind.split(":")[0];
          if (!volumes.some((v) => v.host_path === hostPath)) {
            return `volume mount "${hostPath}" is not in the whitelist`;
          }
        }
      }
    }

    const topVolumes = body["Volumes"] as Record<string, unknown> | undefined;
    if (topVolumes) {
      for (const hostPath of Object.keys(topVolumes)) {
        if (!volumes.some((v) => v.host_path === hostPath)) {
          return `volume "${hostPath}" is not in the whitelist`;
        }
      }
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

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
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

export class ContainerConfigMutator implements Mutator {
  mutate(policy: Policy, body: Record<string, unknown>): void {
    const cc = policy.container_config;
    if (!cc) return;

    const hostConfig = (body["HostConfig"] as Record<string, unknown>) ?? {};
    body["HostConfig"] = hostConfig;

    if (cc.network_mode) hostConfig["NetworkMode"] = cc.network_mode;
    if (cc.restart_policy) hostConfig["RestartPolicy"] = { Name: cc.restart_policy };
    if (cc.security_options?.length) hostConfig["SecurityOpt"] = cc.security_options;
    hostConfig["Privileged"] = false;
    if (cc.user) body["User"] = cc.user;
    if (cc.log_driver) {
      hostConfig["LogConfig"] = { Type: cc.log_driver, Config: cc.log_options ?? {} };
    }
    if (cc.network_mode) forceEndpoints(cc.network_mode, body);
  }
}
