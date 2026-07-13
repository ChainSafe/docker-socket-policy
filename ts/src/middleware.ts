import type { Policy } from "./policy.js";

export interface Gate {
  check(method: string, path: string, policy: Policy, body: Record<string, unknown>): string | null;
}

export interface Mutator {
  mutate(policy: Policy, body: Record<string, unknown>): void;
}

export class Chain {
  private gates: Gate[];
  private mutators: Mutator[];

  constructor(readonly: boolean) {
    this.gates = [];
    this.mutators = [new ContainerConfigMutator()];

    if (readonly) {
      this.gates.push(new ReadonlyGate());
    }
    this.gates.push(new ExecGate());
    this.gates.push(new RegistryGate());
    this.gates.push(new MountSourceGate());
    this.gates.push(new EnvFileGate());
    this.gates.push(new CmdGate());
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

export class ExecGate implements Gate {
  check(_method: string, path: string, _policy: Policy, _body: Record<string, unknown>): string | null {
    return path.includes("/exec") ? "exec is not allowed: docker exec provides a shell escape vector" : null;
  }
}

export class ReadonlyGate implements Gate {
  check(method: string, _path: string, _policy: Policy, _body: Record<string, unknown>): string | null {
    return ["POST", "PUT", "DELETE", "PATCH"].includes(method)
      ? `read-only mode: ${method} requests are not allowed`
      : null;
  }
}

export class RegistryGate implements Gate {
  check(_method: string, _path: string, policy: Policy, body: Record<string, unknown>): string | null {
    const image = body["Image"] as string | undefined;
    if (!image) return null;

    const colonIdx = image.lastIndexOf(":");
    const atIdx = image.lastIndexOf("@");
    const sepIdx = atIdx !== -1 ? atIdx : colonIdx;
    const tagOrDigest = sepIdx !== -1 && sepIdx > image.lastIndexOf("/") ? image.slice(sepIdx + 1) : "";
    const imageName = sepIdx !== -1 && sepIdx > image.lastIndexOf("/") ? image.slice(0, sepIdx) : image;

    const allowed = policy.allowed_image_prefixes.some(
      (prefix) => imageName === prefix || imageName.startsWith(prefix + "/"),
    );
    if (!allowed) return `image "${imageName}" is not in allowed prefixes`;

    if (tagOrDigest) {
      if (tagOrDigest.length > 128) {
        return `image tag/digest exceeds 128 characters`;
      }
      if (tagOrDigest.startsWith("sha256:")) {
        if (!policy.image_digest_allowed) {
          return `image digests not allowed for service ${policy.service_name}`;
        }
        if (!/^sha256:[a-f0-9]{64}$/.test(tagOrDigest)) {
          return `invalid digest format: ${tagOrDigest}`;
        }
      } else if (policy.image_tag_pattern) {
        if (!new RegExp(policy.image_tag_pattern).test(tagOrDigest)) {
          return `image tag "${tagOrDigest}" does not match pattern "${policy.image_tag_pattern}"`;
        }
      }
    }

    return null;
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
  }
}
