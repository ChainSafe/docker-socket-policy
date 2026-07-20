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

      this.policiesByName.set(policy.service_name, policy);
    }
  }

  get(serviceName: string): Policy | undefined {
    return this.policiesByName.get(serviceName);
  }

  getByImage(imageRef: string): Policy | undefined {
    const imageName = extractImageName(imageRef);

    for (const policy of this.policiesByName.values()) {
      for (const prefix of policy.allowed_image_prefixes) {
        if (imageName === prefix || imageName.startsWith(prefix + "/")) {
          return policy;
        }
      }
    }
    return undefined;
  }

  list(): string[] {
    return [...this.policiesByName.keys()];
  }
}

function extractImageName(imageRef: string): string {
  const idx = imageRef.search(/[:@]/);
  return idx === -1 ? imageRef : imageRef.slice(0, idx);
}
