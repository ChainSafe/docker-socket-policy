use crate::policy::Policy;
use std::collections::HashMap;

#[cfg(test)]
use crate::policy::{ContainerConfig, FlagRule, Volume};

pub trait Gate: Send + Sync {
    fn check(&self, _method: &str, _path: &str, _policy: &Policy, _body: &HashMap<String, serde_json::Value>) -> std::result::Result<(), String> {
        Ok(())
    }
}

pub trait Mutator: Send + Sync {
    fn mutate(&self, _policy: &Policy, _body: &mut HashMap<String, serde_json::Value>) {}
}

pub struct Chain {
    gates: Vec<Box<dyn Gate>>,
    mutators: Vec<Box<dyn Mutator>>,
}

pub struct GateResult {
    pub allowed: bool,
    pub reason: String,
    pub modified_body: Option<Vec<u8>>,
}

impl Chain {
    pub fn new(readonly: bool) -> Self {
        let mut gates: Vec<Box<dyn Gate>> = Vec::new();
        if readonly {
            gates.push(Box::new(ReadonlyGate));
        }
        gates.push(Box::new(ExecGate));
        gates.push(Box::new(RegistryGate));
        gates.push(Box::new(MountSourceGate));
        gates.push(Box::new(EnvFileGate));
        gates.push(Box::new(CmdGate));

        let mutators: Vec<Box<dyn Mutator>> = vec![Box::new(ContainerConfigMutator)];

        Chain { gates, mutators }
    }

    pub fn execute(
        &self,
        method: &str,
        path: &str,
        policy: &Policy,
        body: &HashMap<String, serde_json::Value>,
    ) -> GateResult {
        let mut body = body.clone();

        for m in &self.mutators {
            m.mutate(policy, &mut body);
        }

        for g in &self.gates {
            if let Err(reason) = g.check(method, path, policy, &body) {
                return GateResult {
                    allowed: false,
                    reason,
                    modified_body: None,
                };
            }
        }

        let modified = serde_json::to_vec(&body).ok();
        GateResult {
            allowed: true,
            reason: "container create allowed".into(),
            modified_body: modified,
        }
    }
}

fn charset_check(s: &str) -> bool {
    s.len() <= 256 && s.chars().all(|c| matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '.' | '_' | '=' | ':' | '/' | ',' | '-'))
}

pub struct ExecGate;
impl Gate for ExecGate {
    fn check(&self, _method: &str, path: &str, _policy: &Policy, _body: &HashMap<String, serde_json::Value>) -> std::result::Result<(), String> {
        if path.contains("/exec") {
            return Err("exec is not allowed: docker exec provides a shell escape vector".into());
        }
        Ok(())
    }
}

pub struct ReadonlyGate;
impl Gate for ReadonlyGate {
    fn check(&self, method: &str, _path: &str, _policy: &Policy, _body: &HashMap<String, serde_json::Value>) -> std::result::Result<(), String> {
        match method {
            "POST" | "PUT" | "DELETE" | "PATCH" => {
                Err(format!("read-only mode: {} requests are not allowed", method))
            }
            _ => Ok(()),
        }
    }
}

pub struct RegistryGate;
impl Gate for RegistryGate {
    fn check(&self, _method: &str, _path: &str, policy: &Policy, body: &HashMap<String, serde_json::Value>) -> std::result::Result<(), String> {
        let image = body.get("Image").and_then(|v| v.as_str());
        let image = match image {
            Some(s) if !s.is_empty() => s,
            _ => return Ok(()),
        };

        let (image_name, tag_or_digest) = if let Some(idx) = image.find(|c: char| c == ':' || c == '@') {
            (&image[..idx], &image[idx + 1..])
        } else {
            (image, "")
        };

        let allowed = policy.allowed_image_prefixes.iter().any(|prefix| {
            image_name == prefix || image_name.starts_with(&format!("{}/", prefix))
        });
        if !allowed {
            return Err(format!("image {:?} is not in allowed prefixes", image_name));
        }

        if !tag_or_digest.is_empty() {
            if tag_or_digest.len() > 128 {
                return Err("image tag/digest exceeds 128 characters".into());
            }

            if tag_or_digest.starts_with("sha256:") {
                if !policy.image_digest_allowed {
                    return Err(format!("image digests not allowed for service {}", policy.service_name));
                }
                let re = regex::Regex::new(r"^sha256:[a-f0-9]{64}$")
                    .map_err(|e| format!("invalid digest regex: {}", e))?;
                if !re.is_match(tag_or_digest) {
                    return Err(format!("invalid digest format: {}", tag_or_digest));
                }
            } else if let Some(ref pattern) = policy.image_tag_pattern {
                let re = regex::Regex::new(pattern)
                    .map_err(|e| format!("invalid tag pattern regex: {}", e))?;
                if !re.is_match(tag_or_digest) {
                    return Err(format!("image tag {:?} does not match pattern {:?}", tag_or_digest, pattern));
                }
            }
        }

        Ok(())
    }
}

pub struct MountSourceGate;
impl Gate for MountSourceGate {
    fn check(&self, _method: &str, _path: &str, policy: &Policy, body: &HashMap<String, serde_json::Value>) -> std::result::Result<(), String> {
        let volumes = match &policy.volumes {
            Some(v) if !v.is_empty() => v,
            _ => return Ok(()),
        };

        if let Some(host_config) = body.get("HostConfig").and_then(|v| v.as_object()) {
            if let Some(binds) = host_config.get("Binds").and_then(|v| v.as_array()) {
                for bind in binds {
                    let bind_str = bind.as_str().unwrap_or("");
                    let host_path = bind_str.split(':').next().unwrap_or(bind_str);
                    if !volumes.iter().any(|v| v.host_path == host_path) {
                        return Err(format!("volume mount {:?} is not in the whitelist", host_path));
                    }
                }
            }
        }

        if let Some(body_volumes) = body.get("Volumes").and_then(|v| v.as_object()) {
            for host_path in body_volumes.keys() {
                if !volumes.iter().any(|v| v.host_path == *host_path) {
                    return Err(format!("volume {:?} is not in the whitelist", host_path));
                }
            }
        }

        Ok(())
    }
}

pub struct EnvFileGate;
impl Gate for EnvFileGate {
    fn check(&self, _method: &str, _path: &str, policy: &Policy, body: &HashMap<String, serde_json::Value>) -> std::result::Result<(), String> {
        let env_file = match &policy.env_file {
            Some(e) if !e.is_empty() => e,
            _ => return Ok(()),
        };

        if let Some(env) = body.get("Env").and_then(|v| v.as_array()) {
            if !env.is_empty() {
                return Err(format!(
                    "inline environment variables are not allowed for service {}; use env_file: {}",
                    policy.service_name, env_file
                ));
            }
        }

        if let Some(host_config) = body.get("HostConfig").and_then(|v| v.as_object()) {
            if let Some(env) = host_config.get("Env").and_then(|v| v.as_array()) {
                if !env.is_empty() {
                    return Err(format!(
                        "inline environment variables in HostConfig are not allowed for service {}; use env_file: {}",
                        policy.service_name, env_file
                    ));
                }
            }
        }

        Ok(())
    }
}

pub struct CmdGate;
impl Gate for CmdGate {
    fn check(&self, _method: &str, _path: &str, policy: &Policy, body: &HashMap<String, serde_json::Value>) -> std::result::Result<(), String> {
        let cmd = match body.get("Cmd").and_then(|v| v.as_array()) {
            Some(c) => c,
            None => return Ok(()),
        };

        let mut i = 0;
        while i < cmd.len() {
            let arg = cmd[i].as_str().unwrap_or("");
            if !charset_check(arg) {
                return Err(format!("Cmd argument {:?} contains invalid characters", arg));
            }
            if !arg.starts_with('-') {
                i += 1;
                continue;
            }
            let flag = arg.split('=').next().unwrap_or(arg);

            if let Some(denied) = &policy.denied_flags {
                if denied.contains(&flag.to_string()) {
                    return Err(format!("flag {:?} is denied for service {}", flag, policy.service_name));
                }
            }
            if let Some(allowed) = &policy.allowed_cli_flags {
                if !allowed.contains(&flag.to_string()) {
                    return Err(format!("flag {:?} is not in the allowlist for service {}", flag, policy.service_name));
                }
            }

            let value = if let Some(eq_idx) = arg.find('=') {
                arg[eq_idx + 1..].to_string()
            } else if i + 1 < cmd.len() {
                let next = cmd[i + 1].as_str().unwrap_or("");
                if !next.starts_with('-') {
                    i += 1;
                    next.to_string()
                } else {
                    String::new()
                }
            } else {
                String::new()
            };

            if !value.is_empty() {
                if let Some(ref rules) = policy.flag_rules {
                    for rule in rules {
                        if rule.flag == flag {
                            let re = regex::Regex::new(&rule.value_pattern)
                                .map_err(|e| format!("invalid flag rule regex: {}", e))?;
                            if !re.is_match(&value) {
                                return Err(format!("flag {} value {:?} does not match pattern {:?}", flag, value, rule.value_pattern));
                            }
                        }
                    }
                }
            }

            i += 1;
        }

        Ok(())
    }
}

pub struct ContainerConfigMutator;
impl Mutator for ContainerConfigMutator {
    fn mutate(&self, policy: &Policy, body: &mut HashMap<String, serde_json::Value>) {
        let cc = match &policy.container_config {
            Some(c) => c,
            None => return,
        };

        let host_config = body
            .entry("HostConfig".to_string())
            .or_insert_with(|| serde_json::Value::Object(Default::default()));
        let hc = host_config.as_object_mut().unwrap();

        if let Some(nm) = &cc.network_mode {
            hc.insert("NetworkMode".to_string(), serde_json::Value::String(nm.clone()));
        }
        if let Some(rp) = &cc.restart_policy {
            let rp_obj = serde_json::json!({"Name": rp});
            hc.insert("RestartPolicy".to_string(), rp_obj);
        }
        if let Some(so) = &cc.security_options {
            hc.insert("SecurityOpt".to_string(), serde_json::Value::Array(
                so.iter().map(|s| serde_json::Value::String(s.clone())).collect()
            ));
        }
        hc.insert("Privileged".to_string(), serde_json::Value::Bool(false));
        if let Some(u) = &cc.user {
            body.insert("User".to_string(), serde_json::Value::String(u.clone()));
        }
    }
}

fn make_policy(name: &str, prefixes: Vec<&str>) -> Policy {
    Policy {
        service_name: name.to_string(),
        user_id: None,
        group_id: None,
        allowed_image_prefixes: prefixes.iter().map(|s| s.to_string()).collect(),
        image_tag_pattern: None,
        image_digest_allowed: false,
        container_config: None,
        volumes: None,
        ports: None,
        env_file: None,
        allowed_cli_flags: None,
        flag_rules: None,
        denied_flags: None,
    }
}

fn body_from_json(json: serde_json::Value) -> HashMap<String, serde_json::Value> {
    serde_json::from_value(json).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exec_gate_allows_normal_create() {
        let gate = ExecGate;
        let policy = make_policy("test", vec!["alpine"]);
        let body = body_from_json(serde_json::json!({"Image": "alpine"}));
        assert!(gate.check("POST", "/containers/create", &policy, &body).is_ok());
    }

    #[test]
    fn test_exec_gate_denies_exec_path() {
        let gate = ExecGate;
        let policy = make_policy("test", vec!["alpine"]);
        let body = HashMap::new();
        assert!(gate.check("POST", "/containers/test/exec", &policy, &body).is_err());
    }

    #[test]
    fn test_exec_gate_denies_exec_endpoint() {
        let gate = ExecGate;
        let policy = make_policy("test", vec!["alpine"]);
        let body = HashMap::new();
        let result = gate.check("POST", "/exec/abc123/start", &policy, &body);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exec"));
    }

    #[test]
    fn test_readonly_gate_allows_get() {
        let gate = ReadonlyGate;
        let policy = make_policy("test", vec!["alpine"]);
        let body = HashMap::new();
        assert!(gate.check("GET", "/containers/json", &policy, &body).is_ok());
    }

    #[test]
    fn test_readonly_gate_denies_post() {
        let gate = ReadonlyGate;
        let policy = make_policy("test", vec!["alpine"]);
        let body = HashMap::new();
        let result = gate.check("POST", "/containers/create", &policy, &body);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("read-only"));
    }

    #[test]
    fn test_readonly_gate_denies_put() {
        let gate = ReadonlyGate;
        let policy = make_policy("test", vec!["alpine"]);
        let body = HashMap::new();
        assert!(gate.check("PUT", "/some/path", &policy, &body).is_err());
    }

    #[test]
    fn test_readonly_gate_denies_delete() {
        let gate = ReadonlyGate;
        let policy = make_policy("test", vec!["alpine"]);
        let body = HashMap::new();
        assert!(gate.check("DELETE", "/containers/x", &policy, &body).is_err());
    }

    #[test]
    fn test_registry_gate_allows_allowed_image() {
        let gate = RegistryGate;
        let policy = make_policy("test", vec!["alpine", "ubuntu"]);
        let body = body_from_json(serde_json::json!({"Image": "alpine:latest"}));
        assert!(gate.check("POST", "/containers/create", &policy, &body).is_ok());
    }

    #[test]
    fn test_registry_gate_allows_prefix_match() {
        let gate = RegistryGate;
        let policy = make_policy("test", vec!["myreg.io/team"]);
        let body = body_from_json(serde_json::json!({"Image": "myreg.io/team/myapp:v1"}));
        assert!(gate.check("POST", "/containers/create", &policy, &body).is_ok());
    }

    #[test]
    fn test_registry_gate_denies_unknown_image() {
        let gate = RegistryGate;
        let policy = make_policy("test", vec!["alpine"]);
        let body = body_from_json(serde_json::json!({"Image": "ubuntu:latest"}));
        let result = gate.check("POST", "/containers/create", &policy, &body);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not in allowed prefixes"));
    }

    #[test]
    fn test_registry_gate_no_image_field() {
        let gate = RegistryGate;
        let policy = make_policy("test", vec!["alpine"]);
        let body = HashMap::new();
        assert!(gate.check("POST", "/containers/create", &policy, &body).is_ok());
    }

    #[test]
    fn test_mount_source_gate_allows_allowed_volume() {
        let gate = MountSourceGate;
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.volumes = Some(vec![Volume {
            host_path: "/data".into(),
            container_path: "/data".into(),
            read_write: true,
        }]);
        let body = body_from_json(serde_json::json!({
            "HostConfig": {"Binds": ["/data:/data:rw"]}
        }));
        assert!(gate.check("POST", "/containers/create", &policy, &body).is_ok());
    }

    #[test]
    fn test_mount_source_gate_denies_unknown_volume() {
        let gate = MountSourceGate;
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.volumes = Some(vec![Volume {
            host_path: "/data".into(),
            container_path: "/data".into(),
            read_write: true,
        }]);
        let body = body_from_json(serde_json::json!({
            "HostConfig": {"Binds": ["/other:/other:rw"]}
        }));
        let result = gate.check("POST", "/containers/create", &policy, &body);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not in the whitelist"));
    }

    #[test]
    fn test_mount_source_gate_no_volumes_in_policy() {
        let gate = MountSourceGate;
        let policy = make_policy("test", vec!["alpine"]);
        let body = body_from_json(serde_json::json!({
            "HostConfig": {"Binds": ["/data:/data"]}
        }));
        assert!(gate.check("POST", "/containers/create", &policy, &body).is_ok());
    }

    #[test]
    fn test_mount_source_gate_no_body_binds() {
        let gate = MountSourceGate;
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.volumes = Some(vec![Volume {
            host_path: "/data".into(),
            container_path: "/data".into(),
            read_write: true,
        }]);
        let body = HashMap::new();
        assert!(gate.check("POST", "/containers/create", &policy, &body).is_ok());
    }

    #[test]
    fn test_env_file_gate_allows_no_env_in_body() {
        let gate = EnvFileGate;
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.env_file = Some("/etc/env".into());
        let body = HashMap::new();
        assert!(gate.check("POST", "/containers/create", &policy, &body).is_ok());
    }

    #[test]
    fn test_env_file_gate_denies_inline_env() {
        let gate = EnvFileGate;
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.env_file = Some("/etc/env".into());
        let body = body_from_json(serde_json::json!({
            "Env": ["FOO=bar"]
        }));
        let result = gate.check("POST", "/containers/create", &policy, &body);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("env_file"));
    }

    #[test]
    fn test_env_file_gate_no_env_file_in_policy() {
        let gate = EnvFileGate;
        let policy = make_policy("test", vec!["alpine"]);
        let body = body_from_json(serde_json::json!({
            "Env": ["FOO=bar"]
        }));
        assert!(gate.check("POST", "/containers/create", &policy, &body).is_ok());
    }

    #[test]
    fn test_cmd_gate_valid_args() {
        let gate = CmdGate;
        let policy = make_policy("test", vec!["alpine"]);
        let body = body_from_json(serde_json::json!({
            "Cmd": ["nginx", "-g", "daemon_off"]
        }));
        assert!(gate.check("POST", "/containers/create", &policy, &body).is_ok());
    }

    #[test]
    fn test_cmd_gate_invalid_chars() {
        let gate = CmdGate;
        let policy = make_policy("test", vec!["alpine"]);
        let body = body_from_json(serde_json::json!({
            "Cmd": ["valid", "invalid\x00char"]
        }));
        let result = gate.check("POST", "/containers/create", &policy, &body);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid characters"));
    }

    #[test]
    fn test_cmd_gate_denied_flag() {
        let gate = CmdGate;
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.denied_flags = Some(vec!["--privileged".into()]);
        let body = body_from_json(serde_json::json!({
            "Cmd": ["--privileged"]
        }));
        let result = gate.check("POST", "/containers/create", &policy, &body);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("denied"));
    }

    #[test]
    fn test_cmd_gate_allowlisted_flag() {
        let gate = CmdGate;
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.allowed_cli_flags = Some(vec!["--cap-drop".into()]);
        let body = body_from_json(serde_json::json!({
            "Cmd": ["--cap-drop=ALL"]
        }));
        assert!(gate.check("POST", "/containers/create", &policy, &body).is_ok());
    }

    #[test]
    fn test_cmd_gate_not_in_allowlist() {
        let gate = CmdGate;
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.allowed_cli_flags = Some(vec!["--cap-drop".into()]);
        let body = body_from_json(serde_json::json!({
            "Cmd": ["--memory=256m"]
        }));
        let result = gate.check("POST", "/containers/create", &policy, &body);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not in the allowlist"));
    }

    #[test]
    fn test_cmd_gate_no_cmd_in_body() {
        let gate = CmdGate;
        let policy = make_policy("test", vec!["alpine"]);
        let body = HashMap::new();
        assert!(gate.check("POST", "/containers/create", &policy, &body).is_ok());
    }

    #[test]
    fn test_container_config_mutator_sets_network_mode() {
        let mutator = ContainerConfigMutator;
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.container_config = Some(ContainerConfig {
            network_mode: Some("host".into()),
            restart_policy: None,
            security_options: None,
            user: None,
            log_driver: None,
            log_options: None,
        });
        let mut body: HashMap<String, serde_json::Value> = HashMap::new();
        mutator.mutate(&policy, &mut body);
        let hc = body.get("HostConfig").unwrap().as_object().unwrap();
        assert_eq!(hc.get("NetworkMode").unwrap(), "host");
        assert_eq!(hc.get("Privileged").unwrap(), false);
    }

    #[test]
    fn test_container_config_mutator_sets_restart_policy() {
        let mutator = ContainerConfigMutator;
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.container_config = Some(ContainerConfig {
            network_mode: None,
            restart_policy: Some("unless-stopped".into()),
            security_options: None,
            user: None,
            log_driver: None,
            log_options: None,
        });
        let mut body = body_from_json(serde_json::json!({"HostConfig": {}}));
        mutator.mutate(&policy, &mut body);
        let hc = body.get("HostConfig").unwrap().as_object().unwrap();
        let rp = hc.get("RestartPolicy").unwrap();
        assert_eq!(rp.get("Name").unwrap(), "unless-stopped");
    }

    #[test]
    fn test_container_config_mutator_sets_user() {
        let mutator = ContainerConfigMutator;
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.container_config = Some(ContainerConfig {
            network_mode: None,
            restart_policy: None,
            security_options: None,
            user: Some("appuser".into()),
            log_driver: None,
            log_options: None,
        });
        let mut body = HashMap::new();
        mutator.mutate(&policy, &mut body);
        assert_eq!(body.get("User").unwrap(), "appuser");
    }

    #[test]
    fn test_container_config_mutator_noop_when_no_config() {
        let mutator = ContainerConfigMutator;
        let policy = make_policy("test", vec!["alpine"]);
        let mut body = HashMap::new();
        mutator.mutate(&policy, &mut body);
        assert!(body.is_empty());
    }

    #[test]
    fn test_chain_execute_allows() {
        let chain = Chain::new(false);
        let policy = make_policy("test", vec!["alpine"]);
        let body = body_from_json(serde_json::json!({"Image": "alpine"}));
        let result = chain.execute("POST", "/containers/create", &policy, &body);
        assert!(result.allowed);
        assert_eq!(result.reason, "container create allowed");
    }

    #[test]
    fn test_chain_execute_denies_exec_via_gate() {
        let chain = Chain::new(false);
        let policy = make_policy("test", vec!["alpine"]);
        let body = HashMap::new();
        let result = chain.execute("POST", "/containers/test/exec", &policy, &body);
        assert!(!result.allowed);
        assert!(result.reason.contains("exec"));
    }

    #[test]
    fn test_chain_execute_denies_unknown_image_via_registry_gate() {
        let chain = Chain::new(false);
        let policy = make_policy("test", vec!["alpine"]);
        let body = body_from_json(serde_json::json!({"Image": "ubuntu"}));
        let result = chain.execute("POST", "/containers/create", &policy, &body);
        assert!(!result.allowed);
        assert!(result.reason.contains("not in allowed prefixes"));
    }

    #[test]
    fn test_chain_execute_readonly_denies_post() {
        let chain = Chain::new(true);
        let policy = make_policy("test", vec!["alpine"]);
        let body = body_from_json(serde_json::json!({"Image": "alpine"}));
        let result = chain.execute("POST", "/containers/create", &policy, &body);
        assert!(!result.allowed);
        assert!(result.reason.contains("read-only"));
    }

    #[test]
    fn test_chain_execute_with_mutator_sets_hostconfig() {
        let chain = Chain::new(false);
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.container_config = Some(ContainerConfig {
            network_mode: Some("bridge".into()),
            restart_policy: None,
            security_options: None,
            user: None,
            log_driver: None,
            log_options: None,
        });
        let body = body_from_json(serde_json::json!({"Image": "alpine"}));
        let result = chain.execute("POST", "/containers/create", &policy, &body);
        assert!(result.allowed);
        assert!(result.modified_body.is_some());
        let modified: HashMap<String, serde_json::Value> =
            serde_json::from_slice(&result.modified_body.unwrap()).unwrap();
        let hc = modified.get("HostConfig").unwrap().as_object().unwrap();
        assert_eq!(hc.get("NetworkMode").unwrap(), "bridge");
    }

    #[test]
    fn test_charset_check_valid() {
        assert!(charset_check("valid-string_123"));
        assert!(charset_check("a"));
    }

    #[test]
    fn test_charset_check_invalid() {
        assert!(!charset_check("string with spaces"));
        assert!(!charset_check("string\nwith\nnewlines"));
    }

    #[test]
    fn test_charset_check_too_long() {
        let long = "a".repeat(257);
        assert!(!charset_check(&long));
    }

    #[test]
    fn test_registry_gate_allows_tag_matching_pattern() {
        let gate = RegistryGate;
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.image_tag_pattern = Some("^v\\d+\\.\\d+$".into());
        let body = body_from_json(serde_json::json!({"Image": "alpine:v1.0"}));
        assert!(gate.check("POST", "/containers/create", &policy, &body).is_ok());
    }

    #[test]
    fn test_registry_gate_denies_tag_not_matching_pattern() {
        let gate = RegistryGate;
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.image_tag_pattern = Some("^v\\d+\\.\\d+$".into());
        let body = body_from_json(serde_json::json!({"Image": "alpine:latest"}));
        let result = gate.check("POST", "/containers/create", &policy, &body);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("does not match pattern"));
    }

    #[test]
    fn test_registry_gate_allows_digest_when_allowed() {
        let gate = RegistryGate;
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.image_digest_allowed = true;
        let body = body_from_json(serde_json::json!({"Image": "alpine@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"}));
        assert!(gate.check("POST", "/containers/create", &policy, &body).is_ok());
    }

    #[test]
    fn test_registry_gate_denies_digest_when_not_allowed() {
        let gate = RegistryGate;
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.image_digest_allowed = false;
        let body = body_from_json(serde_json::json!({"Image": "alpine@sha256:abc123"}));
        let result = gate.check("POST", "/containers/create", &policy, &body);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("image digest"));
    }

    #[test]
    fn test_registry_gate_denies_invalid_digest_format() {
        let gate = RegistryGate;
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.image_digest_allowed = true;
        let body = body_from_json(serde_json::json!({"Image": "alpine@sha256:xyz"}));
        let result = gate.check("POST", "/containers/create", &policy, &body);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid digest"));
    }

    #[test]
    fn test_registry_gate_denies_tag_exceeds_128_chars() {
        let gate = RegistryGate;
        let policy = make_policy("test", vec!["alpine"]);
        let long_tag = "a".repeat(129);
        let body = body_from_json(serde_json::json!({"Image": format!("alpine:{}", long_tag)}));
        let result = gate.check("POST", "/containers/create", &policy, &body);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("128"));
    }

    #[test]
    fn test_cmd_gate_flag_rule_matches() {
        let gate = CmdGate;
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.flag_rules = Some(vec![FlagRule {
            flag: "--memory".into(),
            value_pattern: "^\\d+m$".into(),
        }]);
        let body = body_from_json(serde_json::json!({
            "Cmd": ["--memory=256m"]
        }));
        assert!(gate.check("POST", "/containers/create", &policy, &body).is_ok());
    }

    #[test]
    fn test_cmd_gate_flag_rule_does_not_match() {
        let gate = CmdGate;
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.flag_rules = Some(vec![FlagRule {
            flag: "--memory".into(),
            value_pattern: "^\\d+m$".into(),
        }]);
        let body = body_from_json(serde_json::json!({
            "Cmd": ["--memory=256g"]
        }));
        let result = gate.check("POST", "/containers/create", &policy, &body);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("does not match pattern"));
    }

    #[test]
    fn test_cmd_gate_flag_rule_with_next_arg_value() {
        let gate = CmdGate;
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.flag_rules = Some(vec![FlagRule {
            flag: "--memory".into(),
            value_pattern: "^\\d+m$".into(),
        }]);
        let body = body_from_json(serde_json::json!({
            "Cmd": ["--memory", "256m"]
        }));
        assert!(gate.check("POST", "/containers/create", &policy, &body).is_ok());
    }

    #[test]
    fn test_cmd_gate_flag_rule_skips_next_arg() {
        let gate = CmdGate;
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.flag_rules = Some(vec![FlagRule {
            flag: "--memory".into(),
            value_pattern: "^\\d+m$".into(),
        }]);
        let body = body_from_json(serde_json::json!({
            "Cmd": ["--memory", "256m", "--cap-drop=ALL"]
        }));
        assert!(gate.check("POST", "/containers/create", &policy, &body).is_ok());
    }

    #[test]
    fn test_mount_source_gate_denies_unknown_volume_in_top_level_volumes() {
        let gate = MountSourceGate;
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.volumes = Some(vec![Volume {
            host_path: "/data".into(),
            container_path: "/data".into(),
            read_write: true,
        }]);
        let body = body_from_json(serde_json::json!({
            "Volumes": {"/other": {}}
        }));
        let result = gate.check("POST", "/containers/create", &policy, &body);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not in the whitelist"));
    }

    #[test]
    fn test_mount_source_gate_allows_volume_in_top_level_volumes() {
        let gate = MountSourceGate;
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.volumes = Some(vec![Volume {
            host_path: "/data".into(),
            container_path: "/data".into(),
            read_write: true,
        }]);
        let body = body_from_json(serde_json::json!({
            "Volumes": {"/data": {}}
        }));
        assert!(gate.check("POST", "/containers/create", &policy, &body).is_ok());
    }

    #[test]
    fn test_env_file_gate_denies_host_config_env() {
        let gate = EnvFileGate;
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.env_file = Some("/etc/env".into());
        let body = body_from_json(serde_json::json!({
            "HostConfig": {"Env": ["FOO=bar"]}
        }));
        let result = gate.check("POST", "/containers/create", &policy, &body);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("HostConfig"));
    }

    #[test]
    fn test_env_file_gate_allows_empty_host_config_env() {
        let gate = EnvFileGate;
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.env_file = Some("/etc/env".into());
        let body = body_from_json(serde_json::json!({
            "HostConfig": {"Env": []}
        }));
        assert!(gate.check("POST", "/containers/create", &policy, &body).is_ok());
    }
}
