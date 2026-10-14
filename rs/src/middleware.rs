use crate::policy::Policy;
use std::collections::HashMap;

#[cfg(test)]
use crate::policy::{ContainerConfig, FlagRule, Volume};

pub trait Gate: Send + Sync {
    fn check(
        &self,
        _method: &str,
        _path: &str,
        _policy: &Policy,
        _body: &HashMap<String, serde_json::Value>,
    ) -> std::result::Result<(), String> {
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
    pub fn new() -> Self {
        let mut gates: Vec<Box<dyn Gate>> = Vec::new();
        gates.push(Box::new(RegistryGate));
        gates.push(Box::new(MountSourceGate));
        gates.push(Box::new(EnvFileGate));
        gates.push(Box::new(CmdGate));
        gates.push(Box::new(NetworkEndpointsGate));

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
    s.len() <= 256
        && s.chars()
            .all(|c| matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '.' | '_' | '=' | ':' | '/' | ',' | '-'))
}

pub struct RegistryGate;
impl Gate for RegistryGate {
    fn check(
        &self,
        _method: &str,
        _path: &str,
        policy: &Policy,
        body: &HashMap<String, serde_json::Value>,
    ) -> std::result::Result<(), String> {
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

        let allowed = policy
            .allowed_image_prefixes
            .iter()
            .any(|prefix| image_name == prefix || image_name.starts_with(&format!("{}/", prefix)));
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
                let re =
                    regex::Regex::new(r"^sha256:[a-f0-9]{64}$").map_err(|e| format!("invalid digest regex: {}", e))?;
                if !re.is_match(tag_or_digest) {
                    return Err(format!("invalid digest format: {}", tag_or_digest));
                }
            } else if let Some(ref pattern) = policy.image_tag_pattern {
                let re = regex::Regex::new(pattern).map_err(|e| format!("invalid tag pattern regex: {}", e))?;
                if !re.is_match(tag_or_digest) {
                    return Err(format!(
                        "image tag {:?} does not match pattern {:?}",
                        tag_or_digest, pattern
                    ));
                }
            }
        }

        Ok(())
    }
}

pub struct MountSourceGate;
impl Gate for MountSourceGate {
    fn check(
        &self,
        _method: &str,
        _path: &str,
        policy: &Policy,
        body: &HashMap<String, serde_json::Value>,
    ) -> std::result::Result<(), String> {
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
    fn check(
        &self,
        _method: &str,
        _path: &str,
        policy: &Policy,
        body: &HashMap<String, serde_json::Value>,
    ) -> std::result::Result<(), String> {
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
    fn check(
        &self,
        _method: &str,
        _path: &str,
        policy: &Policy,
        body: &HashMap<String, serde_json::Value>,
    ) -> std::result::Result<(), String> {
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
                    return Err(format!(
                        "flag {:?} is not in the allowlist for service {}",
                        flag, policy.service_name
                    ));
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
                                return Err(format!(
                                    "flag {} value {:?} does not match pattern {:?}",
                                    flag, value, rule.value_pattern
                                ));
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

/// The network mode the policy forces, if any (#87).
fn forced_network_mode(policy: &Policy) -> Option<&str> {
    policy
        .container_config
        .as_ref()
        .and_then(|cc| cc.network_mode.as_deref())
        .filter(|m| !m.is_empty())
}

/// NetworkingConfig.EndpointsConfig of a create body: Ok(None) when absent
/// or null, Err when NetworkingConfig or EndpointsConfig is not an object.
fn endpoints_config(
    body: &HashMap<String, serde_json::Value>,
) -> std::result::Result<Option<&serde_json::Map<String, serde_json::Value>>, ()> {
    match body.get("NetworkingConfig") {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Object(nc)) => match nc.get("EndpointsConfig") {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(serde_json::Value::Object(eps)) => Ok(Some(eps)),
            Some(_) => Err(()),
        },
        Some(_) => Err(()),
    }
}

/// A network mode in which the container joins no network of its own.
fn detached_network_mode(mode: &str) -> bool {
    mode == "host" || mode == "none" || mode.starts_with("container:")
}

/// When the policy forces network_mode M, every key in
/// NetworkingConfig.EndpointsConfig must be "default" or M (#87). Any other
/// key would attach the container to a network the policy does not allow.
/// ContainerConfigMutator leaves such a request unchanged, so this gate
/// sees what the caller sent.
pub struct NetworkEndpointsGate;
impl Gate for NetworkEndpointsGate {
    fn check(
        &self,
        _method: &str,
        _path: &str,
        policy: &Policy,
        body: &HashMap<String, serde_json::Value>,
    ) -> std::result::Result<(), String> {
        let mode = match forced_network_mode(policy) {
            Some(m) => m,
            None => return Ok(()),
        };
        let eps = match endpoints_config(body) {
            Ok(Some(eps)) => eps,
            Ok(None) => return Ok(()),
            Err(()) => {
                return Err(format!(
                    "NetworkingConfig.EndpointsConfig must be a JSON object; policy forces network_mode {}",
                    mode
                ))
            }
        };
        if let Some(k) = eps.keys().find(|k| k.as_str() != "default" && k.as_str() != mode) {
            return Err(format!(
                "network {:?} is not allowed for service {}; policy forces network_mode {}",
                k, policy.service_name, mode
            ));
        }
        Ok(())
    }
}

/// Make NetworkingConfig.EndpointsConfig consistent with the forced network
/// mode (#87): no entries for host, none and container:<id>; otherwise
/// exactly one entry keyed by the mode, with the settings of the caller's
/// entry for the mode, else of its "default" entry, else {}. A request that
/// NetworkEndpointsGate denies is left unchanged.
fn force_endpoints(mode: &str, body: &mut HashMap<String, serde_json::Value>) {
    let eps = match endpoints_config(body) {
        Ok(Some(eps)) => eps.clone(),
        Ok(None) => serde_json::Map::new(),
        Err(()) => return,
    };
    if eps.keys().any(|k| k.as_str() != "default" && k.as_str() != mode) {
        return;
    }
    let mut forced = serde_json::Map::new();
    if !detached_network_mode(mode) {
        let entry = eps
            .get(mode)
            .or_else(|| eps.get("default"))
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));
        forced.insert(mode.to_string(), entry);
    }
    let nc = body
        .entry("NetworkingConfig".to_string())
        .or_insert_with(|| serde_json::json!({}));
    if !nc.is_object() {
        *nc = serde_json::json!({});
    }
    if let Some(nc) = nc.as_object_mut() {
        nc.insert("EndpointsConfig".to_string(), serde_json::Value::Object(forced));
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
            hc.insert(
                "SecurityOpt".to_string(),
                serde_json::Value::Array(so.iter().map(|s| serde_json::Value::String(s.clone())).collect()),
            );
        }
        hc.insert("Privileged".to_string(), serde_json::Value::Bool(false));
        if let Some(u) = &cc.user {
            body.insert("User".to_string(), serde_json::Value::String(u.clone()));
        }
        if let Some(mode) = forced_network_mode(policy) {
            force_endpoints(mode, body);
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
        let chain = Chain::new();
        let policy = make_policy("test", vec!["alpine"]);
        let body = body_from_json(serde_json::json!({"Image": "alpine"}));
        let result = chain.execute("POST", "/containers/create", &policy, &body);
        assert!(result.allowed);
        assert_eq!(result.reason, "container create allowed");
    }

    #[test]
    fn test_chain_execute_denies_unknown_image_via_registry_gate() {
        let chain = Chain::new();
        let policy = make_policy("test", vec!["alpine"]);
        let body = body_from_json(serde_json::json!({"Image": "ubuntu"}));
        let result = chain.execute("POST", "/containers/create", &policy, &body);
        assert!(!result.allowed);
        assert!(result.reason.contains("not in allowed prefixes"));
    }

    #[test]
    fn test_chain_execute_with_mutator_sets_hostconfig() {
        let chain = Chain::new();
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
        let body = body_from_json(
            serde_json::json!({"Image": "alpine@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"}),
        );
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

    /// When the policy forces network_mode, the endpoint entries in
    /// NetworkingConfig.EndpointsConfig are made consistent with it (#87).
    /// Before #87 they went through as sent, so the Docker CLI's
    /// {"default": {}} made the start fail with "network default not found",
    /// and an extra entry attached the container to a network the policy does
    /// not allow. Rows mirror the runs in the network_endpoints module of
    /// spec/docker_socket_policy.qnt; mynet stands for a named network and
    /// container:beacon for container:x.
    #[test]
    fn test_chain_network_endpoints() {
        let aliases = r#"{"Aliases":["a"]}"#;
        let ec = |entries: &str| format!(r#"{{"EndpointsConfig":{{{}}}}}"#, entries);
        let extra = |mode: &str| {
            format!(
                r#"network "other" is not allowed for service test; policy forces network_mode {}"#,
                mode
            )
        };
        let malformed = "NetworkingConfig.EndpointsConfig must be a JSON object; policy forces network_mode host";
        let both = ec(r#""default":{},"other":{}"#);
        // (row, forced mode ("" = none), NetworkingConfig sent ("" = absent),
        //  NetworkingConfig forwarded when allowed, deny reason when denied)
        let cases: Vec<(&str, &str, String, String, String)> = vec![
            ("hostNoEndpoints", "host", String::new(), ec(""), String::new()),
            (
                "hostDefaultCleared",
                "host",
                ec(r#""default":{}"#),
                ec(""),
                String::new(),
            ),
            (
                "hostOwnCleared",
                "host",
                ec(&format!(r#""host":{}"#, aliases)),
                ec(""),
                String::new(),
            ),
            ("hostExtraDenied", "host", both.clone(), String::new(), extra("host")),
            ("noneNoEndpoints", "none", String::new(), ec(""), String::new()),
            (
                "noneDefaultCleared",
                "none",
                ec(r#""default":{}"#),
                ec(""),
                String::new(),
            ),
            (
                "noneOwnCleared",
                "none",
                ec(&format!(r#""none":{}"#, aliases)),
                ec(""),
                String::new(),
            ),
            ("noneExtraDenied", "none", both.clone(), String::new(), extra("none")),
            (
                "containerNoEndpoints",
                "container:beacon",
                String::new(),
                ec(""),
                String::new(),
            ),
            (
                "containerDefaultCleared",
                "container:beacon",
                ec(r#""default":{}"#),
                ec(""),
                String::new(),
            ),
            (
                "containerOwnCleared",
                "container:beacon",
                ec(&format!(r#""container:beacon":{}"#, aliases)),
                ec(""),
                String::new(),
            ),
            (
                "containerExtraDenied",
                "container:beacon",
                both.clone(),
                String::new(),
                extra("container:beacon"),
            ),
            (
                "bridgeNoEndpoints",
                "bridge",
                String::new(),
                ec(r#""bridge":{}"#),
                String::new(),
            ),
            (
                "bridgeDefaultRekeyed",
                "bridge",
                ec(&format!(r#""default":{}"#, aliases)),
                ec(&format!(r#""bridge":{}"#, aliases)),
                String::new(),
            ),
            (
                "bridgeOwnKept",
                "bridge",
                ec(&format!(r#""bridge":{}"#, aliases)),
                ec(&format!(r#""bridge":{}"#, aliases)),
                String::new(),
            ),
            (
                "bridgeExtraDenied",
                "bridge",
                both.clone(),
                String::new(),
                extra("bridge"),
            ),
            (
                "namedNoEndpoints",
                "mynet",
                String::new(),
                ec(r#""mynet":{}"#),
                String::new(),
            ),
            (
                "namedDefaultRekeyed",
                "mynet",
                ec(&format!(r#""default":{}"#, aliases)),
                ec(&format!(r#""mynet":{}"#, aliases)),
                String::new(),
            ),
            (
                "namedOwnKept",
                "mynet",
                ec(&format!(r#""mynet":{}"#, aliases)),
                ec(&format!(r#""mynet":{}"#, aliases)),
                String::new(),
            ),
            ("namedExtraDenied", "mynet", both.clone(), String::new(), extra("mynet")),
            (
                "namedOwnOverDefault",
                "mynet",
                ec(&format!(r#""default":{},"mynet":{{}}"#, aliases)),
                ec(r#""mynet":{}"#),
                String::new(),
            ),
            // #87: a null NetworkingConfig or EndpointsConfig counts as absent.
            (
                "#87 null NetworkingConfig",
                "host",
                "null".into(),
                ec(""),
                String::new(),
            ),
            (
                "#87 null EndpointsConfig",
                "bridge",
                r#"{"EndpointsConfig":null}"#.into(),
                ec(r#""bridge":{}"#),
                String::new(),
            ),
            // #87: a NetworkingConfig or EndpointsConfig that is not an object is denied.
            (
                "#87 EndpointsConfig array",
                "host",
                r#"{"EndpointsConfig":[]}"#.into(),
                String::new(),
                malformed.into(),
            ),
            (
                "#87 NetworkingConfig string",
                "host",
                r#""default""#.into(),
                String::new(),
                malformed.into(),
            ),
            // #87 control: without a forced network_mode, NetworkingConfig is untouched.
            ("#87 no forced mode", "", both.clone(), both.clone(), String::new()),
        ];
        let chain = Chain::new();
        let mut mismatches = Vec::new();
        for (row, mode, req, want, deny) in cases {
            let mut policy = make_policy("test", vec!["alpine"]);
            policy.container_config = Some(ContainerConfig {
                network_mode: if mode.is_empty() { None } else { Some(mode.into()) },
                restart_policy: Some("unless-stopped".into()),
                security_options: None,
                user: None,
                log_driver: None,
                log_options: None,
            });
            let mut body = body_from_json(serde_json::json!({"Image": "alpine:3.20"}));
            if !req.is_empty() {
                body.insert("NetworkingConfig".into(), serde_json::from_str(&req).unwrap());
            }
            let result = chain.execute("POST", "/containers/create", &policy, &body);
            if !deny.is_empty() {
                if result.allowed || !result.reason.contains(&deny) {
                    mismatches.push(format!(
                        "{}: got allowed={} {:?}, want deny {:?}",
                        row, result.allowed, result.reason, deny
                    ));
                }
                continue;
            }
            if !result.allowed {
                mismatches.push(format!("{}: got deny {:?}, want {}", row, result.reason, want));
                continue;
            }
            let out: HashMap<String, serde_json::Value> =
                serde_json::from_slice(&result.modified_body.unwrap()).unwrap();
            let want_v: serde_json::Value = serde_json::from_str(&want).unwrap();
            let got = out.get("NetworkingConfig").cloned().unwrap_or(serde_json::Value::Null);
            if got != want_v {
                mismatches.push(format!("{}: got {}, want {}", row, got, want));
            }
        }
        assert!(
            mismatches.is_empty(),
            "{} mismatches:\n{}",
            mismatches.len(),
            mismatches.join("\n")
        );
    }

    /// Pins the registry gate's reference parser (#84): a registry port is
    /// not a tag, Docker Hub spellings match the normalised prefix, and the
    /// tag pattern sees only the tag. The policy's prefixes are normalised,
    /// as the manager stores them. Same rows in Go and TypeScript.
    #[test]
    fn test_registry_gate_parses_references() {
        let gate = RegistryGate;
        let mut policy = make_policy(
            "test",
            vec![
                "chainsafe/lodestar",
                "localhost:5000/team",
                "registry.example.com:443/a",
            ],
        );
        policy.image_tag_pattern = Some("^(v[0-9]+|[0-9.]+)$".into());
        let cases = [
            ("localhost:5000/team/app:1.2", None),
            ("localhost:5000/team/app", None),
            ("docker.io/chainsafe/lodestar:v1", None),
            ("registry.example.com:443/a", None),
            ("Registry.Example.com:443/a:2", None),
            (
                "localhost:5000/team/app:latest",
                Some(r#"image tag "latest" does not match pattern "^(v[0-9]+|[0-9.]+)$""#),
            ),
            (
                "localhost:5000/other:1",
                Some(r#"image "localhost:5000/other" is not in allowed prefixes"#),
            ),
            (
                "chainsafe/Lodestar:v1",
                Some(r#"invalid image reference "chainsafe/Lodestar:v1""#),
            ),
        ];
        let mut mismatches = Vec::new();
        for (image, want_err) in cases {
            let body = body_from_json(serde_json::json!({ "Image": image }));
            let got = gate.check("POST", "/containers/create", &policy, &body);
            let ok = match (&got, want_err) {
                (Ok(()), None) => true,
                (Err(e), Some(want)) => e.contains(want),
                _ => false,
            };
            if !ok {
                mismatches.push(format!("{}: got {:?}, want {:?}", image, got, want_err));
            }
        }
        assert!(
            mismatches.is_empty(),
            "registry gate mismatches:\n{}",
            mismatches.join("\n")
        );
    }
}
