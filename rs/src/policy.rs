use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize)]
pub struct Policy {
    pub service_name: String,
    pub user_id: Option<String>,
    pub group_id: Option<String>,
    pub allowed_image_prefixes: Vec<String>,
    pub image_tag_pattern: Option<String>,
    #[serde(default)]
    pub image_digest_allowed: bool,
    pub container_config: Option<ContainerConfig>,
    pub volumes: Option<Vec<Volume>>,
    pub ports: Option<Vec<String>>,
    pub env_file: Option<String>,
    pub allowed_cli_flags: Option<Vec<String>>,
    pub flag_rules: Option<Vec<FlagRule>>,
    pub denied_flags: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ContainerConfig {
    pub network_mode: Option<String>,
    pub restart_policy: Option<String>,
    pub security_options: Option<Vec<String>>,
    pub user: Option<String>,
    pub log_driver: Option<String>,
    pub log_options: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Volume {
    pub host_path: String,
    pub container_path: String,
    pub read_write: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FlagRule {
    pub flag: String,
    pub value_pattern: String,
}

pub struct Manager {
    policies_by_name: HashMap<String, Policy>,
}

impl Manager {
    pub fn from_map(policies: HashMap<String, Policy>) -> Self {
        Manager {
            policies_by_name: policies,
        }
    }

    pub fn new(config_dir: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut policies_by_name = HashMap::new();
        let entries = match std::fs::read_dir(config_dir) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("warn: config dir {} not found, starting with empty policy set", config_dir);
                return Ok(Manager { policies_by_name });
            }
            Err(e) => return Err(e.into()),
        };

        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map_or(true, |e| e != "yaml" && e != "yml") {
                continue;
            }
            let data = std::fs::read_to_string(&path)?;
            let policy: Policy = serde_yaml::from_str(&data)?;
            if policy.service_name.is_empty() {
                return Err("missing service_name".into());
            }
            if policy.allowed_image_prefixes.is_empty() {
                return Err("missing allowed_image_prefixes".into());
            }
            policies_by_name.insert(policy.service_name.clone(), policy);
        }

        Ok(Manager { policies_by_name })
    }

    pub fn get(&self, name: &str) -> Option<&Policy> {
        self.policies_by_name.get(name)
    }

    pub fn get_by_image(&self, image_ref: &str) -> Option<&Policy> {
        let image_name = extract_image_name(image_ref);
        self.policies_by_name.values().find(|p| {
            p.allowed_image_prefixes
                .iter()
                .any(|prefix| image_name == *prefix || image_name.starts_with(&format!("{}/", prefix)))
        })
    }

    pub fn list(&self) -> Vec<&str> {
        self.policies_by_name.keys().map(|s| s.as_str()).collect()
    }
}

pub(crate) fn extract_image_name(image_ref: &str) -> &str {
    if let Some(idx) = image_ref.find(|c: char| c == ':' || c == '@') {
        &image_ref[..idx]
    } else {
        image_ref
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_deserialize_basic() {
        let yaml = r#"
service_name: test-svc
allowed_image_prefixes:
  - myimage
"#;
        let policy: Policy = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(policy.service_name, "test-svc");
        assert_eq!(policy.allowed_image_prefixes, vec!["myimage"]);
        assert!(policy.container_config.is_none());
    }

    #[test]
    fn test_policy_deserialize_all_fields() {
        let yaml = r#"
service_name: full-svc
user_id: "1000"
group_id: "1001"
allowed_image_prefixes:
  - myimage
  - other/prefix
image_tag_pattern: "^v\\d+\\.\\d+$"
image_digest_allowed: true
container_config:
  network_mode: bridge
  restart_policy: always
  security_options:
    - no-new-privileges
  user: appuser
  log_driver: json-file
  log_options:
    max-size: 10m
volumes:
  - host_path: /data
    container_path: /data
    read_write: true
ports:
  - "8080:80"
env_file: /etc/env
allowed_cli_flags:
  - --cap-drop
flag_rules:
  - flag: --memory
    value_pattern: ^\d+m$
denied_flags:
  - --privileged
"#;
        let policy: Policy = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(policy.service_name, "full-svc");
        assert_eq!(policy.user_id, Some("1000".into()));
        assert_eq!(policy.group_id, Some("1001".into()));
        assert_eq!(policy.allowed_image_prefixes.len(), 2);
        assert_eq!(policy.image_tag_pattern, Some("^v\\d+\\.\\d+$".into()));
        assert!(policy.image_digest_allowed);
        let cc = policy.container_config.unwrap();
        assert_eq!(cc.network_mode, Some("bridge".into()));
        assert_eq!(cc.restart_policy, Some("always".into()));
        assert_eq!(cc.security_options, Some(vec!["no-new-privileges".into()]));
        assert_eq!(cc.user, Some("appuser".into()));
        assert_eq!(cc.log_driver, Some("json-file".into()));
        assert!(cc.log_options.unwrap().contains_key("max-size"));
        let vols = policy.volumes.unwrap();
        assert_eq!(vols[0].host_path, "/data");
    }

    #[test]
    fn test_extract_image_name_no_tag() {
        assert_eq!(extract_image_name("myimage"), "myimage");
    }

    #[test]
    fn test_extract_image_name_with_tag() {
        assert_eq!(extract_image_name("myimage:latest"), "myimage");
    }

    #[test]
    fn test_extract_image_name_with_digest() {
        assert_eq!(extract_image_name("myimage@sha256:abc123"), "myimage");
    }

    #[test]
    fn test_extract_image_name_registry_path() {
        assert_eq!(extract_image_name("registry.example.com/myimage:tag"), "registry.example.com/myimage");
    }

    #[test]
    fn test_manager_get() {
        let mut policies = HashMap::new();
        policies.insert(
            "svc1".into(),
            Policy {
                service_name: "svc1".into(),
                user_id: None,
                group_id: None,
                allowed_image_prefixes: vec!["alpine".into()],
                image_tag_pattern: None,
                image_digest_allowed: false,
                container_config: None,
                volumes: None,
                ports: None,
                env_file: None,
                allowed_cli_flags: None,
                flag_rules: None,
                denied_flags: None,
            },
        );
        let mgr = Manager::from_map(policies);
        assert!(mgr.get("svc1").is_some());
        assert_eq!(mgr.get("svc1").unwrap().service_name, "svc1");
        assert!(mgr.get("nonexistent").is_none());
    }

    #[test]
    fn test_manager_get_by_image_exact() {
        let mut policies = HashMap::new();
        policies.insert(
            "svc1".into(),
            Policy {
                service_name: "svc1".into(),
                user_id: None,
                group_id: None,
                allowed_image_prefixes: vec!["alpine".into()],
                image_tag_pattern: None,
                image_digest_allowed: false,
                container_config: None,
                volumes: None,
                ports: None,
                env_file: None,
                allowed_cli_flags: None,
                flag_rules: None,
                denied_flags: None,
            },
        );
        let mgr = Manager::from_map(policies);
        assert_eq!(mgr.get_by_image("alpine").unwrap().service_name, "svc1");
        assert_eq!(mgr.get_by_image("alpine:latest").unwrap().service_name, "svc1");
        assert_eq!(mgr.get_by_image("alpine@sha256:abc").unwrap().service_name, "svc1");
    }

    #[test]
    fn test_manager_get_by_image_prefix() {
        let mut policies = HashMap::new();
        policies.insert(
            "svc1".into(),
            Policy {
                service_name: "svc1".into(),
                user_id: None,
                group_id: None,
                allowed_image_prefixes: vec!["myregistry.io/team".into()],
                image_tag_pattern: None,
                image_digest_allowed: false,
                container_config: None,
                volumes: None,
                ports: None,
                env_file: None,
                allowed_cli_flags: None,
                flag_rules: None,
                denied_flags: None,
            },
        );
        let mgr = Manager::from_map(policies);
        assert!(mgr.get_by_image("ubuntu").is_none());
        assert_eq!(
            mgr.get_by_image("myregistry.io/team/myapp").unwrap().service_name,
            "svc1"
        );
        assert_eq!(
            mgr.get_by_image("myregistry.io/team/myapp:tag").unwrap().service_name,
            "svc1"
        );
    }

    #[test]
    fn test_manager_get_by_image_no_match() {
        let mut policies = HashMap::new();
        policies.insert(
            "svc1".into(),
            Policy {
                service_name: "svc1".into(),
                user_id: None,
                group_id: None,
                allowed_image_prefixes: vec!["alpine".into()],
                image_tag_pattern: None,
                image_digest_allowed: false,
                container_config: None,
                volumes: None,
                ports: None,
                env_file: None,
                allowed_cli_flags: None,
                flag_rules: None,
                denied_flags: None,
            },
        );
        let mgr = Manager::from_map(policies);
        assert!(mgr.get_by_image("ubuntu").is_none());
        assert!(mgr.get_by_image("ubuntu:latest").is_none());
    }

    #[test]
    fn test_manager_list() {
        let mut policies = HashMap::new();
        policies.insert("a".into(), Policy {
            service_name: "a".into(),
            user_id: None, group_id: None,
            allowed_image_prefixes: vec!["img".into()],
            image_tag_pattern: None, image_digest_allowed: false,
            container_config: None, volumes: None, ports: None,
            env_file: None, allowed_cli_flags: None, flag_rules: None, denied_flags: None,
        });
        policies.insert("b".into(), Policy {
            service_name: "b".into(),
            user_id: None, group_id: None,
            allowed_image_prefixes: vec!["img".into()],
            image_tag_pattern: None, image_digest_allowed: false,
            container_config: None, volumes: None, ports: None,
            env_file: None, allowed_cli_flags: None, flag_rules: None, denied_flags: None,
        });
        let mgr = Manager::from_map(policies);
        let mut keys = mgr.list();
        keys.sort();
        assert_eq!(keys, vec!["a", "b"]);
    }

    #[test]
    fn test_policy_missing_service_name() {
        let yaml = r#"
allowed_image_prefixes:
  - myimage
"#;
        let result: Result<Policy, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_policy_empty_allowed_image_prefixes() {
        let yaml = r#"
service_name: test
allowed_image_prefixes: []
"#;
        let policy: Policy = serde_yaml::from_str(yaml).unwrap();
        assert!(policy.allowed_image_prefixes.is_empty());
    }

    #[test]
    fn test_volume_deserialize() {
        let yaml = r#"
host_path: /data
container_path: /mnt/data
read_write: false
"#;
        let vol: Volume = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(vol.host_path, "/data");
        assert_eq!(vol.container_path, "/mnt/data");
        assert!(!vol.read_write);
    }

    #[test]
    fn test_flag_rule_deserialize() {
        let yaml = r#"
flag: --memory
value_pattern: ^\d+[kmg]$
"#;
        let rule: FlagRule = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(rule.flag, "--memory");
        assert_eq!(rule.value_pattern, "^\\d+[kmg]$");
    }
}
