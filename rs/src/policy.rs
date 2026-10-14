use serde::Deserialize;
use std::collections::HashMap;
use std::sync::OnceLock;

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
                eprintln!(
                    "warn: config dir {} not found, starting with empty policy set",
                    config_dir
                );
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
            // Prefixes are compared in normalised form (#84).
            let mut policy = policy;
            let mut prefixes = Vec::with_capacity(policy.allowed_image_prefixes.len());
            for prefix in &policy.allowed_image_prefixes {
                let normalized = normalize_image_prefix(prefix).map_err(|_| {
                    format!(
                        "policy file {} has an invalid allowed_image_prefixes entry \"{}\"",
                        path.display(),
                        prefix
                    )
                })?;
                prefixes.push(normalized);
            }
            policy.allowed_image_prefixes = prefixes;
            policies_by_name.insert(policy.service_name.clone(), policy);
        }

        Ok(Manager { policies_by_name })
    }

    pub fn get(&self, name: &str) -> Option<&Policy> {
        self.policies_by_name.get(name)
    }

    /// The policy whose prefixes match the reference's normalised repository
    /// (#84). An invalid reference matches nothing.
    pub fn get_by_image(&self, image_ref: &str) -> Option<&Policy> {
        let name = parse_image_ref(image_ref).ok()?.name;
        self.policies_by_name
            .values()
            .find(|p| matches_image_prefix(&name, &p.allowed_image_prefixes))
    }

    pub fn list(&self) -> Vec<&str> {
        self.policies_by_name.keys().map(|s| s.as_str()).collect()
    }
}

/// A parsed image reference (#84). `name` is the normalised repository: the
/// registry host, lower-cased, and the path; Docker Hub's host is dropped,
/// and so is `library/` before a single-component name, so `alpine`,
/// `library/alpine` and `docker.io/library/alpine` are all `alpine`. `tag`
/// and `digest` are empty when absent.
#[derive(Debug, Clone, PartialEq)]
pub struct ImageRef {
    pub name: String,
    pub tag: String,
    pub digest: String,
}

const DEFAULT_REGISTRIES: [&str; 3] = ["docker.io", "index.docker.io", "registry-1.docker.io"];

fn domain_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(
            r"^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*(?::[0-9]+)?$",
        )
        .unwrap()
    })
}

fn path_component_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$").unwrap())
}

fn tag_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*$").unwrap())
}

fn sha256_digest_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"^sha256:[a-f0-9]{64}$").unwrap())
}

/// Parses `[registry/]repository[:tag][@digest]` the way Docker does (#84).
/// The digest follows the first `@`; the tag follows the last `:` after the
/// last `/`, so a registry port is not a tag. The first path component is a
/// registry host when it contains `.` or `:` or is `localhost`. Only the
/// host is lower-cased: upper case in the path is invalid. The digest is
/// checked by `check_image_tag`, not here.
pub fn parse_image_ref(reference: &str) -> Result<ImageRef, String> {
    let invalid = || format!("invalid image reference \"{}\"", reference);
    let (rest, digest) = match reference.split_once('@') {
        Some((_, "")) => return Err(invalid()),
        Some((r, d)) => (r, d),
        None => (reference, ""),
    };
    let after_slash = rest.rfind('/').map_or(0, |i| i + 1);
    let (name, tag) = match rest[after_slash..].rfind(':') {
        Some(i) => {
            let tag = &rest[after_slash + i + 1..];
            if !tag_re().is_match(tag) {
                return Err(invalid());
            }
            (&rest[..after_slash + i], tag)
        }
        None => (rest, ""),
    };
    let name = normalize_name(name).ok_or_else(invalid)?;
    Ok(ImageRef {
        name,
        tag: tag.to_string(),
        digest: digest.to_string(),
    })
}

fn normalize_name(name: &str) -> Option<String> {
    let (domain, path) = match name.split_once('/') {
        Some((first, path)) if first.contains('.') || first.contains(':') || first == "localhost" => {
            (Some(first.to_ascii_lowercase()), path)
        }
        _ => (None, name),
    };
    if let Some(d) = &domain {
        if !domain_re().is_match(d) {
            return None;
        }
    }
    if !path.split('/').all(|c| path_component_re().is_match(c)) {
        return None;
    }
    let domain = domain.filter(|d| !DEFAULT_REGISTRIES.contains(&d.as_str()));
    let full = match domain {
        Some(d) => format!("{}/{}", d, path),
        None => match path.strip_prefix("library/") {
            Some(official) if !official.contains('/') => official.to_string(),
            _ => path.to_string(),
        },
    };
    if full.len() > 255 {
        return None;
    }
    Some(full)
}

/// Normalises a policy prefix at load time (#84). A prefix names a
/// repository or a namespace, so a tag or digest makes it invalid.
pub fn normalize_image_prefix(prefix: &str) -> Result<String, String> {
    let r = parse_image_ref(prefix)?;
    if !r.tag.is_empty() || !r.digest.is_empty() {
        return Err(format!("image prefix \"{}\" has a tag or digest", prefix));
    }
    Ok(r.name)
}

/// Matches a normalised repository against normalised prefixes on namespace
/// boundaries ("prefix" or "prefix/..."), never a bare substring.
pub fn matches_image_prefix(name: &str, prefixes: &[String]) -> bool {
    prefixes
        .iter()
        .any(|p| name == p || (name.starts_with(p.as_str()) && name.as_bytes().get(p.len()) == Some(&b'/')))
}

/// Applies a policy's digest and tag rules to a parsed reference: the digest
/// must be allowed and well-formed, the tag must match `image_tag_pattern`.
/// Shared by the registry gate (create) and the router (pull, #83).
pub fn check_image_tag(policy: &Policy, r: &ImageRef) -> Result<(), String> {
    if !r.digest.is_empty() {
        if r.digest.len() > 128 {
            return Err("image tag/digest exceeds 128 characters".into());
        }
        if !policy.image_digest_allowed {
            return Err(format!("image digests not allowed for service {}", policy.service_name));
        }
        if !sha256_digest_re().is_match(&r.digest) {
            return Err(format!("invalid digest format: {}", r.digest));
        }
    }
    if !r.tag.is_empty() {
        if r.tag.len() > 128 {
            return Err("image tag/digest exceeds 128 characters".into());
        }
        if let Some(ref pattern) = policy.image_tag_pattern {
            let re = regex::Regex::new(pattern).map_err(|e| format!("invalid tag pattern regex: {}", e))?;
            if !re.is_match(&r.tag) {
                return Err(format!("image tag {:?} does not match pattern {:?}", r.tag, pattern));
            }
        }
    }
    Ok(())
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

    /// The #84 normalisation table, on the parser itself. The same rows run
    /// in Go and TypeScript.
    #[test]
    fn test_parse_image_ref_table() {
        let digest = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let ghcr = format!("ghcr.io/chainsafe/lodestar@{}", digest);
        let both = format!("alpine:3.19@{}", digest);
        let cases: Vec<(&str, Option<(&str, &str, &str)>)> = vec![
            ("alpine", Some(("alpine", "", ""))),
            ("library/alpine", Some(("alpine", "", ""))),
            ("docker.io/library/alpine", Some(("alpine", "", ""))),
            ("index.docker.io/library/alpine:3.19", Some(("alpine", "3.19", ""))),
            ("registry-1.docker.io/library/alpine", Some(("alpine", "", ""))),
            (
                "docker.io/chainsafe/lodestar:v1",
                Some(("chainsafe/lodestar", "v1", "")),
            ),
            (&ghcr, Some(("ghcr.io/chainsafe/lodestar", "", digest))),
            ("localhost:5000/x/y:2", Some(("localhost:5000/x/y", "2", ""))),
            (
                "registry.example.com:443/a",
                Some(("registry.example.com:443/a", "", "")),
            ),
            (
                "REGISTRY.Example.com:443/a:V1",
                Some(("registry.example.com:443/a", "V1", "")),
            ),
            ("docker.io/library/a/b", Some(("library/a/b", "", ""))),
            ("ghcr.io/library/alpine", Some(("ghcr.io/library/alpine", "", ""))),
            ("localhost/x", Some(("localhost/x", "", ""))),
            ("localhost", Some(("localhost", "", ""))),
            (&both, Some(("alpine", "3.19", digest))),
            ("Alpine", None),
            ("chainsafe/Lodestar", None),
            ("alpine:", None),
            ("alpine@", None),
            ("", None),
            ("a//b", None),
            ("/alpine", None),
            ("alpine/", None),
            ("-alpine", None),
            ("alpine:a/b", None),
            ("a:b/c", None),
            ("alpine:t$g", None),
        ];
        let mut mismatches = Vec::new();
        for (input, want) in &cases {
            let got = parse_image_ref(input);
            let ok = match (&got, want) {
                (Ok(r), Some((name, tag, digest))) => r.name == *name && r.tag == *tag && r.digest == *digest,
                (Err(e), None) => *e == format!("invalid image reference \"{}\"", input),
                _ => false,
            };
            if !ok {
                mismatches.push(format!("{:?}: got {:?}, want {:?}", input, got, want));
            }
        }
        assert!(mismatches.is_empty(), "parse mismatches:\n{}", mismatches.join("\n"));
    }

    /// #84: prefixes are normalised at load time, and a prefix with a tag or
    /// an invalid one fails the load.
    #[test]
    fn test_manager_normalizes_prefixes() {
        let dir = std::env::temp_dir().join(format!("dsp-prefix-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("a.yaml"),
            "service_name: a\nallowed_image_prefixes:\n  - docker.io/library/alpine\n  - GHCR.io/team\n",
        )
        .unwrap();
        let mgr = Manager::new(dir.to_str().unwrap()).unwrap();
        assert_eq!(
            mgr.get("a").unwrap().allowed_image_prefixes,
            vec!["alpine", "ghcr.io/team"]
        );
        for bad in ["alpine:3.19", "Alpine"] {
            std::fs::write(
                dir.join("a.yaml"),
                format!("service_name: a\nallowed_image_prefixes:\n  - \"{}\"\n", bad),
            )
            .unwrap();
            let err = Manager::new(dir.to_str().unwrap())
                .err()
                .expect("load must fail")
                .to_string();
            assert!(err.contains("invalid allowed_image_prefixes entry"), "{}: {}", bad, err);
        }
        std::fs::remove_dir_all(&dir).unwrap();
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
        policies.insert(
            "a".into(),
            Policy {
                service_name: "a".into(),
                user_id: None,
                group_id: None,
                allowed_image_prefixes: vec!["img".into()],
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
        policies.insert(
            "b".into(),
            Policy {
                service_name: "b".into(),
                user_id: None,
                group_id: None,
                allowed_image_prefixes: vec!["img".into()],
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
