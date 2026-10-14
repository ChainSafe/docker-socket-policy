use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};
use std::sync::OnceLock;

#[derive(Debug, Clone, Deserialize)]
pub struct Policy {
    pub service_name: String,
    pub container_names: Option<Vec<String>>,
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

impl Policy {
    /// The container names the policy manages: its container_names, or its
    /// service_name when container_names is unset (#85, #86). Lifecycle
    /// actions and DELETE are forwarded only for covered names.
    pub fn covered_names(&self) -> Vec<&str> {
        match &self.container_names {
            Some(names) => names.iter().map(|s| s.as_str()).collect(),
            None => vec![self.service_name.as_str()],
        }
    }

    /// Whether a create named `name` may use the policy: a policy without
    /// container_names accepts any name, including none (#85).
    pub fn accepts_name(&self, name: &str) -> bool {
        match &self.container_names {
            Some(names) => names.iter().any(|n| n == name),
            None => true,
        }
    }
}

/// A Docker container name without the optional leading slash (#85):
/// `[a-zA-Z0-9][a-zA-Z0-9_.-]*`.
pub fn valid_container_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    match bytes.next() {
        Some(b) if b.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-')
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
    // Sorted by service_name, so selection never depends on map iteration
    // order (#85).
    policies_by_name: BTreeMap<String, Policy>,
}

impl Manager {
    /// Builds a manager without load-time validation, as Go's
    /// NewManagerFromPolicies and TypeScript's Manager.fromPolicies do. Tests
    /// use it to reach states that `new` refuses, such as ambiguity.
    pub fn from_map(policies: HashMap<String, Policy>) -> Self {
        Manager {
            policies_by_name: policies.into_iter().collect(),
        }
    }

    pub fn new(config_dir: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut policies_by_name = BTreeMap::new();
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

        let mut paths = Vec::new();
        for entry in entries {
            let path = entry?.path();
            if path.extension().map_or(true, |e| e != "yaml" && e != "yml") {
                continue;
            }
            paths.push(path);
        }
        paths.sort();

        let mut file_of: HashMap<String, String> = HashMap::new();
        for path in paths {
            let file = path
                .file_name()
                .map(|f| f.to_string_lossy().into_owned())
                .unwrap_or_default();
            let data = std::fs::read_to_string(&path)?;
            let policy: Policy = serde_yaml::from_str(&data)?;
            if policy.service_name.is_empty() {
                return Err("missing service_name".into());
            }
            if policy.allowed_image_prefixes.is_empty() {
                return Err("missing allowed_image_prefixes".into());
            }
            if let Some(names) = &policy.container_names {
                if names.is_empty() {
                    return Err(format!("policy file {}: container_names must not be empty", file).into());
                }
                if let Some(bad) = names.iter().find(|n| !valid_container_name(n)) {
                    return Err(format!(
                        "policy file {}: invalid container name {:?} in container_names",
                        file, bad
                    )
                    .into());
                }
            }
            // A second file with the same service_name used to replace the
            // first silently (#85).
            if let Some(prev) = file_of.get(&policy.service_name) {
                return Err(format!(
                    "policies in {} and {} both use service_name {:?}",
                    prev, file, policy.service_name
                )
                .into());
            }
            file_of.insert(policy.service_name.clone(), file);
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

        let m = Manager { policies_by_name };
        m.check_conflicts(&file_of)?;
        Ok(m)
    }

    /// Fails when two policies could both be selected for one create: their
    /// image prefixes share a namespace, and one of them accepts any name or
    /// their container_names intersect (#85).
    fn check_conflicts(&self, file_of: &HashMap<String, String>) -> Result<(), String> {
        let ordered: Vec<&Policy> = self.policies_by_name.values().collect();
        for (i, a) in ordered.iter().enumerate() {
            for b in &ordered[i + 1..] {
                let Some((pa, pb)) = overlapping_prefixes(&a.allowed_image_prefixes, &b.allowed_image_prefixes) else {
                    continue;
                };
                let reason = match (&a.container_names, &b.container_names) {
                    (None, _) => format!("{:?} has no container_names", a.service_name),
                    (_, None) => format!("{:?} has no container_names", b.service_name),
                    (Some(an), Some(bn)) => match an.iter().filter(|n| bn.contains(n)).min() {
                        Some(shared) => format!("both accept container name {:?}", shared),
                        None => continue,
                    },
                };
                return Err(format!(
                    "conflicting policies {:?} ({}) and {:?} ({}): image prefixes {:?} and {:?} overlap and {}",
                    a.service_name,
                    file_of.get(&a.service_name).map(String::as_str).unwrap_or(""),
                    b.service_name,
                    file_of.get(&b.service_name).map(String::as_str).unwrap_or(""),
                    pa,
                    pb,
                    reason
                ));
            }
        }
        Ok(())
    }

    pub fn get(&self, name: &str) -> Option<&Policy> {
        self.policies_by_name.get(name)
    }

    /// The policy whose prefixes match the reference's normalised repository
    /// (#84). An invalid reference matches nothing.
    pub fn get_by_image(&self, image_ref: &str) -> Option<&Policy> {
        let name = parse_image_ref(image_ref).ok()?.name;
        self.matching_image(&name).into_iter().next()
    }

    /// The policies, sorted by service_name, whose prefixes match a
    /// normalised repository name (#85).
    pub fn matching_image(&self, name: &str) -> Vec<&Policy> {
        self.policies_by_name
            .values()
            .filter(|p| matches_image_prefix(name, &p.allowed_image_prefixes))
            .collect()
    }

    /// The one policy whose image prefixes match the normalised repository
    /// of `image_ref` and which accepts the container name (empty for a
    /// create without ?name=). No match, or more than one, is an error whose
    /// text is the deny message (#85).
    pub fn select_for_create(&self, image_ref: &str, name: &str) -> Result<&Policy, String> {
        let image_name = parse_image_ref(image_ref)?.name;
        let matching = self.matching_image(&image_name);
        let candidates: Vec<&Policy> = matching.iter().copied().filter(|p| p.accepts_name(name)).collect();
        match candidates.as_slice() {
            [p] => Ok(p),
            _ if matching.is_empty() => Err(format!("image {} not allowed by any policy", image_ref)),
            [] if name.is_empty() => Err(format!("image {} requires a container name", image_ref)),
            [] => Err(format!(
                "container name {} not allowed for image {} by any policy",
                name, image_ref
            )),
            many => Err(format!(
                "ambiguous policy for image {} and name {}: {}",
                image_ref,
                name,
                many.iter()
                    .map(|p| p.service_name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
        }
    }

    /// The policies, sorted by service_name, whose covered names include
    /// `name` (#86).
    pub fn covering(&self, name: &str) -> Vec<&Policy> {
        self.policies_by_name
            .values()
            .filter(|p| p.covered_names().contains(&name))
            .collect()
    }

    pub fn list(&self) -> Vec<&str> {
        self.policies_by_name.keys().map(|s| s.as_str()).collect()
    }
}

// The first pair of prefixes where one equals the other or is a namespace (/)
// prefix of it.
fn overlapping_prefixes<'a>(a: &'a [String], b: &'a [String]) -> Option<(&'a str, &'a str)> {
    for pa in a {
        for pb in b {
            if pa == pb || pa.starts_with(&format!("{}/", pb)) || pb.starts_with(&format!("{}/", pa)) {
                return Some((pa, pb));
            }
        }
    }
    None
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
pub(crate) mod tests {
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
                container_names: None,
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
                container_names: None,
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
                container_names: None,
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
                container_names: None,
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
                container_names: None,
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
                container_names: None,
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

    /// Writes policy files into a fresh directory and loads it.
    pub(crate) fn load_dir(files: &[(&str, &str)]) -> Result<Manager, String> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static N: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "dsp-policy-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        // Listener tests change the process umask concurrently; set the mode.
        std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
        for (name, content) in files {
            std::fs::write(dir.join(name), content).unwrap();
        }
        let result = Manager::new(dir.to_str().unwrap()).map_err(|e| e.to_string());
        std::fs::remove_dir_all(&dir).unwrap();
        result
    }

    fn policy(service: &str, names: Option<&[&str]>, prefixes: &[&str]) -> Policy {
        Policy {
            service_name: service.into(),
            container_names: names.map(|n| n.iter().map(|s| s.to_string()).collect()),
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

    fn manager_of(policies: Vec<Policy>) -> Manager {
        Manager::from_map(policies.into_iter().map(|p| (p.service_name.clone(), p)).collect())
    }

    /// The cross-language parity guard for the #85 load-time checks. Two
    /// policies conflict when their image prefixes share a namespace and one
    /// has no container_names or their container_names intersect. Before #85
    /// every row loaded, and a duplicate service_name silently replaced the
    /// first file.
    #[test]
    fn test_manager_load_time_validation() {
        let cases: Vec<(&str, Vec<(&str, &str)>, &str)> = vec![
            (
                "same prefix, no container_names",
                vec![
                    ("a.yaml", "service_name: a\nallowed_image_prefixes: [alpine]\n"),
                    ("b.yaml", "service_name: b\nallowed_image_prefixes: [alpine]\n"),
                ],
                r#"conflicting policies "a" (a.yaml) and "b" (b.yaml): image prefixes "alpine" and "alpine" overlap and "a" has no container_names"#,
            ),
            (
                "one side has no container_names",
                vec![
                    (
                        "a.yaml",
                        "service_name: a\ncontainer_names: [x]\nallowed_image_prefixes: [chainsafe/lodestar]\n",
                    ),
                    ("b.yaml", "service_name: b\nallowed_image_prefixes: [chainsafe]\n"),
                ],
                r#"conflicting policies "a" (a.yaml) and "b" (b.yaml): image prefixes "chainsafe/lodestar" and "chainsafe" overlap and "b" has no container_names"#,
            ),
            (
                "shared container name",
                vec![
                    (
                        "a.yaml",
                        "service_name: a\ncontainer_names: [x, y]\nallowed_image_prefixes: [chainsafe/lodestar]\n",
                    ),
                    (
                        "b.yaml",
                        "service_name: b\ncontainer_names: [z, y]\nallowed_image_prefixes: [chainsafe/lodestar]\n",
                    ),
                ],
                r#"conflicting policies "a" (a.yaml) and "b" (b.yaml): image prefixes "chainsafe/lodestar" and "chainsafe/lodestar" overlap and both accept container name "y""#,
            ),
            (
                "disjoint container names",
                vec![
                    (
                        "a.yaml",
                        "service_name: a\ncontainer_names: [beacon]\nallowed_image_prefixes: [chainsafe/lodestar]\n",
                    ),
                    (
                        "b.yaml",
                        "service_name: b\ncontainer_names: [validator]\nallowed_image_prefixes: [chainsafe/lodestar]\n",
                    ),
                ],
                "",
            ),
            (
                "sibling prefixes do not overlap",
                vec![
                    (
                        "a.yaml",
                        "service_name: a\nallowed_image_prefixes: [chainsafe/lodestar]\n",
                    ),
                    (
                        "b.yaml",
                        "service_name: b\nallowed_image_prefixes: [chainsafe/lodestar-backup]\n",
                    ),
                ],
                "",
            ),
            (
                "duplicate service_name",
                vec![
                    ("a.yaml", "service_name: svc\nallowed_image_prefixes: [alpine]\n"),
                    ("b.yaml", "service_name: svc\nallowed_image_prefixes: [busybox]\n"),
                ],
                r#"policies in a.yaml and b.yaml both use service_name "svc""#,
            ),
            (
                "invalid container name",
                vec![(
                    "a.yaml",
                    "service_name: a\ncontainer_names: [-bad]\nallowed_image_prefixes: [alpine]\n",
                )],
                r#"invalid container name "-bad" in container_names"#,
            ),
            (
                "container name with a slash",
                vec![(
                    "a.yaml",
                    "service_name: a\ncontainer_names: [a/b]\nallowed_image_prefixes: [alpine]\n",
                )],
                r#"invalid container name "a/b" in container_names"#,
            ),
            (
                "empty container_names",
                vec![(
                    "a.yaml",
                    "service_name: a\ncontainer_names: []\nallowed_image_prefixes: [alpine]\n",
                )],
                "container_names must not be empty",
            ),
        ];
        let mut mismatches = Vec::new();
        for (name, files, want) in cases {
            match (load_dir(&files), want) {
                (Ok(_), "") => {}
                (Ok(_), want) => mismatches.push(format!("{name}: loaded, want error {want:?}")),
                (Err(e), "") => mismatches.push(format!("{name}: {e}")),
                (Err(e), want) if !e.contains(want) => mismatches.push(format!("{name}: error {e:?}, want {want:?}")),
                _ => {}
            }
        }
        assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
    }

    /// #85 selection: the one policy matching the image and accepting the
    /// name, the nameless create, and ambiguity.
    #[test]
    fn test_manager_select_for_create() {
        let m = manager_of(vec![
            policy("validator", Some(&["validator"]), &["chainsafe/lodestar"]),
            policy("beacon", Some(&["beacon"]), &["chainsafe/lodestar"]),
            policy("any", None, &["chainsafe"]),
        ]);
        for _ in 0..50 {
            for name in ["beacon", "validator"] {
                let want = format!("ambiguous policy for image chainsafe/lodestar:v1 and name {name}: any, {name}");
                assert_eq!(m.select_for_create("chainsafe/lodestar:v1", name).err(), Some(want));
            }
        }
        assert_eq!(
            m.select_for_create("chainsafe/lodestar:v1", "").unwrap().service_name,
            "any"
        );

        let m = manager_of(vec![
            policy("validator", Some(&["validator"]), &["chainsafe/lodestar"]),
            policy("beacon", Some(&["beacon"]), &["chainsafe/lodestar"]),
        ]);
        for _ in 0..50 {
            for name in ["beacon", "validator"] {
                assert_eq!(
                    m.select_for_create("chainsafe/lodestar:v1", name).unwrap().service_name,
                    name
                );
            }
        }
    }

    #[test]
    fn test_manager_covering() {
        let m = manager_of(vec![
            policy("beacon", None, &["chainsafe/lodestar"]),
            policy("vc", Some(&["validator"]), &["chainsafe/lodestar"]),
        ]);
        for (name, want) in [("beacon", 1), ("validator", 1), ("vc", 0), ("other", 0)] {
            assert_eq!(m.covering(name).len(), want, "covering({name})");
        }
    }
}
