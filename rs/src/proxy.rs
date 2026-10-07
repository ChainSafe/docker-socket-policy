use crate::policy::{Manager, Policy};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    Deny,
    Allow,
    CreateContainer,
}

#[derive(Debug, Clone)]
pub struct RouteResult {
    pub action: Action,
    pub service: Option<String>,
    pub policy: Option<Policy>,
    pub body: Option<HashMap<String, serde_json::Value>>,
    pub container: Option<String>,
    pub image: Option<String>,
    pub deny_msg: Option<String>,
}

pub struct Router {
    manager: Manager,
}

impl Router {
    pub fn new(manager: Manager) -> Self {
        Router { manager }
    }

    pub fn route(
        &self,
        method: &str,
        path: &str,
        body: Option<&HashMap<String, serde_json::Value>>,
    ) -> RouteResult {
        let path = strip_api_version(path);

        // Read-only endpoints
        if path == "/_ping" || path == "/version" || path == "/info" || path.starts_with("/events") {
            return RouteResult {
                action: Action::Allow,
                service: None,
                policy: None,
                body: None,
                container: None,
                image: None,
                deny_msg: None,
            };
        }

        // Denied endpoints
        if path.starts_with("/auth") {
            return deny("auth endpoint is not allowed");
        }
        if path == "/containers/exec" || path.starts_with("/containers/") && path.contains("/exec") {
            return deny("exec is not allowed");
        }
        if path.starts_with("/build") {
            return deny("build is not allowed");
        }
        if path.starts_with("/commit") {
            return deny("commit is not allowed");
        }

        // Container create
        if method == "POST" && path == "/containers/create" {
            return self.route_create(body);
        }

        // Container lifecycle
        if let Some(name) = extract_container_name(path) {
            return match () {
                _ if path.ends_with("/start") && method == "POST" => self.route_by_name(name),
                _ if path.ends_with("/stop") && method == "POST" => self.route_by_name(name),
                _ if path.ends_with("/restart") && method == "POST" => self.route_by_name(name),
                _ if path.ends_with("/kill") && method == "POST" => self.route_by_name(name),
                _ if path.ends_with("/wait") && method == "POST" => self.route_by_name(name),
                _ if path.ends_with("/pause") && method == "POST" => self.route_by_name(name),
                _ if path.ends_with("/unpause") && method == "POST" => self.route_by_name(name),
                _ if path.ends_with("/rename") && method == "POST" => deny("rename is not allowed"),
                _ if path.ends_with("/update") && method == "POST" => deny("update is not allowed"),
                _ if method == "DELETE" => self.route_by_name(name),
                _ if method == "GET" => allow(),
                _ => deny(&format!("endpoint {} {} is not allowed", method, path)),
            };
        }

        // Image pull
        if method == "POST" && path == "/images/create" {
            return self.route_image_pull(body);
        }

        // Default GET/HEAD passthrough
        if method == "GET" || method == "HEAD" {
            return allow();
        }

        deny(&format!("endpoint {} {} is not allowed", method, path))
    }

    fn route_create(&self, body: Option<&HashMap<String, serde_json::Value>>) -> RouteResult {
        let body = match body {
            Some(b) if !b.is_empty() => b,
            _ => return deny("empty request body"),
        };

        let image = body.get("Image").and_then(|v| v.as_str()).unwrap_or("");
        if image.is_empty() {
            return deny("image field is required");
        }

        match self.manager.get_by_image(image) {
            Some(policy) => RouteResult {
                action: Action::CreateContainer,
                service: Some(policy.service_name.clone()),
                policy: Some(policy.clone()),
                body: Some(body.clone()),
                container: None,
                image: Some(image.to_string()),
                deny_msg: None,
            },
            None => deny(&format!("image {} not allowed by any policy", image)),
        }
    }

    fn route_by_name(&self, name: &str) -> RouteResult {
        match self.manager.get(name) {
            Some(policy) => RouteResult {
                action: Action::Allow,
                service: Some(policy.service_name.clone()),
                policy: Some(policy.clone()),
                body: None,
                container: None,
                image: None,
                deny_msg: None,
            },
            None => RouteResult {
                action: Action::Allow,
                service: None,
                policy: None,
                body: None,
                container: Some(name.to_string()),
                image: None,
                deny_msg: None,
            },
        }
    }

    fn route_image_pull(&self, body: Option<&HashMap<String, serde_json::Value>>) -> RouteResult {
        let body = match body {
            Some(b) if !b.is_empty() => b,
            _ => return deny("empty request body"),
        };

        let from_image = body.get("fromImage").and_then(|v| v.as_str()).unwrap_or("");
        if from_image.is_empty() {
            return deny("fromImage field is required for image pull");
        }

        match self.manager.get_by_image(from_image) {
            Some(_) => RouteResult {
                action: Action::Allow,
                service: None,
                policy: None,
                body: None,
                container: None,
                image: Some(from_image.to_string()),
                deny_msg: None,
            },
            None => deny(&format!("image {} not allowed by any policy", from_image)),
        }
    }
}

fn allow() -> RouteResult {
    RouteResult {
        action: Action::Allow,
        service: None,
        policy: None,
        body: None,
        container: None,
        image: None,
        deny_msg: None,
    }
}

fn deny(msg: &str) -> RouteResult {
    RouteResult {
        action: Action::Deny,
        service: None,
        policy: None,
        body: None,
        container: None,
        image: None,
        deny_msg: Some(msg.to_string()),
    }
}

fn strip_api_version(path: &str) -> &str {
    if let Some(rest) = path.strip_prefix("/v") {
        if let Some(idx) = rest.find('/') {
            return &rest[idx..];
        }
    }
    path
}

fn extract_container_name(path: &str) -> Option<&str> {
    let path = path.strip_prefix('/').unwrap_or(path);
    let parts: Vec<&str> = path.split('/').collect();
    // An empty segment is not a name, mirroring Go/TS (#48).
    if parts.len() >= 2 && parts[0] == "containers" && !parts[1].is_empty() && parts[1] != "create" && parts[1] != "json" && parts[1] != "exec" {
        Some(parts[1])
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Policy;

    fn make_manager(prefixes: Vec<&str>) -> Manager {
        let mut policies = std::collections::HashMap::new();
        policies.insert(
            "myservice".into(),
            Policy {
                service_name: "myservice".into(),
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
            },
        );
        Manager::from_map(policies)
    }

    #[test]
    fn test_route_ping() {
        let router = Router::new(make_manager(vec!["alpine"]));
        let result = router.route("GET", "/_ping", None);
        assert_eq!(result.action, Action::Allow);
    }

    #[test]
    fn test_route_version() {
        let router = Router::new(make_manager(vec!["alpine"]));
        let result = router.route("GET", "/version", None);
        assert_eq!(result.action, Action::Allow);
    }

    #[test]
    fn test_route_info() {
        let router = Router::new(make_manager(vec!["alpine"]));
        let result = router.route("GET", "/info", None);
        assert_eq!(result.action, Action::Allow);
    }

    #[test]
    fn test_route_events() {
        let router = Router::new(make_manager(vec!["alpine"]));
        let result = router.route("GET", "/events", None);
        assert_eq!(result.action, Action::Allow);
    }

    #[test]
    fn test_route_auth_denied() {
        let router = Router::new(make_manager(vec!["alpine"]));
        let result = router.route("POST", "/auth", None);
        assert_eq!(result.action, Action::Deny);
    }

    #[test]
    fn test_route_exec_endpoint_denied() {
        let router = Router::new(make_manager(vec!["alpine"]));
        let result = router.route("POST", "/containers/myapp/exec", None);
        assert_eq!(result.action, Action::Deny);
        assert!(result.deny_msg.unwrap().contains("exec"));
    }

    #[test]
    fn test_route_containers_exec_denied() {
        let router = Router::new(make_manager(vec!["alpine"]));
        let result = router.route("POST", "/containers/exec", None);
        assert_eq!(result.action, Action::Deny);
    }

    #[test]
    fn test_route_build_denied() {
        let router = Router::new(make_manager(vec!["alpine"]));
        let result = router.route("POST", "/build", None);
        assert_eq!(result.action, Action::Deny);
    }

    #[test]
    fn test_route_commit_denied() {
        let router = Router::new(make_manager(vec!["alpine"]));
        let result = router.route("POST", "/commit", None);
        assert_eq!(result.action, Action::Deny);
    }

    #[test]
    fn test_route_container_create() {
        let router = Router::new(make_manager(vec!["alpine"]));
        let binding = serde_json::from_value::<HashMap<String, serde_json::Value>>(
            serde_json::json!({"Image": "alpine:latest"}),
        ).unwrap();
        let body = Some(&binding);
        let result = router.route("POST", "/containers/create", body);
        assert_eq!(result.action, Action::CreateContainer);
        assert_eq!(result.service, Some("myservice".into()));
        assert!(result.policy.is_some());
    }

    #[test]
    fn test_route_container_create_empty_body() {
        let router = Router::new(make_manager(vec!["alpine"]));
        let result = router.route("POST", "/containers/create", None);
        assert_eq!(result.action, Action::Deny);
        assert!(result.deny_msg.unwrap().contains("empty"));
    }

    #[test]
    fn test_route_container_create_no_image() {
        let router = Router::new(make_manager(vec!["alpine"]));
        let map: HashMap<String, serde_json::Value> = serde_json::from_value(
            serde_json::json!({"Cmd": ["echo"]}),
        ).unwrap();
        let result = router.route("POST", "/containers/create", Some(&map));
        assert_eq!(result.action, Action::Deny);
        assert!(result.deny_msg.unwrap().contains("image"));
    }

    #[test]
    fn test_route_container_create_image_not_found() {
        let router = Router::new(make_manager(vec!["alpine"]));
        let map: HashMap<String, serde_json::Value> = serde_json::from_value(
            serde_json::json!({"Image": "ubuntu:latest"}),
        ).unwrap();
        let result = router.route("POST", "/containers/create", Some(&map));
        assert_eq!(result.action, Action::Deny);
        assert!(result.deny_msg.unwrap().contains("not allowed by any policy"));
    }

    #[test]
    fn test_route_container_start() {
        let router = Router::new(make_manager(vec!["alpine"]));
        let result = router.route("POST", "/containers/myservice/start", None);
        assert_eq!(result.action, Action::Allow);
        assert_eq!(result.service, Some("myservice".into()));
    }

    #[test]
    fn test_route_container_stop() {
        let router = Router::new(make_manager(vec!["alpine"]));
        let result = router.route("POST", "/containers/myservice/stop", None);
        assert_eq!(result.action, Action::Allow);
    }

    #[test]
    fn test_route_container_restart() {
        let router = Router::new(make_manager(vec!["alpine"]));
        let result = router.route("POST", "/containers/myservice/restart", None);
        assert_eq!(result.action, Action::Allow);
    }

    #[test]
    fn test_route_container_kill() {
        let router = Router::new(make_manager(vec!["alpine"]));
        let result = router.route("POST", "/containers/myservice/kill", None);
        assert_eq!(result.action, Action::Allow);
    }

    #[test]
    fn test_route_container_wait() {
        let router = Router::new(make_manager(vec!["alpine"]));
        let result = router.route("POST", "/containers/myservice/wait", None);
        assert_eq!(result.action, Action::Allow);
    }

    #[test]
    fn test_route_container_pause() {
        let router = Router::new(make_manager(vec!["alpine"]));
        let result = router.route("POST", "/containers/myservice/pause", None);
        assert_eq!(result.action, Action::Allow);
    }

    #[test]
    fn test_route_container_unpause() {
        let router = Router::new(make_manager(vec!["alpine"]));
        let result = router.route("POST", "/containers/myservice/unpause", None);
        assert_eq!(result.action, Action::Allow);
    }

    #[test]
    fn test_route_container_rename_denied() {
        let router = Router::new(make_manager(vec!["alpine"]));
        let result = router.route("POST", "/containers/myservice/rename", None);
        assert_eq!(result.action, Action::Deny);
        assert!(result.deny_msg.unwrap().contains("rename"));
    }

    #[test]
    fn test_route_container_update_denied() {
        let router = Router::new(make_manager(vec!["alpine"]));
        let result = router.route("POST", "/containers/myservice/update", None);
        assert_eq!(result.action, Action::Deny);
        assert!(result.deny_msg.unwrap().contains("update"));
    }

    #[test]
    fn test_route_container_delete_allowed() {
        let router = Router::new(make_manager(vec!["alpine"]));
        let result = router.route("DELETE", "/containers/myservice", None);
        assert_eq!(result.action, Action::Allow);
        assert_eq!(result.service, Some("myservice".into()));
    }

    #[test]
    fn test_route_container_get() {
        let router = Router::new(make_manager(vec!["alpine"]));
        let result = router.route("GET", "/containers/myservice", None);
        assert_eq!(result.action, Action::Allow);
    }

    #[test]
    fn test_route_container_get_json() {
        let router = Router::new(make_manager(vec!["alpine"]));
        let result = router.route("GET", "/containers/json", None);
        assert_eq!(result.action, Action::Allow);
    }

    /// Cross-language parity guard for #24. /containers/<x> is ambiguous: <x>
    /// is usually a container name, but Docker also has reserved endpoints at
    /// that position. Treating one as a container name routes the request down
    /// the lifecycle path, where an unknown container is allowed through — Go
    /// allowed DELETE /containers/json for exactly that reason.
    #[test]
    fn test_route_reserved_path_segments() {
        let router = Router::new(make_manager(vec!["alpine"]));
        let cases = [
            // Reserved: must not be mistaken for a container to remove.
            // reservedJsonDeleteDeniedTest
            ("DELETE", "/containers/json", Action::Deny),
            // reservedCreateDeleteDeniedTest
            ("DELETE", "/containers/create", Action::Deny),
            // reservedExecDeleteDeniedTest: denied by the exec check, before the lifecycle branch.
            ("DELETE", "/containers/exec", Action::Deny),
            // Listing stays allowed, via the GET/HEAD passthrough.
            ("GET", "/containers/json", Action::Allow),
            // A real container name is still routed as a container.
            // realNameDeleteAllowedTest
            ("DELETE", "/containers/mycontainer", Action::Allow),
            ("GET", "/containers/mycontainer", Action::Allow),
            // Reserved words are only reserved in the name position.
            // reservedInSubpathAllowedTest
            ("GET", "/containers/mycontainer/json", Action::Allow),
        ];
        for (method, path, want) in cases {
            let got = router.route(method, path, None);
            assert_eq!(got.action, want, "route({} {})", method, path);
        }
    }

    #[test]
    fn test_extract_container_name_skips_reserved_segments() {
        for reserved in ["create", "json", "exec"] {
            let path = format!("/containers/{}", reserved);
            assert_eq!(extract_container_name(&path), None, "{} should be reserved", path);
        }
        assert_eq!(extract_container_name("/containers/mycontainer"), Some("mycontainer"));
        assert_eq!(
            extract_container_name("/containers/mycontainer/json"),
            Some("mycontainer")
        );
    }

    /// Cross-language parity guard for #48. An empty segment in the name
    /// position (/containers/, /containers//start) is not a container name.
    /// Treating it as one routes the request down the lifecycle path, where an
    /// unknown container is allowed through. Rows mirror the emptyName* runs
    /// in spec/router.qnt.
    #[test]
    fn test_route_empty_container_name() {
        let router = Router::new(make_manager(vec!["alpine"]));
        let cases = [
            // emptyNameDeleteDeniedTest
            ("DELETE", "/containers/", Action::Deny),
            // emptyNameStartDeniedTest
            ("POST", "/containers//start", Action::Deny),
            // emptyNameGetAllowedTest
            ("GET", "/containers/", Action::Allow),
        ];
        for (method, path, want) in cases {
            let got = router.route(method, path, None);
            assert_eq!(got.action, want, "route({} {})", method, path);
        }
    }

    /// Cross-language parity guard for #52 and #57. The Docker CLI prefixes
    /// every request with a dotted API version (/v1.43/containers/create).
    /// The router must strip the prefix and route the rest exactly like the
    /// unversioned path. The table pins one canonical prefix rule,
    /// ^/v\d+(\.\d+)?/ with ASCII digits, in all three languages (#52, #57).
    #[test]
    fn test_route_versioned_paths() {
        let router = Router::new(make_manager(vec!["alpine"]));
        let create_body: HashMap<String, serde_json::Value> =
            serde_json::from_value(serde_json::json!({"Image": "alpine:latest"})).unwrap();
        let cases = [
            // #52: dotted version, container lifecycle delete.
            ("DELETE", "/v1.43/containers/foo", None, Action::Allow),
            // #52: dotted version, container lifecycle start.
            ("POST", "/v1.43/containers/beacon/start", None, Action::Allow),
            // #52: dotted version, create with a policy-allowed image.
            ("POST", "/v1.43/containers/create", Some(&create_body), Action::CreateContainer),
            // #52: undotted control — stripped correctly everywhere already.
            ("POST", "/v1/containers/beacon/start", None, Action::Allow),
            // #52: the reserved segment survives the strip (#24 parity).
            ("DELETE", "/v1.43/containers/json", None, Action::Deny),
            // #57: undotted version, container lifecycle delete.
            ("DELETE", "/v1/containers/foo", None, Action::Allow),
            // #57: multi-digit major version.
            ("DELETE", "/v10.0/containers/foo", None, Action::Allow),
            // #57: /volumes/ is not a version; the daemon routes this as a volume removal.
            ("DELETE", "/volumes/containers/foo", None, Action::Deny),
            // #57: /version/ is not a version prefix.
            ("DELETE", "/version/containers/foo", None, Action::Deny),
            // #57: two dots is not an API version.
            ("DELETE", "/v1.2.3/containers/foo", None, Action::Deny),
            // #57: no digits after v.
            ("DELETE", "/vabc/containers/foo", None, Action::Deny),
            // #57: bare v.
            ("DELETE", "/v/containers/foo", None, Action::Deny),
            // #57: dot without a minor version.
            ("DELETE", "/v1./containers/foo", None, Action::Deny),
            // #57: strip once; the remaining /v1.43/containers/foo matches no route.
            ("DELETE", "/v1/v1.43/containers/foo", None, Action::Deny),
            // #57: a non-ASCII digit (U+0661 ARABIC-INDIC DIGIT ONE) is not a version digit.
            ("DELETE", "/v\u{0661}/containers/foo", None, Action::Deny),
            // #57 sanity row, cannot fail: GET /version is allowed as a read-only request.
            ("GET", "/version", None, Action::Allow),
        ];
        for (method, path, body, want) in cases {
            let got = router.route(method, path, body);
            assert_eq!(got.action, want, "route({} {})", method, path);
        }
    }

    #[test]
    fn test_extract_container_name_skips_empty_segment() {
        for path in ["/containers/", "/containers//start"] {
            assert_eq!(extract_container_name(path), None, "{} has no container name", path);
        }
    }

    #[test]
    fn test_route_image_pull() {
        let router = Router::new(make_manager(vec!["alpine"]));
        let map: HashMap<String, serde_json::Value> = serde_json::from_value(
            serde_json::json!({"fromImage": "alpine"}),
        ).unwrap();
        let result = router.route("POST", "/images/create", Some(&map));
        assert_eq!(result.action, Action::Allow);
        assert_eq!(result.image, Some("alpine".into()));
    }

    #[test]
    fn test_route_image_pull_empty_body() {
        let router = Router::new(make_manager(vec!["alpine"]));
        let result = router.route("POST", "/images/create", None);
        assert_eq!(result.action, Action::Deny);
    }

    #[test]
    fn test_route_image_pull_no_fromimage() {
        let router = Router::new(make_manager(vec!["alpine"]));
        let map: HashMap<String, serde_json::Value> = serde_json::from_value(
            serde_json::json!({"tag": "latest"}),
        ).unwrap();
        let result = router.route("POST", "/images/create", Some(&map));
        assert_eq!(result.action, Action::Deny);
        assert!(result.deny_msg.unwrap().contains("fromImage"));
    }

    #[test]
    fn test_route_image_pull_not_found() {
        let router = Router::new(make_manager(vec!["alpine"]));
        let map: HashMap<String, serde_json::Value> = serde_json::from_value(
            serde_json::json!({"fromImage": "ubuntu"}),
        ).unwrap();
        let result = router.route("POST", "/images/create", Some(&map));
        assert_eq!(result.action, Action::Deny);
        assert!(result.deny_msg.unwrap().contains("not allowed by any policy"));
    }

    #[test]
    fn test_route_default_get_passthrough() {
        let router = Router::new(make_manager(vec!["alpine"]));
        let result = router.route("GET", "/some/random/path", None);
        assert_eq!(result.action, Action::Allow);
    }

    #[test]
    fn test_route_default_head_passthrough() {
        let router = Router::new(make_manager(vec!["alpine"]));
        let result = router.route("HEAD", "/some/path", None);
        assert_eq!(result.action, Action::Allow);
    }

    #[test]
    fn test_route_unknown_method_denied() {
        let router = Router::new(make_manager(vec!["alpine"]));
        let result = router.route("OPTIONS", "/some/path", None);
        assert_eq!(result.action, Action::Deny);
    }

    #[test]
    fn test_route_strip_api_version() {
        let router = Router::new(make_manager(vec!["alpine"]));
        let result = router.route("GET", "/v1.24/_ping", None);
        assert_eq!(result.action, Action::Allow);
    }

    #[test]
    fn test_route_container_by_name_no_policy() {
        let router = Router::new(make_manager(vec!["alpine"]));
        let result = router.route("POST", "/containers/unknown-container/start", None);
        assert_eq!(result.action, Action::Allow);
        assert!(result.service.is_none());
        assert_eq!(result.container, Some("unknown-container".into()));
    }

    #[test]
    fn test_container_create_body_passthrough() {
        let router = Router::new(make_manager(vec!["alpine"]));
        let map: HashMap<String, serde_json::Value> = serde_json::from_value(
            serde_json::json!({"Image": "alpine", "Cmd": ["sleep", "100"]}),
        ).unwrap();
        let result = router.route("POST", "/containers/create", Some(&map));
        assert_eq!(result.action, Action::CreateContainer);
        let b = result.body.unwrap();
        assert_eq!(b.get("Cmd").unwrap().as_array().unwrap()[0], "sleep");
    }

    #[test]
    fn test_deny_action_fields() {
        let router = Router::new(make_manager(vec!["alpine"]));
        let result = router.route("POST", "/auth", None);
        assert_eq!(result.action, Action::Deny);
        assert!(result.service.is_none());
        assert!(result.policy.is_none());
        assert!(result.body.is_none());
        assert!(result.container.is_none());
        assert!(result.image.is_none());
    }

    #[test]
    fn test_allow_action_fields() {
        let router = Router::new(make_manager(vec!["alpine"]));
        let result = router.route("GET", "/_ping", None);
        assert_eq!(result.action, Action::Allow);
        assert!(result.service.is_none());
        assert!(result.policy.is_none());
        assert!(result.body.is_none());
    }
}
