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
    readonly: bool,
}

impl Router {
    pub fn new(manager: Manager) -> Self {
        Router {
            manager,
            readonly: false,
        }
    }

    /// Sets read-only mode (--readonly) and returns the router.
    pub fn with_readonly(mut self, readonly: bool) -> Self {
        self.readonly = readonly;
        self
    }

    pub fn route(&self, method: &str, path: &str, body: Option<&HashMap<String, serde_json::Value>>) -> RouteResult {
        // Read-only mode denies every write, for every path (#75).
        if self.readonly && method != "GET" && method != "HEAD" {
            return deny(&format!("read-only mode: {} requests are not allowed", method));
        }

        // The daemon decodes the path before routing, so deny any escape (#53).
        if path.contains('%') {
            return deny("percent-encoded path not allowed");
        }

        // An empty interior segment can hide a denied prefix such as /exec (#55).
        if path.contains("//") {
            return deny("empty path segment not allowed");
        }

        let path = strip_api_version(path);

        // Denied endpoints
        if path.starts_with("/auth") {
            return deny("auth endpoint is not allowed");
        }
        if is_exec_path(path) {
            return deny("exec is not allowed");
        }
        if is_attach_path(path) {
            return deny("attach is not allowed");
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
                _ if method == "GET" || method == "HEAD" => allow(),
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

// Strips one leading /v<N>/ or /v<N>.<M>/ (ASCII digits only); anything else is left as is (#57).
fn strip_api_version(path: &str) -> &str {
    let Some(rest) = path.strip_prefix("/v") else {
        return path;
    };
    let bytes = rest.as_bytes();
    let digits = |from: usize| bytes[from..].iter().take_while(|b| b.is_ascii_digit()).count();
    let major = digits(0);
    if major == 0 {
        return path;
    }
    let mut i = major;
    if bytes.get(i) == Some(&b'.') {
        let minor = digits(i + 1);
        if minor == 0 {
            return path;
        }
        i += 1 + minor;
    }
    if bytes.get(i) == Some(&b'/') {
        return &rest[i..];
    }
    path
}

// Exec is matched on whole segments, so a name like exec-runner is not exec (#49).
fn is_exec_path(path: &str) -> bool {
    let mut segs = path.strip_prefix('/').unwrap_or(path).split('/');
    match segs.next() {
        Some("exec") => true,
        Some("containers") => segs.any(|s| s == "exec"),
        _ => false,
    }
}

// Attach is matched on whole segments after /containers, so a name like
// attach-runner is not attach (#76).
fn is_attach_path(path: &str) -> bool {
    let mut segs = path.strip_prefix('/').unwrap_or(path).split('/');
    segs.next() == Some("containers") && segs.any(|s| s == "attach")
}

fn extract_container_name(path: &str) -> Option<&str> {
    let path = path.strip_prefix('/').unwrap_or(path);
    let parts: Vec<&str> = path.split('/').collect();
    // An empty segment is not a name, mirroring Go/TS (#48).
    if parts.len() >= 2
        && parts[0] == "containers"
        && !parts[1].is_empty()
        && parts[1] != "create"
        && parts[1] != "json"
        && parts[1] != "exec"
    {
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
        let binding =
            serde_json::from_value::<HashMap<String, serde_json::Value>>(serde_json::json!({"Image": "alpine:latest"}))
                .unwrap();
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
        let map: HashMap<String, serde_json::Value> =
            serde_json::from_value(serde_json::json!({"Cmd": ["echo"]})).unwrap();
        let result = router.route("POST", "/containers/create", Some(&map));
        assert_eq!(result.action, Action::Deny);
        assert!(result.deny_msg.unwrap().contains("image"));
    }

    #[test]
    fn test_route_container_create_image_not_found() {
        let router = Router::new(make_manager(vec!["alpine"]));
        let map: HashMap<String, serde_json::Value> =
            serde_json::from_value(serde_json::json!({"Image": "ubuntu:latest"})).unwrap();
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
            ("DELETE", "/containers/json", Action::Deny, None),
            // reservedCreateDeleteDeniedTest
            ("DELETE", "/containers/create", Action::Deny, None),
            // reservedExecDeleteDeniedTest: denied by the exec check, before the lifecycle branch.
            ("DELETE", "/containers/exec", Action::Deny, Some("exec is not allowed")),
            // Listing stays allowed, via the GET/HEAD passthrough.
            ("GET", "/containers/json", Action::Allow, None),
            // A real container name is still routed as a container.
            // realNameDeleteAllowedTest
            ("DELETE", "/containers/mycontainer", Action::Allow, None),
            ("GET", "/containers/mycontainer", Action::Allow, None),
            // Reserved words are only reserved in the name position.
            // reservedInSubpathAllowedTest
            ("GET", "/containers/mycontainer/json", Action::Allow, None),
        ];
        let mut mismatches = Vec::new();
        for (method, path, want, want_msg) in cases {
            let got = router.route(method, path, None);
            if got.action != want || (want_msg.is_some() && got.deny_msg.as_deref() != want_msg) {
                mismatches.push(format!(
                    "{} {}: got {:?}/{}, want {:?}/{}",
                    method,
                    path,
                    got.action,
                    got.deny_msg.as_deref().unwrap_or("-"),
                    want,
                    want_msg.unwrap_or("-")
                ));
            }
        }
        assert!(mismatches.is_empty(), "mismatches:\n{}", mismatches.join("\n"));
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
        let mut mismatches = Vec::new();
        for (method, path, want) in cases {
            let got = router.route(method, path, None);
            if got.action != want {
                mismatches.push(format!(
                    "{} {}: got {:?}/{}, want {:?}",
                    method,
                    path,
                    got.action,
                    got.deny_msg.as_deref().unwrap_or("-"),
                    want
                ));
            }
        }
        assert!(mismatches.is_empty(), "mismatches:\n{}", mismatches.join("\n"));
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
            (
                "POST",
                "/v1.43/containers/create",
                Some(&create_body),
                Action::CreateContainer,
            ),
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
        let mut mismatches = Vec::new();
        for (method, path, body, want) in cases {
            let got = router.route(method, path, body);
            if got.action != want {
                mismatches.push(format!(
                    "{} {}: got {:?}/{}, want {:?}",
                    method,
                    path,
                    got.action,
                    got.deny_msg.as_deref().unwrap_or("-"),
                    want
                ));
            }
        }
        assert!(mismatches.is_empty(), "mismatches:\n{}", mismatches.join("\n"));
    }

    /// Cross-language parity guard for #53. The daemon percent-decodes the
    /// path before it routes, so any % in the path lets the proxy and the
    /// daemon read the same request differently. A path containing % is
    /// denied for every method. Paths are given raw, as the handler routes
    /// them. Rows mirror the percent* runs in spec/router.qnt.
    #[test]
    fn test_route_percent_encoded_paths() {
        let router = Router::new(make_manager(vec!["alpine"]));
        let cases = [
            // percentSlashDeleteDeniedTest (#53)
            ("DELETE", "/containers/%2F", Action::Deny),
            // percentLowerSlashDeleteDeniedTest (#53)
            ("DELETE", "/containers/%2f", Action::Deny),
            // percentReservedDeleteDeniedTest (#53): %6A%73%6F%6E decodes to json.
            ("DELETE", "/containers/%6A%73%6F%6E", Action::Deny),
            // percentSubpathStartDeniedTest (#53): a pin; raw routing already denies it.
            // It discriminates only in Go's handler before #53, which decoded first;
            // the foo%20bar handler test covers that.
            ("POST", "/containers/beacon%2Fstart", Action::Deny),
            // percentNameStartDeniedTest (#53)
            ("POST", "/containers/%2F/start", Action::Deny),
            // percentGetDeniedTest (#53)
            ("GET", "/containers/%2F", Action::Deny),
            // #53, language-only: the rule covers every method, HEAD included.
            ("HEAD", "/containers/%2F", Action::Deny),
            // #53: the check runs on the versioned path too.
            ("DELETE", "/v1.45/containers/foo%25", Action::Deny),
            // #53: an encoded version prefix is not stripped.
            ("DELETE", "/v%31/containers/foo", Action::Deny),
            // #53: network names that need escaping are denied, GET included.
            ("GET", "/networks/a%20b", Action::Deny),
            // #53 control: a plain name is still routed as a container.
            ("DELETE", "/containers/foo", Action::Allow),
        ];
        let mut mismatches = Vec::new();
        for (method, path, want) in cases {
            let got = router.route(method, path, None);
            let msg = got.deny_msg.as_deref().unwrap_or("-");
            if got.action != want || (want == Action::Deny && !msg.contains("percent-encoded")) {
                let want_msg = if want == Action::Deny { "*percent-encoded*" } else { "-" };
                mismatches.push(format!(
                    "{} {}: got {:?}/{}, want {:?}/{}",
                    method, path, got.action, msg, want, want_msg
                ));
            }
        }
        assert!(mismatches.is_empty(), "mismatches:\n{}", mismatches.join("\n"));
    }

    /// Cross-language parity guard for #49. Exec and create are matched on
    /// whole path segments. Exec is denied for every method when the first
    /// segment is exec, or when the first segment is containers and a later
    /// segment is exactly exec; a name that only contains exec routes
    /// normally. POST /containers/create and POST /images/create match only
    /// with exactly two segments. Rows mirror the exec* and create* runs in
    /// spec/router.qnt.
    #[test]
    fn test_route_exec_and_exact_endpoints() {
        let router = Router::new(make_manager(vec!["alpine"]));
        let create_body: HashMap<String, serde_json::Value> =
            serde_json::from_value(serde_json::json!({"Image": "alpine:latest"})).unwrap();
        let pull_body: HashMap<String, serde_json::Value> =
            serde_json::from_value(serde_json::json!({"fromImage": "alpine:latest"})).unwrap();
        let exec = Some("exec is not allowed");
        let cases = [
            // execSubpathDeleteDeniedTest (#49)
            ("DELETE", "/containers/mycontainer/exec", None, Action::Deny, exec),
            // execSubpathPostDeniedTest (#49)
            ("POST", "/containers/mycontainer/exec", None, Action::Deny, exec),
            // execPrefixNameStartAllowedTest (#49): an unknown container.
            ("POST", "/containers/exec-runner/start", None, Action::Allow, None),
            // execPrefixNameDeleteAllowedTest (#49): an unknown container.
            ("DELETE", "/containers/exec-runner", None, Action::Allow, None),
            // execPrefixNameGetAllowedTest (#49)
            ("GET", "/containers/exec-runner/json", None, Action::Allow, None),
            // execNamespaceGetDeniedTest (#49): exec inspect leaks command lines.
            ("GET", "/exec/abc/json", None, Action::Deny, exec),
            // execNamespacePostDeniedTest (#49)
            ("POST", "/exec/abc/start", None, Action::Deny, exec),
            // createSubpathDeniedTest (#49): an allowed image, so only the path decides.
            (
                "POST",
                "/containers/create/extra",
                Some(&create_body),
                Action::Deny,
                None,
            ),
            // Exec is matched under containers or exec only (#49, language-only).
            ("GET", "/images/exec", None, Action::Allow, None),
            // An allowed image, so only the path decides (#49, language-only).
            ("POST", "/images/create/extra", Some(&pull_body), Action::Deny, None),
            // A name ending in exec is a plain name (#49, language-only).
            ("GET", "/containers/myexec/json", None, Action::Allow, None),
            // A name starting with exec is a plain name (#49, language-only).
            ("DELETE", "/containers/executor", None, Action::Allow, None),
            // The reserved name, decided by the exec check (#49, language-only).
            ("GET", "/containers/exec/json", None, Action::Deny, exec),
            // A top-level name starting with exec is not the exec namespace (#49, language-only).
            ("GET", "/executor", None, Action::Allow, None),
        ];
        let mut mismatches = Vec::new();
        for (method, path, body, want, want_msg) in cases {
            let got = router.route(method, path, body);
            // Exact match: the default deny for POST /containers/x/exec ends in
            // "exec is not allowed" too, so a substring check passes vacuously.
            if got.action != want || (want_msg.is_some() && got.deny_msg.as_deref() != want_msg) {
                mismatches.push(format!(
                    "{} {}: got {:?}/{}, want {:?}/{}",
                    method,
                    path,
                    got.action,
                    got.deny_msg.as_deref().unwrap_or("-"),
                    want,
                    want_msg.unwrap_or("-")
                ));
            }
        }
        assert!(mismatches.is_empty(), "mismatches:\n{}", mismatches.join("\n"));
    }

    /// Cross-language parity guard for #55. A path with an empty interior
    /// segment (// anywhere in the path) is denied for every method, after the
    /// percent check and before the API-version strip; a single trailing slash
    /// is not interior. HEAD on a named container is routed like GET. Rows
    /// mirror the emptyLeadingExecGetDenied, emptyInteriorGetDenied and
    /// headNamedContainerAllowed runs in spec/router.qnt.
    #[test]
    fn test_route_empty_segments_and_head() {
        let router = Router::new(make_manager(vec!["alpine"]));
        let empty = Some("empty path segment not allowed");
        let percent = Some("percent-encoded path not allowed");
        let exec = Some("exec is not allowed");
        let cases = [
            // emptyLeadingExecGetDeniedTest (#55): the leading empty segment hid the exec namespace.
            ("GET", "//exec/abc/json", Action::Deny, empty),
            // #55: the empty segment after the version prefix hides the exec namespace too.
            ("GET", "/v1.45//exec/abc/json", Action::Deny, empty),
            // #55: the check runs before the version strip.
            ("GET", "//v1.45/exec/abc/json", Action::Deny, empty),
            // emptyInteriorGetDeniedTest (#55)
            ("GET", "/containers//json", Action::Deny, empty),
            // #55: emptyNameStartDeniedTest (#48) is now decided by the empty segment check.
            ("POST", "/containers//start", Action::Deny, empty),
            // #55: an empty name followed by a trailing slash.
            ("DELETE", "/containers//", Action::Deny, empty),
            // #55: the read-only endpoints are not exempt.
            ("GET", "//_ping", Action::Deny, empty),
            // #55: the percent check runs first.
            ("GET", "//containers/%2F", Action::Deny, percent),
            // #55 control: a single trailing slash is not an empty interior segment.
            ("GET", "/containers/", Action::Allow, None),
            // #55 control: the root path.
            ("GET", "/", Action::Allow, None),
            // headNamedContainerAllowedTest (#55)
            ("HEAD", "/containers/mycontainer", Action::Allow, None),
            // #55: HEAD on a container subpath.
            ("HEAD", "/containers/mycontainer/json", Action::Allow, None),
            // #55: the exec check still denies HEAD.
            ("HEAD", "/containers/mycontainer/exec", Action::Deny, exec),
        ];
        let mut mismatches = Vec::new();
        for (method, path, want, want_msg) in cases {
            let got = router.route(method, path, None);
            if got.action != want || got.deny_msg.as_deref() != want_msg {
                mismatches.push(format!(
                    "{} {}: got {:?}/{}, want {:?}/{}",
                    method,
                    path,
                    got.action,
                    got.deny_msg.as_deref().unwrap_or("-"),
                    want,
                    want_msg.unwrap_or("-")
                ));
            }
        }
        assert!(mismatches.is_empty(), "mismatches:\n{}", mismatches.join("\n"));
    }

    /// Cross-language parity guard for #75. With --readonly, every request
    /// whose method is not GET or HEAD is denied first in the router, for
    /// every path. Before #75 the flag only reached the middleware chain,
    /// which runs on the create route alone, so lifecycle POSTs, DELETE
    /// /containers/{name} and image pulls were forwarded. Rows mirror the
    /// readonly* runs in spec/router.qnt.
    #[test]
    fn test_route_readonly() {
        let router = Router::new(make_manager(vec!["chainsafe/lodestar"])).with_readonly(true);
        let post = Some("read-only mode: POST requests are not allowed");
        let create_body: HashMap<String, serde_json::Value> =
            serde_json::from_value(serde_json::json!({"Image": "chainsafe/lodestar:latest"})).unwrap();
        let pull_body: HashMap<String, serde_json::Value> =
            serde_json::from_value(serde_json::json!({"fromImage": "chainsafe/lodestar", "tag": "latest"})).unwrap();
        let cases = [
            // readonlyGetAllowedTest (#75)
            ("GET", "/containers/json", None, Action::Allow, None),
            // readonlyHeadAllowedTest (#75)
            ("HEAD", "/containers/mycontainer", None, Action::Allow, None),
            // #75: the read-only endpoints stay allowed.
            ("GET", "/_ping", None, Action::Allow, None),
            // readonlyLifecycleStopDeniedTest (#75)
            ("POST", "/containers/mycontainer/stop", None, Action::Deny, post),
            // #75: the other lifecycle actions too.
            ("POST", "/containers/mycontainer/start", None, Action::Deny, post),
            // readonlyDeleteDeniedTest (#75)
            (
                "DELETE",
                "/containers/mycontainer",
                None,
                Action::Deny,
                Some("read-only mode: DELETE requests are not allowed"),
            ),
            // #75: an image pull of an allowed image.
            ("POST", "/images/create", Some(&pull_body), Action::Deny, post),
            // readonlyCreateDeniedTest (#75): an allowed image, so only the flag decides.
            ("POST", "/containers/create", Some(&create_body), Action::Deny, post),
            // #75: methods outside the spec's universe.
            (
                "PUT",
                "/containers/mycontainer/archive",
                None,
                Action::Deny,
                Some("read-only mode: PUT requests are not allowed"),
            ),
            // #75: the check runs before the API-version strip.
            ("POST", "/v1.45/containers/mycontainer/stop", None, Action::Deny, post),
        ];
        let mut mismatches = Vec::new();
        for (method, path, body, want, want_msg) in cases {
            let got = router.route(method, path, body);
            if got.action != want || got.deny_msg.as_deref() != want_msg {
                mismatches.push(format!(
                    "{} {}: got {:?}/{}, want {:?}/{}",
                    method,
                    path,
                    got.action,
                    got.deny_msg.as_deref().unwrap_or("-"),
                    want,
                    want_msg.unwrap_or("-")
                ));
            }
        }
        // #75: the flag gates the rule; without it a lifecycle POST is routed as before.
        let off =
            Router::new(make_manager(vec!["chainsafe/lodestar"])).route("POST", "/containers/mycontainer/stop", None);
        if off.deny_msg.as_deref() == post {
            mismatches.push("POST /containers/mycontainer/stop without --readonly: got the read-only deny".to_string());
        }
        assert!(mismatches.is_empty(), "mismatches:\n{}", mismatches.join("\n"));
    }

    /// Cross-language parity guard for #76. attach as a whole segment after
    /// /containers/{name} is denied for every method, right after the exec
    /// check. Before #76 GET .../attach/ws fell through to the GET
    /// passthrough. Rows mirror the attach* runs in spec/router.qnt.
    #[test]
    fn test_route_attach() {
        let router = Router::new(make_manager(vec!["alpine"]));
        let attach = Some("attach is not allowed");
        let cases = [
            // attachGetDeniedTest (#76): the websocket attach endpoint.
            ("GET", "/containers/mycontainer/attach/ws", Action::Deny, attach),
            // attachPostDeniedTest (#76)
            ("POST", "/containers/mycontainer/attach", Action::Deny, attach),
            // attachHeadDeniedTest (#76)
            ("HEAD", "/containers/mycontainer/attach", Action::Deny, attach),
            // #76: the check runs after the API-version strip.
            ("GET", "/v1.45/containers/mycontainer/attach/ws", Action::Deny, attach),
            // #76: every method.
            ("DELETE", "/containers/mycontainer/attach", Action::Deny, attach),
            // #76 control: attach-runner is a name like any other.
            ("GET", "/containers/attach-runner/json", Action::Allow, None),
            // #76 control: other container reads stay allowed.
            ("GET", "/containers/mycontainer/logs", Action::Allow, None),
            ("GET", "/containers/json", Action::Allow, None),
        ];
        let mut mismatches = Vec::new();
        for (method, path, want, want_msg) in cases {
            let got = router.route(method, path, None);
            if got.action != want || got.deny_msg.as_deref() != want_msg {
                mismatches.push(format!(
                    "{} {}: got {:?}/{}, want {:?}/{}",
                    method,
                    path,
                    got.action,
                    got.deny_msg.as_deref().unwrap_or("-"),
                    want,
                    want_msg.unwrap_or("-")
                ));
            }
        }
        assert!(mismatches.is_empty(), "mismatches:\n{}", mismatches.join("\n"));
    }

    /// Cross-language parity guard for #78. /_ping, /version, /info and
    /// /events admit only GET and HEAD, through the read passthrough; every
    /// other method gets the default deny. Before #78 an early clause allowed
    /// them for every method, and /events as a prefix also matched
    /// /eventsxyz. Rows mirror the ping* runs in spec/router.qnt.
    #[test]
    fn test_route_read_endpoint_methods() {
        let router = Router::new(make_manager(vec!["alpine"]));
        let cases = [
            // pingPostDeniedTest (#78)
            (
                "POST",
                "/_ping",
                Action::Deny,
                Some("endpoint POST /_ping is not allowed"),
            ),
            // pingDeleteDeniedTest (#78)
            (
                "DELETE",
                "/_ping",
                Action::Deny,
                Some("endpoint DELETE /_ping is not allowed"),
            ),
            // #78: every read endpoint, every non-read method.
            (
                "DELETE",
                "/version",
                Action::Deny,
                Some("endpoint DELETE /version is not allowed"),
            ),
            ("PUT", "/info", Action::Deny, Some("endpoint PUT /info is not allowed")),
            (
                "POST",
                "/events",
                Action::Deny,
                Some("endpoint POST /events is not allowed"),
            ),
            (
                "CONNECT",
                "/_ping",
                Action::Deny,
                Some("endpoint CONNECT /_ping is not allowed"),
            ),
            // #78: the daemon's CORS preflight, denied on purpose.
            (
                "OPTIONS",
                "/_ping",
                Action::Deny,
                Some("endpoint OPTIONS /_ping is not allowed"),
            ),
            // #78: the old /events prefix match.
            (
                "POST",
                "/eventsxyz",
                Action::Deny,
                Some("endpoint POST /eventsxyz is not allowed"),
            ),
            // #78: the check runs after the API-version strip.
            (
                "POST",
                "/v1.45/_ping",
                Action::Deny,
                Some("endpoint POST /_ping is not allowed"),
            ),
            // pingGetAllowedTest (#78)
            ("GET", "/_ping", Action::Allow, None),
            // pingHeadAllowedTest (#78)
            ("HEAD", "/_ping", Action::Allow, None),
            ("GET", "/version", Action::Allow, None),
            ("HEAD", "/version", Action::Allow, None),
            ("GET", "/info", Action::Allow, None),
            ("HEAD", "/info", Action::Allow, None),
            ("GET", "/events", Action::Allow, None),
            ("HEAD", "/events", Action::Allow, None),
            ("GET", "/v1.45/_ping", Action::Allow, None),
            // #78 pin: a read on an unknown path stays on the passthrough.
            ("GET", "/eventsxyz", Action::Allow, None),
        ];
        let mut mismatches = Vec::new();
        for (method, path, want, want_msg) in cases {
            let got = router.route(method, path, None);
            if got.action != want || got.deny_msg.as_deref() != want_msg {
                mismatches.push(format!(
                    "{} {}: got {:?}/{}, want {:?}/{}",
                    method,
                    path,
                    got.action,
                    got.deny_msg.as_deref().unwrap_or("-"),
                    want,
                    want_msg.unwrap_or("-")
                ));
            }
        }
        assert!(mismatches.is_empty(), "mismatches:\n{}", mismatches.join("\n"));
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
        let map: HashMap<String, serde_json::Value> =
            serde_json::from_value(serde_json::json!({"fromImage": "alpine"})).unwrap();
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
        let map: HashMap<String, serde_json::Value> =
            serde_json::from_value(serde_json::json!({"tag": "latest"})).unwrap();
        let result = router.route("POST", "/images/create", Some(&map));
        assert_eq!(result.action, Action::Deny);
        assert!(result.deny_msg.unwrap().contains("fromImage"));
    }

    #[test]
    fn test_route_image_pull_not_found() {
        let router = Router::new(make_manager(vec!["alpine"]));
        let map: HashMap<String, serde_json::Value> =
            serde_json::from_value(serde_json::json!({"fromImage": "ubuntu"})).unwrap();
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
        let map: HashMap<String, serde_json::Value> =
            serde_json::from_value(serde_json::json!({"Image": "alpine", "Cmd": ["sleep", "100"]})).unwrap();
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
