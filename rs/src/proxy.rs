use crate::policy::{check_image_tag, parse_image_ref, Manager, Policy};
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

    /// Routes a request whose body, if any, is the parsed JSON body. It is
    /// `route_request` with `has_body` set when `body` is `Some`.
    pub fn route(&self, method: &str, target: &str, body: Option<&HashMap<String, serde_json::Value>>) -> RouteResult {
        self.route_request(method, target, body.is_some(), body)
    }

    /// Routes a request. `target` is the raw request target: the path, still
    /// percent-encoded, and the query string, if any. The path checks read
    /// the path only; the image pull reads the query (#83). `has_body`
    /// reports a non-empty raw body of any Content-Type; `body` is that body
    /// parsed as JSON, or `None`.
    pub fn route_request(
        &self,
        method: &str,
        target: &str,
        has_body: bool,
        body: Option<&HashMap<String, serde_json::Value>>,
    ) -> RouteResult {
        // Read-only mode denies every write, for every path (#75).
        if self.readonly && method != "GET" && method != "HEAD" {
            return deny(&format!("read-only mode: {} requests are not allowed", method));
        }

        let (path, query) = target.split_once('?').unwrap_or((target, ""));

        // The daemon decodes the path before routing, so deny any escape (#53).
        if path.contains('%') {
            return deny("percent-encoded path not allowed");
        }

        // An empty interior segment can hide a denied prefix such as /exec (#55).
        if path.contains("//") {
            return deny("empty path segment not allowed");
        }

        // A . or .. segment can hide a denied prefix the same way (#70).
        if has_dot_segment(path) {
            return deny("dot path segment not allowed");
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
            return self.route_image_pull(query, has_body);
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
        if let Err(msg) = parse_image_ref(image) {
            return deny(&msg);
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

    /// Image pull (#83). The Docker CLI sends `fromImage` and `tag` in the
    /// query string and no body.
    /// The image then gets the create checks: a policy prefix on the
    /// normalised repository (#84), and that policy's tag and digest rules.
    fn route_image_pull(&self, raw_query: &str, has_body: bool) -> RouteResult {
        // The daemon reads a form body's fromImage over the query's, so a
        // body could name any image: a pull has no body, whatever its
        // Content-Type.
        if has_body {
            return deny("image pull must not have a request body");
        }
        let params = match parse_query(raw_query) {
            Some(p) => p,
            None => return deny("invalid query string"),
        };
        for key in ["fromImage", "tag", "fromSrc"] {
            if params.iter().filter(|(k, _)| k == key).count() > 1 {
                return deny(&format!("duplicate {} query parameter", key));
            }
        }
        let get = |key: &str| params.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str());
        if get("fromSrc").is_some() {
            return deny("image import (fromSrc) is not allowed");
        }
        let from_image = get("fromImage").unwrap_or("");
        if from_image.is_empty() {
            return deny("fromImage query parameter is required for image pull");
        }
        let mut image_ref = match parse_image_ref(from_image) {
            Ok(r) => r,
            Err(msg) => return deny(&msg),
        };
        let tag = get("tag").unwrap_or("");
        if !tag.is_empty() {
            if !image_ref.tag.is_empty() || !image_ref.digest.is_empty() {
                return deny(&format!(
                    "fromImage {} already has a tag or digest; the tag query parameter is ambiguous",
                    from_image
                ));
            }
            // The CLI sends a digest in tag; a tag never contains ':'.
            let sep = if tag.contains(':') { '@' } else { ':' };
            image_ref = match parse_image_ref(&format!("{}{}{}", from_image, sep, tag)) {
                Ok(r) => r,
                Err(msg) => return deny(&msg),
            };
        }
        // With neither, the daemon pulls every tag of the repository.
        if image_ref.tag.is_empty() && image_ref.digest.is_empty() {
            return deny("image pull without a tag or digest pulls every tag and is not allowed");
        }
        let policy = match self.manager.get_by_image(&image_ref.name) {
            Some(p) => p,
            None => return deny(&format!("image {} not allowed by any policy", from_image)),
        };
        if let Err(msg) = check_image_tag(policy, &image_ref) {
            return deny(&msg);
        }
        RouteResult {
            action: Action::Allow,
            service: Some(policy.service_name.clone()),
            policy: None,
            body: None,
            container: None,
            image: Some(from_image.to_string()),
            deny_msg: None,
        }
    }
}

/// Parses a query string as Go's `url.ParseQuery` does, which is what the
/// daemon uses: `&` separates pairs, `+` is a space, and a `;` or a bad
/// `%` escape fails the whole query.
fn parse_query(raw: &str) -> Option<Vec<(String, String)>> {
    let mut out = Vec::new();
    for part in raw.split('&') {
        if part.contains(';') {
            return None;
        }
        if part.is_empty() {
            continue;
        }
        let (k, v) = part.split_once('=').unwrap_or((part, ""));
        out.push((query_unescape(k)?, query_unescape(v)?));
    }
    Some(out)
}

fn query_unescape(s: &str) -> Option<String> {
    let hex = |b: u8| (b as char).to_digit(16).map(|d| d as u8);
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hi = hex(*bytes.get(i + 1)?)?;
                let lo = hex(*bytes.get(i + 2)?)?;
                out.push(hi << 4 | lo);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    Some(String::from_utf8_lossy(&out).into_owned())
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

// A segment that is exactly . or ..; names such as .hidden or a.b are not
// dot segments (#70).
fn has_dot_segment(path: &str) -> bool {
    path.split('/').any(|s| s == "." || s == "..")
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
            (
                "POST",
                "/images/create/extra?fromImage=alpine&tag=latest",
                None,
                Action::Deny,
                None,
            ),
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
            (
                "POST",
                "/images/create?fromImage=chainsafe%2Flodestar&tag=latest",
                None,
                Action::Deny,
                post,
            ),
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
            (
                "PATCH",
                "/_ping",
                Action::Deny,
                Some("endpoint PATCH /_ping is not allowed"),
            ),
            // A lowercase method is an extension method, not CONNECT: the router denies it.
            (
                "connect",
                "/_ping",
                Action::Deny,
                Some("endpoint connect /_ping is not allowed"),
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

    /// Cross-language parity guard for #70. A path with a segment that is
    /// exactly . or .. is denied for every method, right after the // check
    /// and before the API-version strip. Before #70 GET /./exec/<id>/json
    /// had a first segment of ".", so the exec check missed it and the GET
    /// passthrough forwarded it. Rows mirror the dot* runs in
    /// spec/router.qnt.
    #[test]
    fn test_route_dot_segments() {
        let router = Router::new(make_manager(vec!["alpine"]));
        let dot = Some("dot path segment not allowed");
        let cases = [
            // dotLeadingExecGetDeniedTest (#70): the leading . hid the exec namespace.
            ("GET", "/./exec/abc/json", Action::Deny, dot),
            // dotDotExecGetDeniedTest (#70)
            ("GET", "/x/../exec/abc/json", Action::Deny, dot),
            // dotInContainerPathDeniedTest (#70)
            ("GET", "/containers/x/./exec", Action::Deny, dot),
            // #70: .. climbing out of the container path.
            ("GET", "/containers/x/../../exec/abc/json", Action::Deny, dot),
            // #70: the check runs before the version strip.
            ("GET", "/v1.45/./_ping", Action::Deny, dot),
            // #70: every method.
            ("DELETE", "/containers/..", Action::Deny, dot),
            ("POST", "/containers/x/./start", Action::Deny, dot),
            // #70: the dot hid the attach deny too.
            ("GET", "/containers/./x/attach/ws", Action::Deny, dot),
            // #70 control: names with dots are names.
            ("GET", "/containers/.hidden/json", Action::Allow, None),
            ("GET", "/containers/a.b/json", Action::Allow, None),
            ("GET", "/containers/.../json", Action::Allow, None),
            // #70: the // check runs first.
            ("GET", "//./_ping", Action::Deny, Some("empty path segment not allowed")),
            // #70: an encoded dot is denied by the percent check (#53).
            (
                "GET",
                "/containers/%2e/json",
                Action::Deny,
                Some("percent-encoded path not allowed"),
            ),
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

    const TEST_DIGEST: &str = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    /// The policy set for the #83 and #84 tables, loaded from YAML so that
    /// the prefixes go through load-time normalisation: beacon's prefixes are
    /// written docker.io/chainsafe/lodestar and Registry.Example.com:443/a.
    fn pull_test_manager() -> Manager {
        let dir = std::env::temp_dir().join(format!("dsp-pull-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("probe.yaml"),
            "service_name: probe\nallowed_image_prefixes:\n  - alpine\nimage_digest_allowed: true\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("beacon.yaml"),
            "service_name: beacon\nallowed_image_prefixes:\n  - docker.io/chainsafe/lodestar\n  - ghcr.io/chainsafe/lodestar\n  - localhost:5000/x\n  - Registry.Example.com:443/a\nimage_tag_pattern: '^(v[0-9]+|[0-9]+)$'\n",
        )
        .unwrap();
        let manager = Manager::new(dir.to_str().unwrap()).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        manager
    }

    /// Cross-language parity guard for #83 and #84. POST /images/create is
    /// routed on its query string, the way the Docker CLI sends it: fromImage
    /// (fully qualified, URL-encoded) and tag, with an empty body. The body is
    /// ignored, fromSrc (import) is denied, and the image gets the create
    /// checks: a policy prefix on the normalised repository, then that
    /// policy's tag pattern and digest rule. Rows mirror the pull* runs in
    /// spec/router.qnt; the rest are language-only.
    #[test]
    fn test_route_pull_query() {
        let router = Router::new(pull_test_manager());
        let alpine_body: HashMap<String, serde_json::Value> =
            serde_json::from_value(serde_json::json!({"fromImage": "alpine"})).unwrap();
        let old_body: HashMap<String, serde_json::Value> =
            serde_json::from_value(serde_json::json!({"fromImage": "alpine:3.19"})).unwrap();
        let not_allowed = |image: &str| format!("image {} not allowed by any policy", image);
        let required = "fromImage query parameter is required for image pull".to_string();
        let body_msg = "image pull must not have a request body".to_string();
        let from_src = "image import (fromSrc) is not allowed".to_string();
        let enc_digest = TEST_DIGEST.replace(':', "%3A");
        let cases: Vec<(
            String,
            Option<&HashMap<String, serde_json::Value>>,
            Action,
            &str,
            String,
        )> = vec![
            // pullCliAllowedTest (#83): the issue's reproduction, as the CLI sends it.
            (
                "/v1.56/images/create?fromImage=docker.io%2Flibrary%2Falpine&tag=3.19".into(),
                None,
                Action::Allow,
                "probe",
                String::new(),
            ),
            // pullShortNameAllowedTest (#84)
            (
                "/images/create?fromImage=alpine&tag=3.19".into(),
                None,
                Action::Allow,
                "probe",
                String::new(),
            ),
            // pullLibraryNameAllowedTest (#84)
            (
                "/images/create?fromImage=library%2Falpine&tag=latest".into(),
                None,
                Action::Allow,
                "probe",
                String::new(),
            ),
            // pullCliOrgAllowedTest (#84): the prefix is written docker.io/chainsafe/lodestar.
            (
                "/images/create?fromImage=docker.io%2Fchainsafe%2Flodestar&tag=v1".into(),
                None,
                Action::Allow,
                "beacon",
                String::new(),
            ),
            // #84: the tag in fromImage, on another Docker Hub host name.
            (
                "/images/create?fromImage=index.docker.io%2Flibrary%2Falpine%3A3.19".into(),
                None,
                Action::Allow,
                "probe",
                String::new(),
            ),
            // #83: the CLI sends a digest in tag.
            (
                format!("/images/create?fromImage=alpine&tag={}", enc_digest),
                None,
                Action::Allow,
                "probe",
                String::new(),
            ),
            // #83: a digest in fromImage.
            (
                format!("/images/create?fromImage=alpine%40{}", enc_digest),
                None,
                Action::Allow,
                "probe",
                String::new(),
            ),
            // #83: image_digest_allowed is false for beacon.
            (
                format!(
                    "/images/create?fromImage=ghcr.io%2Fchainsafe%2Flodestar&tag={}",
                    enc_digest
                ),
                None,
                Action::Deny,
                "",
                "image digests not allowed for service beacon".into(),
            ),
            // #84: a registry port is not a tag.
            (
                "/images/create?fromImage=localhost%3A5000%2Fx%2Fy&tag=2".into(),
                None,
                Action::Allow,
                "beacon",
                String::new(),
            ),
            // #84: the registry host is compared lower-cased.
            (
                "/images/create?fromImage=REGISTRY.example.com%3A443%2Fa&tag=1".into(),
                None,
                Action::Allow,
                "beacon",
                String::new(),
            ),
            // #83: the tag pattern applies to pulls.
            (
                "/images/create?fromImage=chainsafe%2Flodestar&tag=latest".into(),
                None,
                Action::Deny,
                "",
                r#"image tag "latest" does not match pattern "^(v[0-9]+|[0-9]+)$""#.into(),
            ),
            // pullDisallowedCliDeniedTest (#83)
            (
                "/images/create?fromImage=docker.io%2Fattacker%2Fmalware&tag=latest".into(),
                None,
                Action::Deny,
                "",
                not_allowed("docker.io/attacker/malware"),
            ),
            // pullOtherRegistryDeniedTest (#84): another registry is not Docker Hub's alpine.
            (
                "/images/create?fromImage=localhost%3A5000%2Falpine&tag=1".into(),
                None,
                Action::Deny,
                "",
                not_allowed("localhost:5000/alpine"),
            ),
            // #84: the prefix match stays on namespace boundaries.
            (
                "/images/create?fromImage=alpine-evil&tag=1".into(),
                None,
                Action::Deny,
                "",
                not_allowed("alpine-evil"),
            ),
            // pullNoFromImageDeniedTest (#83)
            ("/images/create".into(), None, Action::Deny, "", required.clone()),
            // #83: the old contract, fromImage in a JSON body: a pull has no body.
            (
                "/images/create".into(),
                Some(&old_body),
                Action::Deny,
                "",
                body_msg.clone(),
            ),
            // pullBodyIgnoredDeniedTest (#83): the daemon would pull the query's image.
            (
                "/images/create?fromImage=attacker%2Fmalware&tag=latest".into(),
                Some(&alpine_body),
                Action::Deny,
                "",
                body_msg.clone(),
            ),
            // pullJsonBodyDeniedTest (#83): any body is denied, even one that agrees.
            (
                "/images/create?fromImage=alpine&tag=3.19".into(),
                Some(&alpine_body),
                Action::Deny,
                "",
                body_msg.clone(),
            ),
            // pullImportDeniedTest (#83): the daemon would import the tarball as alpine:latest.
            (
                "/images/create?fromSrc=http%3A%2F%2Fexample.com%2Fx.tar&repo=alpine&tag=latest".into(),
                None,
                Action::Deny,
                "",
                from_src.clone(),
            ),
            // pullImportWithImageDeniedTest (#83)
            (
                "/images/create?fromImage=alpine&tag=latest&fromSrc=-".into(),
                None,
                Action::Deny,
                "",
                from_src.clone(),
            ),
            // #83: a tag in fromImage and in tag is ambiguous.
            (
                "/images/create?fromImage=alpine%3A3.19&tag=3.20".into(),
                None,
                Action::Deny,
                "",
                "fromImage alpine:3.19 already has a tag or digest; the tag query parameter is ambiguous".into(),
            ),
            // #83: no tag and no digest pulls every tag.
            (
                "/images/create?fromImage=alpine".into(),
                None,
                Action::Deny,
                "",
                "image pull without a tag or digest pulls every tag and is not allowed".into(),
            ),
            // #84: upper case in the repository path is invalid.
            (
                "/images/create?fromImage=Alpine&tag=latest".into(),
                None,
                Action::Deny,
                "",
                r#"invalid image reference "Alpine""#.into(),
            ),
            // #83: a repeated parameter could be read two ways.
            (
                "/images/create?fromImage=alpine&fromImage=attacker%2Fmalware&tag=1".into(),
                None,
                Action::Deny,
                "",
                "duplicate fromImage query parameter".into(),
            ),
            // #83: the daemon rejects a malformed query; so does the proxy.
            (
                "/images/create?fromImage=alpine%zz&tag=1".into(),
                None,
                Action::Deny,
                "",
                "invalid query string".into(),
            ),
            // #53 still holds: the percent check reads the path, not the query.
            (
                "/images/%63reate?fromImage=alpine&tag=1".into(),
                None,
                Action::Deny,
                "",
                "percent-encoded path not allowed".into(),
            ),
        ];
        let mut mismatches = Vec::new();
        for (path, body, want, service, want_msg) in &cases {
            let got = router.route("POST", path, *body);
            let got_service = got.service.as_deref().unwrap_or("");
            let got_msg = got.deny_msg.as_deref().unwrap_or("");
            if got.action != *want || got_service != *service || got_msg != want_msg {
                mismatches.push(format!(
                    "POST {}: got {:?}/{:?}/{:?}, want {:?}/{:?}/{:?}",
                    path, got.action, got_service, got_msg, want, service, want_msg
                ));
            }
        }
        assert!(
            mismatches.is_empty(),
            "pull routing mismatches:\n{}",
            mismatches.join("\n")
        );
    }

    /// The normalisation table for #84, on the create route: each spelling
    /// selects the policy its normalised repository matches, and a path with
    /// upper case is invalid. The same table runs in Go and TypeScript.
    #[test]
    fn test_route_image_normalization() {
        let router = Router::new(pull_test_manager());
        let not_allowed = |image: &str| format!("image {} not allowed by any policy", image);
        let ghcr_digest = format!("ghcr.io/chainsafe/lodestar@{}", TEST_DIGEST);
        let cases: Vec<(&str, Action, &str, String)> = vec![
            ("alpine", Action::CreateContainer, "probe", String::new()),
            ("library/alpine", Action::CreateContainer, "probe", String::new()),
            (
                "docker.io/library/alpine",
                Action::CreateContainer,
                "probe",
                String::new(),
            ),
            ("docker.io/alpine", Action::CreateContainer, "probe", String::new()),
            (
                "index.docker.io/library/alpine:3.19",
                Action::CreateContainer,
                "probe",
                String::new(),
            ),
            (
                "docker.io/chainsafe/lodestar:v1",
                Action::CreateContainer,
                "beacon",
                String::new(),
            ),
            (
                "chainsafe/lodestar:v1",
                Action::CreateContainer,
                "beacon",
                String::new(),
            ),
            (
                "registry-1.docker.io/chainsafe/lodestar:v1",
                Action::CreateContainer,
                "beacon",
                String::new(),
            ),
            (&ghcr_digest, Action::CreateContainer, "beacon", String::new()),
            ("localhost:5000/x/y:2", Action::CreateContainer, "beacon", String::new()),
            (
                "registry.example.com:443/a",
                Action::CreateContainer,
                "beacon",
                String::new(),
            ),
            (
                "Alpine:latest",
                Action::Deny,
                "",
                r#"invalid image reference "Alpine:latest""#.into(),
            ),
            (
                "chainsafe/Lodestar:v1",
                Action::Deny,
                "",
                r#"invalid image reference "chainsafe/Lodestar:v1""#.into(),
            ),
            ("alpine-evil", Action::Deny, "", not_allowed("alpine-evil")),
            (
                "ghcr.io/library/alpine",
                Action::Deny,
                "",
                not_allowed("ghcr.io/library/alpine"),
            ),
            (
                "ghcr.io/chainsafe/lodestar-evil",
                Action::Deny,
                "",
                not_allowed("ghcr.io/chainsafe/lodestar-evil"),
            ),
            (
                "localhost:5000/xy:1",
                Action::Deny,
                "",
                not_allowed("localhost:5000/xy:1"),
            ),
        ];
        let mut mismatches = Vec::new();
        for (image, want, service, want_msg) in &cases {
            let body: HashMap<String, serde_json::Value> =
                serde_json::from_value(serde_json::json!({ "Image": image })).unwrap();
            let got = router.route("POST", "/containers/create", Some(&body));
            let got_service = got.service.as_deref().unwrap_or("");
            let got_msg = got.deny_msg.as_deref().unwrap_or("");
            if got.action != *want || got_service != *service || got_msg != want_msg {
                mismatches.push(format!(
                    "create {}: got {:?}/{:?}/{:?}, want {:?}/{:?}/{:?}",
                    image, got.action, got_service, got_msg, want, service, want_msg
                ));
            }
        }
        assert!(
            mismatches.is_empty(),
            "normalisation mismatches:\n{}",
            mismatches.join("\n")
        );
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
