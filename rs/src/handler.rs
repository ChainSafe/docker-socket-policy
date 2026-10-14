use crate::audit::AuditLogger;
use crate::middleware::Chain;
use crate::proxy::{Action, RouteResult, Router};
use crate::transport::Transport;
use crate::transport::TransportError;
use bytes::Bytes;
use http_body_util::BodyExt;
use http_body_util::Full;
use hyper::{header, Method, Request, Response, StatusCode};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{info, warn};

pub struct Handler {
    router: Arc<Router>,
    chain: Chain,
    audit: AuditLogger,
    transport: Box<dyn Transport>,
}

impl Handler {
    pub fn new(router: Arc<Router>, chain: Chain, audit: AuditLogger, transport: Box<dyn Transport>) -> Self {
        Handler {
            router,
            chain,
            audit,
            transport,
        }
    }

    pub async fn handle<B>(&self, req: Request<B>) -> Response<Full<Bytes>>
    where
        B: http_body::Body<Data = Bytes> + Send,
    {
        let (parts, body) = req.into_parts();
        let method = parts.method.to_string();
        let path = parts.uri.path().to_string();
        let target = parts
            .uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or(&path)
            .to_string();
        let full_uri = parts.uri.to_string();
        let headers = parts.headers.clone();
        let version = parts.version;

        // Refuse CONNECT before anything else, whatever its target or headers:
        // it asks for a tunnel, which the proxy never provides (#78).
        if parts.method == Method::CONNECT {
            let msg = "CONNECT is not allowed";
            warn!("denied {} {}: {}", method, full_uri, msg);
            self.audit.deny(&method, &full_uri, msg);
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Full::new(Bytes::from(msg)))
                .unwrap();
        }

        // Refuse protocol upgrades next: forwarding one would
        // hand the caller a raw stream to the daemon (#76).
        if is_upgrade_request(&headers) {
            let msg = "protocol upgrade not allowed";
            warn!("denied {} {}: {}", method, path, msg);
            self.audit.deny(&method, &target, msg);
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Full::new(Bytes::from(msg)))
                .unwrap();
        }

        let mut body_bytes = match body.collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(_) => {
                warn!("failed to read request body");
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Full::new(Bytes::from("failed to read request body")))
                    .unwrap();
            }
        };

        let body_json: Option<HashMap<String, serde_json::Value>> =
            if !body_bytes.is_empty() && serde_json::from_slice::<serde_json::Value>(&body_bytes).is_ok() {
                serde_json::from_slice(&body_bytes).ok()
            } else {
                None
            };

        // Route on the raw target: the path still percent-encoded (#53), and the
        // query, which the image pull reads (#83).
        let mut route = self
            .router
            .route_request(&method, &target, !body_bytes.is_empty(), body_json.as_ref());

        // A lifecycle action or DELETE on a name that no policy covers
        // directly: ask the daemon which container it is (#86).
        if route.action == Action::ResolveContainer {
            let id = route.container.clone().unwrap_or_default();
            route = self.resolve_container(&id).await;
        }

        if route.action == Action::Deny {
            let msg = route.deny_msg.unwrap_or_default();
            warn!("denied {} {}: {}", method, path, msg);
            match &route.resolved_name {
                Some(name) => self
                    .audit
                    .deny(&method, &target, &format!("{} (resolved to {})", msg, name)),
                None => self.audit.deny(&method, &target, &msg),
            }
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Full::new(Bytes::from(msg)))
                .unwrap();
        }

        if route.action == Action::CreateContainer {
            if let (Some(policy), Some(body)) = (&route.policy, &route.body) {
                let result = self.chain.execute(&method, &path, policy, body);
                if !result.allowed {
                    warn!("denied by middleware {} {}: {}", method, path, result.reason);
                    self.audit.deny(&method, &target, &result.reason);
                    return Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .body(Full::new(Bytes::from(result.reason)))
                        .unwrap();
                }
                if let Some(ref modified) = result.modified_body {
                    body_bytes = Bytes::from(modified.clone());
                }
            }
        }

        info!("allowed {} {}", method, path);
        match &route.resolved_name {
            Some(name) => self.audit.allow_reason(
                &method,
                &target,
                &format!(
                    "container {} resolved to {}",
                    route.container.as_deref().unwrap_or(""),
                    name
                ),
            ),
            None => self.audit.allow(&method, &target),
        }

        let mut forwarded = Request::builder()
            .method(method.as_str())
            .uri(&full_uri)
            .version(version)
            .body(Full::new(body_bytes.clone()))
            .unwrap();
        *forwarded.headers_mut() = headers;
        forwarded
            .headers_mut()
            .insert(header::CONTENT_LENGTH, body_bytes.len().into());

        match self.transport.forward(forwarded).await {
            Ok(resp) => resp,
            Err(TransportError::SocketPermission(e)) => {
                warn!("denied: socket permission error: {}", e);
                Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(Full::new(Bytes::from("permission denied on Docker socket")))
                    .unwrap()
            }
            Err(e) => {
                warn!("forward error: {}", e);
                Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Full::new(Bytes::from(format!("proxy error: {}", e))))
                    .unwrap()
            }
        }
    }
}

impl Handler {
    /// Asks the daemon for GET /containers/{id}/json and allows the request
    /// only if the container's name is covered by a policy. A 404, an
    /// uncovered name or any other failure denies: it fails closed (#86).
    async fn resolve_container(&self, id: &str) -> RouteResult {
        let not_managed = |resolved: Option<String>| RouteResult {
            resolved_name: resolved,
            ..deny_result(format!("container {} is not managed by any policy", id))
        };
        let cannot_resolve = |reason: String| deny_result(format!("cannot resolve container {}: {}", id, reason));

        let req = match Request::builder()
            .method("GET")
            .uri(format!("/containers/{}/json", path_escape(id)))
            .header(header::HOST, "docker")
            .body(Full::new(Bytes::new()))
        {
            Ok(r) => r,
            Err(e) => return cannot_resolve(e.to_string()),
        };
        let resp = match self.transport.forward(req).await {
            Ok(r) => r,
            Err(e) => return cannot_resolve(e.to_string()),
        };
        match resp.status() {
            StatusCode::OK => {}
            StatusCode::NOT_FOUND => return not_managed(None),
            other => return cannot_resolve(format!("daemon returned {}", other.as_u16())),
        }
        let body = match resp.into_body().collect().await {
            Ok(c) => c.to_bytes(),
            Err(_) => return cannot_resolve("unreadable inspect response".into()),
        };
        let name = serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v.get("Name").and_then(|n| n.as_str()).map(str::to_string))
            .filter(|n| !n.is_empty());
        let Some(name) = name else {
            return cannot_resolve("unreadable inspect response".into());
        };
        let name = name.strip_prefix('/').unwrap_or(&name).to_string();

        let covering = self.router.manager().covering(&name);
        if covering.is_empty() {
            return not_managed(Some(name));
        }
        let policy = if covering.len() == 1 {
            Some(covering[0].clone())
        } else {
            None
        };
        RouteResult {
            action: Action::Allow,
            service: policy.as_ref().map(|p| p.service_name.clone()),
            policy,
            body: None,
            container: Some(id.to_string()),
            resolved_name: Some(name),
            image: None,
            deny_msg: None,
        }
    }
}

fn deny_result(msg: String) -> RouteResult {
    RouteResult {
        action: Action::Deny,
        service: None,
        policy: None,
        body: None,
        container: None,
        resolved_name: None,
        image: None,
        deny_msg: Some(msg),
    }
}

/// Percent-encodes everything but RFC 3986 unreserved characters, so the id
/// stays one path segment.
fn path_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

/// An Upgrade header, or a Connection header that lists the upgrade token.
fn is_upgrade_request(headers: &hyper::HeaderMap) -> bool {
    headers.contains_key(header::UPGRADE)
        || headers.get_all(header::CONNECTION).iter().any(|v| {
            v.as_bytes()
                .split(|&b| b == b',')
                .any(|tok| tok.trim_ascii().eq_ignore_ascii_case(b"upgrade"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::middleware::Chain;
    use crate::policy::{Manager, Policy};
    use crate::proxy::Router;
    use crate::transport::Transport;
    use async_trait::async_trait;

    struct MockTransport {
        captured_body: Arc<std::sync::Mutex<Option<Bytes>>>,
        captured_headers: Arc<std::sync::Mutex<Option<hyper::HeaderMap>>>,
    }

    impl MockTransport {
        fn new() -> (
            Self,
            Arc<std::sync::Mutex<Option<Bytes>>>,
            Arc<std::sync::Mutex<Option<hyper::HeaderMap>>>,
        ) {
            let captured = Arc::new(std::sync::Mutex::new(None));
            let captured_headers = Arc::new(std::sync::Mutex::new(None));
            (
                MockTransport {
                    captured_body: captured.clone(),
                    captured_headers: captured_headers.clone(),
                },
                captured,
                captured_headers,
            )
        }
    }

    #[async_trait]
    impl Transport for MockTransport {
        async fn forward(&self, req: Request<Full<Bytes>>) -> Result<Response<Full<Bytes>>, TransportError> {
            *self.captured_headers.lock().unwrap() = Some(req.headers().clone());
            let body = req.into_body();
            let collected = http_body_util::BodyExt::collect(body)
                .await
                .expect("collecting in-memory body cannot fail");
            let bytes = collected.to_bytes();
            *self.captured_body.lock().unwrap() = Some(bytes.clone());
            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Full::new(bytes))
                .unwrap())
        }
    }

    fn make_test_handler() -> (
        Handler,
        Arc<std::sync::Mutex<Option<Bytes>>>,
        Arc<std::sync::Mutex<Option<hyper::HeaderMap>>>,
    ) {
        use crate::policy::ContainerConfig;
        let mut policies = std::collections::HashMap::new();
        policies.insert(
            "svc".into(),
            Policy {
                service_name: "svc".into(),
                container_names: None,
                user_id: None,
                group_id: None,
                allowed_image_prefixes: vec!["alpine".into()],
                image_tag_pattern: None,
                image_digest_allowed: false,
                container_config: Some(ContainerConfig {
                    network_mode: Some("bridge".into()),
                    restart_policy: None,
                    security_options: None,
                    user: None,
                    log_driver: None,
                    log_options: None,
                }),
                volumes: None,
                ports: None,
                env_file: None,
                allowed_cli_flags: None,
                flag_rules: None,
                denied_flags: None,
            },
        );
        let manager = Manager::from_map(policies);
        let router = Arc::new(Router::new(manager));
        let chain = Chain::new();
        let audit = AuditLogger::new("/dev/null").unwrap();
        let (mock_transport, captured, captured_headers) = MockTransport::new();
        let handler = Handler::new(router, chain, audit, Box::new(mock_transport));
        (handler, captured, captured_headers)
    }

    #[tokio::test]
    async fn test_handler_forwards_modified_body() {
        let (handler, captured, captured_headers) = make_test_handler();
        let body = serde_json::json!({"Image": "alpine", "Cmd": ["sleep", "100"]});
        let body_bytes = serde_json::to_vec(&body).unwrap();

        let req = Request::post("http://localhost/containers/create")
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(body_bytes)))
            .unwrap();

        let resp = handler.handle(req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let captured = captured.lock().unwrap();
        let captured_body: serde_json::Value = serde_json::from_slice(captured.as_ref().unwrap()).unwrap();
        assert!(captured_body.get("HostConfig").is_some());
        let hc = captured_body.get("HostConfig").unwrap();
        assert_eq!(hc.get("Privileged"), Some(&serde_json::Value::Bool(false)));

        let headers = captured_headers.lock().unwrap();
        let cl = headers
            .as_ref()
            .unwrap()
            .get(hyper::header::CONTENT_LENGTH)
            .expect("content-length header must be present");
        assert_eq!(
            cl.to_str().unwrap().parse::<usize>().unwrap(),
            captured.as_ref().unwrap().len(),
            "content-length must match the modified body length"
        );
    }

    #[derive(Copy, Clone)]
    enum FailureKind {
        SocketPermission,
        Other,
    }

    struct FailingTransport {
        kind: FailureKind,
    }

    #[async_trait]
    impl Transport for FailingTransport {
        async fn forward(&self, _req: Request<Full<Bytes>>) -> Result<Response<Full<Bytes>>, TransportError> {
            match self.kind {
                FailureKind::SocketPermission => Err(TransportError::SocketPermission(std::io::Error::from(
                    std::io::ErrorKind::PermissionDenied,
                ))),
                FailureKind::Other => Err(TransportError::Other(Box::<dyn std::error::Error + Send + Sync>::from(
                    "connection refused",
                ))),
            }
        }
    }

    fn make_forward_failing_handler(kind: FailureKind) -> Handler {
        use crate::policy::ContainerConfig;
        let mut policies = std::collections::HashMap::new();
        policies.insert(
            "svc".into(),
            Policy {
                service_name: "svc".into(),
                container_names: None,
                user_id: None,
                group_id: None,
                allowed_image_prefixes: vec!["alpine".into()],
                image_tag_pattern: None,
                image_digest_allowed: false,
                container_config: Some(ContainerConfig {
                    network_mode: Some("bridge".into()),
                    restart_policy: None,
                    security_options: None,
                    user: None,
                    log_driver: None,
                    log_options: None,
                }),
                volumes: None,
                ports: None,
                env_file: None,
                allowed_cli_flags: None,
                flag_rules: None,
                denied_flags: None,
            },
        );
        let manager = Manager::from_map(policies);
        let router = Arc::new(Router::new(manager));
        let chain = Chain::new();
        let audit = AuditLogger::new("/dev/null").unwrap();
        let transport = FailingTransport { kind };
        Handler::new(router, chain, audit, Box::new(transport))
    }

    #[tokio::test]
    async fn test_handler_socket_permission_returns_403() {
        let handler = make_forward_failing_handler(FailureKind::SocketPermission);
        let req = Request::get("http://localhost/_ping")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp = handler.handle(req).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_handler_forward_error_returns_502() {
        let handler = make_forward_failing_handler(FailureKind::Other);
        let req = Request::get("http://localhost/_ping")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp = handler.handle(req).await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    fn make_deny_handler() -> (Handler, Arc<std::sync::Mutex<Option<Bytes>>>) {
        use crate::policy::ContainerConfig;
        let mut policies = std::collections::HashMap::new();
        policies.insert(
            "svc".into(),
            Policy {
                service_name: "svc".into(),
                container_names: None,
                user_id: None,
                group_id: None,
                allowed_image_prefixes: vec!["alpine".into()],
                image_tag_pattern: None,
                image_digest_allowed: false,
                container_config: Some(ContainerConfig {
                    network_mode: Some("bridge".into()),
                    restart_policy: None,
                    security_options: None,
                    user: None,
                    log_driver: None,
                    log_options: None,
                }),
                volumes: None,
                ports: None,
                env_file: None,
                allowed_cli_flags: Some(vec!["--cap-drop".into()]),
                flag_rules: None,
                denied_flags: None,
            },
        );
        let manager = Manager::from_map(policies);
        let router = Arc::new(Router::new(manager));
        let chain = Chain::new();
        let audit = AuditLogger::new("/dev/null").unwrap();
        let (mock_transport, captured, _captured_headers) = MockTransport::new();
        let handler = Handler::new(router, chain, audit, Box::new(mock_transport));
        (handler, captured)
    }

    #[tokio::test]
    async fn test_handler_denies_by_middleware() {
        let (handler, _captured) = make_deny_handler();
        let body = serde_json::json!({"Image": "alpine", "Cmd": ["--privileged"]});
        let body_bytes = serde_json::to_vec(&body).unwrap();

        let req = Request::post("http://localhost/containers/create")
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(body_bytes)))
            .unwrap();

        let resp = handler.handle(req).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    struct UriRecordingTransport {
        captured_uri: Arc<std::sync::Mutex<Option<hyper::Uri>>>,
    }

    #[async_trait]
    impl Transport for UriRecordingTransport {
        async fn forward(&self, req: Request<Full<Bytes>>) -> Result<Response<Full<Bytes>>, TransportError> {
            *self.captured_uri.lock().unwrap() = Some(req.uri().clone());
            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Full::new(Bytes::new()))
                .unwrap())
        }
    }

    fn make_uri_recording_handler() -> (Handler, Arc<std::sync::Mutex<Option<hyper::Uri>>>) {
        let manager = Manager::from_map(std::collections::HashMap::new());
        let router = Arc::new(Router::new(manager));
        let chain = Chain::new();
        let audit = AuditLogger::new("/dev/null").unwrap();
        let captured_uri = Arc::new(std::sync::Mutex::new(None));
        let transport = UriRecordingTransport {
            captured_uri: captured_uri.clone(),
        };
        (Handler::new(router, chain, audit, Box::new(transport)), captured_uri)
    }

    /// #75: --readonly is enforced in the router, so a delete never reaches
    /// the daemon. Before #75 the flag only reached the chain, which runs on
    /// create.
    #[tokio::test]
    async fn test_handler_readonly_denies_delete() {
        let manager = Manager::from_map(std::collections::HashMap::new());
        let router = Arc::new(Router::new(manager).with_readonly(true));
        let audit = AuditLogger::new("/dev/null").unwrap();
        let captured_uri = Arc::new(std::sync::Mutex::new(None));
        let transport = UriRecordingTransport {
            captured_uri: captured_uri.clone(),
        };
        let handler = Handler::new(router, Chain::new(), audit, Box::new(transport));
        let req = Request::delete("http://localhost/containers/mycontainer")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp = handler.handle(req).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            String::from_utf8_lossy(&body),
            "read-only mode: DELETE requests are not allowed"
        );
        assert!(captured_uri.lock().unwrap().is_none(), "expected no forward");
    }

    /// #53: Rust routed on the raw name and forwarded it; the daemon decodes
    /// it to "foo bar" and acts on that container.
    #[tokio::test]
    async fn test_handler_denies_percent_encoded_name() {
        let (handler, captured_uri) = make_uri_recording_handler();
        let req = Request::delete("http://localhost/containers/foo%20bar")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp = handler.handle(req).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8_lossy(&body);
        assert!(body.contains("percent-encoded"), "deny reason = {:?}", body);
        assert!(captured_uri.lock().unwrap().is_none(), "expected no forward");
    }

    /// #53: the daemon reads %2F as a request about "/".
    #[tokio::test]
    async fn test_handler_denies_percent_encoded_slash() {
        let (handler, captured_uri) = make_uri_recording_handler();
        let req = Request::delete("http://localhost/containers/%2F")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp = handler.handle(req).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8_lossy(&body);
        assert!(body.contains("percent-encoded"), "deny reason = {:?}", body);
        assert!(captured_uri.lock().unwrap().is_none(), "expected no forward");
    }

    /// #53: the rule looks at the path only; an encoded query string is
    /// routine (docker ps --filter) and must reach the daemon unchanged.
    #[tokio::test]
    async fn test_handler_forwards_percent_encoded_query() {
        let (handler, captured_uri) = make_uri_recording_handler();
        let query = "filters=%7B%22status%22%3A%5B%22running%22%5D%7D";
        let req = Request::get(format!("http://localhost/containers/json?{}", query))
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp = handler.handle(req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let captured = captured_uri.lock().unwrap();
        let uri = captured.as_ref().expect("expected request to be forwarded");
        assert_eq!(uri.query(), Some(query));
    }

    /// #83: a pull with a body is never forwarded. The daemon reads a form
    /// body's fromImage over the query's, so an allowed image in the query
    /// and another in the body would pull the body's. Any body is denied,
    /// whatever its Content-Type.
    #[tokio::test]
    async fn test_handler_pull_denies_body() {
        let cases = [
            ("application/x-www-form-urlencoded", "fromImage=busybox&tag=latest"),
            ("application/json", r#"{"fromImage":"alpine"}"#),
            ("text/plain", "x"),
        ];
        for (content_type, body) in cases {
            let policy: crate::policy::Policy =
                serde_yaml::from_str("service_name: probe\nallowed_image_prefixes:\n  - alpine\n").unwrap();
            let mut policies = std::collections::HashMap::new();
            policies.insert("probe".to_string(), policy);
            let router = Arc::new(Router::new(Manager::from_map(policies)));
            let captured_uri = Arc::new(std::sync::Mutex::new(None));
            let transport = UriRecordingTransport {
                captured_uri: captured_uri.clone(),
            };
            let audit = AuditLogger::new("/dev/null").unwrap();
            let handler = Handler::new(router, Chain::new(), audit, Box::new(transport));
            let req = Request::post("http://localhost/v1.56/images/create?fromImage=alpine&tag=3.19")
                .header("content-type", content_type)
                .body(Full::new(Bytes::from(body)))
                .unwrap();
            let resp = handler.handle(req).await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{}", content_type);
            let got = resp.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(
                String::from_utf8_lossy(&got),
                "image pull must not have a request body",
                "{}",
                content_type
            );
            assert!(
                captured_uri.lock().unwrap().is_none(),
                "{}: expected no forward",
                content_type
            );
        }
    }

    /// #55: the audit uri is the raw request target, query and escapes
    /// included, for allowed and denied requests alike.
    #[tokio::test]
    async fn test_handler_audit_uri_is_request_target() {
        let log_path = std::env::temp_dir().join(format!(
            "handler-audit-uri-{}-{}.log",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&log_path);
        let manager = Manager::from_map(std::collections::HashMap::new());
        let router = Arc::new(Router::new(manager));
        let audit = AuditLogger::new(log_path.to_str().unwrap()).unwrap();
        let captured_uri = Arc::new(std::sync::Mutex::new(None));
        let transport = UriRecordingTransport { captured_uri };
        let handler = Handler::new(router, Chain::new(), audit, Box::new(transport));

        let targets = [
            ("GET", "/containers/json?all=1", "ALLOW"),
            ("DELETE", "/containers/a%2Fb?force=1", "DENY"),
        ];
        for (method, target, _) in targets {
            let req = Request::builder()
                .method(method)
                .uri(format!("http://localhost{}", target))
                .body(Full::new(Bytes::new()))
                .unwrap();
            handler.handle(req).await;
        }

        let contents = std::fs::read_to_string(&log_path).unwrap();
        let _ = std::fs::remove_file(&log_path);
        let entries: Vec<serde_json::Value> = contents.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(entries.len(), targets.len(), "audit log:\n{}", contents);
        let mut mismatches = Vec::new();
        for ((method, target, decision), entry) in targets.iter().zip(&entries) {
            if entry["decision"] != *decision || entry["uri"] != *target {
                mismatches.push(format!(
                    "{} {}: got {}/{}, want {:?}/{:?}",
                    method, target, entry["decision"], entry["uri"], decision, target
                ));
            }
        }
        assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
    }

    /// #76: any protocol upgrade is refused before the body is read and
    /// before routing, so the transport never sees it. Before #76 a websocket
    /// attach went through the GET passthrough to the daemon.
    #[tokio::test]
    async fn test_handler_refuses_protocol_upgrade() {
        let log_path = std::env::temp_dir().join(format!(
            "handler-upgrade-{}-{}.log",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&log_path);
        let manager = Manager::from_map(std::collections::HashMap::new());
        let router = Arc::new(Router::new(manager));
        let audit = AuditLogger::new(log_path.to_str().unwrap()).unwrap();
        let captured_uri = Arc::new(std::sync::Mutex::new(None));
        let transport = UriRecordingTransport {
            captured_uri: captured_uri.clone(),
        };
        let handler = Handler::new(router, Chain::new(), audit, Box::new(transport));
        let refused = "protocol upgrade not allowed";

        let cases: [(&str, &str, &[(&str, &str)]); 3] = [
            (
                "websocket",
                "/containers/json",
                &[("Upgrade", "websocket"), ("Connection", "Upgrade")],
            ),
            (
                "connection token only",
                "/_ping",
                &[("Connection", "keep-alive, Upgrade")],
            ),
            ("upgrade header only", "/_ping", &[("Upgrade", "h2c")]),
        ];
        let mut mismatches = Vec::new();
        for (name, target, headers) in cases {
            let mut req = Request::get(format!("http://localhost{}", target));
            for (k, v) in headers {
                req = req.header(*k, *v);
            }
            let resp = handler.handle(req.body(Full::new(Bytes::new())).unwrap()).await;
            let status = resp.status();
            let body = resp.into_body().collect().await.unwrap().to_bytes();
            if status != StatusCode::FORBIDDEN || body != refused {
                mismatches.push(format!("{}: got {} {:?}", name, status, String::from_utf8_lossy(&body)));
            }
            if captured_uri.lock().unwrap().take().is_some() {
                mismatches.push(format!("{}: forwarded", name));
            }
        }

        let req = Request::get("http://localhost/containers/json")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp = handler.handle(req).await;
        if resp.status() != StatusCode::OK || captured_uri.lock().unwrap().is_none() {
            mismatches.push("plain GET /containers/json: not forwarded".to_string());
        }

        let contents = std::fs::read_to_string(&log_path).unwrap();
        let _ = std::fs::remove_file(&log_path);
        let first: serde_json::Value = serde_json::from_str(contents.lines().next().unwrap()).unwrap();
        if first["method"] != "GET"
            || first["uri"] != "/containers/json"
            || first["decision"] != "DENY"
            || first["reason"] != refused
        {
            mismatches.push(format!("audit entry: {}", first));
        }
        assert!(mismatches.is_empty(), "mismatches:\n{}", mismatches.join("\n"));
    }

    /// #78: CONNECT is refused before the upgrade check and before routing,
    /// so the transport never sees it, in origin form and in authority form.
    /// Before #78 CONNECT /_ping matched the early read-endpoint allow and
    /// was forwarded.
    #[tokio::test]
    async fn test_handler_refuses_connect() {
        let log_path = std::env::temp_dir().join(format!(
            "handler-connect-{}-{}.log",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&log_path);
        let manager = Manager::from_map(std::collections::HashMap::new());
        let router = Arc::new(Router::new(manager));
        let audit = AuditLogger::new(log_path.to_str().unwrap()).unwrap();
        let captured_uri = Arc::new(std::sync::Mutex::new(None));
        let transport = UriRecordingTransport {
            captured_uri: captured_uri.clone(),
        };
        let handler = Handler::new(router, Chain::new(), audit, Box::new(transport));
        let refused = "CONNECT is not allowed";

        let cases: [(&str, &str, &[(&str, &str)]); 3] = [
            ("origin form", "/_ping", &[]),
            ("authority form", "localhost:80", &[]),
            (
                "with Upgrade",
                "/_ping",
                &[("Upgrade", "websocket"), ("Connection", "Upgrade")],
            ),
        ];
        let mut mismatches = Vec::new();
        for (name, target, headers) in cases {
            let mut req = Request::builder().method("CONNECT").uri(target);
            for (k, v) in headers {
                req = req.header(*k, *v);
            }
            let resp = handler.handle(req.body(Full::new(Bytes::new())).unwrap()).await;
            let status = resp.status();
            let body = resp.into_body().collect().await.unwrap().to_bytes();
            if status != StatusCode::FORBIDDEN || body != refused {
                mismatches.push(format!("{}: got {} {:?}", name, status, String::from_utf8_lossy(&body)));
            }
            if captured_uri.lock().unwrap().take().is_some() {
                mismatches.push(format!("{}: forwarded", name));
            }
        }

        let contents = std::fs::read_to_string(&log_path).unwrap();
        let _ = std::fs::remove_file(&log_path);
        let lines: Vec<&str> = contents.lines().collect();
        for (i, want_uri) in ["/_ping", "localhost:80", "/_ping"].iter().enumerate() {
            let Some(line) = lines.get(i) else {
                mismatches.push(format!("audit entry missing for {}", want_uri));
                continue;
            };
            let entry: serde_json::Value = serde_json::from_str(line).unwrap();
            if entry["method"] != "CONNECT"
                || entry["uri"] != *want_uri
                || entry["decision"] != "DENY"
                || entry["reason"] != refused
            {
                mismatches.push(format!("audit entry: {}", entry));
            }
        }
        assert!(mismatches.is_empty(), "mismatches:\n{}", mismatches.join("\n"));
    }

    /// #83: the handler hands the query to the router. A pull sent the Docker
    /// CLI way, empty body and image in the query, is forwarded with its
    /// query unchanged, and a disallowed one is not forwarded.
    #[tokio::test]
    async fn test_handler_pull_routes_on_query() {
        let make = || {
            let policy: crate::policy::Policy =
                serde_yaml::from_str("service_name: probe\nallowed_image_prefixes:\n  - alpine\n").unwrap();
            let mut policies = std::collections::HashMap::new();
            policies.insert("probe".to_string(), policy);
            let router = Arc::new(Router::new(Manager::from_map(policies)));
            let captured_uri = Arc::new(std::sync::Mutex::new(None));
            let transport = UriRecordingTransport {
                captured_uri: captured_uri.clone(),
            };
            let audit = AuditLogger::new("/dev/null").unwrap();
            (
                Handler::new(router, Chain::new(), audit, Box::new(transport)),
                captured_uri,
            )
        };

        let (handler, captured_uri) = make();
        let query = "fromImage=docker.io%2Flibrary%2Falpine&tag=3.19";
        let req = Request::post(format!("http://localhost/v1.56/images/create?{}", query))
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp = handler.handle(req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let captured = captured_uri.lock().unwrap();
        let uri = captured.as_ref().expect("expected the allowed pull to be forwarded");
        assert_eq!(uri.query(), Some(query));

        let (handler, captured_uri) = make();
        let req = Request::post("http://localhost/v1.56/images/create?fromImage=busybox&tag=latest")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp = handler.handle(req).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            String::from_utf8_lossy(&body),
            "image busybox not allowed by any policy"
        );
        assert!(captured_uri.lock().unwrap().is_none(), "expected no forward");
    }

    const BEACON_ID: &str = "4f6e1d2c9a7b8c3d4e5f60718293a4b5c6d7e8f9012345678901234567890abc";
    const MONITORING_ID: &str = "9d8c7b6a5f4e3d2c1b0a99887766554433221100ffeeddccbbaa998877665544";

    /// Answers GET /containers/{id}/json from a table of id -> container
    /// name, as the daemon does, and records every request.
    struct DaemonTransport {
        names: HashMap<String, String>,
        status: Option<StatusCode>,
        requests: Arc<std::sync::Mutex<Vec<String>>>,
        last_body: Arc<std::sync::Mutex<Option<Bytes>>>,
    }

    #[async_trait]
    impl Transport for DaemonTransport {
        async fn forward(&self, req: Request<Full<Bytes>>) -> Result<Response<Full<Bytes>>, TransportError> {
            let path = req.uri().path().to_string();
            self.requests.lock().unwrap().push(format!("{} {}", req.method(), path));
            if req.method() == Method::GET && path.starts_with("/containers/") && path.ends_with("/json") {
                if let Some(status) = self.status {
                    return Ok(Response::builder()
                        .status(status)
                        .body(Full::new(Bytes::from("boom")))
                        .unwrap());
                }
                let id = &path["/containers/".len()..path.len() - "/json".len()];
                return Ok(match self.names.get(id) {
                    Some(name) => Response::builder()
                        .status(StatusCode::OK)
                        .body(Full::new(Bytes::from(
                            serde_json::json!({"Id": "4f6e1d2c9a7b", "Name": format!("/{name}")}).to_string(),
                        )))
                        .unwrap(),
                    None => Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(Full::new(Bytes::from("no such container")))
                        .unwrap(),
                });
            }
            let body = req.into_body().collect().await.unwrap().to_bytes();
            *self.last_body.lock().unwrap() = Some(body);
            Ok(Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(Full::new(Bytes::new()))
                .unwrap())
        }
    }

    struct DaemonHandle {
        requests: Arc<std::sync::Mutex<Vec<String>>>,
        last_body: Arc<std::sync::Mutex<Option<Bytes>>>,
        log_path: std::path::PathBuf,
    }

    fn make_daemon_handler(files: &[(&str, &str)], status: Option<StatusCode>) -> (Handler, DaemonHandle) {
        let names: HashMap<String, String> = [
            ("beacon", "beacon"),
            (BEACON_ID, "beacon"),
            (&BEACON_ID[..12], "beacon"),
            ("dsp-monitoring", "dsp-monitoring"),
            (MONITORING_ID, "dsp-monitoring"),
            (&MONITORING_ID[..12], "dsp-monitoring"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
        let last_body = Arc::new(std::sync::Mutex::new(None));
        let transport = DaemonTransport {
            names,
            status,
            requests: requests.clone(),
            last_body: last_body.clone(),
        };
        let log_path = std::env::temp_dir().join(format!(
            "handler-coverage-{}-{}.log",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let manager = crate::policy::tests::load_dir(files).unwrap();
        let audit = AuditLogger::new(log_path.to_str().unwrap()).unwrap();
        let handler = Handler::new(Arc::new(Router::new(manager)), Chain::new(), audit, Box::new(transport));
        (
            handler,
            DaemonHandle {
                requests,
                last_body,
                log_path,
            },
        )
    }

    const BEACON_ONLY: [(&str, &str); 1] = [(
        "beacon.yaml",
        "service_name: beacon\nallowed_image_prefixes:\n  - chainsafe/lodestar\n",
    )];

    async fn send(handler: &Handler, method: &str, target: &str, body: &str) -> (StatusCode, String) {
        let req = Request::builder()
            .method(method)
            .uri(format!("http://localhost{target}"))
            .body(Full::new(Bytes::from(body.to_string())))
            .unwrap();
        let resp = handler.handle(req).await;
        let status = resp.status();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    /// The handler half of #86: a lifecycle action or DELETE is forwarded
    /// only if its target is a container a policy covers. A name, full ID or
    /// short ID is resolved with GET /containers/{id}/json. Before #86 every
    /// row was forwarded.
    #[tokio::test]
    async fn test_handler_lifecycle_coverage() {
        let not_managed = |id: &str| format!("container {id} is not managed by any policy");
        let inspect = |id: &str| vec![format!("GET /containers/{id}/json")];
        let beacon_short = &BEACON_ID[..12];
        let mon_short = &MONITORING_ID[..12];
        let cases: Vec<(&str, &str, String, StatusCode, String, Vec<String>)> = vec![
            (
                "covered name",
                "POST",
                "/v1.45/containers/beacon/stop?t=1".into(),
                StatusCode::NO_CONTENT,
                String::new(),
                vec![],
            ),
            (
                "covered full ID",
                "POST",
                format!("/containers/{BEACON_ID}/kill"),
                StatusCode::NO_CONTENT,
                String::new(),
                inspect(BEACON_ID),
            ),
            (
                "covered short ID",
                "DELETE",
                format!("/containers/{beacon_short}?force=1"),
                StatusCode::NO_CONTENT,
                String::new(),
                inspect(beacon_short),
            ),
            // uncoveredNameStopDeniedTest: an operator container.
            (
                "uncovered name",
                "POST",
                "/containers/dsp-monitoring/stop".into(),
                StatusCode::FORBIDDEN,
                not_managed("dsp-monitoring"),
                inspect("dsp-monitoring"),
            ),
            (
                "uncovered full ID",
                "POST",
                format!("/containers/{MONITORING_ID}/kill"),
                StatusCode::FORBIDDEN,
                not_managed(MONITORING_ID),
                inspect(MONITORING_ID),
            ),
            (
                "uncovered short ID",
                "DELETE",
                format!("/containers/{mon_short}"),
                StatusCode::FORBIDDEN,
                not_managed(mon_short),
                inspect(mon_short),
            ),
            // realNameDeleteDeniedTest: the daemon answers 404.
            (
                "unknown name",
                "DELETE",
                "/containers/mycontainer".into(),
                StatusCode::FORBIDDEN,
                not_managed("mycontainer"),
                inspect("mycontainer"),
            ),
            // execPrefixNameStartDeniedTest
            (
                "unknown exec-prefixed name",
                "POST",
                "/containers/exec-runner/start".into(),
                StatusCode::FORBIDDEN,
                not_managed("exec-runner"),
                inspect("exec-runner"),
            ),
        ];
        let mut mismatches = Vec::new();
        for (name, method, target, status, body, inspects) in cases {
            let (handler, d) = make_daemon_handler(&BEACON_ONLY, None);
            let (got_status, got_body) = send(&handler, method, &target, "").await;
            let _ = std::fs::remove_file(&d.log_path);
            if got_status != status || (!body.is_empty() && got_body != body) {
                mismatches.push(format!("{name}: got {got_status} {got_body:?}, want {status} {body:?}"));
            }
            let mut want = inspects;
            if status != StatusCode::FORBIDDEN {
                want.push(format!("{method} {}", target.split('?').next().unwrap()));
            }
            let seen = d.requests.lock().unwrap().clone();
            if seen != want {
                mismatches.push(format!("{name}: daemon saw {seen:?}, want {want:?}"));
            }
        }
        assert!(mismatches.is_empty(), "mismatches:\n{}", mismatches.join("\n"));
    }

    /// A daemon error other than 404 fails closed with its own message (#86).
    #[tokio::test]
    async fn test_handler_lifecycle_resolve_fails_closed() {
        let (handler, d) = make_daemon_handler(&BEACON_ONLY, Some(StatusCode::INTERNAL_SERVER_ERROR));
        let short = &BEACON_ID[..12];
        let (status, body) = send(&handler, "POST", &format!("/containers/{short}/stop"), "").await;
        let _ = std::fs::remove_file(&d.log_path);
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, format!("cannot resolve container {short}: daemon returned 500"));
        assert_eq!(d.requests.lock().unwrap().len(), 1, "only the inspect");
    }

    /// The resolved name is audited with the request (#86).
    #[tokio::test]
    async fn test_handler_lifecycle_audits_resolved_name() {
        let (handler, d) = make_daemon_handler(&BEACON_ONLY, None);
        send(&handler, "POST", &format!("/containers/{}/start", &BEACON_ID[..12]), "").await;
        send(
            &handler,
            "POST",
            &format!("/containers/{}/start", &MONITORING_ID[..12]),
            "",
        )
        .await;
        let contents = std::fs::read_to_string(&d.log_path).unwrap();
        let _ = std::fs::remove_file(&d.log_path);
        let lines: Vec<serde_json::Value> = contents.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(lines.len(), 2, "{contents}");
        assert_eq!(lines[0]["decision"], "ALLOW");
        assert_eq!(
            lines[0]["reason"],
            format!("container {} resolved to beacon", &BEACON_ID[..12])
        );
        assert_eq!(lines[1]["decision"], "DENY");
        assert_eq!(
            lines[1]["reason"],
            format!(
                "container {} is not managed by any policy (resolved to dsp-monitoring)",
                &MONITORING_ID[..12]
            )
        );
    }

    /// The #85 reproduction through the handler: two policies for one image
    /// force different users, and each create named for one of them gets
    /// that policy's user, every time.
    #[tokio::test]
    async fn test_handler_create_selects_by_name() {
        let files = [
            (
                "a.yaml",
                "service_name: svc-a\ncontainer_names: [svc-a]\nallowed_image_prefixes: [alpine]\ncontainer_config: { user: \"1111:1111\" }\n",
            ),
            (
                "b.yaml",
                "service_name: svc-b\ncontainer_names: [svc-b]\nallowed_image_prefixes: [alpine]\ncontainer_config: { user: \"2222:2222\" }\n",
            ),
        ];
        let (handler, d) = make_daemon_handler(&files, None);
        let body = r#"{"Image":"alpine:3.20","Cmd":["true"]}"#;
        for i in 0..50 {
            for (name, user) in [("svc-a", "1111:1111"), ("svc-b", "2222:2222")] {
                *d.last_body.lock().unwrap() = None;
                let (status, msg) =
                    send(&handler, "POST", &format!("/v1.45/containers/create?name={name}"), body).await;
                assert_eq!(status, StatusCode::NO_CONTENT, "iteration {i} {name}: {msg}");
                let fwd: serde_json::Value =
                    serde_json::from_slice(d.last_body.lock().unwrap().as_ref().unwrap()).unwrap();
                assert_eq!(fwd["User"], user, "iteration {i}: create ?name={name}");
            }
        }
        let (status, msg) = send(&handler, "POST", "/containers/create", r#"{"Image":"alpine:3.20"}"#).await;
        let _ = std::fs::remove_file(&d.log_path);
        assert_eq!(
            (status, msg.as_str()),
            (StatusCode::FORBIDDEN, "image alpine:3.20 requires a container name")
        );
    }
}
