use crate::audit::AuditLogger;
use crate::middleware::Chain;
use crate::proxy::{Action, Router};
use crate::transport::Transport;
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::{Request, Response, StatusCode};
use http_body_util::Full;
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
        Handler { router, chain, audit, transport }
    }

    pub async fn handle<B>(&self, req: Request<B>) -> Response<Full<Bytes>>
    where
        B: http_body::Body<Data = Bytes> + Send,
    {
        let (parts, body) = req.into_parts();
        let method = parts.method.to_string();
        let path = parts.uri.path().to_string();
        let full_uri = parts.uri.to_string();
        let headers = parts.headers.clone();
        let version = parts.version;

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

        let route = self.router.route(&method, &path, body_json.as_ref());

        if route.action == Action::Deny {
            let msg = route.deny_msg.unwrap_or_default();
            warn!("denied {} {}: {}", method, path, msg);
            self.audit.deny(&method, &path, &msg);
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
                    self.audit.deny(&method, &path, &result.reason);
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
        self.audit.allow(&method, &path);

        let mut forwarded = Request::builder()
            .method(method.as_str())
            .uri(&full_uri)
            .version(version)
            .body(Full::new(body_bytes))
            .unwrap();
        *forwarded.headers_mut() = headers;

        match self.transport.forward(forwarded).await {
            Ok(resp) => resp,
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
    }

    impl MockTransport {
        fn new() -> (Self, Arc<std::sync::Mutex<Option<Bytes>>>) {
            let captured = Arc::new(std::sync::Mutex::new(None));
            (MockTransport { captured_body: captured.clone() }, captured)
        }
    }

    #[async_trait]
    impl Transport for MockTransport {
        async fn forward(
            &self,
            req: Request<Full<Bytes>>,
        ) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error + Send + Sync>> {
            let body = req.into_body();
            let collected = http_body_util::BodyExt::collect(body).await?;
            let bytes = collected.to_bytes();
            *self.captured_body.lock().unwrap() = Some(bytes.clone());
            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Full::new(bytes))
                .unwrap())
        }
    }

    fn make_test_handler() -> (Handler, Arc<std::sync::Mutex<Option<Bytes>>>) {
        use crate::policy::ContainerConfig;
        let mut policies = std::collections::HashMap::new();
        policies.insert(
            "svc".into(),
            Policy {
                service_name: "svc".into(),
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
        let chain = Chain::new(false);
        let audit = AuditLogger::new("/dev/null").unwrap();
        let (mock_transport, captured) = MockTransport::new();
        let handler = Handler::new(router, chain, audit, Box::new(mock_transport));
        (handler, captured)
    }

    #[tokio::test]
    async fn test_handler_forwards_modified_body() {
        let (handler, captured) = make_test_handler();
        let body = serde_json::json!({"Image": "alpine", "Cmd": ["sleep", "100"]});
        let body_bytes = serde_json::to_vec(&body).unwrap();

        let req = Request::post("http://localhost/containers/create")
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(body_bytes)))
            .unwrap();

        let resp = handler.handle(req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let captured = captured.lock().unwrap();
        let captured_body: serde_json::Value =
            serde_json::from_slice(captured.as_ref().unwrap()).unwrap();
        assert!(captured_body.get("HostConfig").is_some());
        let hc = captured_body.get("HostConfig").unwrap();
        assert_eq!(hc.get("Privileged"), Some(&serde_json::Value::Bool(false)));
    }

    fn make_deny_handler() -> (Handler, Arc<std::sync::Mutex<Option<Bytes>>>) {
        use crate::policy::ContainerConfig;
        let mut policies = std::collections::HashMap::new();
        policies.insert(
            "svc".into(),
            Policy {
                service_name: "svc".into(),
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
        let chain = Chain::new(false);
        let audit = AuditLogger::new("/dev/null").unwrap();
        let (mock_transport, captured) = MockTransport::new();
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
}
