use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::Full;
use hyper::client::conn::http1;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use std::io;

/// A forwarding failure. `SocketPermission` is a distinct variant so the
/// gateway can surface group-restricted socket denial as 403 Forbidden,
/// mirroring middleware policy denials (the socket is the security boundary).
#[derive(Debug)]
pub enum TransportError {
    SocketPermission(io::Error),
    Other(Box<dyn std::error::Error + Send + Sync>),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::SocketPermission(e) => write!(f, "permission denied on Docker socket: {e}"),
            TransportError::Other(e) => write!(f, "proxy error: {e}"),
        }
    }
}

impl std::error::Error for TransportError {}

#[async_trait]
pub trait Transport: Send + Sync {
    async fn forward(
        &self,
        req: Request<Full<Bytes>>,
    ) -> Result<Response<Full<Bytes>>, TransportError>;
}

pub struct UnixSocketTransport {
    docker_host: String,
}

impl UnixSocketTransport {
    pub fn new(docker_host: &str) -> Self {
        UnixSocketTransport {
            docker_host: docker_host.to_string(),
        }
    }
}

fn map_connect_error(e: io::Error) -> TransportError {
    match e.kind() {
        io::ErrorKind::PermissionDenied => TransportError::SocketPermission(e),
        _ => TransportError::Other(Box::new(e)),
    }
}

#[async_trait]
impl Transport for UnixSocketTransport {
    async fn forward(
        &self,
        req: Request<Full<Bytes>>,
    ) -> Result<Response<Full<Bytes>>, TransportError> {
        let stream = match tokio::net::UnixStream::connect(&self.docker_host).await {
            Ok(s) => s,
            Err(e) => return Err(map_connect_error(e)),
        };
        let io = TokioIo::new(stream);

        let (mut sender, conn) = http1::Builder::new()
            .handshake::<_, Full<Bytes>>(io)
            .await
            .map_err(|e| TransportError::Other(Box::new(e)))?;

        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::warn!("docker connection error: {}", e);
            }
        });

        let resp = sender
            .send_request(req)
            .await
            .map_err(|e| TransportError::Other(Box::new(e)))?;

        let (parts, body) = resp.into_parts();
        let collected = http_body_util::BodyExt::collect(body)
            .await
            .map_err(|e| TransportError::Other(Box::new(e)))?;
        let bytes = collected.to_bytes();

        Ok(Response::from_parts(parts, Full::new(bytes)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_forward_missing_socket_errors() {
        let transport = UnixSocketTransport::new("/nonexistent/docker.sock");
        let req = Request::builder()
            .uri("/_ping")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let res = transport.forward(req).await;
        assert!(res.is_err(), "expected forwarding to a missing socket to fail");
        assert!(!matches!(res, Err(TransportError::SocketPermission(_))));
    }

    #[test]
    fn test_map_connect_error_kinds() {
        let perm = io::Error::from(io::ErrorKind::PermissionDenied);
        assert!(matches!(map_connect_error(perm), TransportError::SocketPermission(_)));

        let not_found = io::Error::from(io::ErrorKind::NotFound);
        assert!(matches!(map_connect_error(not_found), TransportError::Other(_)));

        let conn_refused = io::Error::from(io::ErrorKind::ConnectionRefused);
        assert!(matches!(map_connect_error(conn_refused), TransportError::Other(_)));
    }
}