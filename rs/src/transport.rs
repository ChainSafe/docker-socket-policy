use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::Full;
use hyper::client::conn::http1;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;

#[async_trait]
pub trait Transport: Send + Sync {
    async fn forward(
        &self,
        req: Request<Full<Bytes>>,
    ) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error + Send + Sync>>;
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

#[async_trait]
impl Transport for UnixSocketTransport {
    async fn forward(
        &self,
        req: Request<Full<Bytes>>,
    ) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error + Send + Sync>> {
        let stream = tokio::net::UnixStream::connect(&self.docker_host).await?;
        let io = TokioIo::new(stream);

        let (mut sender, conn) = http1::Builder::new()
            .handshake::<_, Full<Bytes>>(io)
            .await?;

        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::warn!("docker connection error: {}", e);
            }
        });

        let resp = sender.send_request(req).await?;

        let (parts, body) = resp.into_parts();
        let collected = http_body_util::BodyExt::collect(body).await?;
        let bytes = collected.to_bytes();

        Ok(Response::from_parts(parts, Full::new(bytes)))
    }
}
