// Only the `Cli` struct fields legitimately go unread if a listener is
// disabled by config; broader dead_code cleanup across policy/proxy/
// middleware (pre-existing, unrelated to this fix) is tracked separately.
#![allow(dead_code)]

mod audit;
mod handler;
mod middleware;
mod policy;
mod proxy;
mod transport;

use clap::Parser;
use hyper::body::Incoming as IncomingBody;
use hyper::Request;
use hyper_util::rt::TokioIo;
use std::io;
use std::os::unix::io::{FromRawFd, RawFd};
use std::os::unix::net::UnixListener as StdUnixListener;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tracing_subscriber::EnvFilter;

/// Raw fd systemd passes for the first socket under socket activation
/// (`sd_listen_fds` convention: fds start at 3).
const SYSTEMD_SOCKET_FD: RawFd = 3;

/// Pause after a failed `accept` before retrying, so persistent errors
/// (fd exhaustion, non-listening fd) don't spin the loop at 100% CPU.
const ACCEPT_ERROR_BACKOFF: std::time::Duration = std::time::Duration::from_millis(100);

#[derive(Parser)]
#[command(name = "docker-socket-policy")]
struct Cli {
    #[arg(long, default_value = "/var/run/docker-socket-policy.sock")]
    listen_socket: String,

    #[arg(long, default_value = "127.0.0.1:2375")]
    listen_tcp: String,

    #[arg(long, default_value = "/var/run/docker.sock")]
    docker_host: String,

    #[arg(long, default_value = "/etc/docker-socket-policy/services")]
    config_dir: String,

    #[arg(long, default_value = "/var/log/docker-socket-policy.log")]
    log_file: String,

    #[arg(long, default_value_t = false)]
    readonly: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .init();

    let cli = Cli::parse();

    let policy_manager = policy::Manager::new(&cli.config_dir)?;
    tracing::info!("loaded {} policies", policy_manager.list().len());

    let router = Arc::new(proxy::Router::new(policy_manager));
    let chain = middleware::Chain::new(cli.readonly);
    let audit = match audit::AuditLogger::new(&cli.log_file) {
        Ok(logger) => logger,
        Err(e) => {
            eprintln!("warn: audit logging disabled: {}", e);
            audit::AuditLogger::nop()
        }
    };
    let transport: Box<dyn transport::Transport> = Box::new(transport::UnixSocketTransport::new(&cli.docker_host));
    let handler = Arc::new(handler::Handler::new(router, chain, audit, transport));

    // A broadcast channel lets every listener task shut down independently
    // when a signal arrives, without one listener's loop owning the others.
    // Both receivers are created BEFORE the signal tasks spawn: a broadcast
    // send with zero receivers is silently dropped, so subscribing later
    // would open a window where an early signal is lost.
    let (shutdown_tx, unix_shutdown_rx) = broadcast::channel::<()>(1);
    let tcp_shutdown_rx = shutdown_tx.subscribe();

    {
        let tx = shutdown_tx.clone();
        tokio::spawn(async move {
            tokio::signal::ctrl_c().await.ok();
            tracing::info!("received SIGINT, shutting down");
            let _ = tx.send(());
        });
    }

    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let tx = shutdown_tx.clone();
        tokio::spawn(async move {
            sigterm.recv().await;
            tracing::info!("received SIGTERM, shutting down");
            let _ = tx.send(());
        });
    }

    let unix_handle = spawn_unix_listener(handler.clone(), cli.listen_socket.clone(), unix_shutdown_rx);
    let tcp_handle = spawn_tcp_listener(handler.clone(), cli.listen_tcp.clone(), tcp_shutdown_rx);

    let _ = tokio::join!(unix_handle, tcp_handle);
    tracing::info!("shutdown complete");

    Ok(())
}

/// Binds the Unix socket listener for `--listen-socket`.
///
/// `fd://3` selects systemd socket activation (the socket is already bound
/// and listening; we just adopt the fd). Any other value is treated as a
/// filesystem path: a stale socket file left over from a previous run is
/// removed before binding, matching the Go implementation.
fn bind_unix_listener(addr: &str) -> io::Result<tokio::net::UnixListener> {
    if addr == "fd://3" {
        return unix_listener_from_raw_fd(SYSTEMD_SOCKET_FD);
    }

    if let Err(e) = std::fs::remove_file(addr) {
        if e.kind() != io::ErrorKind::NotFound {
            return Err(e);
        }
    }
    tokio::net::UnixListener::bind(addr)
}

/// Wraps an existing raw fd as a Tokio `UnixListener`.
///
/// Split out from [`bind_unix_listener`] so the fd-adoption mechanics
/// (set non-blocking, hand to Tokio) can be exercised in tests against an
/// arbitrary fd, instead of only against the real systemd fd 3.
fn unix_listener_from_raw_fd(fd: RawFd) -> io::Result<tokio::net::UnixListener> {
    // SAFETY: `from_raw_fd` requires that we take exclusive ownership of the
    // fd, which we do — nothing else in this process uses fd 3. The fd itself
    // comes from user input (`--listen-socket=fd://3`) and may not actually
    // be a listening AF_UNIX socket; that is not a soundness issue, as misuse
    // surfaces as an `io::Error` from the syscalls below (or from `accept`),
    // never as undefined behavior.
    let std_listener = unsafe { StdUnixListener::from_raw_fd(fd) };
    std_listener.set_nonblocking(true)?;
    tokio::net::UnixListener::from_std(std_listener)
}

fn spawn_unix_listener(
    handler: Arc<handler::Handler>,
    addr: String,
    mut shutdown_rx: broadcast::Receiver<()>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let listener = match bind_unix_listener(&addr) {
            Ok(l) => l,
            Err(e) => {
                tracing::error!("failed to bind unix socket {}: {}", addr, e);
                return;
            }
        };
        tracing::info!("listening on unix socket {}", addr);

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, _)) => {
                            tokio::spawn(serve_connection(handler.clone(), stream));
                        }
                        Err(e) => {
                            // Back off briefly: persistent accept errors
                            // (e.g. EMFILE, or a bad fd under socket
                            // activation) would otherwise busy-loop.
                            tracing::warn!("accept error on unix socket: {}", e);
                            tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    tracing::info!("unix socket listener shutting down");
                    break;
                }
            }
        }
    })
}

fn spawn_tcp_listener(
    handler: Arc<handler::Handler>,
    addr: String,
    mut shutdown_rx: broadcast::Receiver<()>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let socket_addr: std::net::SocketAddr = match addr.parse() {
            Ok(a) => a,
            Err(e) => {
                tracing::error!("invalid TCP listen address {}: {}", addr, e);
                return;
            }
        };
        let listener = match tokio::net::TcpListener::bind(socket_addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!("failed to bind TCP {}: {}", socket_addr, e);
                return;
            }
        };
        tracing::info!("listening on TCP {}", socket_addr);

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, _)) => {
                            tokio::spawn(serve_connection(handler.clone(), stream));
                        }
                        Err(e) => {
                            // Back off briefly: persistent accept errors
                            // (e.g. EMFILE) would otherwise busy-loop.
                            tracing::warn!("accept error on TCP socket: {}", e);
                            tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    tracing::info!("TCP listener shutting down");
                    break;
                }
            }
        }
    })
}

async fn serve_connection<S>(handler: Arc<handler::Handler>, stream: S)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(stream);
    let svc = hyper::service::service_fn(move |req: Request<IncomingBody>| {
        let h = handler.clone();
        async move { Ok::<_, hyper::Error>(h.handle(req).await) }
    });

    if let Err(e) = hyper::server::conn::http1::Builder::new()
        .serve_connection(io, svc)
        .await
    {
        tracing::warn!("connection error: {}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::io::IntoRawFd;

    fn unique_socket_path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("dsp-test-{}.sock", rand::random::<u64>()))
    }

    #[tokio::test]
    async fn test_bind_unix_listener_removes_stale_socket_file() {
        let path = unique_socket_path();
        // Simulate a stale socket file left behind by a previous run.
        std::fs::write(&path, b"stale").unwrap();

        let result = bind_unix_listener(path.to_str().unwrap());
        assert!(
            result.is_ok(),
            "expected stale socket file to be removed and bind to succeed: {:?}",
            result.err()
        );

        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn test_bind_unix_listener_binds_fresh_path() {
        let path = unique_socket_path();

        let result = bind_unix_listener(path.to_str().unwrap());
        assert!(result.is_ok(), "expected bind to a fresh path to succeed: {:?}", result.err());
        assert!(path.exists(), "expected socket file to be created");

        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn test_unix_listener_from_raw_fd_wraps_existing_socket() {
        let path = unique_socket_path();
        let std_listener = StdUnixListener::bind(&path).unwrap();
        let fd = std_listener.into_raw_fd();

        let result = unix_listener_from_raw_fd(fd);
        assert!(result.is_ok(), "expected wrapping an existing listening fd to succeed: {:?}", result.err());

        std::fs::remove_file(&path).ok();
    }
}
