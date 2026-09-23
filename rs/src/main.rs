// Broader dead_code cleanup across policy/proxy/middleware (pre-existing,
// unrelated to this change) is tracked separately.
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
use std::os::unix::fs::FileTypeExt;
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

    if let Err(msg) = validate_listen_socket(&cli.listen_socket) {
        tracing::error!("{}", msg);
        std::process::exit(2);
    }
    if let Err(msg) = validate_docker_host(&cli.docker_host) {
        tracing::error!("{}", msg);
        std::process::exit(2);
    }

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

    // A broadcast channel lets the listener task shut down independently when a
    // signal arrives, without the signal handlers owning the listener's loop.
    // The receiver is created BEFORE the signal tasks spawn: a broadcast send
    // with zero receivers is silently dropped, so subscribing later would open
    // a window where an early signal is lost.
    let (shutdown_tx, unix_shutdown_rx) = broadcast::channel::<()>(1);

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

    // Bind before spawning so a bind failure is fatal: the Unix socket is the
    // process's only listener, so a running-but-unbound proxy is never useful.
    let listener = bind_unix_listener(&cli.listen_socket).map_err(|e| {
        tracing::error!("failed to bind unix socket {}: {}", cli.listen_socket, e);
        e
    })?;
    let unix_handle = spawn_unix_listener(
        handler.clone(),
        listener,
        cli.listen_socket.clone(),
        unix_shutdown_rx,
    );

    let _ = unix_handle.await;
    tracing::info!("shutdown complete");

    Ok(())
}

/// Binds the Unix socket listener for `--listen-socket`.
///
/// This is the proxy's only listener by design: peer credentials and filesystem
/// ownership on the socket are the access-control boundary, and a TCP listener
/// would have neither.
///
/// `fd://3` selects systemd socket activation (the socket is already bound
/// and listening; we just adopt the fd). Any other value is treated as a
/// filesystem path: a stale socket left over from a previous run is removed
/// before binding, matching the Go implementation.
fn bind_unix_listener(addr: &str) -> io::Result<tokio::net::UnixListener> {
    if addr == "fd://3" {
        return unix_listener_from_raw_fd(SYSTEMD_SOCKET_FD);
    }

    // Remove a stale socket, but only a socket: blindly removing would let a
    // mistyped path silently delete an operator's file, so anything that is
    // not a socket is an error rather than something to clear out of the way.
    match std::fs::symlink_metadata(addr) {
        Ok(meta) => {
            if !meta.file_type().is_socket() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("refusing to remove {}: not a socket ({:?})", addr, meta.file_type()),
                ));
            }
            std::fs::remove_file(addr)?;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    tokio::net::UnixListener::bind(addr)
}

/// Rejects `--listen-socket` values that would not produce a filesystem-visible
/// Unix socket. Several of them otherwise bind something surprising rather than
/// failing: `tcp://0.0.0.0:2375` becomes a file named `tcp:/0.0.0.0:2375`.
/// Mirrors `validateListenSocket` in Go and `parseListenSocket` in TypeScript.
fn validate_listen_socket(addr: &str) -> Result<(), String> {
    let activation = format!("fd://{}", SYSTEMD_SOCKET_FD);
    if addr.is_empty() {
        Err("--listen-socket must not be empty".to_string())
    } else if addr == activation {
        Ok(())
    } else if addr.starts_with("fd://") {
        Err(format!(
            "--listen-socket only supports {} for socket activation, got: {}",
            activation, addr
        ))
    } else if ["tcp://", "http://", "https://", "unix://"]
        .iter()
        .any(|s| addr.starts_with(s))
    {
        Err(format!(
            "--listen-socket only supports Unix socket paths, got: {}",
            addr
        ))
    } else if addr.starts_with('@') || addr.starts_with('\0') {
        Err(format!(
            "--listen-socket must be a filesystem path; abstract sockets have no permissions \
             and would be reachable by any process, got: {}",
            addr
        ))
    } else if !addr.starts_with('/') {
        Err(format!("--listen-socket must be an absolute path, got: {}", addr))
    } else {
        Ok(())
    }
}

/// Rejects non-Unix Docker daemon addresses. Connecting to the daemon over TCP
/// would bypass the user/group ownership on the daemon socket, which is what
/// constrains the proxy's own access.
fn validate_docker_host(addr: &str) -> Result<(), String> {
    if addr.is_empty() {
        return Err("--docker-host must not be empty".to_string());
    }
    if ["tcp://", "http://", "https://", "unix://"]
        .iter()
        .any(|s| addr.starts_with(s))
    {
        return Err(format!(
            "--docker-host only supports Unix socket paths, got: {}",
            addr
        ));
    }
    Ok(())
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

    // Confirm the fd really is an AF_UNIX socket rather than relying on a later
    // accept to fail. A unit with ListenStream=127.0.0.1:2375 hands us a TCP
    // socket, and treating it as a Unix socket would either serve plain TCP or
    // wedge the accept loop warning at every retry.
    std_listener.local_addr().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "fd {} is not a Unix socket ({}): set ListenStream to a filesystem path \
                 in the .socket unit",
                fd, e
            ),
        )
    })?;

    std_listener.set_nonblocking(true)?;
    tokio::net::UnixListener::from_std(std_listener)
}

fn spawn_unix_listener(
    handler: Arc<handler::Handler>,
    listener: tokio::net::UnixListener,
    addr: String,
    mut shutdown_rx: broadcast::Receiver<()>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
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
    async fn test_bind_unix_listener_removes_stale_socket() {
        let path = unique_socket_path();
        // A real socket left behind by an unclean shutdown. Dropping the
        // listener does not unlink it, so the file outlives the process.
        let stale = StdUnixListener::bind(&path).unwrap();
        drop(stale);
        assert!(path.exists(), "precondition: stale socket should still be on disk");

        let result = bind_unix_listener(path.to_str().unwrap());
        assert!(
            result.is_ok(),
            "expected stale socket to be removed and bind to succeed: {:?}",
            result.err()
        );

        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn test_bind_unix_listener_refuses_to_delete_non_socket() {
        // A mistyped --listen-socket must not silently destroy data.
        let path = unique_socket_path();
        std::fs::write(&path, b"important data").unwrap();

        let result = bind_unix_listener(path.to_str().unwrap());
        assert!(result.is_err(), "expected a regular file to be refused, not deleted");
        assert!(
            result.unwrap_err().to_string().contains("not a socket"),
            "error should explain that the path is not a socket"
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"important data",
            "the file must be left untouched"
        );

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_validate_listen_socket() {
        // Accepted.
        for addr in ["/var/run/docker-socket-policy.sock", "fd://3"] {
            assert!(validate_listen_socket(addr).is_ok(), "{} should be accepted", addr);
        }

        // Rejected, with the reason that should be reported.
        let cases = [
            ("", "must not be empty"),
            ("fd://4", "only supports fd://3"),
            ("fd://0", "only supports fd://3"),
            ("fd://abc", "only supports fd://3"),
            ("tcp://0.0.0.0:2375", "only supports Unix socket paths"),
            ("http://0.0.0.0:2375", "only supports Unix socket paths"),
            ("https://0.0.0.0:2375", "only supports Unix socket paths"),
            ("unix:///var/run/d.sock", "only supports Unix socket paths"),
            ("@dsp", "abstract sockets have no permissions"),
            ("\0dsp", "abstract sockets have no permissions"),
            // The likeliest --listen-tcp migration mistake: drop the scheme,
            // keep the address. Binding it would create a file called
            // "0.0.0.0:2375" and report success while being unreachable.
            ("0.0.0.0:2375", "must be an absolute path"),
            ("dsp.sock", "must be an absolute path"),
        ];
        for (addr, want) in cases {
            let err = validate_listen_socket(addr)
                .expect_err(&format!("{:?} should be rejected", addr));
            assert!(err.contains(want), "error for {:?} was {:?}, want it to contain {:?}", addr, err, want);
        }
    }

    #[test]
    fn test_validate_docker_host() {
        assert!(validate_docker_host("/var/run/docker.sock").is_ok());

        let cases = [
            ("", "must not be empty"),
            ("tcp://dind:2375", "only supports Unix socket paths"),
            ("http://dind:2375", "only supports Unix socket paths"),
            ("https://dind:2375", "only supports Unix socket paths"),
            ("unix:///var/run/docker.sock", "only supports Unix socket paths"),
        ];
        for (addr, want) in cases {
            let err = validate_docker_host(addr)
                .expect_err(&format!("{:?} should be rejected", addr));
            assert!(err.contains(want), "error for {:?} was {:?}", addr, err);
        }
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

    /// Regression guard for socket activation handing back the wrong socket
    /// family: a unit with ListenStream=127.0.0.1:2375 would otherwise wedge
    /// the accept loop instead of failing, while the process looked healthy.
    #[tokio::test]
    async fn test_unix_listener_from_raw_fd_rejects_tcp_socket() {
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let fd = tcp.into_raw_fd();

        let err = unix_listener_from_raw_fd(fd)
            .expect_err("expected a TCP socket at the activation fd to be rejected");
        assert!(
            err.to_string().contains("not a Unix socket"),
            "error should explain the fd is not a Unix socket, got: {}",
            err
        );
    }
}
