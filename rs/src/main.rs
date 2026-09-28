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
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
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

/// Set around bind(2) so the socket is created at 0600 and is never briefly
/// reachable by group or world. bind() applies 0777 & !umask, and
/// 0777 & !0177 == 0600. A chmod after the fact would leave a window in which
/// the socket is already listening at the ambient mode.
const BIND_UMASK: libc::mode_t = 0o177;

/// Upper bound on how long in-flight requests are given to finish after a
/// shutdown signal. This is a cap, not a delay: shutdown returns as soon as
/// the last connection closes. Matches the Go and TypeScript implementations.
const SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

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

    /// Octal mode for the listening socket (ignored for fd://3).
    #[arg(long, default_value = "0660")]
    listen_socket_mode: String,

    /// Group name or gid to own the listening socket (ignored for fd://3).
    #[arg(long)]
    listen_socket_group: Option<String>,
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
    let socket_mode = match parse_socket_mode(&cli.listen_socket_mode) {
        Ok(m) => m,
        Err(msg) => {
            tracing::error!("{}", msg);
            std::process::exit(2);
        }
    };
    let socket_gid = match cli.listen_socket_group.as_deref().map(resolve_group).transpose() {
        Ok(g) => g,
        Err(msg) => {
            tracing::error!("{}", msg);
            std::process::exit(2);
        }
    };

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
    let listener = bind_unix_listener(&cli.listen_socket, socket_mode, socket_gid).map_err(|e| {
        tracing::error!("failed to bind unix socket {}: {}", cli.listen_socket, e);
        e
    })?;
    let unix_handle = spawn_unix_listener(
        handler.clone(),
        listener,
        cli.listen_socket.clone(),
        unix_shutdown_rx,
        shutdown_tx.clone(),
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
fn bind_unix_listener(addr: &str, mode: u32, gid: Option<u32>) -> io::Result<tokio::net::UnixListener> {
    if addr == "fd://3" {
        // Under socket activation systemd owns the socket and applies its own
        // SocketMode/SocketGroup; re-chmod'ing here would fight the unit.
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

    // umask is process-global and not thread-safe. This runs during startup,
    // before any connection is served, so nothing else is creating files.
    // SAFETY: umask(2) cannot fail and has no preconditions.
    let previous = unsafe { libc::umask(BIND_UMASK) };
    let listener = tokio::net::UnixListener::bind(addr);
    // SAFETY: as above; restores the caller's umask.
    unsafe { libc::umask(previous) };
    let listener = listener?;

    // Widen from 0600 to the configured mode only once ownership is correct,
    // so the socket is never reachable by the wrong group.
    if let Some(gid) = gid {
        std::os::unix::fs::chown(addr, None, Some(gid)).map_err(|e| {
            io::Error::new(e.kind(), format!("setting group on {}: {}", addr, e))
        })?;
    }
    std::fs::set_permissions(addr, std::fs::Permissions::from_mode(mode))
        .map_err(|e| io::Error::new(e.kind(), format!("setting mode on {}: {}", addr, e)))?;

    Ok(listener)
}

/// Maps `--listen-socket-group` to a gid. A numeric value is used as-is so a
/// deployment without the group in /etc/group (or NSS) can still be configured.
fn resolve_group(group: &str) -> Result<u32, String> {
    if let Ok(gid) = group.parse::<u32>() {
        return Ok(gid);
    }
    let name = std::ffi::CString::new(group)
        .map_err(|_| format!("--listen-socket-group {:?}: contains a NUL byte", group))?;

    // getgrnam_r is the reentrant form; the non-_r variant returns a pointer
    // into a shared static buffer.
    let mut grp: libc::group = unsafe { std::mem::zeroed() };
    let mut buf = vec![0_i8; 4096];
    let mut result: *mut libc::group = std::ptr::null_mut();
    // SAFETY: all pointers are valid for the duration of the call and the
    // buffer length matches the allocation.
    let rc = unsafe {
        libc::getgrnam_r(
            name.as_ptr(),
            &mut grp,
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 {
        return Err(format!(
            "--listen-socket-group {:?}: lookup failed: {}",
            group,
            io::Error::from_raw_os_error(rc)
        ));
    }
    if result.is_null() {
        return Err(format!("--listen-socket-group {:?}: no such group", group));
    }
    Ok(grp.gr_gid)
}

/// Parses an octal mode and rejects anything world-writable. connect(2) on an
/// AF_UNIX socket requires write permission, so a world-writable socket is
/// reachable by every local uid — there is deliberately no opt-out.
fn parse_socket_mode(s: &str) -> Result<u32, String> {
    if s.is_empty() {
        return Err("--listen-socket-mode must not be empty".to_string());
    }
    let mode = u32::from_str_radix(s, 8)
        .map_err(|_| format!("--listen-socket-mode {:?}: not an octal mode", s))?;
    if mode > 0o777 {
        return Err(format!("--listen-socket-mode {:?}: must be within 0777", s));
    }
    if mode & 0o002 != 0 {
        return Err(format!(
            "--listen-socket-mode {:?} is world-writable: every local user could connect \
             to the proxy, which disables the access-control boundary",
            s
        ));
    }
    Ok(mode)
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
    shutdown_tx: broadcast::Sender<()>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        tracing::info!("listening on unix socket {}", addr);

        // Connections are tracked rather than detached. `tokio::spawn`ing them
        // and returning would drop the runtime with the tasks still running,
        // aborting in-flight responses mid-write.
        let mut conns = tokio::task::JoinSet::new();

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, _)) => {
                            // Subscribe per connection so a keep-alive
                            // connection sitting idle between requests is told
                            // to close, instead of holding shutdown open until
                            // the timeout.
                            conns.spawn(serve_connection(
                                handler.clone(),
                                stream,
                                shutdown_tx.subscribe(),
                            ));
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

        // Stop accepting, then drain. Each connection has already been told to
        // shut down gracefully, so this returns as soon as the last in-flight
        // request finishes rather than waiting out the timeout.
        drop(listener);
        unlink_listen_socket(&addr);
        let drained = tokio::time::timeout(SHUTDOWN_TIMEOUT, async {
            while conns.join_next().await.is_some() {}
        })
        .await;
        if drained.is_err() {
            tracing::error!(
                "drain deadline exceeded after {:?}, abandoning in-flight connections",
                SHUTDOWN_TIMEOUT
            );
            conns.shutdown().await;
        }
    })
}

/// Removes the listening socket after a clean shutdown.
///
/// Unlike Go's `net.UnixListener` and Node, tokio's `UnixListener` does not
/// unlink the path when dropped, so without this a clean exit leaves the socket
/// file behind. It is recovered on the next start (`bind_unix_listener` clears
/// a stale socket), but the three implementations should behave the same.
///
/// Under socket activation the socket belongs to systemd, which will hand the
/// same fd to the next start — unlinking it there would break the socket unit.
fn unlink_listen_socket(addr: &str) {
    if addr == format!("fd://{}", SYSTEMD_SOCKET_FD) {
        return;
    }
    match std::fs::remove_file(addr) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => tracing::warn!("could not remove socket {}: {}", addr, e),
    }
}

async fn serve_connection<S>(
    handler: Arc<handler::Handler>,
    stream: S,
    mut shutdown_rx: broadcast::Receiver<()>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(stream);
    let svc = hyper::service::service_fn(move |req: Request<IncomingBody>| {
        let h = handler.clone();
        async move { Ok::<_, hyper::Error>(h.handle(req).await) }
    });

    let conn = hyper::server::conn::http1::Builder::new().serve_connection(io, svc);
    tokio::pin!(conn);

    tokio::select! {
        res = conn.as_mut() => {
            if let Err(e) = res {
                tracing::warn!("connection error: {}", e);
            }
        }
        _ = shutdown_rx.recv() => {
            // Finish the request currently being served, then close rather
            // than reading another off this keep-alive connection.
            conn.as_mut().graceful_shutdown();
            if let Err(e) = conn.await {
                tracing::warn!("connection error during graceful shutdown: {}", e);
            }
        }
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

        let result = bind_unix_listener(path.to_str().unwrap(), 0o660, None);
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

        let result = bind_unix_listener(path.to_str().unwrap(), 0o660, None);
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

        let result = bind_unix_listener(path.to_str().unwrap(), 0o660, None);
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

    /// Transport that stalls before replying, so a request can be held
    /// in-flight while a shutdown signal is delivered.
    struct SlowTransport {
        delay: std::time::Duration,
    }

    #[async_trait::async_trait]
    impl transport::Transport for SlowTransport {
        async fn forward(
            &self,
            _req: hyper::Request<http_body_util::Full<bytes::Bytes>>,
        ) -> Result<hyper::Response<http_body_util::Full<bytes::Bytes>>, transport::TransportError>
        {
            tokio::time::sleep(self.delay).await;
            Ok(hyper::Response::builder()
                .status(418)
                .body(http_body_util::Full::new(bytes::Bytes::from("teapot")))
                .unwrap())
        }
    }

    fn test_handler(delay: std::time::Duration) -> Arc<handler::Handler> {
        let manager = policy::Manager::from_map(std::collections::HashMap::new());
        let router = Arc::new(proxy::Router::new(manager));
        let chain = middleware::Chain::new(false);
        let audit = audit::AuditLogger::new("/dev/null").unwrap();
        Arc::new(handler::Handler::new(
            router,
            chain,
            audit,
            Box::new(SlowTransport { delay }),
        ))
    }

    /// Sends a minimal HTTP/1.1 request over the Unix socket and reads the
    /// whole reply. Written by hand to keep the test free of a client dep.
    async fn get_over_unix(path: &std::path::Path, target: &str) -> io::Result<String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::UnixStream::connect(path).await?;
        stream
            .write_all(format!("GET {target} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
            .await?;
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await?;
        Ok(String::from_utf8_lossy(&buf).into_owned())
    }

    /// Regression test: the listener task must return promptly once signalled.
    /// Waiting out `SHUTDOWN_TIMEOUT` would mean `docker stop` (10s grace)
    /// always escalates to SIGKILL.
    #[tokio::test]
    async fn test_listener_shuts_down_promptly_when_idle() {
        let path = unique_socket_path();
        let listener = bind_unix_listener(path.to_str().unwrap(), 0o660, None).unwrap();
        let (tx, rx) = broadcast::channel::<()>(1);

        let handle = spawn_unix_listener(
            test_handler(std::time::Duration::ZERO),
            listener,
            path.to_str().unwrap().to_string(),
            rx,
            tx.clone(),
        );

        tx.send(()).unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(5), handle)
            .await
            .expect("listener did not shut down within 5s")
            .expect("listener task panicked");

        std::fs::remove_file(&path).ok();
    }

    /// Exiting fast is only correct if it still drains. A request that is
    /// mid-flight when the signal lands must receive its response.
    #[tokio::test]
    async fn test_listener_drains_in_flight_request() {
        let path = unique_socket_path();
        let listener = bind_unix_listener(path.to_str().unwrap(), 0o660, None).unwrap();
        let (tx, rx) = broadcast::channel::<()>(1);

        let handle = spawn_unix_listener(
            test_handler(std::time::Duration::from_millis(300)),
            listener,
            path.to_str().unwrap().to_string(),
            rx,
            tx.clone(),
        );

        let req_path = path.clone();
        let request = tokio::spawn(async move { get_over_unix(&req_path, "/_ping").await });

        // Let the request reach the (stalling) transport before signalling.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        tx.send(()).unwrap();

        let reply = tokio::time::timeout(std::time::Duration::from_secs(5), request)
            .await
            .expect("in-flight request never completed")
            .expect("request task panicked")
            .expect("in-flight request was aborted by shutdown");
        assert!(
            reply.contains("418"),
            "in-flight request should have been drained, got: {reply}"
        );

        tokio::time::timeout(std::time::Duration::from_secs(5), handle)
            .await
            .expect("listener did not return after draining")
            .expect("listener task panicked");

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_parse_socket_mode() {
        for (input, want) in [("0660", 0o660), ("660", 0o660), ("0600", 0o600), ("0640", 0o640)] {
            assert_eq!(parse_socket_mode(input), Ok(want), "{} should parse", input);
        }
        for (input, want) in [
            ("", "must not be empty"),
            ("0x1ff", "not an octal mode"),
            ("668", "not an octal mode"),
            ("1777", "within 0777"),
            // connect(2) needs write, so o+w means every local uid can connect.
            ("0666", "world-writable"),
            ("0777", "world-writable"),
            ("0602", "world-writable"),
        ] {
            let err = parse_socket_mode(input)
                .expect_err(&format!("{:?} should be rejected", input));
            assert!(err.contains(want), "error for {:?} was {:?}", input, err);
        }
    }

    /// Regression test for #40: the mode used to be whatever the umask left
    /// behind, which is 0755 by default. connect(2) requires write permission,
    /// so the documented group grant silently did not work, and under umask 0
    /// the socket was 0777 to every local uid.
    #[tokio::test]
    async fn test_bind_applies_socket_mode() {
        for mode in [0o660_u32, 0o600, 0o640] {
            let path = unique_socket_path();
            let listener = bind_unix_listener(path.to_str().unwrap(), mode, None).unwrap();

            let got = std::fs::symlink_metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(got, mode, "socket mode was {:o}, want {:o}", got, mode);

            drop(listener);
            std::fs::remove_file(&path).ok();
        }
    }

    /// The ambient umask must not influence the result: that was the bug.
    #[tokio::test]
    async fn test_bind_ignores_ambient_umask() {
        // SAFETY: umask(2) cannot fail. Restored below.
        let previous = unsafe { libc::umask(0) };
        let path = unique_socket_path();
        let listener = bind_unix_listener(path.to_str().unwrap(), 0o660, None).unwrap();
        // SAFETY: as above.
        unsafe { libc::umask(previous) };

        let got = std::fs::symlink_metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(got, 0o660, "socket mode was {:o} under umask 0, want 0660", got);
        assert_eq!(got & 0o002, 0, "socket is world-writable: any local uid could connect");

        drop(listener);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_resolve_group() {
        // A numeric value is taken as a gid without consulting /etc/group.
        assert_eq!(resolve_group("2001"), Ok(2001));
        assert!(resolve_group("definitely-no-such-group-xyz").is_err());
        // Whatever gid 0 is called on this platform must round-trip.
        let root_group = if cfg!(target_os = "macos") { "wheel" } else { "root" };
        if let Ok(gid) = resolve_group(root_group) {
            assert_eq!(gid, 0, "{} should be gid 0", root_group);
        }
    }

    /// A clean shutdown must not leave the socket file on disk, matching Go
    /// and TypeScript. tokio does not unlink on drop, so this is explicit.
    #[tokio::test]
    async fn test_listener_unlinks_socket_on_shutdown() {
        let path = unique_socket_path();
        let listener = bind_unix_listener(path.to_str().unwrap(), 0o660, None).unwrap();
        let (tx, rx) = broadcast::channel::<()>(1);

        let handle = spawn_unix_listener(
            test_handler(std::time::Duration::ZERO),
            listener,
            path.to_str().unwrap().to_string(),
            rx,
            tx.clone(),
        );

        assert!(path.exists(), "precondition: socket should be bound");
        tx.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), handle)
            .await
            .expect("listener did not shut down")
            .expect("listener task panicked");

        assert!(
            !path.exists(),
            "socket file was left behind after a clean shutdown"
        );
        std::fs::remove_file(&path).ok();
    }

    /// Socket activation is the exception: the socket belongs to systemd and
    /// must survive the process, or the unit cannot hand it to the next start.
    #[test]
    fn test_unlink_listen_socket_spares_socket_activation() {
        let path = unique_socket_path();
        std::fs::write(&path, b"stand-in for a systemd-owned socket").unwrap();

        unlink_listen_socket(&format!("fd://{}", SYSTEMD_SOCKET_FD));
        assert!(path.exists(), "precondition check only");

        unlink_listen_socket(path.to_str().unwrap());
        assert!(!path.exists(), "a path-based socket should be removed");
    }

    /// An idle keep-alive connection must not hold shutdown open until the
    /// timeout: the connection is told to close, not merely left alone.
    #[tokio::test]
    async fn test_listener_releases_idle_keepalive_connection() {
        let path = unique_socket_path();
        let listener = bind_unix_listener(path.to_str().unwrap(), 0o660, None).unwrap();
        let (tx, rx) = broadcast::channel::<()>(1);

        let handle = spawn_unix_listener(
            test_handler(std::time::Duration::ZERO),
            listener,
            path.to_str().unwrap().to_string(),
            rx,
            tx.clone(),
        );

        // Open a connection and leave it parked with no request on it.
        let _idle = tokio::net::UnixStream::connect(&path).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        tx.send(()).unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(5), handle)
            .await
            .expect("idle keep-alive connection held shutdown open")
            .expect("listener task panicked");

        std::fs::remove_file(&path).ok();
    }
}
