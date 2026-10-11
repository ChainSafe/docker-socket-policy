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
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tracing_subscriber::EnvFilter;

/// Mode applied to the listening socket. connect(2) on an AF_UNIX socket
/// requires write permission, so 0660 is what actually grants the owning group
/// access.
const SOCKET_MODE: u32 = 0o660;

/// Group given the socket when `--listen-socket-group` is not passed, as
/// dockerd does with `docker`.
const DEFAULT_SOCKET_GROUP: &str = "docker-socket-policy";

/// Pause after a failed `accept` before retrying, so persistent errors
/// (e.g. fd exhaustion) don't spin the loop at 100% CPU.
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

    /// Group owning the socket (default docker-socket-policy; "" = the proxy's own group)
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
    // SAFETY: getegid(2) cannot fail.
    let egid = unsafe { libc::getegid() };
    let socket_gid = match select_socket_group(cli.listen_socket_group.as_deref(), resolve_group, egid) {
        Ok((gid, warning)) => {
            if let Some(warning) = warning {
                tracing::warn!("{}", warning);
            }
            gid
        }
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
    // `_lock`, not `_`: a `_` pattern drops the File at once, releasing the
    // single-instance lock while the proxy is still serving.
    let (listener, _lock) = open_listener(&cli.listen_socket, Some(socket_gid)).map_err(|e| {
        tracing::error!("failed to start listener on {}: {}", cli.listen_socket, e);
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
    // Release the lock only once the socket is closed and unlinked, so the
    // next instance never finds our socket still in place.
    drop(_lock);
    tracing::info!("shutdown complete");

    Ok(())
}

/// Takes the single-instance lock, clears the socket path and binds it. The
/// returned lock must be held for the life of the process: dropping it would
/// let a second instance take the path.
fn open_listener(addr: &str, gid: Option<u32>) -> io::Result<(tokio::net::UnixListener, std::fs::File)> {
    // On an error below, `lock` is dropped on return, releasing the flock.
    let lock = acquire_instance_lock(addr)?;
    prepare_socket_path(addr)?;
    let listener = bind_unix_listener(addr, gid)?;
    Ok((listener, lock))
}

/// Takes an exclusive flock on `<socket_path>.lock`, which replaces dockerd's
/// pidfile. The kernel drops the lock on any exit, including SIGKILL, so it
/// never goes stale, and it needs no PID check, so it also works across PID
/// namespaces. The file is never truncated or unlinked: unlinking a lock file
/// reopens the race it exists to close. O_NOFOLLOW stops a symlink planted at
/// the lock path from redirecting O_CREAT elsewhere.
fn acquire_instance_lock(socket_path: &str) -> io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;

    let lock_path = format!("{}.lock", socket_path);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&lock_path)
        .map_err(|e| io::Error::new(e.kind(), format!("opening lock {}: {}", lock_path, e)))?;
    // SAFETY: the fd is owned by `file` and open for the duration of the call.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!(
                    "{} is in use by another instance (lock {} held)",
                    socket_path, lock_path
                ),
            ));
        }
        return Err(io::Error::new(e.kind(), format!("locking {}: {}", lock_path, e)));
    }
    Ok(file)
}

/// Bounds the connect(2) that tells a live socket from a stale one.
const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

/// Clears the socket path for bind, following the existing-path table in
/// spec/listener-design.md. Only a socket that refuses connections is removed.
/// A live one belongs to another process, possibly an instance that takes no
/// lock (TypeScript, or v0.2.21 and earlier), and replacing it would cut that
/// process off silently. Anything that is not a socket is refused, so a
/// mistyped path cannot silently delete an operator's data.
fn prepare_socket_path(path: &str) -> io::Result<()> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(io::Error::new(e.kind(), format!("checking {}: {}", path, e))),
    };
    if !meta.file_type().is_socket() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("refusing to remove {}: not a socket ({:?})", path, meta.file_type()),
        ));
    }

    // std's connect has no timeout, so it runs on its own thread. On timeout
    // the thread is left to finish on its own; the socket is live either way.
    let (tx, rx) = std::sync::mpsc::channel();
    let target = path.to_string();
    std::thread::spawn(move || {
        let _ = tx.send(std::os::unix::net::UnixStream::connect(target).map(drop));
    });
    let in_use = || {
        io::Error::new(
            io::ErrorKind::AddrInUse,
            format!("{} is in use by another process", path),
        )
    };
    match rx.recv_timeout(PROBE_TIMEOUT) {
        Ok(Ok(())) | Err(std::sync::mpsc::RecvTimeoutError::Timeout) => return Err(in_use()),
        Ok(Err(e)) if e.raw_os_error() == Some(libc::ECONNREFUSED) => {}
        Ok(Err(e)) => {
            return Err(io::Error::new(
                e.kind(),
                format!("refusing to remove {}: connect: {}", path, e),
            ))
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            return Err(io::Error::other(format!(
                "refusing to remove {}: connect probe did not complete",
                path
            )))
        }
    }

    std::fs::remove_file(path).map_err(|e| io::Error::new(e.kind(), format!("removing stale socket {}: {}", path, e)))
}

/// Binds the Unix socket listener for `--listen-socket`.
///
/// This is the proxy's only listener by design: peer credentials and filesystem
/// ownership on the socket are the access-control boundary, and a TCP listener
/// would have neither.
///
/// The path must already be clear; `open_listener` runs `prepare_socket_path`
/// first.
fn bind_unix_listener(addr: &str, gid: Option<u32>) -> io::Result<tokio::net::UnixListener> {
    // umask is process-global and not thread-safe. This runs during startup,
    // before any connection is served, so nothing else is creating files.
    // SAFETY: umask(2) cannot fail and has no preconditions.
    let previous = unsafe { libc::umask(BIND_UMASK) };
    let listener = tokio::net::UnixListener::bind(addr);
    // SAFETY: as above; restores the caller's umask.
    unsafe { libc::umask(previous) };
    let listener = listener?;

    // Widen from 0600 to SOCKET_MODE only once ownership is correct,
    // so the socket is never reachable by the wrong group.
    if let Some(gid) = gid {
        std::os::unix::fs::chown(addr, None, Some(gid)).map_err(|e| {
            if e.raw_os_error() == Some(libc::EPERM) {
                io::Error::new(
                    e.kind(),
                    format!(
                        "cannot give {} to group {}: the proxy's user must be a member of it \
                         (SupplementaryGroups= / group_add:)",
                        addr, gid
                    ),
                )
            } else {
                io::Error::new(e.kind(), format!("setting group on {}: {}", addr, e))
            }
        })?;
    }
    std::fs::set_permissions(addr, std::fs::Permissions::from_mode(SOCKET_MODE))
        .map_err(|e| io::Error::new(e.kind(), format!("setting mode on {}: {}", addr, e)))?;

    Ok(listener)
}

/// Picks the socket's group the way dockerd does
/// (moby/daemon/listeners/listeners_linux.go). `None` means the flag was not
/// passed: the default group is used if it exists, and otherwise the proxy
/// falls back to its own group with a warning. An explicit group that does not
/// resolve is an error. An explicit `""` selects the proxy's own group.
fn select_socket_group(
    flag: Option<&str>,
    lookup: impl Fn(&str) -> Result<u32, String>,
    egid: u32,
) -> Result<(u32, Option<String>), String> {
    match flag {
        None => match lookup(DEFAULT_SOCKET_GROUP) {
            Ok(gid) => Ok((gid, None)),
            Err(_) => Ok((
                egid,
                Some(format!(
                    "group {} not found, using the proxy's own group {}",
                    DEFAULT_SOCKET_GROUP, egid
                )),
            )),
        },
        Some("") => Ok((egid, None)),
        Some(group) => lookup(group).map(|gid| (gid, None)),
    }
}

const MAX_SOCKET_GID: u32 = u32::MAX - 1;

/// Maps `--listen-socket-group` to a gid. A numeric value is used as-is so a
/// deployment without the group in /etc/group (or NSS) can still be configured.
fn resolve_group(group: &str) -> Result<u32, String> {
    if !group.is_empty() && group.bytes().all(|b| b.is_ascii_digit()) {
        // u32::MAX is chown's "don't change" sentinel.
        return match group.parse::<u32>() {
            Ok(gid) if gid <= MAX_SOCKET_GID => Ok(gid),
            _ => Err(format!(
                "--listen-socket-group {:?}: gid out of range (0-{})",
                group, MAX_SOCKET_GID
            )),
        };
    }
    let name =
        std::ffi::CString::new(group).map_err(|_| format!("--listen-socket-group {:?}: contains a NUL byte", group))?;

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

/// Rejects `--listen-socket` values that would not produce a filesystem-visible
/// Unix socket. Several of them otherwise bind something surprising rather than
/// failing: `tcp://0.0.0.0:2375` becomes a file named `tcp:/0.0.0.0:2375`.
/// Mirrors `validateListenSocket` in Go and `parseListenSocket` in TypeScript.
fn validate_listen_socket(addr: &str) -> Result<(), String> {
    if addr.is_empty() {
        Err("--listen-socket must not be empty".to_string())
    } else if ["fd://", "tcp://", "http://", "https://", "unix://"]
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
        return Err(format!("--docker-host only supports Unix socket paths, got: {}", addr));
    }
    Ok(())
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
                            // (e.g. EMFILE) would otherwise busy-loop.
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
        let drained =
            tokio::time::timeout(SHUTDOWN_TIMEOUT, async { while conns.join_next().await.is_some() {} }).await;
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
/// file behind. It is recovered on the next start (`prepare_socket_path` clears
/// a stale socket), but the three implementations should behave the same.
fn unlink_listen_socket(addr: &str) {
    match std::fs::remove_file(addr) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => tracing::warn!("could not remove socket {}: {}", addr, e),
    }
}

async fn serve_connection<S>(handler: Arc<handler::Handler>, stream: S, mut shutdown_rx: broadcast::Receiver<()>)
where
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
    use std::os::unix::net::UnixListener as StdUnixListener;

    fn unique_socket_path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("dsp-test-{}.sock", rand::random::<u64>()))
    }

    /// A directory under the temp dir, removed on drop. Paths inside it stay
    /// well under macOS's 104-byte sun_path limit.
    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!("dsp-{}", rand::random::<u32>()));
            std::fs::create_dir(&dir).unwrap();
            // Set explicitly: bind_unix_listener's umask is process-global, so
            // a bind in a parallel test can strip the directory's x bit.
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            TempDir(dir)
        }

        fn join(&self, name: &str) -> String {
            self.0.join(name).to_str().unwrap().to_string()
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }

    /// Held by `test_lock_released_on_sigkill` from before its fork until the
    /// child has closed every inherited fd, and by tests that rely on closing
    /// an fd. Without it a child forked at the wrong moment keeps a copy of a
    /// "closed" listener or lock alive, so a stale socket probes as live or a
    /// dropped lock stays held.
    static FORK_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn fork_guard() -> std::sync::MutexGuard<'static, ()> {
        FORK_GUARD.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Leaves a socket file at path with nothing listening on it, as an
    /// unclean shutdown would: connect(2) to it is refused. Dropping a std
    /// listener does not unlink its path.
    fn seed_stale_socket(path: &str) {
        let _guard = fork_guard();
        drop(StdUnixListener::bind(path).unwrap());
    }

    fn inode(path: &str) -> u64 {
        use std::os::unix::fs::MetadataExt;
        std::fs::symlink_metadata(path).unwrap().ino()
    }

    fn is_root() -> bool {
        // SAFETY: geteuid(2) cannot fail.
        unsafe { libc::geteuid() == 0 }
    }

    #[tokio::test]
    async fn test_open_listener_replaces_stale_socket() {
        let dir = TempDir::new();
        let path = dir.join("stale.sock");
        seed_stale_socket(&path);

        let result = open_listener(&path, None);
        assert!(result.is_ok(), "open_listener over a stale socket: {:?}", result.err());
    }

    /// A mistyped --listen-socket must not silently destroy data.
    #[tokio::test]
    async fn test_open_listener_refuses_to_delete_non_socket() {
        let dir = TempDir::new();

        let path = dir.join("important.txt");
        std::fs::write(&path, b"important data").unwrap();
        let err = open_listener(&path, None).expect_err("regular file was not refused");
        assert!(
            err.to_string().contains("not a socket"),
            "error = {:?}",
            err.to_string()
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"important data", "file was modified");

        let path = dir.join("adir");
        std::fs::create_dir(&path).unwrap();
        assert!(open_listener(&path, None).is_err(), "directory was not refused");
        assert!(std::path::Path::new(&path).is_dir(), "directory was removed");
    }

    /// One case per row of the existing-path table in
    /// spec/listener-design.md; the case names match the Quint runs.
    #[test]
    fn test_prepare_socket_path() {
        // path_absent_binds
        {
            let dir = TempDir::new();
            let path = dir.join("absent.sock");
            assert!(prepare_socket_path(&path).is_ok());
        }

        // path_stale_replaced
        {
            let dir = TempDir::new();
            let path = dir.join("stale.sock");
            seed_stale_socket(&path);
            let result = prepare_socket_path(&path);
            assert!(result.is_ok(), "prepare_socket_path(stale) = {:?}", result.err());
            assert!(std::fs::symlink_metadata(&path).is_err(), "stale socket still present");
        }

        // path_live_refused
        {
            let dir = TempDir::new();
            let path = dir.join("live.sock");
            let live = StdUnixListener::bind(&path).unwrap();
            let before = inode(&path);

            let err = prepare_socket_path(&path).expect_err("live socket was not refused");
            assert_eq!(err.to_string(), format!("{} is in use by another process", path));
            assert_eq!(inode(&path), before, "live socket was replaced");

            // Scoped so `live` outlives the dial: the accept may take the
            // probe's queued connection, and a thread owning the listener
            // would then close it before the dial below.
            std::thread::scope(|s| {
                let accepted = s.spawn(|| live.accept().map(drop));
                std::os::unix::net::UnixStream::connect(&path).expect("live listener no longer reachable");
                accepted.join().unwrap().expect("live listener no longer accepts");
            });
        }

        // path_connect_error_refused: connect(2) needs write permission on the
        // socket, so a 0000 socket yields EACCES. It is neither live nor
        // provably stale, so it is left alone.
        if is_root() {
            eprintln!("skipping path_connect_error_refused: root ignores socket permissions");
        } else {
            let dir = TempDir::new();
            let path = dir.join("eacces.sock");
            seed_stale_socket(&path);
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
            let err = prepare_socket_path(&path).expect_err("0000 socket was not refused");
            let want = format!("refusing to remove {}", path);
            assert!(
                err.to_string().starts_with(&want),
                "error = {:?}, want prefix {:?}",
                err.to_string(),
                want
            );
            assert!(std::fs::symlink_metadata(&path).is_ok(), "socket was removed");
        }

        // path_not_socket_refused
        {
            let dir = TempDir::new();
            let path = dir.join("file.txt");
            std::fs::write(&path, b"data").unwrap();
            let err = prepare_socket_path(&path).expect_err("regular file was not refused");
            let want = format!("refusing to remove {}: not a socket", path);
            assert!(
                err.to_string().starts_with(&want),
                "error = {:?}, want prefix {:?}",
                err.to_string(),
                want
            );
            assert_eq!(std::fs::read(&path).unwrap(), b"data", "regular file was modified");
        }
    }

    /// Covers the Quint run second_instance_lock_refused.
    #[test]
    fn test_acquire_instance_lock() {
        let _guard = fork_guard();
        let dir = TempDir::new();
        let path = dir.join("lock.sock");
        let lock_path = format!("{}.lock", path);

        let first = acquire_instance_lock(&path).expect("first acquire_instance_lock");

        let err = acquire_instance_lock(&path).expect_err("second acquisition succeeded");
        assert_eq!(
            err.to_string(),
            format!("{} is in use by another instance (lock {} held)", path, lock_path)
        );

        let mode = std::fs::symlink_metadata(&lock_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "lock file mode = {:o}, want 0600", mode);

        drop(first);
        assert!(
            std::fs::symlink_metadata(&lock_path).is_ok(),
            "lock file removed on drop, want it kept"
        );

        acquire_instance_lock(&path).expect("acquire_instance_lock after drop");
    }

    /// A symlink planted at <path>.lock must not be followed: O_CREAT through
    /// it would create or lock a file of the attacker's choosing.
    #[test]
    fn test_acquire_instance_lock_refuses_symlink() {
        let dir = TempDir::new();
        let path = dir.join("sym.sock");
        let target = dir.join("target");
        std::os::unix::fs::symlink(&target, format!("{}.lock", path)).unwrap();

        let err = acquire_instance_lock(&path).expect_err("lock through a symlink succeeded");
        assert!(
            err.to_string().contains(&format!("{}.lock", path)),
            "error = {:?}, want it to name {}.lock",
            err.to_string(),
            path
        );
        assert!(
            std::fs::symlink_metadata(&target).is_err(),
            "symlink target was created"
        );
    }

    #[test]
    fn test_acquire_instance_lock_unreadable() {
        if is_root() {
            eprintln!("skipping: root ignores file permissions");
            return;
        }
        let dir = TempDir::new();
        let path = dir.join("unreadable.sock");
        let lock_path = format!("{}.lock", path);
        std::fs::write(&lock_path, b"").unwrap();
        std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o000)).unwrap();

        let err = acquire_instance_lock(&path).expect_err("lock on a 0000 file succeeded");
        assert!(
            err.to_string().contains(&lock_path),
            "error = {:?}, want it to name {}",
            err.to_string(),
            lock_path
        );
    }

    #[test]
    fn test_open_listener_concurrent() {
        const RACERS: usize = 8;
        let rt = tokio::runtime::Runtime::new().unwrap();
        let dir = TempDir::new();

        for i in 0..50 {
            let path = dir.join(&format!("c{}.sock", i));
            let barrier = Arc::new(std::sync::Barrier::new(RACERS));
            let racers: Vec<_> = (0..RACERS)
                .map(|_| {
                    let (path, barrier, handle) = (path.clone(), barrier.clone(), rt.handle().clone());
                    std::thread::spawn(move || {
                        // tokio's UnixListener registers with the runtime's reactor.
                        let _enter = handle.enter();
                        barrier.wait();
                        open_listener(&path, None)
                    })
                })
                .collect();
            let results: Vec<_> = racers.into_iter().map(|r| r.join().unwrap()).collect();

            let want = format!("{} is in use by another instance (lock {}.lock held)", path, path);
            let mut winner = None;
            for result in results {
                match result {
                    Ok(pair) => {
                        assert!(
                            winner.is_none(),
                            "iteration {}: more than one open_listener succeeded",
                            i
                        );
                        winner = Some(pair);
                    }
                    Err(e) => assert_eq!(e.to_string(), want, "iteration {}: loser error", i),
                }
            }
            let (listener, lock) = winner.unwrap_or_else(|| panic!("iteration {}: no open_listener succeeded", i));

            let _client = std::os::unix::net::UnixStream::connect(&path)
                .unwrap_or_else(|e| panic!("iteration {}: dialing winner: {}", i, e));
            rt.block_on(async {
                tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept())
                    .await
                    .unwrap_or_else(|_| panic!("iteration {}: winner did not accept within 5s", i))
                    .unwrap_or_else(|e| panic!("iteration {}: winner accept: {}", i, e));
            });

            drop(listener);
            drop(lock);
        }
    }

    /// Kills and reaps the forked child even if an assertion fails first.
    struct ChildGuard(libc::pid_t);

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            if self.0 > 0 {
                // SAFETY: self.0 is our own unreaped child.
                unsafe {
                    libc::kill(self.0, libc::SIGKILL);
                    libc::waitpid(self.0, std::ptr::null_mut(), 0);
                }
            }
        }
    }

    /// Covers the Quint run crash_releases_lock: the kernel drops the flock on
    /// any exit, so a killed instance never leaves a stale lock behind.
    #[test]
    fn test_lock_released_on_sigkill() {
        let dir = TempDir::new();
        let path = dir.join("kill.sock");
        let lock_path = std::ffi::CString::new(format!("{}.lock", path)).unwrap();

        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: fds has room for the two descriptors pipe(2) writes.
        assert_eq!(
            unsafe { libc::pipe(fds.as_mut_ptr()) },
            0,
            "pipe: {}",
            io::Error::last_os_error()
        );
        let (read_fd, write_fd) = (fds[0], fds[1]);
        // SAFETY: sysconf(3) has no preconditions.
        let max_fd = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) }.clamp(256, 65536) as libc::c_int;

        let fork_lock = fork_guard();
        // SAFETY: the child calls only async-signal-safe functions (close,
        // open, flock, write, pause, _exit) on memory prepared before fork,
        // and never returns into the test harness.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            unsafe {
                // Drop every inherited fd but the pipe, so the child cannot
                // hold another test's lock or listener open.
                for fd in 3..max_fd {
                    if fd != write_fd {
                        libc::close(fd);
                    }
                }
                let fd = libc::open(
                    lock_path.as_ptr(),
                    libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    0o600 as libc::c_uint,
                );
                let ok = fd >= 0 && libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) == 0;
                let byte: u8 = if ok { b'r' } else { b'e' };
                libc::write(write_fd, &byte as *const u8 as *const libc::c_void, 1);
                if !ok {
                    libc::_exit(1);
                }
                loop {
                    libc::pause();
                }
            }
        }
        assert!(pid > 0, "fork: {}", io::Error::last_os_error());
        let mut child = ChildGuard(pid);
        // SAFETY: write_fd is ours and open.
        unsafe { libc::close(write_fd) };

        let mut pfd = libc::pollfd {
            fd: read_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pfd is a valid pollfd for the duration of the call.
        let ready = unsafe { libc::poll(&mut pfd, 1, 10_000) };
        let mut byte = 0u8;
        // SAFETY: byte is a valid 1-byte buffer.
        let n = if ready == 1 {
            unsafe { libc::read(read_fd, &mut byte as *mut u8 as *mut libc::c_void, 1) }
        } else {
            0
        };
        unsafe { libc::close(read_fd) };
        drop(fork_lock);
        assert_eq!(ready, 1, "child did not report ready within 10s");
        assert_eq!((n, byte), (1, b'r'), "child failed to take the lock");

        assert!(
            acquire_instance_lock(&path).is_err(),
            "acquired the lock while the child held it"
        );

        // SAFETY: pid is our unreaped child.
        unsafe {
            assert_eq!(
                libc::kill(pid, libc::SIGKILL),
                0,
                "kill: {}",
                io::Error::last_os_error()
            );
            assert_eq!(libc::waitpid(pid, std::ptr::null_mut(), 0), pid, "waitpid");
        }
        child.0 = 0;

        acquire_instance_lock(&path).expect("acquire_instance_lock after SIGKILL");
    }

    #[test]
    fn test_validate_listen_socket() {
        // Accepted.
        assert!(validate_listen_socket("/var/run/docker-socket-policy.sock").is_ok());

        // Rejected, with the reason that should be reported.
        let cases = [
            ("", "must not be empty"),
            // Socket activation was removed; fd:// is just another scheme now.
            ("fd://3", "only supports Unix socket paths"),
            ("fd://4", "only supports Unix socket paths"),
            ("fd://0", "only supports Unix socket paths"),
            ("fd://abc", "only supports Unix socket paths"),
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
            let err = validate_listen_socket(addr).expect_err(&format!("{:?} should be rejected", addr));
            assert!(
                err.contains(want),
                "error for {:?} was {:?}, want it to contain {:?}",
                addr,
                err,
                want
            );
        }
    }

    /// The socket mode is fixed. A deployment still passing the flag must fail
    /// at startup rather than silently get a different mode than it asked for.
    #[test]
    fn test_listen_socket_mode_flag_removed() {
        let err = Cli::try_parse_from(["x", "--listen-socket-mode=0660"])
            .err()
            .expect("--listen-socket-mode should be rejected");
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
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
            let err = validate_docker_host(addr).expect_err(&format!("{:?} should be rejected", addr));
            assert!(err.contains(want), "error for {:?} was {:?}", addr, err);
        }
    }

    #[tokio::test]
    async fn test_bind_unix_listener_binds_fresh_path() {
        let path = unique_socket_path();

        let result = bind_unix_listener(path.to_str().unwrap(), None);
        assert!(
            result.is_ok(),
            "expected bind to a fresh path to succeed: {:?}",
            result.err()
        );
        assert!(path.exists(), "expected socket file to be created");

        std::fs::remove_file(&path).ok();
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
        ) -> Result<hyper::Response<http_body_util::Full<bytes::Bytes>>, transport::TransportError> {
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
        let listener = bind_unix_listener(path.to_str().unwrap(), None).unwrap();
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
        let listener = bind_unix_listener(path.to_str().unwrap(), None).unwrap();
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

    /// Regression test for #40: the mode used to be whatever the umask left
    /// behind, which is 0755 by default. connect(2) requires write permission,
    /// so the documented group grant silently did not work, and under umask 0
    /// the socket was 0777 to every local uid.
    #[tokio::test]
    async fn test_bind_applies_socket_mode() {
        let path = unique_socket_path();
        let listener = bind_unix_listener(path.to_str().unwrap(), None).unwrap();

        let got = std::fs::symlink_metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(got, 0o660, "socket mode was {:o}, want 0660", got);

        drop(listener);
        std::fs::remove_file(&path).ok();
    }

    /// The ambient umask must not influence the result: that was the bug.
    #[tokio::test]
    async fn test_bind_ignores_ambient_umask() {
        // SAFETY: umask(2) cannot fail. Restored below.
        let previous = unsafe { libc::umask(0) };
        let path = unique_socket_path();
        let listener = bind_unix_listener(path.to_str().unwrap(), None).unwrap();
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

    #[test]
    fn test_resolve_group_rejects_out_of_range_gid() {
        // 4294967295 is chown's "don't change" sentinel; larger values do not
        // fit a gid_t at all.
        assert_eq!(resolve_group("4294967294"), Ok(4294967294));
        for v in ["4294967295", "4294967296", "12345678901234567890"] {
            assert_eq!(
                resolve_group(v),
                Err(format!(
                    "--listen-socket-group {:?}: gid out of range (0-4294967294)",
                    v
                ))
            );
        }
        // Only a digit string is numeric; a sign makes it a (nonexistent) name.
        for v in ["+4294967296", "+5"] {
            assert!(resolve_group(v).is_err(), "resolve_group({:?}) should fail", v);
        }
    }

    /// Mirrors the Quint group_* actions and Go's TestSelectSocketGroup.
    #[test]
    fn test_select_socket_group() {
        const EGID: u32 = 65532;
        let known = |name: &str| -> Result<u32, String> {
            match name {
                "docker-socket-policy" => Ok(2001),
                "ops" => Ok(3001),
                _ => Err(format!("--listen-socket-group {:?}: unknown group", name)),
            }
        };
        let none =
            |name: &str| -> Result<u32, String> { Err(format!("--listen-socket-group {:?}: unknown group", name)) };

        // group_default_present
        assert_eq!(select_socket_group(None, known, EGID), Ok((2001, None)));
        // group_default_missing_warns
        assert_eq!(
            select_socket_group(None, none, EGID),
            Ok((
                EGID,
                Some("group docker-socket-policy not found, using the proxy's own group 65532".to_string())
            ))
        );
        // group_explicit_present
        assert_eq!(select_socket_group(Some("ops"), known, EGID), Ok((3001, None)));
        // group_explicit_missing_fails
        assert!(select_socket_group(Some("nope"), known, EGID).is_err());
        // group_empty_uses_own
        assert_eq!(select_socket_group(Some(""), known, EGID), Ok((EGID, None)));
    }

    /// An absent flag selects the default group; an explicit empty value
    /// selects the proxy's own. The two must stay distinguishable.
    #[test]
    fn test_group_flag_empty_vs_absent() {
        let parse = |args: &[&str]| {
            let mut argv = vec!["x"];
            argv.extend_from_slice(args);
            Cli::try_parse_from(argv).unwrap().listen_socket_group
        };
        assert_eq!(parse(&[]), None);
        assert_eq!(parse(&["--listen-socket-group="]), Some(String::new()));
        assert_eq!(parse(&["--listen-socket-group", ""]), Some(String::new()));
    }

    /// A non-root proxy that is not a member of the selected group cannot
    /// chown the socket to it. The error must say what to fix.
    #[tokio::test]
    async fn test_bind_chown_eperm_names_group() {
        // SAFETY: geteuid/getegid cannot fail.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipping: root can chown to any group");
            return;
        }
        // SAFETY: a zero-length query returns the group count; the second
        // call fills a buffer of exactly that size.
        let n = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
        if n > 0 {
            let mut groups = vec![0 as libc::gid_t; n as usize];
            let n = unsafe { libc::getgroups(n, groups.as_mut_ptr()) };
            if n > 0 && groups[..n as usize].contains(&0) {
                eprintln!("skipping: process is a member of gid 0, so chown to it succeeds");
                return;
            }
        }
        let dir = TempDir::new();
        // BSD semantics (macOS) give a new file its directory's group, which
        // is gid 0 under /tmp, and chown to the current group is always
        // allowed. Give the directory our own group so the socket does not
        // start out in gid 0.
        let egid = unsafe { libc::getegid() };
        std::os::unix::fs::chown(&dir.0, None, Some(egid)).unwrap();
        let path = dir.join("eperm.sock");

        let result = bind_unix_listener(&path, Some(0));
        let err = result.expect_err("bind_unix_listener(path, Some(0)) as non-root succeeded, want EPERM");
        let want = "the proxy's user must be a member of it";
        assert!(
            err.to_string().contains(want),
            "error = {:?}, want it to contain {:?}",
            err.to_string(),
            want
        );
        let meta = std::fs::symlink_metadata(&path);
        assert!(
            matches!(&meta, Err(e) if e.kind() == io::ErrorKind::NotFound),
            "socket left on disk after chown failed: symlink_metadata = {:?}",
            meta
        );
    }

    /// A clean shutdown must not leave the socket file on disk, matching Go
    /// and TypeScript. tokio does not unlink on drop, so this is explicit.
    #[tokio::test]
    async fn test_listener_unlinks_socket_on_shutdown() {
        let path = unique_socket_path();
        let listener = bind_unix_listener(path.to_str().unwrap(), None).unwrap();
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

        assert!(!path.exists(), "socket file was left behind after a clean shutdown");
        std::fs::remove_file(&path).ok();
    }

    /// An idle keep-alive connection must not hold shutdown open until the
    /// timeout: the connection is told to close, not merely left alone.
    #[tokio::test]
    async fn test_listener_releases_idle_keepalive_connection() {
        let path = unique_socket_path();
        let listener = bind_unix_listener(path.to_str().unwrap(), None).unwrap();
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
