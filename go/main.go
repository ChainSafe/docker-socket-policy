package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ChainSafe/docker-socket-policy/go/internal/audit"
	"github.com/ChainSafe/docker-socket-policy/go/internal/middleware"
	"github.com/ChainSafe/docker-socket-policy/go/internal/policy"
	"github.com/ChainSafe/docker-socket-policy/go/internal/proxy"
)

var Version = "dev"

func main() {
	listenSocket := flag.String("listen-socket", "/var/run/docker-socket-policy.sock",
		"Unix socket to listen on (or fd://3 for systemd socket activation)")
	dockerHost := flag.String("docker-host", "/var/run/docker.sock",
		"Docker daemon socket path")
	configDir := flag.String("config-dir", "/etc/docker-socket-policy/services",
		"Policy config directory")
	logFile := flag.String("log-file", "/var/log/docker-socket-policy.log",
		"Audit log file (JSON)")
	readonly := flag.Bool("readonly", false,
		"Enable read-only mode (deny all POST/PUT/DELETE)")
	listenSocketMode := flag.String("listen-socket-mode", "0660",
		"Octal mode for the listening socket (ignored for fd://3)")
	listenSocketGroup := flag.String("listen-socket-group", "",
		"Group name or gid to own the listening socket (ignored for fd://3)")
	flag.Parse()

	if err := validateListenSocket(*listenSocket); err != nil {
		slog.Error(err.Error())
		os.Exit(2)
	}
	if err := validateDockerHost(*dockerHost); err != nil {
		slog.Error(err.Error())
		os.Exit(2)
	}
	socketMode, err := parseSocketMode(*listenSocketMode)
	if err != nil {
		slog.Error(err.Error())
		os.Exit(2)
	}
	socketGID, err := resolveGroup(*listenSocketGroup)
	if err != nil {
		slog.Error(err.Error())
		os.Exit(2)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	auditLog, err := audit.NewLogger(*logFile)
	if err != nil {
		slog.Warn("audit logging disabled", "error", err)
		auditLog = audit.NewNopLogger()
	}
	defer auditLog.Close()

	policyManager, err := policy.NewManager(*configDir)
	if err != nil {
		slog.Error("failed to load policies", "error", err)
		os.Exit(1)
	}
	slog.Info("loaded policies", "count", len(policyManager.List()), "config_dir", *configDir)

	router := proxy.NewRouter(policyManager)
	chain := middleware.NewChain(*readonly)
	transport := proxy.NewTransport(*dockerHost)
	handler := proxy.NewHandler(router, chain, auditLog, transport)

	listener, err := unixListener(*listenSocket, socketMode, socketGID)
	if err != nil {
		slog.Error("failed to start listener", "addr", *listenSocket, "error", err)
		os.Exit(1)
	}

	done := serve(ctx, listener, *listenSocket, handler)

	<-ctx.Done()
	slog.Info("shutting down...")

	// Wait for the drain to actually finish. Waiting on a timer instead would
	// stall every shutdown for the full timeout: docker stop allows 10s before
	// SIGKILL, so the proxy would never shut down gracefully at all.
	<-done
	slog.Info("shutdown complete")
}

// systemdSocketFD is the first fd systemd passes under socket activation
// (sd_listen_fds convention: fds start at 3).
const systemdSocketFD = 3

// validateListenSocket rejects --listen-socket values that would not produce a
// filesystem-visible Unix socket. Without this, several of them bind something
// surprising rather than failing: "tcp://0.0.0.0:2375" becomes a file named
// "tcp:/0.0.0.0:2375", and on Linux a leading "@" puts Go in the abstract
// namespace, where the socket has no inode, no mode and no owner and every
// process in the network namespace can connect to it unconditionally.
func validateListenSocket(addr string) error {
	switch {
	case addr == "":
		return errors.New("--listen-socket must not be empty")
	case addr == fmt.Sprintf("fd://%d", systemdSocketFD):
		return nil
	case strings.HasPrefix(addr, "fd://"):
		return fmt.Errorf("--listen-socket only supports fd://%d for socket activation, got: %s",
			systemdSocketFD, addr)
	case strings.HasPrefix(addr, "tcp://"),
		strings.HasPrefix(addr, "http://"),
		strings.HasPrefix(addr, "https://"),
		strings.HasPrefix(addr, "unix://"):
		return fmt.Errorf("--listen-socket only supports Unix socket paths, got: %s", addr)
	case strings.HasPrefix(addr, "@"), strings.HasPrefix(addr, "\x00"):
		return fmt.Errorf("--listen-socket must be a filesystem path; abstract sockets have no "+
			"permissions and would be reachable by any process, got: %s", addr)
	case !strings.HasPrefix(addr, "/"):
		return fmt.Errorf("--listen-socket must be an absolute path, got: %s", addr)
	}
	return nil
}

// validateDockerHost rejects non-Unix Docker daemon addresses. Connecting to the
// daemon over TCP would bypass the user/group ownership on the daemon socket,
// which is what constrains the proxy's own access.
func validateDockerHost(addr string) error {
	if addr == "" {
		return errors.New("--docker-host must not be empty")
	}
	for _, scheme := range []string{"tcp://", "http://", "https://", "unix://"} {
		if strings.HasPrefix(addr, scheme) {
			return fmt.Errorf("--docker-host only supports Unix socket paths, got: %s", addr)
		}
	}
	return nil
}

// listenerFromFile adopts an already-bound socket, as passed by systemd.
//
// Split out from unixListener so the type check can be exercised in tests
// against an arbitrary fd rather than only against the real fd 3, mirroring
// Rust's unix_listener_from_raw_fd.
func listenerFromFile(f *os.File) (net.Listener, error) {
	l, err := net.FileListener(f)
	if err != nil {
		return nil, err
	}
	// net.FileListener returns whatever the fd actually is. A unit with
	// ListenStream=127.0.0.1:2375 hands back a TCP socket, and serving it
	// would silently reinstate the TCP listener this proxy does not have.
	if _, ok := l.(*net.UnixListener); !ok {
		l.Close()
		return nil, fmt.Errorf("fd %d is a %T, not a Unix socket: set ListenStream to a "+
			"filesystem path in the .socket unit", systemdSocketFD, l)
	}
	return l, nil
}

// defaultListenSocketMode is the mode applied to the listening socket when
// --listen-socket-mode is not given. connect(2) on an AF_UNIX socket requires
// write permission, so 0660 is what actually grants the owning group access.
const defaultListenSocketMode = 0o660

// bindUmask is set around bind(2) so the socket is created at 0600 and is never
// briefly reachable by group or world. bind() applies 0777 &^ umask, and
// 0777 &^ 0177 == 0600. Correcting with chmod after the fact would leave a
// window in which the socket is already listening at the ambient mode.
const bindUmask = 0o177

// resolveGroup maps --listen-socket-group to a gid. A numeric value is used
// as-is so deployments without the group in /etc/group (or NSS) still work.
func resolveGroup(group string) (int, error) {
	if group == "" {
		return -1, nil
	}
	if gid, err := strconv.Atoi(group); err == nil {
		if gid < 0 {
			return -1, fmt.Errorf("--listen-socket-group %q: negative gid", group)
		}
		return gid, nil
	}
	g, err := user.LookupGroup(group)
	if err != nil {
		return -1, fmt.Errorf("--listen-socket-group %q: %w", group, err)
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return -1, fmt.Errorf("--listen-socket-group %q: gid %q is not numeric", group, g.Gid)
	}
	return gid, nil
}

// parseSocketMode accepts an octal mode and rejects anything world-writable.
// A world-writable socket is connectable by every local uid, which removes the
// boundary entirely, so there is deliberately no opt-out.
func parseSocketMode(s string) (os.FileMode, error) {
	if s == "" {
		return 0, fmt.Errorf("--listen-socket-mode must not be empty")
	}
	m, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("--listen-socket-mode %q: not an octal mode", s)
	}
	if m > 0o777 {
		return 0, fmt.Errorf("--listen-socket-mode %q: must be within 0777", s)
	}
	if m&0o002 != 0 {
		return 0, fmt.Errorf("--listen-socket-mode %q is world-writable: every local user "+
			"could connect to the proxy, which disables the access-control boundary", s)
	}
	return os.FileMode(m), nil
}

// unixListener binds the proxy's only listening socket. Listening is Unix-socket
// only by design: filesystem ownership on the socket is the access-control
// boundary, and a TCP listener would have none.
//
// The mode is set explicitly rather than inherited from the ambient umask.
// Left to the umask the socket is 0755 by default — connect(2) needs write, so
// the documented "add the caller to the socket's group" grant does not work —
// and 0777 under umask 0, which lets any local uid drive the Docker API.
func unixListener(addr string, mode os.FileMode, gid int) (net.Listener, error) {
	if addr == fmt.Sprintf("fd://%d", systemdSocketFD) {
		// Under socket activation systemd owns the socket and applies its own
		// SocketMode/SocketGroup. Re-chmod'ing it here would fight the unit.
		return listenerFromFile(os.NewFile(systemdSocketFD, "socket"))
	}

	// Remove a stale socket from a previous run, but only a socket: os.Remove
	// also unlinks regular files and rmdir's empty directories, so ignoring its
	// error would let a mistyped path silently delete an operator's data.
	if info, err := os.Lstat(addr); err == nil {
		if info.Mode()&fs.ModeSocket == 0 {
			return nil, fmt.Errorf("refusing to remove %s: not a socket (mode %s)", addr, info.Mode())
		}
		if err := os.Remove(addr); err != nil {
			return nil, fmt.Errorf("removing stale socket %s: %w", addr, err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("checking %s: %w", addr, err)
	}

	// umask is process-global and not thread-safe. This runs during startup,
	// before any request handling, so nothing else is creating files.
	old := syscall.Umask(bindUmask)
	l, err := net.Listen("unix", addr)
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}

	// Widen from 0600 to the configured mode only after ownership is right,
	// so the socket is never group-reachable by the wrong group.
	if gid >= 0 {
		if err := os.Chown(addr, -1, gid); err != nil {
			l.Close()
			return nil, fmt.Errorf("setting group on %s: %w", addr, err)
		}
	}
	if err := os.Chmod(addr, mode); err != nil {
		l.Close()
		return nil, fmt.Errorf("setting mode on %s: %w", addr, err)
	}

	return l, nil
}

// shutdownTimeout bounds how long in-flight requests are given to finish once
// a signal arrives. It is an upper bound, not a delay: shutdown returns as
// soon as the last request drains.
const shutdownTimeout = 30 * time.Second

// serve runs the proxy until ctx is cancelled and returns a channel that is
// closed once the server has finished draining. Callers must wait on that
// channel rather than on a timer, so that shutdown takes as long as the
// in-flight requests need and no longer.
func serve(ctx context.Context, listener net.Listener, addr string, handler http.Handler) <-chan struct{} {
	server := &http.Server{Handler: handler}
	done := make(chan struct{})
	served := make(chan struct{})

	go func() {
		defer close(served)
		slog.Info("listening", "network", "unix", "addr", addr)
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("server error", "network", "unix", "addr", addr, "error", err)
		}
	}()

	go func() {
		defer close(done)
		<-ctx.Done()
		// Shutdown closes idle keep-alive connections immediately and waits
		// only on active requests, so an idle proxy exits at once.
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer shutdownCancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			slog.Error("drain deadline exceeded", "addr", addr, "error", err)
		}
		// Shutdown can win the race against Serve even starting, in which case
		// Serve closes the listener on its own way out. Wait for that, or the
		// process can exit while the socket is still bound and leave the file
		// behind for the next start to clean up.
		<-served
	}()

	return done
}
