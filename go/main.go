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
	flag.Parse()

	if err := validateListenSocket(*listenSocket); err != nil {
		slog.Error(err.Error())
		os.Exit(2)
	}
	if err := validateDockerHost(*dockerHost); err != nil {
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

	listener, err := unixListener(*listenSocket)
	if err != nil {
		slog.Error("failed to start listener", "addr", *listenSocket, "error", err)
		os.Exit(1)
	}

	go serve(ctx, listener, *listenSocket, handler)

	<-ctx.Done()
	slog.Info("shutting down...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	<-shutdownCtx.Done()
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

// unixListener binds the proxy's only listening socket. Listening is Unix-socket
// only by design: filesystem ownership on the socket is the access-control
// boundary, and a TCP listener would have none.
func unixListener(addr string) (net.Listener, error) {
	if addr == fmt.Sprintf("fd://%d", systemdSocketFD) {
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

	return net.Listen("unix", addr)
}

func serve(ctx context.Context, listener net.Listener, addr string, handler http.Handler) {
	server := &http.Server{Handler: handler}
	go func() {
		<-ctx.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()
		server.Shutdown(shutdownCtx)
	}()

	slog.Info("listening", "network", "unix", "addr", addr)
	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		slog.Error("server error", "network", "unix", "addr", addr, "error", err)
	}
}
