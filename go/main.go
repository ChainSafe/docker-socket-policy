package main

import (
	"context"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
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

// unixListener binds the proxy's only listening socket. Listening is Unix-socket
// only by design: peer credentials and filesystem ownership on the socket are the
// access-control boundary, and a TCP listener would have neither.
func unixListener(addr string) (net.Listener, error) {
	if addr == "fd://3" {
		return net.FileListener(os.NewFile(3, "socket"))
	}
	_ = os.Remove(addr)
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
