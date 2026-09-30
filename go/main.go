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
	"runtime"
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
		"Unix socket path to listen on")
	dockerHost := flag.String("docker-host", "/var/run/docker.sock",
		"Docker daemon socket path")
	configDir := flag.String("config-dir", "/etc/docker-socket-policy/services",
		"Policy config directory")
	logFile := flag.String("log-file", "/var/log/docker-socket-policy.log",
		"Audit log file (JSON)")
	readonly := flag.Bool("readonly", false,
		"Enable read-only mode (deny all POST/PUT/DELETE)")
	// The value is read with flagValueIfSet, never through the returned
	// pointer: absent (default group) and "" (own group) must stay distinct.
	flag.String("listen-socket-group", "",
		`Group owning the socket (default docker-socket-policy; "" = the proxy's own group)`)
	flag.Parse()

	if err := validateListenSocket(*listenSocket); err != nil {
		slog.Error(err.Error())
		os.Exit(2)
	}
	if err := validateDockerHost(*dockerHost); err != nil {
		slog.Error(err.Error())
		os.Exit(2)
	}
	socketGID, warning, err := selectSocketGroup(
		flagValueIfSet(flag.CommandLine, "listen-socket-group"), resolveGroup, os.Getegid())
	if err != nil {
		slog.Error(err.Error())
		os.Exit(2)
	}
	if warning != "" {
		slog.Warn(warning)
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

	listener, lock, err := openListener(*listenSocket, socketGID)
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
	// Release the lock only once the socket is closed and unlinked, so the
	// next instance never finds our socket still in place.
	lock.Close()
	slog.Info("shutdown complete")
	// *os.File closes its fd from a finalizer once unreachable, which would
	// drop the flock early; keep lock reachable until main returns.
	runtime.KeepAlive(lock)
}

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
	case strings.HasPrefix(addr, "fd://"),
		strings.HasPrefix(addr, "tcp://"),
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

// socketMode is the mode applied to the listening socket. connect(2) on an
// AF_UNIX socket requires write permission, so 0660 is what actually grants the
// owning group access.
const socketMode os.FileMode = 0o660

// bindUmask is set around bind(2) so the socket is created at 0600 and is never
// briefly reachable by group or world. bind() applies 0777 &^ umask, and
// 0777 &^ 0177 == 0600. Correcting with chmod after the fact would leave a
// window in which the socket is already listening at the ambient mode.
const bindUmask = 0o177

// defaultSocketGroup is the group the socket is given when
// --listen-socket-group is not passed, as dockerd defaults to "docker".
const defaultSocketGroup = "docker-socket-policy"

// flagValueIfSet returns the value of the named flag if it was passed on the
// command line, or nil if it was not. It distinguishes an absent flag from one
// explicitly set to "".
func flagValueIfSet(fs *flag.FlagSet, name string) *string {
	var value *string
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			v := f.Value.String()
			value = &v
		}
	})
	return value
}

// selectSocketGroup picks the socket's group the way dockerd does
// (moby/daemon/listeners/listeners_linux.go). A nil flagValue means the flag
// was not passed: the default group is used if it exists, and otherwise the
// proxy falls back to its own group with a warning. An explicit group that
// does not resolve is an error. An explicit "" selects the proxy's own group.
func selectSocketGroup(flagValue *string, lookup func(string) (int, error), egid int) (int, string, error) {
	if flagValue == nil {
		gid, err := lookup(defaultSocketGroup)
		if err != nil {
			return egid, fmt.Sprintf("group %s not found, using the proxy's own group %d",
				defaultSocketGroup, egid), nil
		}
		return gid, "", nil
	}
	if *flagValue == "" {
		return egid, "", nil
	}
	gid, err := lookup(*flagValue)
	if err != nil {
		return -1, "", err
	}
	return gid, "", nil
}

// resolveGroup maps a group name or gid to a gid. A numeric value is used
// as-is so deployments without the group in /etc/group (or NSS) still work.
func resolveGroup(group string) (int, error) {
	if isAllDigits(group) {
		// 4294967295 is chown's "don't change" sentinel, and chown keeps only
		// the low 32 bits of anything larger (4294967296 would become root).
		gid, err := strconv.ParseUint(group, 10, 32)
		if err != nil || gid > maxSocketGid {
			return -1, fmt.Errorf("--listen-socket-group %q: gid out of range (0-%d)", group, maxSocketGid)
		}
		return int(gid), nil
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

const maxSocketGid = 4294967294

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// openListener takes the single-instance lock, clears the socket path and
// binds it. The returned lock must be held, and kept reachable, for the life
// of the process: dropping it would let a second instance take the path.
func openListener(addr string, gid int) (net.Listener, *os.File, error) {
	lock, err := acquireInstanceLock(addr)
	if err != nil {
		return nil, nil, err
	}
	if err := prepareSocketPath(addr); err != nil {
		lock.Close()
		return nil, nil, err
	}
	l, err := unixListener(addr, gid)
	if err != nil {
		lock.Close()
		return nil, nil, err
	}
	return l, lock, nil
}

// acquireInstanceLock takes an exclusive flock on <socketPath>.lock, which
// replaces dockerd's pidfile. The kernel drops the lock on any exit, including
// SIGKILL, so it never goes stale, and it needs no PID check, so it also works
// across PID namespaces. The file is never truncated or unlinked: unlinking a
// lock file reopens the race it exists to close. O_NOFOLLOW stops a symlink
// planted at the lock path from redirecting O_CREAT elsewhere.
func acquireInstanceLock(socketPath string) (*os.File, error) {
	lockPath := socketPath + ".lock"
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening lock %s: %w", lockPath, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("%s is in use by another instance (lock %s held)", socketPath, lockPath)
		}
		return nil, fmt.Errorf("locking %s: %w", lockPath, err)
	}
	return f, nil
}

// probeTimeout bounds the connect(2) that tells a live socket from a stale one.
const probeTimeout = time.Second

// prepareSocketPath clears the socket path for bind, following the
// existing-path table in spec/listener-design.md. Only a socket that refuses
// connections is removed. A live one belongs to another process, possibly an
// instance that takes no lock (TypeScript, or v0.2.21 and earlier), and
// replacing it would cut that process off silently. Anything that is not a
// socket is refused: os.Remove also unlinks regular files and rmdir's empty
// directories, so a mistyped path would silently delete an operator's data.
func prepareSocketPath(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("checking %s: %w", path, err)
	}
	if info.Mode()&fs.ModeSocket == 0 {
		return fmt.Errorf("refusing to remove %s: not a socket (mode %s)", path, info.Mode())
	}

	conn, err := net.DialTimeout("unix", path, probeTimeout)
	if err == nil {
		conn.Close()
		return fmt.Errorf("%s is in use by another process", path)
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return fmt.Errorf("%s is in use by another process", path)
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		var errno syscall.Errno
		if errors.As(err, &errno) {
			return fmt.Errorf("refusing to remove %s: connect: %w", path, errno)
		}
		return fmt.Errorf("refusing to remove %s: %w", path, err)
	}

	if err := os.Remove(path); err != nil {
		return fmt.Errorf("removing stale socket %s: %w", path, err)
	}
	return nil
}

// unixListener binds the proxy's only listening socket. Listening is Unix-socket
// only by design: filesystem ownership on the socket is the access-control
// boundary, and a TCP listener would have none.
//
// The mode is set explicitly rather than inherited from the ambient umask.
// Left to the umask the socket is 0755 by default — connect(2) needs write, so
// the documented "add the caller to the socket's group" grant does not work —
// and 0777 under umask 0, which lets any local uid drive the Docker API.
//
// main always passes the gid chosen by selectSocketGroup; a negative gid skips
// the chown and exists only for tests.
//
// The path must already be clear; openListener runs prepareSocketPath first.
func unixListener(addr string, gid int) (net.Listener, error) {
	// umask is process-global and not thread-safe. This runs during startup,
	// before any request handling, so nothing else is creating files.
	old := syscall.Umask(bindUmask)
	l, err := net.Listen("unix", addr)
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}

	// Widen from 0600 to socketMode only after ownership is right,
	// so the socket is never group-reachable by the wrong group.
	if gid >= 0 {
		if err := os.Chown(addr, -1, gid); err != nil {
			l.Close()
			if errors.Is(err, syscall.EPERM) {
				return nil, fmt.Errorf("cannot give %s to group %d: the proxy's user must be a member of it "+
					"(SupplementaryGroups= / group_add:)", addr, gid)
			}
			return nil, fmt.Errorf("setting group on %s: %w", addr, err)
		}
	}
	if err := os.Chmod(addr, socketMode); err != nil {
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
