package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestValidateListenSocket(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		wantErr string // substring; empty means the value must be accepted
	}{
		{"absolute path", "/var/run/docker-socket-policy.sock", ""},
		{"systemd activation", "fd://3", ""},
		{"empty", "", "must not be empty"},
		{"other fd", "fd://4", "only supports fd://3"},
		{"fd zero", "fd://0", "only supports fd://3"},
		{"fd garbage", "fd://abc", "only supports fd://3"},
		// The flag this proxy deliberately no longer has. Someone migrating
		// from --listen-tcp is likely to carry the value across.
		{"tcp scheme", "tcp://0.0.0.0:2375", "only supports Unix socket paths"},
		{"http scheme", "http://0.0.0.0:2375", "only supports Unix socket paths"},
		{"https scheme", "https://0.0.0.0:2375", "only supports Unix socket paths"},
		{"unix scheme", "unix:///var/run/d.sock", "only supports Unix socket paths"},
		// Go's net package maps a leading "@" to the Linux abstract namespace,
		// where the socket has no inode, no mode and no owner.
		{"abstract at-sign", "@dsp", "abstract sockets have no permissions"},
		{"abstract nul", "\x00dsp", "abstract sockets have no permissions"},
		// The likeliest --listen-tcp migration mistake: drop the scheme, keep
		// the address. Binding it would create a file named "0.0.0.0:2375".
		{"bare host port", "0.0.0.0:2375", "must be an absolute path"},
		{"relative path", "dsp.sock", "must be an absolute path"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateListenSocket(tt.addr)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validateListenSocket(%q) = %v, want nil", tt.addr, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("validateListenSocket(%q) = nil, want error containing %q", tt.addr, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("validateListenSocket(%q) = %q, want it to contain %q", tt.addr, err, tt.wantErr)
			}
		})
	}
}

func TestValidateDockerHost(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		wantErr string
	}{
		{"unix path", "/var/run/docker.sock", ""},
		{"empty", "", "must not be empty"},
		// Reaching the daemon over TCP would bypass the user/group ownership
		// on the daemon socket, which is what constrains the proxy itself.
		{"tcp scheme", "tcp://dind:2375", "only supports Unix socket paths"},
		{"http scheme", "http://dind:2375", "only supports Unix socket paths"},
		{"https scheme", "https://dind:2375", "only supports Unix socket paths"},
		{"unix scheme", "unix:///var/run/docker.sock", "only supports Unix socket paths"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDockerHost(tt.addr)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validateDockerHost(%q) = %v, want nil", tt.addr, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("validateDockerHost(%q) = %v, want error containing %q", tt.addr, err, tt.wantErr)
			}
		})
	}
}

// shortTempDir returns a temp dir under /tmp rather than t.TempDir().
// sun_path is capped at 104 bytes on macOS and 108 on Linux, and the
// per-test paths t.TempDir() produces on macOS exceed that, so binding
// inside one fails with EINVAL regardless of the code under test.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "dsp-test-")
	if err != nil {
		t.Fatalf("creating temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func TestUnixListenerBindsFreshPath(t *testing.T) {
	path := filepath.Join(shortTempDir(t), "fresh.sock")

	l, err := unixListener(path, defaultListenSocketMode, -1)
	if err != nil {
		t.Fatalf("unixListener(%q) = %v, want nil", path, err)
	}
	defer l.Close()

	if _, ok := l.(*net.UnixListener); !ok {
		t.Fatalf("unixListener returned %T, want *net.UnixListener", l)
	}
	if info, err := os.Lstat(path); err != nil {
		t.Fatalf("socket not created: %v", err)
	} else if info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("created %s, want a socket", info.Mode())
	}
}

func TestUnixListenerReplacesStaleSocket(t *testing.T) {
	path := filepath.Join(shortTempDir(t), "stale.sock")

	// Leave a real socket behind, as an unclean shutdown would.
	first, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("seeding stale socket: %v", err)
	}
	first.Close()
	// net.Listen's listener unlinks on Close, so recreate the stale entry.
	stale, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("re-seeding stale socket: %v", err)
	}
	_ = stale

	l, err := unixListener(path, defaultListenSocketMode, -1)
	if err != nil {
		t.Fatalf("unixListener over stale socket = %v, want nil", err)
	}
	l.Close()
}

func TestUnixListenerRefusesToDeleteNonSocket(t *testing.T) {
	// A mistyped --listen-socket must not silently destroy data. os.Remove
	// would happily unlink a regular file and rmdir an empty directory.
	t.Run("regular file", func(t *testing.T) {
		path := filepath.Join(shortTempDir(t), "important.txt")
		if err := os.WriteFile(path, []byte("important data"), 0o644); err != nil {
			t.Fatal(err)
		}

		if _, err := unixListener(path, defaultListenSocketMode, -1); err == nil {
			t.Fatal("unixListener over a regular file = nil, want error")
		} else if !strings.Contains(err.Error(), "not a socket") {
			t.Fatalf("error = %q, want it to mention 'not a socket'", err)
		}

		if got, err := os.ReadFile(path); err != nil {
			t.Fatalf("file was destroyed: %v", err)
		} else if string(got) != "important data" {
			t.Fatalf("file contents = %q, want them untouched", got)
		}
	})

	t.Run("directory", func(t *testing.T) {
		path := filepath.Join(shortTempDir(t), "adir")
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Fatal(err)
		}

		if _, err := unixListener(path, defaultListenSocketMode, -1); err == nil {
			t.Fatal("unixListener over a directory = nil, want error")
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("directory was removed: %v", err)
		}
	})
}

// TestListenerFromFileRejectsTCPSocket is the regression guard for the hole
// that motivated validating socket activation at all: net.FileListener returns
// whatever the fd actually is, so a .socket unit with
// ListenStream=127.0.0.1:2375 would otherwise reinstate a TCP listener while
// the proxy logged "listening network=unix".
func TestListenerFromFileRejectsTCPSocket(t *testing.T) {
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("creating TCP listener: %v", err)
	}
	defer tcp.Close()

	f, err := tcp.(*net.TCPListener).File()
	if err != nil {
		t.Fatalf("extracting TCP fd: %v", err)
	}
	defer f.Close()

	l, err := listenerFromFile(f)
	if err == nil {
		l.Close()
		t.Fatal("listenerFromFile accepted a TCP socket, want an error")
	}
	if !strings.Contains(err.Error(), "not a Unix socket") {
		t.Fatalf("error = %q, want it to mention 'not a Unix socket'", err)
	}
}

// TestListenerFromFileAcceptsUnixSocket is the positive half: genuine socket
// activation must still work.
func TestListenerFromFileAcceptsUnixSocket(t *testing.T) {
	path := filepath.Join(shortTempDir(t), "activated.sock")
	unix, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("creating Unix listener: %v", err)
	}
	defer unix.Close()

	f, err := unix.(*net.UnixListener).File()
	if err != nil {
		t.Fatalf("extracting Unix fd: %v", err)
	}
	defer f.Close()

	l, err := listenerFromFile(f)
	if err != nil {
		t.Fatalf("listenerFromFile on a Unix socket = %v, want nil", err)
	}
	defer l.Close()

	if _, ok := l.(*net.UnixListener); !ok {
		t.Fatalf("listenerFromFile returned %T, want *net.UnixListener", l)
	}
}

// unixClient returns an HTTP client that talks to a Unix socket.
func unixClient(path string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", path)
			},
		},
	}
}

// TestServeReturnsPromptlyWhenIdle is the regression test for the shutdown
// path. main() used to wait on the shutdown timeout context itself, so every
// signal cost a fixed 30s whether or not anything was in flight. docker stop
// allows 10s before SIGKILL, so the proxy was always killed and graceful
// shutdown never once completed. Nothing caught it because the integration
// suites assert HTTP status codes and cannot observe process lifecycle.
func TestServeReturnsPromptlyWhenIdle(t *testing.T) {
	path := filepath.Join(shortTempDir(t), "idle.sock")
	l, err := unixListener(path, defaultListenSocketMode, -1)
	if err != nil {
		t.Fatalf("unixListener: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := serve(ctx, l, path, http.NotFoundHandler())

	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("serve did not return within 5s of cancellation; "+
			"shutdownTimeout is %s, so this is the fixed-delay bug", shutdownTimeout)
	}
}

// TestServeWaitsForInFlightRequest guards the opposite failure: exiting fast
// is only correct if it still drains. A handler that is mid-response when the
// signal arrives must be allowed to finish.
func TestServeWaitsForInFlightRequest(t *testing.T) {
	path := filepath.Join(shortTempDir(t), "inflight.sock")
	l, err := unixListener(path, defaultListenSocketMode, -1)
	if err != nil {
		t.Fatalf("unixListener: %v", err)
	}

	const work = 300 * time.Millisecond
	started := make(chan struct{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		time.Sleep(work)
		w.WriteHeader(http.StatusTeapot)
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := serve(ctx, l, path, handler)

	type result struct {
		code int
		err  error
	}
	res := make(chan result, 1)
	go func() {
		resp, err := unixClient(path).Get("http://localhost/slow")
		if err != nil {
			res <- result{err: err}
			return
		}
		defer resp.Body.Close()
		res <- result{code: resp.StatusCode}
	}()

	// Signal only once the handler is genuinely mid-flight.
	<-started
	cancel()

	select {
	case r := <-res:
		if r.err != nil {
			t.Fatalf("in-flight request aborted by shutdown: %v", r.err)
		}
		if r.code != http.StatusTeapot {
			t.Fatalf("in-flight request got %d, want %d", r.code, http.StatusTeapot)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight request never completed")
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not return after the in-flight request drained")
	}
}

// TestServeStopsAcceptingAfterShutdown confirms the listener is actually
// closed, not merely ignored: a connection attempt after shutdown must fail.
func TestServeStopsAcceptingAfterShutdown(t *testing.T) {
	path := filepath.Join(shortTempDir(t), "closed.sock")
	l, err := unixListener(path, defaultListenSocketMode, -1)
	if err != nil {
		t.Fatalf("unixListener: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := serve(ctx, l, path, http.NotFoundHandler())
	cancel()
	<-done

	if _, err := net.Dial("unix", path); err == nil {
		t.Fatal("connected after shutdown, want the listener closed")
	}
}

func TestParseSocketMode(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    os.FileMode
		wantErr string
	}{
		{"default", "0660", 0o660, ""},
		{"no leading zero", "660", 0o660, ""},
		{"owner only", "0600", 0o600, ""},
		{"group read only", "0640", 0o640, ""},
		{"empty", "", 0, "must not be empty"},
		{"not octal", "0x1ff", 0, "not an octal mode"},
		{"decimal 8 is invalid octal", "668", 0, "not an octal mode"},
		{"too wide", "1777", 0, "within 0777"},
		// connect(2) needs write, so o+w means every local uid can connect.
		{"world writable", "0666", 0, "world-writable"},
		{"world writable 0777", "0777", 0, "world-writable"},
		{"world writable 0602", "0602", 0, "world-writable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseSocketMode(tt.in)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("parseSocketMode(%q) = %v, want nil", tt.in, err)
				}
				if got != tt.want {
					t.Fatalf("parseSocketMode(%q) = %o, want %o", tt.in, got, tt.want)
				}
				return
			}
			if err == nil {
				t.Fatalf("parseSocketMode(%q) = nil error, want %q", tt.in, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("parseSocketMode(%q) error = %q, want it to contain %q", tt.in, err, tt.wantErr)
			}
		})
	}
}

// TestUnixListenerAppliesMode is the regression test for #40: the mode used to
// be whatever the umask left behind, which is 0755 by default. connect(2)
// requires write permission, so the group grant the README documents silently
// did not work, and under umask 0 the socket was 0777 to every local uid.
func TestUnixListenerAppliesMode(t *testing.T) {
	for _, mode := range []os.FileMode{0o660, 0o600, 0o640} {
		t.Run(fmt.Sprintf("%o", mode), func(t *testing.T) {
			path := filepath.Join(shortTempDir(t), "mode.sock")
			l, err := unixListener(path, mode, -1)
			if err != nil {
				t.Fatalf("unixListener: %v", err)
			}
			defer l.Close()

			info, err := os.Lstat(path)
			if err != nil {
				t.Fatalf("stat: %v", err)
			}
			if got := info.Mode().Perm(); got != mode {
				t.Fatalf("socket mode = %o, want %o", got, mode)
			}
		})
	}
}

// The ambient umask must not influence the result: that was the whole bug.
func TestUnixListenerIgnoresAmbientUmask(t *testing.T) {
	// umask 0 is the dangerous case — it used to produce a 0777 socket.
	old := syscall.Umask(0)
	defer syscall.Umask(old)

	path := filepath.Join(shortTempDir(t), "umask.sock")
	l, err := unixListener(path, 0o660, -1)
	if err != nil {
		t.Fatalf("unixListener: %v", err)
	}
	defer l.Close()

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o660 {
		t.Fatalf("socket mode = %o under umask 0, want 0660", got)
	}
	if info.Mode().Perm()&0o002 != 0 {
		t.Fatal("socket is world-writable: any local uid could connect")
	}
}

func TestResolveGroup(t *testing.T) {
	if gid, err := resolveGroup(""); err != nil || gid != -1 {
		t.Fatalf("resolveGroup(\"\") = %d, %v; want -1, nil", gid, err)
	}
	// A numeric value is taken as a gid without consulting /etc/group, so a
	// container without the group defined can still be configured.
	if gid, err := resolveGroup("2001"); err != nil || gid != 2001 {
		t.Fatalf("resolveGroup(\"2001\") = %d, %v; want 2001, nil", gid, err)
	}
	if _, err := resolveGroup("definitely-no-such-group-xyz"); err == nil {
		t.Fatal("resolveGroup on an unknown group = nil error, want a failure")
	}
	// Every Unix has gid 0 under some name; resolve it by name and check it
	// round-trips to a number.
	if g, err := user.LookupGroupId("0"); err == nil {
		if gid, err := resolveGroup(g.Name); err != nil || gid != 0 {
			t.Fatalf("resolveGroup(%q) = %d, %v; want 0, nil", g.Name, gid, err)
		}
	}
}
