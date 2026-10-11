package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
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
		{"empty", "", "must not be empty"},
		// Socket activation was removed; fd:// is just another scheme now.
		{"fd 3", "fd://3", "only supports Unix socket paths"},
		{"other fd", "fd://4", "only supports Unix socket paths"},
		{"fd zero", "fd://0", "only supports Unix socket paths"},
		{"fd garbage", "fd://abc", "only supports Unix socket paths"},
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

// TestListenSocketModeFlagRemoved guards against the flag creeping back: the
// socket mode is fixed, and a deployment still passing the flag must fail at
// startup rather than silently get a different mode than it asked for.
func TestListenSocketModeFlagRemoved(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "docker-socket-policy")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	out, err := exec.Command(bin, "--listen-socket-mode=0660").CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 2 {
		t.Fatalf("running with --listen-socket-mode: err = %v, want exit status 2\n%s", err, out)
	}
	if !strings.Contains(string(out), "flag provided but not defined") {
		t.Fatalf("output = %q, want it to contain %q", out, "flag provided but not defined")
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

	l, err := unixListener(path, -1)
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

// seedStaleSocket leaves a socket file at path with nothing listening on it,
// as an unclean shutdown would: connect(2) to it is refused.
func seedStaleSocket(t *testing.T, path string) {
	t.Helper()
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("seeding stale socket: %v", err)
	}
	ul := l.(*net.UnixListener)
	ul.SetUnlinkOnClose(false)
	ul.Close()
}

func inode(t *testing.T, path string) uint64 {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return uint64(info.Sys().(*syscall.Stat_t).Ino)
}

func TestOpenListenerReplacesStaleSocket(t *testing.T) {
	path := filepath.Join(shortTempDir(t), "stale.sock")
	seedStaleSocket(t, path)

	l, lock, err := openListener(path, -1)
	if err != nil {
		t.Fatalf("openListener over stale socket = %v, want nil", err)
	}
	l.Close()
	lock.Close()
}

// TestPrepareSocketPath has one case per row of the existing-path table in
// spec/listener-design.md; the subtest names match the Quint runs.
func TestPrepareSocketPath(t *testing.T) {
	t.Run("pathAbsentBinds", func(t *testing.T) {
		path := filepath.Join(shortTempDir(t), "absent.sock")
		if err := prepareSocketPath(path); err != nil {
			t.Fatalf("prepareSocketPath(absent) = %v, want nil", err)
		}
	})

	t.Run("pathStaleReplaced", func(t *testing.T) {
		path := filepath.Join(shortTempDir(t), "stale.sock")
		seedStaleSocket(t, path)
		if err := prepareSocketPath(path); err != nil {
			t.Fatalf("prepareSocketPath(stale) = %v, want nil", err)
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stale socket still present after prepare: %v", err)
		}
	})

	t.Run("pathLiveRefused", func(t *testing.T) {
		path := filepath.Join(shortTempDir(t), "live.sock")
		l, err := net.Listen("unix", path)
		if err != nil {
			t.Fatalf("binding live socket: %v", err)
		}
		defer l.Close()
		before := inode(t, path)

		err = prepareSocketPath(path)
		if want := path + " is in use by another process"; err == nil || err.Error() != want {
			t.Fatalf("prepareSocketPath(live) = %v, want %q", err, want)
		}
		if after := inode(t, path); after != before {
			t.Fatalf("live socket inode changed %d -> %d: it was replaced", before, after)
		}

		accepted := make(chan error, 1)
		go func() {
			c, err := l.Accept()
			if err == nil {
				c.Close()
			}
			accepted <- err
		}()
		c, err := net.Dial("unix", path)
		if err != nil {
			t.Fatalf("live listener no longer reachable: %v", err)
		}
		c.Close()
		if err := <-accepted; err != nil {
			t.Fatalf("live listener no longer accepts: %v", err)
		}
	})

	// connect(2) needs write permission on the socket, so a 0000 socket
	// yields EACCES: neither live nor provably stale, so it is left alone.
	t.Run("pathConnectErrorRefused", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root ignores socket permissions")
		}
		path := filepath.Join(shortTempDir(t), "eacces.sock")
		seedStaleSocket(t, path)
		if err := os.Chmod(path, 0); err != nil {
			t.Fatal(err)
		}
		err := prepareSocketPath(path)
		if want := "refusing to remove " + path + ": connect: permission denied"; err == nil || err.Error() != want {
			t.Fatalf("prepareSocketPath(0000 socket) = %v, want %q", err, want)
		}
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("socket was removed: %v", err)
		}
	})

	t.Run("pathNotSocketRefused", func(t *testing.T) {
		path := filepath.Join(shortTempDir(t), "file.txt")
		if err := os.WriteFile(path, []byte("data"), 0o644); err != nil {
			t.Fatal(err)
		}
		err := prepareSocketPath(path)
		if want := "refusing to remove " + path + ": not a socket"; err == nil || !strings.HasPrefix(err.Error(), want) {
			t.Fatalf("prepareSocketPath(regular file) = %v, want prefix %q", err, want)
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("regular file was removed: %v", err)
		}
	})
}

// TestAcquireInstanceLock covers the Quint run secondInstanceLockRefused.
func TestAcquireInstanceLock(t *testing.T) {
	path := filepath.Join(shortTempDir(t), "lock.sock")

	first, err := acquireInstanceLock(path)
	if err != nil {
		t.Fatalf("first acquireInstanceLock = %v, want nil", err)
	}

	_, err = acquireInstanceLock(path)
	want := path + " is in use by another instance (lock " + path + ".lock held)"
	if err == nil || err.Error() != want {
		t.Fatalf("second acquireInstanceLock = %v, want %q", err, want)
	}

	info, err := os.Lstat(path + ".lock")
	if err != nil {
		t.Fatalf("stat lock file: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("lock file mode = %o, want 0600", got)
	}

	if err := first.Close(); err != nil {
		t.Fatalf("closing first lock: %v", err)
	}
	if _, err := os.Lstat(path + ".lock"); err != nil {
		t.Fatalf("lock file removed on Close, want it kept: %v", err)
	}

	second, err := acquireInstanceLock(path)
	if err != nil {
		t.Fatalf("acquireInstanceLock after Close = %v, want nil", err)
	}
	second.Close()
}

// A symlink planted at <path>.lock must not be followed: O_CREAT through it
// would create or lock a file of the attacker's choosing.
func TestAcquireInstanceLockRefusesSymlink(t *testing.T) {
	dir := shortTempDir(t)
	path := filepath.Join(dir, "sym.sock")
	target := filepath.Join(dir, "target")
	if err := os.Symlink(target, path+".lock"); err != nil {
		t.Fatal(err)
	}

	if f, err := acquireInstanceLock(path); err == nil {
		f.Close()
		t.Fatal("acquireInstanceLock through a symlink = nil, want error")
	} else if !strings.Contains(err.Error(), path+".lock") {
		t.Fatalf("error = %q, want it to name %s.lock", err, path)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("symlink target was created: %v", err)
	}
}

func TestAcquireInstanceLockUnreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores file permissions")
	}
	path := filepath.Join(shortTempDir(t), "unreadable.sock")
	if err := os.WriteFile(path+".lock", nil, 0o000); err != nil {
		t.Fatal(err)
	}

	if f, err := acquireInstanceLock(path); err == nil {
		f.Close()
		t.Fatal("acquireInstanceLock on a 0000 lock file = nil, want error")
	} else if !strings.Contains(err.Error(), path+".lock") {
		t.Fatalf("error = %q, want it to name %s.lock", err, path)
	}
}

// *os.File has a finalizer that closes the fd, which would drop the flock.
// The lock must hold for as long as main keeps its reference.
func TestInstanceLockSurvivesGC(t *testing.T) {
	path := filepath.Join(shortTempDir(t), "gc.sock")
	lock, err := acquireInstanceLock(path)
	if err != nil {
		t.Fatalf("acquireInstanceLock = %v", err)
	}

	runtime.GC()
	runtime.GC()

	if f, err := acquireInstanceLock(path); err == nil {
		f.Close()
		t.Fatal("lock was released by GC while still referenced")
	}
	lock.Close()
	runtime.KeepAlive(lock)
}

func TestOpenListenerConcurrent(t *testing.T) {
	dir := shortTempDir(t)
	const racers = 8

	type result struct {
		l    net.Listener
		lock *os.File
		err  error
	}

	for i := 0; i < 50; i++ {
		path := filepath.Join(dir, fmt.Sprintf("c%d.sock", i))
		start := make(chan struct{})
		results := make(chan result, racers)
		var wg sync.WaitGroup
		for j := 0; j < racers; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				l, lock, err := openListener(path, -1)
				results <- result{l, lock, err}
			}()
		}
		close(start)
		wg.Wait()
		close(results)

		var winner *result
		for r := range results {
			if r.err == nil {
				if winner != nil {
					t.Fatalf("iteration %d: more than one openListener succeeded", i)
				}
				r := r
				winner = &r
				continue
			}
			if want := path + " is in use by another instance (lock " + path + ".lock held)"; r.err.Error() != want {
				t.Fatalf("iteration %d: loser error = %q, want %q", i, r.err, want)
			}
		}
		if winner == nil {
			t.Fatalf("iteration %d: no openListener succeeded", i)
		}

		accepted := make(chan error, 1)
		go func() {
			c, err := winner.l.Accept()
			if err == nil {
				c.Close()
			}
			accepted <- err
		}()
		c, err := net.Dial("unix", path)
		if err != nil {
			t.Fatalf("iteration %d: dialing winner: %v", i, err)
		}
		c.Close()
		if err := <-accepted; err != nil {
			t.Fatalf("iteration %d: winner did not accept: %v", i, err)
		}

		winner.l.Close()
		winner.lock.Close()
	}
}

const holdLockEnv = "DSP_TEST_HOLD_LOCK"

// TestHelperHoldLock is not a test on its own: TestLockReleasedOnSIGKILL
// re-executes the test binary to run it as a child that holds the lock.
func TestHelperHoldLock(t *testing.T) {
	path := os.Getenv(holdLockEnv)
	if path == "" {
		t.Skip("helper process for TestLockReleasedOnSIGKILL")
	}
	lock, err := acquireInstanceLock(path)
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
	defer runtime.KeepAlive(lock)
	fmt.Println("ready")
	select {}
}

// TestLockReleasedOnSIGKILL covers the Quint run crashReleasesLock: the
// kernel drops the flock on any exit, so a killed instance never leaves a
// stale lock behind.
func TestLockReleasedOnSIGKILL(t *testing.T) {
	path := filepath.Join(shortTempDir(t), "kill.sock")

	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperHoldLock$")
	cmd.Env = append(os.Environ(), holdLockEnv+"="+path)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })

	ready := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if scanner.Text() == "ready" {
				ready <- nil
				return
			}
		}
		ready <- fmt.Errorf("child exited before holding the lock: %v", scanner.Err())
	}()
	select {
	case err := <-ready:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("child did not report ready within 10s")
	}

	if f, err := acquireInstanceLock(path); err == nil {
		f.Close()
		t.Fatal("acquired the lock while the child held it")
	}

	if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	cmd.Wait()

	lock, err := acquireInstanceLock(path)
	if err != nil {
		t.Fatalf("acquireInstanceLock after SIGKILL = %v, want nil", err)
	}
	lock.Close()
}

func TestOpenListenerRefusesToDeleteNonSocket(t *testing.T) {
	// A mistyped --listen-socket must not silently destroy data. os.Remove
	// would happily unlink a regular file and rmdir an empty directory.
	t.Run("regular file", func(t *testing.T) {
		path := filepath.Join(shortTempDir(t), "important.txt")
		if err := os.WriteFile(path, []byte("important data"), 0o644); err != nil {
			t.Fatal(err)
		}

		if _, _, err := openListener(path, -1); err == nil {
			t.Fatal("openListener over a regular file = nil, want error")
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

		if _, _, err := openListener(path, -1); err == nil {
			t.Fatal("openListener over a directory = nil, want error")
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("directory was removed: %v", err)
		}
	})
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
	l, err := unixListener(path, -1)
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
	l, err := unixListener(path, -1)
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
	l, err := unixListener(path, -1)
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

// TestUnixListenerAppliesMode is the regression test for #40: the mode used to
// be whatever the umask left behind, which is 0755 by default. connect(2)
// requires write permission, so the group grant the README documents silently
// did not work, and under umask 0 the socket was 0777 to every local uid.
func TestUnixListenerAppliesMode(t *testing.T) {
	path := filepath.Join(shortTempDir(t), "mode.sock")
	l, err := unixListener(path, -1)
	if err != nil {
		t.Fatalf("unixListener: %v", err)
	}
	defer l.Close()

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o660 {
		t.Fatalf("socket mode = %o, want 0660", got)
	}
}

// The ambient umask must not influence the result: that was the whole bug.
func TestUnixListenerIgnoresAmbientUmask(t *testing.T) {
	// umask 0 is the dangerous case — it used to produce a 0777 socket.
	old := syscall.Umask(0)
	defer syscall.Umask(old)

	path := filepath.Join(shortTempDir(t), "umask.sock")
	l, err := unixListener(path, -1)
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

func TestResolveGroupRejectsOutOfRangeGid(t *testing.T) {
	// 4294967295 is chown's "don't change" sentinel and larger values would
	// be truncated to their low 32 bits (4294967296 -> 0, root).
	if gid, err := resolveGroup("4294967294"); err != nil || gid != 4294967294 {
		t.Fatalf("resolveGroup(\"4294967294\") = %d, %v; want 4294967294, nil", gid, err)
	}
	for _, v := range []string{"4294967295", "4294967296", "12345678901234567890"} {
		_, err := resolveGroup(v)
		want := fmt.Sprintf("--listen-socket-group %q: gid out of range (0-4294967294)", v)
		if err == nil || err.Error() != want {
			t.Fatalf("resolveGroup(%q) error = %v, want %q", v, err, want)
		}
	}
	// Only a digit string is numeric; a sign makes it a (nonexistent) name.
	for _, v := range []string{"+4294967296", "+5"} {
		if gid, err := resolveGroup(v); err == nil {
			t.Fatalf("resolveGroup(%q) = %d, nil; want an error", v, gid)
		}
	}
	if _, err := resolveGroup("-5"); err == nil || !strings.Contains(err.Error(), "negative gid") {
		t.Fatalf("resolveGroup(\"-5\") error = %v, want a negative gid error", err)
	}
}

// TestSelectSocketGroup has one case per row of the group-selection table in
// spec/listener-design.md; the subtest names match the Quint runs.
func TestSelectSocketGroup(t *testing.T) {
	const egid = 65532
	known := func(groups map[string]int) func(string) (int, error) {
		return func(name string) (int, error) {
			if gid, ok := groups[name]; ok {
				return gid, nil
			}
			return -1, fmt.Errorf("--listen-socket-group %q: unknown group", name)
		}
	}
	both := known(map[string]int{"docker-socket-policy": 2001, "ops": 3001})

	tests := []struct {
		name        string
		flagValue   *string
		lookup      func(string) (int, error)
		wantGID     int
		wantWarning string
		wantErr     bool
	}{
		{"groupDefaultPresent", nil, both, 2001, "", false},
		{"groupDefaultMissingWarns", nil, known(nil), egid,
			"group docker-socket-policy not found, using the proxy's own group 65532", false},
		{"groupExplicitPresent", ptr("ops"), both, 3001, "", false},
		{"groupExplicitMissingFails", ptr("nope"), both, 0, "", true},
		{"groupEmptyUsesOwn", ptr(""), both, egid, "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gid, warning, err := selectSocketGroup(tt.flagValue, tt.lookup, egid)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("selectSocketGroup = %d, %q, nil; want an error", gid, warning)
				}
				return
			}
			if err != nil {
				t.Fatalf("selectSocketGroup error = %v, want nil", err)
			}
			if gid != tt.wantGID {
				t.Fatalf("gid = %d, want %d", gid, tt.wantGID)
			}
			if warning != tt.wantWarning {
				t.Fatalf("warning = %q, want %q", warning, tt.wantWarning)
			}
		})
	}
}

// groupFlagFromArgs parses args with a fresh flag set and reports the
// --listen-socket-group value the way main does, via flagValueIfSet.
func groupFlagFromArgs(args []string) *string {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("listen-socket-group", "", "")
	if err := fs.Parse(args); err != nil {
		panic(err)
	}
	return flagValueIfSet(fs, "listen-socket-group")
}

// An explicit empty value means "the proxy's own group" and must not be
// confused with the flag being absent, which means the default group.
func TestFlagEmptyVsAbsent(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want *string
	}{
		{"absent", []string{}, nil},
		{"equals empty", []string{"--listen-socket-group="}, ptr("")},
		{"separate empty", []string{"--listen-socket-group", ""}, ptr("")},
		{"named", []string{"--listen-socket-group=ops"}, ptr("ops")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := groupFlagFromArgs(tt.args)
			switch {
			case tt.want == nil && got != nil:
				t.Fatalf("groupFlagFromArgs(%q) = %q, want nil", tt.args, *got)
			case tt.want != nil && got == nil:
				t.Fatalf("groupFlagFromArgs(%q) = nil, want %q", tt.args, *tt.want)
			case tt.want != nil && *got != *tt.want:
				t.Fatalf("groupFlagFromArgs(%q) = %q, want %q", tt.args, *got, *tt.want)
			}
		})
	}
}

func ptr(s string) *string { return &s }

// A non-root proxy that is not a member of the selected group cannot chown the
// socket to it. The error must say what to fix rather than surface a bare EPERM.
func TestUnixListenerChownEPERMNamesGroup(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can chown to any group")
	}
	if os.Getegid() == 0 {
		t.Skip("process's own group is gid 0, so chown to it succeeds")
	}
	if groups, err := os.Getgroups(); err == nil {
		for _, g := range groups {
			if g == 0 {
				t.Skip("process is a member of gid 0, so chown to it succeeds")
			}
		}
	}
	dir := shortTempDir(t)
	// BSD semantics (macOS) give a new file its directory's group, which is
	// gid 0 under /tmp, and chown to the current group is always allowed.
	// Give the directory our own group so the socket starts out not in gid 0.
	if err := os.Chown(dir, -1, os.Getegid()); err != nil {
		t.Fatalf("chown temp dir to egid: %v", err)
	}
	path := filepath.Join(dir, "eperm.sock")
	l, err := unixListener(path, 0)
	if err == nil {
		l.Close()
		t.Fatal("unixListener(path, 0) as non-root = nil, want EPERM")
	}
	if want := "the proxy's user must be a member of it"; !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %q, want it to contain %q", err, want)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket left on disk after chown failed: Lstat err = %v", err)
	}
}
