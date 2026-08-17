package proxy

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"syscall"
	"testing"
)

func TestTransport_NonExistentSocketReturns502(t *testing.T) {
	tr := NewTransport("/nonexistent/docker.sock")
	req := httptest.NewRequest("GET", "/_ping", nil)
	rec := httptest.NewRecorder()

	tr.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 for non-existent socket, got %d", rec.Code)
	}
}

func TestTransport_SocketPermissionReturns403(t *testing.T) {
	// EACCES mapped to 403 — group-restricted socket denial must be
	// indistinguishable from a middleware policy denial.
	tr := NewTransport("/nonexistent/docker.sock")
	proxy := tr.proxy

	errHandler := proxy.ErrorHandler
	if errHandler == nil {
		t.Fatal("expected proxy to have an error handler")
	}

	rec := httptest.NewRecorder()
	errHandler(rec, httptest.NewRequest("GET", "/_ping", nil), syscall.EACCES)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for EACCES, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	errHandler(rec, httptest.NewRequest("GET", "/_ping", nil), syscall.EPERM)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for EPERM, got %d", rec.Code)
	}
}

func TestIsSocketPermissionDenied(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"bare EACCES", syscall.EACCES, true},
		{"bare EPERM", syscall.EPERM, true},
		{"wrapped EACCES", &osPathError{parent: &osSyscallError{err: syscall.EACCES}}, true},
		{"ECONNREFUSED", syscall.ECONNREFUSED, false},
		{"generic error", errors.New("boom"), false},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isSocketPermissionDenied(tc.err); got != tc.want {
				t.Fatalf("isSocketPermissionDenied(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// Minimal wrap chain replicating the net/http error shape for a failed dial
// (os.PathError -> os.SyscallError -> underlying errno).
type osPathError struct {
	parent error
}

func (e *osPathError) Error() string { return "dial: " + e.parent.Error() }
func (e *osPathError) Unwrap() error { return e.parent }

type osSyscallError struct {
	err error
}

func (e *osSyscallError) Error() string { return "connect: " + e.err.Error() }
func (e *osSyscallError) Unwrap() error { return e.err }