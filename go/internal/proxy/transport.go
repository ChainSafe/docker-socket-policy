package proxy

import (
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"syscall"
)

type ReverseProxy struct {
	proxy *httputil.ReverseProxy
}

func NewTransport(dockerHost string) *ReverseProxy {
	return &ReverseProxy{
		proxy: &httputil.ReverseProxy{
			Director: func(req *http.Request) {
				req.URL.Scheme = "http"
				req.URL.Host = "docker"
				req.RequestURI = ""
			},
			Transport: &http.Transport{
				Dial: func(network, addr string) (net.Conn, error) {
					return net.Dial("unix", dockerHost)
				},
			},
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				if isSocketPermissionDenied(err) {
					http.Error(w, "permission denied on Docker socket", http.StatusForbidden)
					return
				}
				http.Error(w, "proxy error: "+err.Error(), http.StatusBadGateway)
			},
		},
	}
}

// isSocketPermissionDenied reports whether the error chain originates from a
// permission failure connecting to the Docker Unix socket (EACCES or EPERM).
// Group-restricted sockets are the security model, so a permission denial on
// the socket surfaces as 403 Forbidden, indistinguishable from a middleware
// policy denial.
func isSocketPermissionDenied(err error) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	return errno == syscall.EACCES || errno == syscall.EPERM
}

func (t *ReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t.proxy.ServeHTTP(w, r)
}
