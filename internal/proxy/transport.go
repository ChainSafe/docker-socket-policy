package proxy

import (
	"net"
	"net/http"
	"net/http/httputil"
)

// ReverseProxy is a proxy that forwards HTTP requests to a Docker daemon
// over a Unix socket.
type ReverseProxy struct {
	proxy *httputil.ReverseProxy
}

// NewTransport creates a ReverseProxy that connects to the Docker daemon
// at the given Unix socket path.
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
		},
	}
}

// ServeHTTP forwards the request to the Docker daemon and writes the response.
func (t *ReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t.proxy.ServeHTTP(w, r)
}
