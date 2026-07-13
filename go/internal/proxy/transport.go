package proxy

import (
	"net"
	"net/http"
	"net/http/httputil"
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
		},
	}
}

func (t *ReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t.proxy.ServeHTTP(w, r)
}
