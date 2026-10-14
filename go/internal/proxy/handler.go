package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/ChainSafe/docker-socket-policy/go/internal/audit"
	"github.com/ChainSafe/docker-socket-policy/go/internal/middleware"
)

type Transport interface {
	ServeHTTP(w http.ResponseWriter, r *http.Request)
}

type Handler struct {
	router    *Router
	chain     *middleware.Chain
	auditLog  *audit.Logger
	transport Transport
}

func NewHandler(router *Router, chain *middleware.Chain, auditLog *audit.Logger, transport Transport) *Handler {
	return &Handler{
		router:    router,
		chain:     chain,
		auditLog:  auditLog,
		transport: transport,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Refuse CONNECT before anything else, whatever its target or headers: it
	// asks for a tunnel, which the proxy never provides (#78).
	if r.Method == http.MethodConnect {
		const msg = "CONNECT is not allowed"
		slog.Warn("denied", "method", r.Method, "path", r.RequestURI, "reason", msg)
		h.auditLog.Deny(r.Method, r.RequestURI, msg, map[string]interface{}{"method": r.Method, "path": r.RequestURI})
		http.Error(w, msg, http.StatusForbidden)
		return
	}

	// Refuse protocol upgrades before anything else: the reverse proxy would
	// relay a 101 and hand the caller a raw stream to the daemon (#76).
	if isUpgradeRequest(r.Header) {
		const msg = "protocol upgrade not allowed"
		slog.Warn("denied", "method", r.Method, "path", r.URL.EscapedPath(), "reason", msg)
		h.auditLog.Deny(r.Method, r.RequestURI, msg, map[string]interface{}{"method": r.Method, "path": r.URL.EscapedPath()})
		http.Error(w, msg, http.StatusForbidden)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		slog.Warn("failed to read request body", "error", err)
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}
	r.Body.Close()

	var bodyJSON map[string]interface{}
	contentTypeIsJSON := len(body) > 0 && json.Valid(body)
	if contentTypeIsJSON {
		if err := json.Unmarshal(body, &bodyJSON); err != nil {
			slog.Warn("failed to parse JSON body", "error", err)
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
	}

	// Route on the raw path: r.URL.Path is already decoded and would hide %-escapes (#53).
	// The query goes along for the image pull, which reads it (#83).
	path := r.URL.EscapedPath()
	target := path
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	route := h.router.RouteRequest(r.Method, target, len(body) > 0, bodyJSON)

	// A lifecycle action or DELETE on a name that no policy covers directly:
	// ask the daemon which container it is (#86).
	if route.Action == ActionResolveContainer {
		route = h.resolveContainer(r, route.Container)
	}

	extra := map[string]interface{}{
		"method": r.Method,
		"path":   path,
	}
	if route.Service != "" {
		extra["service"] = route.Service
	}
	if route.Image != "" {
		extra["image"] = route.Image
	}
	if route.Container != "" {
		extra["container"] = route.Container
	}
	if route.ResolvedName != "" {
		extra["resolved_name"] = route.ResolvedName
	}

	if route.Action == ActionDeny {
		slog.Warn("denied", "method", r.Method, "path", path, "reason", route.DenyMsg)
		h.auditLog.Deny(r.Method, r.RequestURI, route.DenyMsg, extra)
		http.Error(w, route.DenyMsg, http.StatusForbidden)
		return
	}

	if route.Action == ActionCreateContainer && route.Policy != nil && bodyJSON != nil {
		result := h.chain.Execute(r, route.Policy, bodyJSON)
		if !result.Allowed {
			slog.Warn("denied by middleware", "method", r.Method, "path", path, "reason", result.Reason)
			h.auditLog.Deny(r.Method, r.RequestURI, result.Reason, extra)
			http.Error(w, result.Reason, http.StatusForbidden)
			return
		}

		if result.ModifiedBody != nil {
			r.Body = io.NopCloser(bytes.NewReader(result.ModifiedBody))
			r.ContentLength = int64(len(result.ModifiedBody))
		} else {
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
	} else {
		r.Body = io.NopCloser(bytes.NewReader(body))
	}

	slog.Info("allowed", "method", r.Method, "path", path)
	h.auditLog.Allow(r.Method, r.RequestURI, "request allowed", extra)

	h.transport.ServeHTTP(w, r)
}

// maxInspectBody bounds the inspect response read during resolution.
const maxInspectBody = 4 << 20

// resolveContainer asks the daemon for GET /containers/{id}/json and allows
// the request only if the container's name is covered by a policy. A 404, an
// uncovered name or any other failure denies: it fails closed (#86).
func (h *Handler) resolveContainer(r *http.Request, id string) *RouteResult {
	notManaged := &RouteResult{Action: ActionDeny, Container: id, DenyMsg: fmt.Sprintf("container %s is not managed by any policy", id)}
	cannotResolve := func(reason string) *RouteResult {
		return &RouteResult{Action: ActionDeny, Container: id, DenyMsg: fmt.Sprintf("cannot resolve container %s: %s", id, reason)}
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, "/containers/"+url.PathEscape(id)+"/json", nil)
	if err != nil {
		return cannotResolve(err.Error())
	}
	rec := newCaptureWriter(maxInspectBody)
	h.transport.ServeHTTP(rec, req)

	switch {
	case rec.status == http.StatusNotFound:
		return notManaged
	case rec.status != http.StatusOK:
		return cannotResolve(fmt.Sprintf("daemon returned %d", rec.status))
	case rec.overflow:
		return cannotResolve("inspect response too large")
	}

	var inspect struct {
		Name string `json:"Name"`
	}
	if err := json.Unmarshal(rec.body.Bytes(), &inspect); err != nil || inspect.Name == "" {
		return cannotResolve("unreadable inspect response")
	}
	name := strings.TrimPrefix(inspect.Name, "/")

	ps := h.router.manager.Covering(name)
	if len(ps) == 0 {
		notManaged.ResolvedName = name
		return notManaged
	}
	res := &RouteResult{Action: ActionAllow, Container: id, ResolvedName: name}
	if len(ps) == 1 {
		res.Service = ps[0].ServiceName
		res.Policy = ps[0]
	}
	return res
}

// captureWriter is an http.ResponseWriter that keeps the status and up to
// limit bytes of the body.
type captureWriter struct {
	header   http.Header
	status   int
	body     bytes.Buffer
	limit    int
	overflow bool
}

func newCaptureWriter(limit int) *captureWriter {
	return &captureWriter{header: make(http.Header), limit: limit}
}

func (c *captureWriter) Header() http.Header { return c.header }

func (c *captureWriter) WriteHeader(status int) {
	if c.status == 0 {
		c.status = status
	}
}

func (c *captureWriter) Write(p []byte) (int, error) {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	if room := c.limit - c.body.Len(); len(p) > room {
		c.overflow = true
		if room > 0 {
			c.body.Write(p[:room])
		}
		return len(p), nil
	}
	return c.body.Write(p)
}

// isUpgradeRequest reports an Upgrade header, or a Connection header that
// lists the upgrade token.
func isUpgradeRequest(h http.Header) bool {
	if _, ok := h["Upgrade"]; ok {
		return true
	}
	for _, v := range h.Values("Connection") {
		for _, tok := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), "upgrade") {
				return true
			}
		}
	}
	return false
}
