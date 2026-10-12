package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
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
	path := r.URL.EscapedPath()
	route := h.router.Route(r.Method, path, bodyJSON)

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
