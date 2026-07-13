package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"

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

	route := h.router.Route(r.Method, r.URL.Path, bodyJSON)

	extra := map[string]interface{}{
		"method": r.Method,
		"path":   r.URL.Path,
	}
	if route.Service != "" {
		extra["service"] = route.Service
	}
	if route.Image != "" {
		extra["image"] = route.Image
	}

	if route.Action == ActionDeny {
		slog.Warn("denied", "method", r.Method, "path", r.URL.Path, "reason", route.DenyMsg)
		h.auditLog.Deny(r.Method, r.RequestURI, route.DenyMsg, extra)
		http.Error(w, route.DenyMsg, http.StatusForbidden)
		return
	}

	if route.Action == ActionCreateContainer && route.Policy != nil && bodyJSON != nil {
		result := h.chain.Execute(r, route.Policy, bodyJSON)
		if !result.Allowed {
			slog.Warn("denied by middleware", "method", r.Method, "path", r.URL.Path, "reason", result.Reason)
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

	slog.Info("allowed", "method", r.Method, "path", r.URL.Path)
	h.auditLog.Allow(r.Method, r.RequestURI, "request allowed", extra)

	h.transport.ServeHTTP(w, r)
}
