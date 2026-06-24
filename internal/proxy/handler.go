package proxy

import (
	"bytes"
	"io"
	"log"
	"net/http"

	"github.com/google/uuid"

	"github.com/ChainSafe/docker-socket-policy/internal/audit"
	"github.com/ChainSafe/docker-socket-policy/internal/middleware"
	"github.com/ChainSafe/docker-socket-policy/internal/types"
)

// Handler is the HTTP handler for the Docker socket proxy.
type Handler struct {
	router    *Router
	chain     *middleware.Chain
	auditLog  *audit.Logger
	transport *ReverseProxy
}

// NewHandler creates a new proxy handler.
func NewHandler(router *Router, chain *middleware.Chain, auditLog *audit.Logger, transport *ReverseProxy) *Handler {
	return &Handler{
		router:    router,
		chain:     chain,
		auditLog:  auditLog,
		transport: transport,
	}
}

// ServeHTTP handles an incoming HTTP request.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := uuid.New().String()

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("[%s] Failed to read body: %v", requestID, err)
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}
	r.Body.Close()

	route := h.router.Route(r.Method, r.URL.Path, body)

	extra := map[string]interface{}{
		"request_id": requestID,
	}
	if route.Service != "" {
		extra["service"] = route.Service
	}
	if route.Image != "" {
		extra["image"] = route.Image
	}

	// If the route action is deny, return immediately
	if route.Action == types.ActionDeny {
		log.Printf("[%s] DENIED %s %s: %s", requestID, r.Method, r.RequestURI, route.DenyMsg)
		h.auditLog.Deny(r.Method, r.RequestURI, route.DenyMsg, extra)
		http.Error(w, route.DenyMsg, http.StatusForbidden)
		return
	}

	result := h.chain.Execute(r, route)

	if !result.Allowed {
		log.Printf("[%s] DENIED %s %s: %s", requestID, r.Method, r.RequestURI, result.Reason)
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

	log.Printf("[%s] ALLOWED %s %s: %s", requestID, r.Method, r.RequestURI, result.Reason)
	h.auditLog.Allow(r.Method, r.RequestURI, result.Reason, extra)

	h.transport.ServeHTTP(w, r)
}
