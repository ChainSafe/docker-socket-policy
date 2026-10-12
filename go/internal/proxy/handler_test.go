package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ChainSafe/docker-socket-policy/go/internal/audit"
	"github.com/ChainSafe/docker-socket-policy/go/internal/middleware"
	"github.com/ChainSafe/docker-socket-policy/go/internal/policy"
)

type recorderTransport struct {
	lastRequest *http.Request
	handler     http.HandlerFunc
}

func (t *recorderTransport) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t.lastRequest = r
	if t.handler != nil {
		t.handler(w, r)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func newTestHandler(t *testing.T, configFiles map[string]string, transport *recorderTransport) *Handler {
	t.Helper()

	var configDir string
	if len(configFiles) > 0 {
		dir := t.TempDir()
		for name, content := range configFiles {
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, []byte(content), 0644); err != nil {
				t.Fatalf("failed to write %s: %v", name, err)
			}
		}
		configDir = dir
	} else {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "empty.yaml"), []byte(`
service_name: default
allowed_image_prefixes:
  - scratch
`), 0644)
		configDir = dir
	}

	policyManager, err := policy.NewManager(configDir)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	auditLog, err := audit.NewLogger(filepath.Join(t.TempDir(), "audit.log"))
	if err != nil {
		t.Fatalf("NewLogger failed: %v", err)
	}
	t.Cleanup(func() { auditLog.Close() })

	router := NewRouter(policyManager)
	chain := middleware.NewChain()

	return NewHandler(router, chain, auditLog, transport)
}

func TestHandler_DeniesRoute(t *testing.T) {
	rec := &recorderTransport{}
	h := newTestHandler(t, nil, rec)

	req := httptest.NewRequest("POST", "/build", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

// newPercentRequest builds a request from a raw target and checks that the
// escaped path really carries the % (#53).
func newPercentRequest(t *testing.T, method, target string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	if !strings.Contains(req.URL.EscapedPath(), "%") {
		t.Fatalf("precondition: EscapedPath() = %q has no %%", req.URL.EscapedPath())
	}
	return req
}

// #53: before the fix the Go handler routed on the decoded r.URL.Path
// ("foo bar"), so a router-only fix would never see the '%' and would let
// this through. The handler must route on the escaped path.
func TestHandler_DeniesPercentEncodedName(t *testing.T) {
	rec := &recorderTransport{}
	h := newTestHandler(t, nil, rec)

	req := newPercentRequest(t, "DELETE", "/containers/foo%20bar")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "percent-encoded") {
		t.Fatalf("expected a percent-encoded deny reason, got %q", w.Body.String())
	}
	if rec.lastRequest != nil {
		t.Fatal("expected no forward for a percent-encoded path")
	}
}

// #53: the daemon reads %2F as a request about "/".
func TestHandler_DeniesPercentEncodedSlash(t *testing.T) {
	rec := &recorderTransport{}
	h := newTestHandler(t, nil, rec)

	req := newPercentRequest(t, "DELETE", "/containers/%2F")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "percent-encoded") {
		t.Fatalf("expected a percent-encoded deny reason, got %q", w.Body.String())
	}
	if rec.lastRequest != nil {
		t.Fatal("expected no forward for a percent-encoded path")
	}
}

// #53: the rule looks at the path only; an encoded query string is routine
// (docker ps --filter) and must reach the daemon unchanged.
func TestHandler_ForwardsPercentEncodedQuery(t *testing.T) {
	rec := &recorderTransport{}
	h := newTestHandler(t, nil, rec)

	const query = "filters=%7B%22status%22%3A%5B%22running%22%5D%7D"
	req := httptest.NewRequest("GET", "/containers/json?"+query, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if rec.lastRequest == nil {
		t.Fatal("expected request to be forwarded")
	}
	if got := rec.lastRequest.URL.RawQuery; got != query {
		t.Fatalf("forwarded query = %q, want %q", got, query)
	}
}

// #55: the audit uri is the raw request target, query and escapes included,
// for allowed and denied requests alike.
func TestHandlerAuditURIIsRequestTarget(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "default.yaml"), []byte("service_name: default\nallowed_image_prefixes:\n  - scratch\n"), 0644)
	policyManager, err := policy.NewManager(dir)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	logPath := filepath.Join(t.TempDir(), "audit.log")
	auditLog, err := audit.NewLogger(logPath)
	if err != nil {
		t.Fatalf("NewLogger failed: %v", err)
	}
	defer auditLog.Close()
	h := NewHandler(NewRouter(policyManager), middleware.NewChain(), auditLog, &recorderTransport{})

	targets := []struct{ method, target, decision string }{
		{"GET", "/containers/json?all=1", "ALLOW"},
		{"DELETE", "/containers/a%2Fb?force=1", "DENY"},
	}
	for _, tc := range targets {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(tc.method, tc.target, nil))
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("reading audit log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != len(targets) {
		t.Fatalf("audit log has %d lines, want %d:\n%s", len(lines), len(targets), data)
	}
	for i, tc := range targets {
		var entry struct {
			URI      string `json:"uri"`
			Decision string `json:"decision"`
		}
		if err := json.Unmarshal([]byte(lines[i]), &entry); err != nil {
			t.Fatalf("line %d: %v", i, err)
		}
		if entry.Decision != tc.decision {
			t.Errorf("%s %s: decision = %q, want %q", tc.method, tc.target, entry.Decision, tc.decision)
		}
		if entry.URI != tc.target {
			t.Errorf("%s %s: audit uri = %q, want %q", tc.method, tc.target, entry.URI, tc.target)
		}
	}
}

// #75: --readonly is enforced in the router, so a delete never reaches the
// daemon. Before #75 the flag only reached the chain, which runs on create.
func TestHandler_ReadonlyDeniesDelete(t *testing.T) {
	rec := &recorderTransport{}
	h := newTestHandler(t, nil, rec)
	h.router = h.router.WithReadonly(true)

	req := httptest.NewRequest("DELETE", "/containers/mycontainer", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
	if got := strings.TrimSpace(w.Body.String()); got != "read-only mode: DELETE requests are not allowed" {
		t.Fatalf("deny reason = %q", got)
	}
	if rec.lastRequest != nil {
		t.Fatal("expected no forward in read-only mode")
	}
}

func TestHandler_CreateContainerValid(t *testing.T) {
	rec := &recorderTransport{}
	h := newTestHandler(t, map[string]string{
		"beacon.yaml": `
service_name: beacon
allowed_image_prefixes:
  - chainsafe/lodestar
container_config:
  network_mode: host
`,
	}, rec)

	body := map[string]interface{}{
		"Image": "chainsafe/lodestar:next",
	}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/containers/create", bytes.NewReader(bodyBytes))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code == http.StatusForbidden {
		t.Fatalf("unexpected 403: %s", w.Body.String())
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if rec.lastRequest == nil {
		t.Fatal("expected request to be forwarded")
	}

	forwardedBody, _ := io.ReadAll(rec.lastRequest.Body)
	var forwarded map[string]interface{}
	json.Unmarshal(forwardedBody, &forwarded)

	hc, ok := forwarded["HostConfig"].(map[string]interface{})
	if !ok {
		t.Fatal("expected HostConfig in forwarded body")
	}
	if hc["NetworkMode"] != "host" {
		t.Fatalf("expected NetworkMode=host, got %v", hc["NetworkMode"])
	}
}

func TestHandler_CreateContainerDenied(t *testing.T) {
	rec := &recorderTransport{}
	h := newTestHandler(t, map[string]string{
		"beacon.yaml": `
service_name: beacon
allowed_image_prefixes:
  - chainsafe/lodestar
`,
	}, rec)

	body := map[string]interface{}{"Image": "ubuntu:latest"}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/containers/create", bytes.NewReader(bodyBytes))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
	if rec.lastRequest != nil {
		t.Fatal("expected no forward for denied request")
	}
}

func TestHandler_BodyReadError(t *testing.T) {
	rec := &recorderTransport{}
	h := newTestHandler(t, nil, rec)

	req := httptest.NewRequest("POST", "/containers/create", &errorReader{})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for body read error, got %d", w.Code)
	}
}

type errorReader struct{}

func (r *errorReader) Read(p []byte) (int, error) {
	return 0, errors.New("simulated read error")
}

func TestHandler_EmptyBody(t *testing.T) {
	rec := &recorderTransport{}
	h := newTestHandler(t, nil, rec)

	req := httptest.NewRequest("POST", "/containers/create", bytes.NewReader(nil))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for empty body, got %d", w.Code)
	}
}

func TestHandler_NonJSONBodyReadOnly(t *testing.T) {
	rec := &recorderTransport{}
	h := newTestHandler(t, nil, rec)

	req := httptest.NewRequest("GET", "/_ping", bytes.NewReader([]byte("not json at all")))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code == http.StatusBadRequest {
		t.Fatalf("unexpected 400 for non-JSON body on read-only endpoint")
	}
}

func TestHandler_ContentLengthPreserved(t *testing.T) {
	rec := &recorderTransport{}
	h := newTestHandler(t, map[string]string{
		"beacon.yaml": `
service_name: beacon
allowed_image_prefixes:
  - chainsafe/lodestar
container_config:
  network_mode: host
`,
	}, rec)

	body := map[string]interface{}{
		"Image": "chainsafe/lodestar:next",
	}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/containers/create", bytes.NewReader(bodyBytes))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if rec.lastRequest == nil {
		t.Fatal("expected request to be forwarded")
	}

	if rec.lastRequest.ContentLength <= 0 {
		t.Fatalf("expected positive ContentLength, got %d", rec.lastRequest.ContentLength)
	}

	forwardedBody, _ := io.ReadAll(rec.lastRequest.Body)
	if int64(len(forwardedBody)) != rec.lastRequest.ContentLength {
		t.Fatalf("ContentLength %d does not match body size %d", rec.lastRequest.ContentLength, len(forwardedBody))
	}
}

// #76: any protocol upgrade is refused before the body is read and before
// routing, so the transport never sees it. Before #76 a websocket attach went
// through the GET passthrough and Go relayed the daemon's 101.
func TestHandlerRefusesProtocolUpgrade(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "default.yaml"), []byte("service_name: default\nallowed_image_prefixes:\n  - scratch\n"), 0644)
	policyManager, err := policy.NewManager(dir)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	logPath := filepath.Join(t.TempDir(), "audit.log")
	auditLog, err := audit.NewLogger(logPath)
	if err != nil {
		t.Fatalf("NewLogger failed: %v", err)
	}
	defer auditLog.Close()
	const refused = "protocol upgrade not allowed"

	tests := []struct {
		name    string
		target  string
		headers map[string]string
	}{
		{"websocket", "/containers/json", map[string]string{"Upgrade": "websocket", "Connection": "Upgrade"}},
		{"connection token only", "/_ping", map[string]string{"Connection": "keep-alive, Upgrade"}},
		{"upgrade header only", "/_ping", map[string]string{"Upgrade": "h2c"}},
	}
	var mismatches []string
	for _, tt := range tests {
		rec := &recorderTransport{}
		h := NewHandler(NewRouter(policyManager), middleware.NewChain(), auditLog, rec)
		req := httptest.NewRequest("GET", tt.target, nil)
		for k, v := range tt.headers {
			req.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if got := strings.TrimSpace(w.Body.String()); w.Code != http.StatusForbidden || got != refused {
			mismatches = append(mismatches, tt.name+": "+http.StatusText(w.Code)+" "+got)
		}
		if rec.lastRequest != nil {
			mismatches = append(mismatches, tt.name+": forwarded")
		}
	}

	rec := &recorderTransport{}
	h := NewHandler(NewRouter(policyManager), middleware.NewChain(), auditLog, rec)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/containers/json", nil))
	if w.Code != http.StatusOK || rec.lastRequest == nil {
		mismatches = append(mismatches, "plain GET /containers/json: not forwarded")
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("reading audit log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var entry struct {
		Method   string `json:"method"`
		URI      string `json:"uri"`
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("audit line 0: %v", err)
	}
	if entry.Method != "GET" || entry.URI != "/containers/json" || entry.Decision != "DENY" || entry.Reason != refused {
		mismatches = append(mismatches, "audit entry: "+lines[0])
	}

	if len(mismatches) > 0 {
		t.Fatalf("protocol upgrade mismatches:\n%s", strings.Join(mismatches, "\n"))
	}
}
