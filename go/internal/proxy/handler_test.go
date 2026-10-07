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
	chain := middleware.NewChain(false)

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
