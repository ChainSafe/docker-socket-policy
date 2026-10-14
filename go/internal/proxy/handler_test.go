package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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
// TestHandler_PullDeniesBody checks that a pull with a body is never
// forwarded (#83). The daemon reads a form body's fromImage over the query's,
// so an allowed image in the query and another in the body would pull the
// body's. Any body is denied, whatever its Content-Type or framing.
func TestHandler_PullDeniesBody(t *testing.T) {
	files := map[string]string{"probe.yaml": "service_name: probe\nallowed_image_prefixes:\n  - alpine\n"}
	const target = "/v1.56/images/create?fromImage=alpine&tag=3.19"
	tests := []struct {
		name        string
		contentType string
		body        string
		chunked     bool
	}{
		{"form body", "application/x-www-form-urlencoded", "fromImage=busybox&tag=latest", false},
		{"chunked form body", "application/x-www-form-urlencoded", "fromImage=busybox&tag=latest", true},
		{"JSON body", "application/json", `{"fromImage":"alpine"}`, false},
		{"text body", "text/plain", "x", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := &recorderTransport{}
			h := newTestHandler(t, files, rec)
			req := httptest.NewRequest("POST", target, strings.NewReader(tt.body))
			req.Header.Set("Content-Type", tt.contentType)
			if tt.chunked {
				req.ContentLength = -1
				req.TransferEncoding = []string{"chunked"}
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != http.StatusForbidden || rec.lastRequest != nil {
				t.Fatalf("status %d, forwarded %v, want 403 and no forward", w.Code, rec.lastRequest != nil)
			}
			if got := strings.TrimSpace(w.Body.String()); got != "image pull must not have a request body" {
				t.Errorf("deny body = %q", got)
			}
		})
	}
}

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

// #78: CONNECT is refused before the upgrade check and before routing, so the
// transport never sees it, in origin form and in authority form. Before #78
// CONNECT /_ping matched the early read-endpoint allow and was forwarded.
func TestHandlerRefusesConnect(t *testing.T) {
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
	const refused = "CONNECT is not allowed"

	tests := []struct {
		name    string
		target  string
		headers map[string]string
	}{
		{"origin form", "/_ping", nil},
		{"authority form", "localhost:80", nil},
		{"with Upgrade", "/_ping", map[string]string{"Upgrade": "websocket", "Connection": "Upgrade"}},
	}
	var mismatches []string
	for _, tt := range tests {
		rec := &recorderTransport{}
		h := NewHandler(NewRouter(policyManager), middleware.NewChain(), auditLog, rec)
		req := httptest.NewRequest("CONNECT", tt.target, nil)
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

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("reading audit log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	wantURIs := []string{"/_ping", "localhost:80", "/_ping"}
	for i, wantURI := range wantURIs {
		if i >= len(lines) {
			mismatches = append(mismatches, "audit entry missing for "+wantURI)
			continue
		}
		var entry struct {
			Method   string `json:"method"`
			URI      string `json:"uri"`
			Decision string `json:"decision"`
			Reason   string `json:"reason"`
		}
		if err := json.Unmarshal([]byte(lines[i]), &entry); err != nil {
			t.Fatalf("audit line %d: %v", i, err)
		}
		if entry.Method != "CONNECT" || entry.URI != wantURI || entry.Decision != "DENY" || entry.Reason != refused {
			mismatches = append(mismatches, "audit entry: "+lines[i])
		}
	}

	if len(mismatches) > 0 {
		t.Fatalf("CONNECT mismatches:\n%s", strings.Join(mismatches, "\n"))
	}
}

// TestHandler_PullRoutesOnQuery checks that the handler hands the query to
// the router (#83): a pull sent the Docker CLI way, empty body and image in
// the query, is forwarded with its query unchanged, and a disallowed one is
// not forwarded.
func TestHandler_PullRoutesOnQuery(t *testing.T) {
	files := map[string]string{"probe.yaml": "service_name: probe\nallowed_image_prefixes:\n  - alpine\n"}
	const query = "fromImage=docker.io%2Flibrary%2Falpine&tag=3.19"

	rec := &recorderTransport{}
	h := newTestHandler(t, files, rec)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/v1.56/images/create?"+query, nil))
	if w.Code != http.StatusOK || rec.lastRequest == nil {
		t.Fatalf("allowed pull: status %d, forwarded %v: %s", w.Code, rec.lastRequest != nil, w.Body.String())
	}
	if rec.lastRequest.URL.RawQuery != query {
		t.Errorf("forwarded query = %q, want %q", rec.lastRequest.URL.RawQuery, query)
	}

	rec = &recorderTransport{}
	h = newTestHandler(t, files, rec)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/v1.56/images/create?fromImage=busybox&tag=latest", nil))
	if w.Code != http.StatusForbidden || rec.lastRequest != nil {
		t.Fatalf("disallowed pull: status %d, forwarded %v", w.Code, rec.lastRequest != nil)
	}
	if !strings.Contains(w.Body.String(), "image busybox not allowed by any policy") {
		t.Errorf("deny body = %q", w.Body.String())
	}
}

// daemonTransport answers GET /containers/{id}/json from a table of
// id -> container name, as the daemon does, and records every request.
type daemonTransport struct {
	names    map[string]string
	status   int // when non-zero, every inspect answers this status
	requests []string
}

func (t *daemonTransport) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t.requests = append(t.requests, r.Method+" "+r.URL.EscapedPath())
	if r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/containers/") && strings.HasSuffix(r.URL.Path, "/json") {
		if t.status != 0 {
			http.Error(w, "boom", t.status)
			return
		}
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/containers/"), "/json")
		name, ok := t.names[id]
		if !ok {
			http.Error(w, `{"message":"No such container: `+id+`"}`, http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"Id": "4f6e1d2c9a7b", "Name": "/" + name})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

const (
	beaconID     = "4f6e1d2c9a7b8c3d4e5f60718293a4b5c6d7e8f9012345678901234567890abc"
	monitoringID = "9d8c7b6a5f4e3d2c1b0a99887766554433221100ffeeddccbbaa998877665544"
)

func newDaemonTransport() *daemonTransport {
	return &daemonTransport{names: map[string]string{
		"beacon":          "beacon",
		beaconID:          "beacon",
		beaconID[:12]:     "beacon",
		"dsp-monitoring":  "dsp-monitoring",
		monitoringID:      "dsp-monitoring",
		monitoringID[:12]: "dsp-monitoring",
	}}
}

func newCoverageHandler(t *testing.T, transport Transport) (*Handler, string) {
	t.Helper()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "beacon.yaml"), []byte("service_name: beacon\nallowed_image_prefixes:\n  - chainsafe/lodestar\n"), 0644)
	m, err := policy.NewManager(dir)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	logPath := filepath.Join(t.TempDir(), "audit.log")
	auditLog, err := audit.NewLogger(logPath)
	if err != nil {
		t.Fatalf("NewLogger failed: %v", err)
	}
	t.Cleanup(func() { auditLog.Close() })
	return NewHandler(NewRouter(m), middleware.NewChain(), auditLog, transport), logPath
}

// TestHandlerLifecycleCoverage is the handler half of #86: a lifecycle action
// or DELETE is forwarded only if its target is a container a policy covers.
// A name, full ID or short ID is resolved with GET /containers/{id}/json.
// Before #86 every row was forwarded.
func TestHandlerLifecycleCoverage(t *testing.T) {
	notManaged := func(id string) string { return "container " + id + " is not managed by any policy" }
	tests := []struct {
		name     string
		method   string
		target   string
		status   int
		body     string
		inspects []string // inspect requests the proxy sends before deciding
	}{
		{"covered name", "POST", "/v1.45/containers/beacon/stop?t=1", http.StatusNoContent, "", nil},
		{"covered full ID", "POST", "/containers/" + beaconID + "/kill", http.StatusNoContent, "", []string{"GET /containers/" + beaconID + "/json"}},
		{"covered short ID", "DELETE", "/containers/" + beaconID[:12] + "?force=1", http.StatusNoContent, "", []string{"GET /containers/" + beaconID[:12] + "/json"}},
		// uncoveredNameStopDeniedTest: an operator container.
		{"uncovered name", "POST", "/containers/dsp-monitoring/stop", http.StatusForbidden, notManaged("dsp-monitoring"), []string{"GET /containers/dsp-monitoring/json"}},
		{"uncovered full ID", "POST", "/containers/" + monitoringID + "/kill", http.StatusForbidden, notManaged(monitoringID), []string{"GET /containers/" + monitoringID + "/json"}},
		{"uncovered short ID", "DELETE", "/containers/" + monitoringID[:12], http.StatusForbidden, notManaged(monitoringID[:12]), []string{"GET /containers/" + monitoringID[:12] + "/json"}},
		// realNameDeleteDeniedTest: the daemon answers 404.
		{"unknown name", "DELETE", "/containers/mycontainer", http.StatusForbidden, notManaged("mycontainer"), []string{"GET /containers/mycontainer/json"}},
		// execPrefixNameStartDeniedTest
		{"unknown exec-prefixed name", "POST", "/containers/exec-runner/start", http.StatusForbidden, notManaged("exec-runner"), []string{"GET /containers/exec-runner/json"}},
		// A read is not resolved.
		{"inspect read", "GET", "/containers/dsp-monitoring/json", http.StatusOK, "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := newDaemonTransport()
			h, _ := newCoverageHandler(t, d)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(tt.method, tt.target, nil))
			if rec.Code != tt.status {
				t.Fatalf("%s %s: status %d, want %d (%s)", tt.method, tt.target, rec.Code, tt.status, rec.Body.String())
			}
			if tt.body != "" && strings.TrimSpace(rec.Body.String()) != tt.body {
				t.Fatalf("%s %s: body %q, want %q", tt.method, tt.target, rec.Body.String(), tt.body)
			}
			want := append([]string{}, tt.inspects...)
			if tt.status != http.StatusForbidden {
				u, _ := url.Parse(tt.target)
				want = append(want, tt.method+" "+u.EscapedPath())
			}
			if strings.Join(d.requests, "\n") != strings.Join(want, "\n") {
				t.Fatalf("%s %s: daemon saw %q, want %q", tt.method, tt.target, d.requests, want)
			}
		})
	}
}

// A daemon error other than 404 fails closed with its own message (#86).
func TestHandlerLifecycleResolveFailsClosed(t *testing.T) {
	d := newDaemonTransport()
	d.status = http.StatusInternalServerError
	h, _ := newCoverageHandler(t, d)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/containers/"+beaconID[:12]+"/stop", nil))
	want := "cannot resolve container " + beaconID[:12] + ": daemon returned 500"
	if rec.Code != http.StatusForbidden || strings.TrimSpace(rec.Body.String()) != want {
		t.Fatalf("status %d body %q, want 403 %q", rec.Code, rec.Body.String(), want)
	}
	if len(d.requests) != 1 {
		t.Fatalf("daemon saw %q, want only the inspect", d.requests)
	}
}

// The resolved name is audited with the request (#86).
func TestHandlerLifecycleAuditsResolvedName(t *testing.T) {
	d := newDaemonTransport()
	h, logPath := newCoverageHandler(t, d)
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/containers/"+beaconID[:12]+"/start", nil))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/containers/"+monitoringID[:12]+"/start", nil))
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("reading audit log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("audit log has %d lines, want 2:\n%s", len(lines), data)
	}
	for i, want := range []struct{ decision, name, service string }{{"ALLOW", "beacon", "beacon"}, {"DENY", "dsp-monitoring", ""}} {
		var entry struct {
			Decision string            `json:"decision"`
			Extra    map[string]string `json:"extra"`
		}
		if err := json.Unmarshal([]byte(lines[i]), &entry); err != nil {
			t.Fatalf("line %d: %v", i, err)
		}
		if entry.Decision != want.decision || entry.Extra["resolved_name"] != want.name || entry.Extra["service"] != want.service {
			t.Fatalf("line %d = %s, want %s with resolved_name %q service %q", i, lines[i], want.decision, want.name, want.service)
		}
	}
}

// TestHandlerCreateSelectsByName is the #85 reproduction through the handler:
// two policies for one image force different users, and each create named
// for one of them gets that policy's user, every time.
func TestHandlerCreateSelectsByName(t *testing.T) {
	rec := &recorderTransport{}
	h := newTestHandler(t, map[string]string{
		"a.yaml": "service_name: svc-a\ncontainer_names: [svc-a]\nallowed_image_prefixes: [alpine]\ncontainer_config: { user: \"1111:1111\" }\n",
		"b.yaml": "service_name: svc-b\ncontainer_names: [svc-b]\nallowed_image_prefixes: [alpine]\ncontainer_config: { user: \"2222:2222\" }\n",
	}, rec)
	for i := 0; i < 50; i++ {
		for _, tc := range []struct{ name, user string }{{"svc-a", "1111:1111"}, {"svc-b", "2222:2222"}} {
			rec.lastRequest = nil
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest("POST", "/v1.45/containers/create?name="+tc.name, strings.NewReader(`{"Image":"alpine:3.20","Cmd":["true"]}`)))
			if w.Code != http.StatusOK || rec.lastRequest == nil {
				t.Fatalf("iteration %d %s: status %d (%s)", i, tc.name, w.Code, w.Body.String())
			}
			var fwd map[string]interface{}
			b, _ := io.ReadAll(rec.lastRequest.Body)
			if err := json.Unmarshal(b, &fwd); err != nil {
				t.Fatalf("forwarded body: %v", err)
			}
			if fwd["User"] != tc.user {
				t.Fatalf("iteration %d: create ?name=%s forwarded User %v, want %s", i, tc.name, fwd["User"], tc.user)
			}
		}
	}

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/containers/create", strings.NewReader(`{"Image":"alpine:3.20"}`)))
	if w.Code != http.StatusForbidden || strings.TrimSpace(w.Body.String()) != "image alpine:3.20 requires a container name" {
		t.Fatalf("nameless create: status %d body %q", w.Code, w.Body.String())
	}
}
