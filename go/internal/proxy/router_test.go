package proxy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ChainSafe/docker-socket-policy/go/internal/policy"
)

func newTestManager(t *testing.T, files map[string]string) *policy.Manager {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatalf("failed to write %s: %v", name, err)
		}
	}
	m, err := policy.NewManager(dir)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	return m
}

func TestRouterDenyAuth(t *testing.T) {
	m := newTestManager(t, map[string]string{
		"beacon.yaml": `
service_name: beacon
allowed_image_prefixes:
  - chainsafe/lodestar
`,
	})
	r := NewRouter(m)
	result := r.Route("POST", "/auth", nil)
	if result.Action != ActionDeny {
		t.Fatalf("expected ActionDeny, got %v", result.Action)
	}
}

func TestRouterAllowPing(t *testing.T) {
	m := newTestManager(t, nil)
	r := NewRouter(m)
	result := r.Route("GET", "/_ping", nil)
	if result.Action != ActionAllow {
		t.Fatalf("expected ActionAllow, got %v", result.Action)
	}
}

func TestRouterAllowVersion(t *testing.T) {
	m := newTestManager(t, nil)
	r := NewRouter(m)
	result := r.Route("GET", "/version", nil)
	if result.Action != ActionAllow {
		t.Fatalf("expected ActionAllow, got %v", result.Action)
	}
}

func TestRouterDenyExec(t *testing.T) {
	m := newTestManager(t, nil)
	r := NewRouter(m)
	result := r.Route("POST", "/containers/foo/exec", nil)
	if result.Action != ActionDeny {
		t.Fatalf("expected ActionDeny, got %v", result.Action)
	}
}

func TestRouterDenyBuild(t *testing.T) {
	m := newTestManager(t, nil)
	r := NewRouter(m)
	result := r.Route("POST", "/build", nil)
	if result.Action != ActionDeny {
		t.Fatalf("expected ActionDeny, got %v", result.Action)
	}
}

func TestRouterCreateContainerValidImage(t *testing.T) {
	m := newTestManager(t, map[string]string{
		"beacon.yaml": `
service_name: beacon
allowed_image_prefixes:
  - chainsafe/lodestar
`,
	})
	r := NewRouter(m)
	body := map[string]interface{}{
		"Image": "chainsafe/lodestar:next",
	}
	result := r.Route("POST", "/containers/create", body)
	if result.Action != ActionCreateContainer {
		t.Fatalf("expected ActionCreateContainer, got %v: %s", result.Action, result.DenyMsg)
	}
	if result.Service != "beacon" {
		t.Fatalf("expected service 'beacon', got '%s'", result.Service)
	}
	if result.Image != "chainsafe/lodestar:next" {
		t.Fatalf("expected image 'chainsafe/lodestar:next', got '%s'", result.Image)
	}
	if result.Policy == nil {
		t.Fatal("expected non-nil policy")
	}
}

func TestRouterCreateContainerDeniedImage(t *testing.T) {
	m := newTestManager(t, map[string]string{
		"beacon.yaml": `
service_name: beacon
allowed_image_prefixes:
  - chainsafe/lodestar
`,
	})
	r := NewRouter(m)
	body := map[string]interface{}{
		"Image": "ubuntu:latest",
	}
	result := r.Route("POST", "/containers/create", body)
	if result.Action != ActionDeny {
		t.Fatalf("expected ActionDeny, got %v", result.Action)
	}
}

func TestRouterCreateContainerMissingImage(t *testing.T) {
	m := newTestManager(t, map[string]string{
		"beacon.yaml": `
service_name: beacon
allowed_image_prefixes:
  - chainsafe/lodestar
`,
	})
	r := NewRouter(m)
	body := map[string]interface{}{}
	result := r.Route("POST", "/containers/create", body)
	if result.Action != ActionDeny {
		t.Fatalf("expected ActionDeny, got %v", result.Action)
	}
}

func TestRouterContainerLifecycle(t *testing.T) {
	m := newTestManager(t, map[string]string{
		"beacon.yaml": `
service_name: beacon
allowed_image_prefixes:
  - chainsafe/lodestar
`,
	})
	r := NewRouter(m)

	verbs := []string{"start", "stop", "restart", "kill", "wait", "pause", "unpause"}
	for _, verb := range verbs {
		result := r.Route("POST", "/containers/beacon/"+verb, nil)
		if result.Action != ActionAllow {
			t.Errorf("POST /containers/beacon/%s: expected ActionAllow, got %v: %s", verb, result.Action, result.DenyMsg)
		}
		if result.Service != "beacon" {
			t.Errorf("POST /containers/beacon/%s: expected service 'beacon', got '%s'", verb, result.Service)
		}
	}

	result := r.Route("DELETE", "/containers/beacon", nil)
	if result.Action != ActionAllow {
		t.Fatalf("DELETE /containers/beacon: expected ActionAllow, got %v: %s", result.Action, result.DenyMsg)
	}
}

func TestRouterContainerLifecycleDenyRename(t *testing.T) {
	m := newTestManager(t, nil)
	r := NewRouter(m)
	result := r.Route("POST", "/containers/beacon/rename", nil)
	if result.Action != ActionDeny {
		t.Fatalf("expected ActionDeny, got %v", result.Action)
	}
}

func TestRouterContainerLifecycleDenyUpdate(t *testing.T) {
	m := newTestManager(t, nil)
	r := NewRouter(m)
	result := r.Route("POST", "/containers/beacon/update", nil)
	if result.Action != ActionDeny {
		t.Fatalf("expected ActionDeny, got %v", result.Action)
	}
}

func TestRouterAllowInfo(t *testing.T) {
	m := newTestManager(t, nil)
	r := NewRouter(m)
	result := r.Route("GET", "/info", nil)
	if result.Action != ActionAllow {
		t.Fatalf("expected ActionAllow, got %v", result.Action)
	}
}

func TestRouterAllowEvents(t *testing.T) {
	m := newTestManager(t, nil)
	r := NewRouter(m)
	result := r.Route("GET", "/events", nil)
	if result.Action != ActionAllow {
		t.Fatalf("expected ActionAllow, got %v", result.Action)
	}
}

func TestRouterAllowEventsWithQuery(t *testing.T) {
	m := newTestManager(t, nil)
	r := NewRouter(m)
	result := r.Route("GET", "/events?since=123&until=456", nil)
	if result.Action != ActionAllow {
		t.Fatalf("expected ActionAllow, got %v", result.Action)
	}
}

func TestRouterDenyCommit(t *testing.T) {
	m := newTestManager(t, nil)
	r := NewRouter(m)
	result := r.Route("POST", "/commit", nil)
	if result.Action != ActionDeny {
		t.Fatalf("expected ActionDeny, got %v", result.Action)
	}
}

func TestRouterDefaultDeny(t *testing.T) {
	m := newTestManager(t, nil)
	r := NewRouter(m)
	result := r.Route("POST", "/some/random/endpoint", nil)
	if result.Action != ActionDeny {
		t.Fatalf("expected ActionDeny, got %v", result.Action)
	}
}

func TestRouterStripAPIVersion(t *testing.T) {
	m := newTestManager(t, nil)
	r := NewRouter(m)
	result := r.Route("GET", "/v1.41/_ping", nil)
	if result.Action != ActionAllow {
		t.Fatalf("expected ActionAllow for /v1.41/_ping, got %v", result.Action)
	}
}

func TestRouterImagePull(t *testing.T) {
	m := newTestManager(t, map[string]string{
		"beacon.yaml": `
service_name: beacon
allowed_image_prefixes:
  - chainsafe/lodestar
`,
	})
	r := NewRouter(m)

	body := map[string]interface{}{
		"fromImage": "chainsafe/lodestar:next",
	}
	result := r.Route("POST", "/images/create", body)
	if result.Action != ActionAllow {
		t.Fatalf("expected ActionAllow, got %v: %s", result.Action, result.DenyMsg)
	}
	if result.Image != "chainsafe/lodestar:next" {
		t.Fatalf("expected image 'chainsafe/lodestar:next', got '%s'", result.Image)
	}
}

func TestRouterImagePullDenied(t *testing.T) {
	m := newTestManager(t, map[string]string{
		"beacon.yaml": `
service_name: beacon
allowed_image_prefixes:
  - chainsafe/lodestar
`,
	})
	r := NewRouter(m)

	body := map[string]interface{}{
		"fromImage": "ubuntu:latest",
	}
	result := r.Route("POST", "/images/create", body)
	if result.Action != ActionDeny {
		t.Fatalf("expected ActionDeny, got %v", result.Action)
	}
}

func TestRouterGetContainerLogs(t *testing.T) {
	m := newTestManager(t, nil)
	r := NewRouter(m)
	result := r.Route("GET", "/containers/beacon/logs", nil)
	if result.Action != ActionAllow {
		t.Fatalf("expected ActionAllow for GET container logs, got %v", result.Action)
	}
}

func TestRouterDenyPostOnReadOnly(t *testing.T) {
	m := newTestManager(t, nil)
	r := NewRouter(m)
	result := r.Route("POST", "/containers/beacon/logs", nil)
	if result.Action != ActionDeny {
		t.Fatalf("expected ActionDeny for POST on non-lifecycle path, got %v", result.Action)
	}
}

// TestRouterReservedPathSegments is the cross-language parity guard for #24.
//
// /containers/<x> is ambiguous: <x> is usually a container name, but Docker
// also has reserved endpoints at that position (/containers/json to list,
// /containers/create to create). Treating a reserved word as a container name
// sends the request down the lifecycle path, where an unknown container is
// allowed through — so DELETE /containers/json was allowed in Go while Rust
// and TypeScript denied it.
//
// GET stays allowed either way: it reaches the GET/HEAD passthrough instead.
func TestRouterReservedPathSegments(t *testing.T) {
	m := newTestManager(t, map[string]string{
		"beacon.yaml": `
service_name: beacon
allowed_image_prefixes:
  - chainsafe/lodestar
`,
	})
	r := NewRouter(m)

	tests := []struct {
		method  string
		path    string
		want    Action
		wantMsg string
	}{
		// Reserved: must not be mistaken for a container to remove.
		// reservedJsonDeleteDeniedTest
		{"DELETE", "/containers/json", ActionDeny, ""},
		// reservedCreateDeleteDeniedTest
		{"DELETE", "/containers/create", ActionDeny, ""},
		// reservedExecDeleteDeniedTest: denied by the exec check, before the lifecycle branch.
		{"DELETE", "/containers/exec", ActionDeny, "exec is not allowed"},
		// Listing and inspecting stay allowed via the GET/HEAD passthrough.
		{"GET", "/containers/json", ActionAllow, ""},
		// A real container name is still routed as a container.
		// realNameDeleteAllowedTest
		{"DELETE", "/containers/mycontainer", ActionAllow, ""},
		{"GET", "/containers/mycontainer", ActionAllow, ""},
		// The reserved word as a *sub*-resource is a normal inspect.
		// reservedInSubpathAllowedTest
		{"GET", "/containers/mycontainer/json", ActionAllow, ""},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			got := r.Route(tt.method, tt.path, nil)
			if got.Action != tt.want {
				t.Fatalf("Route(%s, %s) = %v, want %v (deny msg: %q)",
					tt.method, tt.path, got.Action, tt.want, got.DenyMsg)
			}
			if tt.wantMsg != "" && got.DenyMsg != tt.wantMsg {
				t.Fatalf("Route(%s, %s) deny msg = %q, want %q",
					tt.method, tt.path, got.DenyMsg, tt.wantMsg)
			}
		})
	}
}

func TestExtractContainerNameSkipsReservedSegments(t *testing.T) {
	for _, reserved := range []string{"create", "json", "exec"} {
		if got := extractContainerName("/containers/" + reserved); got != "" {
			t.Errorf("extractContainerName(/containers/%s) = %q, want \"\"", reserved, got)
		}
	}
	if got := extractContainerName("/containers/mycontainer"); got != "mycontainer" {
		t.Errorf("extractContainerName(/containers/mycontainer) = %q, want \"mycontainer\"", got)
	}
	// Reserved words are only reserved in the name position.
	if got := extractContainerName("/containers/mycontainer/json"); got != "mycontainer" {
		t.Errorf("extractContainerName(/containers/mycontainer/json) = %q, want \"mycontainer\"", got)
	}
}

// TestRouteEmptyContainerName is the cross-language parity guard for #48.
//
// An empty segment in the name position (/containers/, /containers//start) is
// not a container name. Treating it as one routes the request down the
// lifecycle path, where an unknown container is allowed through — Rust did
// exactly that. Rows mirror the emptyName* runs in spec/router.qnt.
func TestRouteEmptyContainerName(t *testing.T) {
	m := newTestManager(t, map[string]string{
		"beacon.yaml": `
service_name: beacon
allowed_image_prefixes:
  - chainsafe/lodestar
`,
	})
	r := NewRouter(m)

	tests := []struct {
		method string
		path   string
		want   Action
	}{
		// emptyNameDeleteDeniedTest
		{"DELETE", "/containers/", ActionDeny},
		// emptyNameStartDeniedTest
		{"POST", "/containers//start", ActionDeny},
		// emptyNameGetAllowedTest
		{"GET", "/containers/", ActionAllow},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			got := r.Route(tt.method, tt.path, nil)
			if got.Action != tt.want {
				t.Fatalf("Route(%s, %s) = %v, want %v (deny msg: %q)",
					tt.method, tt.path, got.Action, tt.want, got.DenyMsg)
			}
		})
	}
}

// TestRouteVersionedPaths is the cross-language parity guard for #52 and #57.
//
// The Docker CLI prefixes every request with a dotted API version
// (/v1.43/containers/create). The router must strip the prefix and route the
// rest exactly like the unversioned path. The table pins one canonical prefix
// rule, ^/v\d+(\.\d+)?/ with ASCII digits, in all three languages (#52, #57).
func TestRouteVersionedPaths(t *testing.T) {
	m := newTestManager(t, map[string]string{
		"beacon.yaml": `
service_name: beacon
allowed_image_prefixes:
  - chainsafe/lodestar
`,
	})
	r := NewRouter(m)

	tests := []struct {
		method string
		path   string
		body   map[string]interface{}
		want   Action
	}{
		// #52: dotted version, container lifecycle delete.
		{"DELETE", "/v1.43/containers/foo", nil, ActionAllow},
		// #52: dotted version, container lifecycle start.
		{"POST", "/v1.43/containers/beacon/start", nil, ActionAllow},
		// #52: dotted version, create with a policy-allowed image.
		{"POST", "/v1.43/containers/create", map[string]interface{}{"Image": "chainsafe/lodestar:next"}, ActionCreateContainer},
		// #52: undotted control — stripped correctly everywhere already.
		{"POST", "/v1/containers/beacon/start", nil, ActionAllow},
		// #52: the reserved segment survives the strip (#24 parity).
		{"DELETE", "/v1.43/containers/json", nil, ActionDeny},
		// #57: undotted version, container lifecycle delete.
		{"DELETE", "/v1/containers/foo", nil, ActionAllow},
		// #57: multi-digit major version.
		{"DELETE", "/v10.0/containers/foo", nil, ActionAllow},
		// #57: /volumes/ is not a version; the daemon routes this as a volume removal.
		{"DELETE", "/volumes/containers/foo", nil, ActionDeny},
		// #57: /version/ is not a version prefix.
		{"DELETE", "/version/containers/foo", nil, ActionDeny},
		// #57: two dots is not an API version.
		{"DELETE", "/v1.2.3/containers/foo", nil, ActionDeny},
		// #57: no digits after v.
		{"DELETE", "/vabc/containers/foo", nil, ActionDeny},
		// #57: bare v.
		{"DELETE", "/v/containers/foo", nil, ActionDeny},
		// #57: dot without a minor version.
		{"DELETE", "/v1./containers/foo", nil, ActionDeny},
		// #57: strip once; the remaining /v1.43/containers/foo matches no route.
		{"DELETE", "/v1/v1.43/containers/foo", nil, ActionDeny},
		// #57: a non-ASCII digit (U+0661 ARABIC-INDIC DIGIT ONE) is not a version digit.
		{"DELETE", "/v\u0661/containers/foo", nil, ActionDeny},
		// #57 sanity row, cannot fail: GET /version is allowed as a read-only request.
		{"GET", "/version", nil, ActionAllow},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			got := r.Route(tt.method, tt.path, tt.body)
			if got.Action != tt.want {
				t.Fatalf("Route(%s, %s) = %v, want %v (deny msg: %q)",
					tt.method, tt.path, got.Action, tt.want, got.DenyMsg)
			}
		})
	}
}

// TestRoutePercentEncodedPaths is the cross-language parity guard for #53.
//
// The daemon percent-decodes the path before it routes, so any % in the path
// lets the proxy and the daemon read the same request differently. A path
// containing % is denied for every method. Paths are given raw, as the handler
// passes r.URL.EscapedPath(). Rows mirror the percent* runs in spec/router.qnt.
func TestRoutePercentEncodedPaths(t *testing.T) {
	m := newTestManager(t, map[string]string{
		"beacon.yaml": `
service_name: beacon
allowed_image_prefixes:
  - chainsafe/lodestar
`,
	})
	r := NewRouter(m)

	tests := []struct {
		method string
		path   string
		want   Action
	}{
		// percentSlashDeleteDeniedTest (#53)
		{"DELETE", "/containers/%2F", ActionDeny},
		// percentLowerSlashDeleteDeniedTest (#53)
		{"DELETE", "/containers/%2f", ActionDeny},
		// percentReservedDeleteDeniedTest (#53): %6A%73%6F%6E decodes to json.
		{"DELETE", "/containers/%6A%73%6F%6E", ActionDeny},
		// percentSubpathStartDeniedTest (#53): a pin; raw routing already denies it.
		// It discriminates only in Go's handler before #53, which decoded first;
		// the foo%20bar handler test covers that.
		{"POST", "/containers/beacon%2Fstart", ActionDeny},
		// percentNameStartDeniedTest (#53)
		{"POST", "/containers/%2F/start", ActionDeny},
		// percentGetDeniedTest (#53)
		{"GET", "/containers/%2F", ActionDeny},
		// #53, language-only: the rule covers every method, HEAD included.
		{"HEAD", "/containers/%2F", ActionDeny},
		// #53: the check runs on the versioned path too.
		{"DELETE", "/v1.45/containers/foo%25", ActionDeny},
		// #53: an encoded version prefix is not stripped.
		{"DELETE", "/v%31/containers/foo", ActionDeny},
		// #53: network names that need escaping are denied, GET included.
		{"GET", "/networks/a%20b", ActionDeny},
		// #53 control: a plain name is still routed as a container.
		{"DELETE", "/containers/foo", ActionAllow},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			got := r.Route(tt.method, tt.path, nil)
			if got.Action != tt.want {
				t.Fatalf("Route(%s, %s) = %v, want %v (deny msg: %q)",
					tt.method, tt.path, got.Action, tt.want, got.DenyMsg)
			}
			if tt.want == ActionDeny && !strings.Contains(got.DenyMsg, "percent-encoded") {
				t.Fatalf("Route(%s, %s) deny msg = %q, want it to contain %q",
					tt.method, tt.path, got.DenyMsg, "percent-encoded")
			}
		})
	}
}

// TestRouteExecAndExactEndpoints is the cross-language parity guard for #49.
//
// Exec and create are matched on whole path segments. Exec is denied for every
// method when the first segment is exec, or when the first segment is
// containers and a later segment is exactly exec; a name that only contains
// exec routes normally. POST /containers/create and POST /images/create match
// only with exactly two segments. Rows mirror the exec* and create* runs in
// spec/router.qnt.
func TestRouteExecAndExactEndpoints(t *testing.T) {
	m := newTestManager(t, map[string]string{
		"beacon.yaml": `
service_name: beacon
allowed_image_prefixes:
  - chainsafe/lodestar
`,
	})
	r := NewRouter(m)
	createBody := map[string]interface{}{"Image": "chainsafe/lodestar:next"}
	pullBody := map[string]interface{}{"fromImage": "chainsafe/lodestar:next"}

	tests := []struct {
		method  string
		path    string
		body    map[string]interface{}
		want    Action
		wantMsg string
	}{
		// execSubpathDeleteDeniedTest (#49)
		{"DELETE", "/containers/mycontainer/exec", nil, ActionDeny, "exec is not allowed"},
		// execSubpathPostDeniedTest (#49)
		{"POST", "/containers/mycontainer/exec", nil, ActionDeny, "exec is not allowed"},
		// execPrefixNameStartAllowedTest (#49): an unknown container.
		{"POST", "/containers/exec-runner/start", nil, ActionAllow, ""},
		// execPrefixNameDeleteAllowedTest (#49): an unknown container.
		{"DELETE", "/containers/exec-runner", nil, ActionAllow, ""},
		// execPrefixNameGetAllowedTest (#49)
		{"GET", "/containers/exec-runner/json", nil, ActionAllow, ""},
		// execNamespaceGetDeniedTest (#49): exec inspect leaks command lines.
		{"GET", "/exec/abc/json", nil, ActionDeny, "exec is not allowed"},
		// execNamespacePostDeniedTest (#49)
		{"POST", "/exec/abc/start", nil, ActionDeny, "exec is not allowed"},
		// createSubpathDeniedTest (#49): an allowed image, so only the path decides.
		{"POST", "/containers/create/extra", createBody, ActionDeny, ""},
		// Exec is matched under containers or exec only (#49, language-only).
		{"GET", "/images/exec", nil, ActionAllow, ""},
		// An allowed image, so only the path decides (#49, language-only).
		{"POST", "/images/create/extra", pullBody, ActionDeny, ""},
		// A name ending in exec is a plain name (#49, language-only).
		{"GET", "/containers/myexec/json", nil, ActionAllow, ""},
		// A name starting with exec is a plain name (#49, language-only).
		{"DELETE", "/containers/executor", nil, ActionAllow, ""},
		// The reserved name, decided by the exec check (#49, language-only).
		{"GET", "/containers/exec/json", nil, ActionDeny, "exec is not allowed"},
		// A top-level name starting with exec is not the exec namespace (#49, language-only).
		{"GET", "/executor", nil, ActionAllow, ""},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			got := r.Route(tt.method, tt.path, tt.body)
			if got.Action != tt.want {
				t.Fatalf("Route(%s, %s) = %v, want %v (deny msg: %q)",
					tt.method, tt.path, got.Action, tt.want, got.DenyMsg)
			}
			// Exact match: the default deny for POST /containers/x/exec ends in
			// "exec is not allowed" too, so a substring check passes vacuously.
			if tt.wantMsg != "" && got.DenyMsg != tt.wantMsg {
				t.Fatalf("Route(%s, %s) deny msg = %q, want %q",
					tt.method, tt.path, got.DenyMsg, tt.wantMsg)
			}
		})
	}
}

// TestRouteEmptySegmentsAndHead is the cross-language parity guard for #55.
//
// A path with an empty interior segment (// anywhere in the path) is denied
// for every method, after the percent check and before the API-version strip;
// a single trailing slash is not interior. HEAD on a named container is routed
// like GET. Rows mirror the emptyLeadingExecGetDenied, emptyInteriorGetDenied
// and headNamedContainerAllowed runs in spec/router.qnt.
func TestRouteEmptySegmentsAndHead(t *testing.T) {
	m := newTestManager(t, map[string]string{
		"beacon.yaml": `
service_name: beacon
allowed_image_prefixes:
  - chainsafe/lodestar
`,
	})
	r := NewRouter(m)
	empty := "empty path segment not allowed"
	percent := "percent-encoded path not allowed"
	exec := "exec is not allowed"

	tests := []struct {
		method  string
		path    string
		want    Action
		wantMsg string
	}{
		// emptyLeadingExecGetDeniedTest (#55): the leading empty segment hid the exec namespace.
		{"GET", "//exec/abc/json", ActionDeny, empty},
		// #55: the empty segment after the version prefix hides the exec namespace too.
		{"GET", "/v1.45//exec/abc/json", ActionDeny, empty},
		// #55: the check runs before the version strip.
		{"GET", "//v1.45/exec/abc/json", ActionDeny, empty},
		// emptyInteriorGetDeniedTest (#55)
		{"GET", "/containers//json", ActionDeny, empty},
		// #55: emptyNameStartDeniedTest (#48) is now decided by the empty segment check.
		{"POST", "/containers//start", ActionDeny, empty},
		// #55: an empty name followed by a trailing slash.
		{"DELETE", "/containers//", ActionDeny, empty},
		// #55: the read-only endpoints are not exempt.
		{"GET", "//_ping", ActionDeny, empty},
		// #55: the percent check runs first.
		{"GET", "//containers/%2F", ActionDeny, percent},
		// #55 control: a single trailing slash is not an empty interior segment.
		{"GET", "/containers/", ActionAllow, ""},
		// #55 control: the root path.
		{"GET", "/", ActionAllow, ""},
		// headNamedContainerAllowedTest (#55)
		{"HEAD", "/containers/mycontainer", ActionAllow, ""},
		// #55: HEAD on a container subpath.
		{"HEAD", "/containers/mycontainer/json", ActionAllow, ""},
		// #55: the exec check still denies HEAD.
		{"HEAD", "/containers/mycontainer/exec", ActionDeny, exec},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			got := r.Route(tt.method, tt.path, nil)
			if got.Action != tt.want || got.DenyMsg != tt.wantMsg {
				t.Fatalf("Route(%s, %s) = %v/%q, want %v/%q",
					tt.method, tt.path, got.Action, got.DenyMsg, tt.want, tt.wantMsg)
			}
		})
	}
}

func TestExtractContainerNameSkipsEmptySegment(t *testing.T) {
	for _, path := range []string{"/containers/", "/containers//start"} {
		if got := extractContainerName(path); got != "" {
			t.Errorf("extractContainerName(%s) = %q, want \"\"", path, got)
		}
	}
}
