package proxy

import (
	"net/url"
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

// pullTestPolicies is the policy set for the #83 and #84 tables. beacon's
// prefixes are written in spellings that normalisation must reduce at load
// time: docker.io/chainsafe/lodestar is chainsafe/lodestar, and the registry
// host Registry.Example.com:443 is lower-cased.
var pullTestPolicies = map[string]string{
	"probe.yaml": `
service_name: probe
allowed_image_prefixes:
  - alpine
image_digest_allowed: true
`,
	"beacon.yaml": `
service_name: beacon
allowed_image_prefixes:
  - docker.io/chainsafe/lodestar
  - ghcr.io/chainsafe/lodestar
  - localhost:5000/x
  - Registry.Example.com:443/a
image_tag_pattern: '^(v[0-9]+|[0-9]+)$'
`,
}

const testDigest = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

// TestRoutePullQuery is the cross-language parity guard for #83 and #84.
//
// POST /images/create is routed on its query string, the way the Docker CLI
// sends it: fromImage (fully qualified, URL-encoded) and tag, with an empty
// body. The body is ignored, fromSrc (import) is denied, and the image gets
// the create checks: a policy prefix on the normalised repository, then that
// policy's tag pattern and digest rule. Rows mirror the pull* runs in
// spec/router.qnt; the rest are language-only.
func TestRoutePullQuery(t *testing.T) {
	r := NewRouter(newTestManager(t, pullTestPolicies))
	alpineBody := map[string]interface{}{"fromImage": "alpine"}
	notAllowed := func(image string) string { return "image " + image + " not allowed by any policy" }
	required := "fromImage query parameter is required for image pull"
	bodyMsg := "image pull must not have a request body"
	fromSrc := "image import (fromSrc) is not allowed"

	tests := []struct {
		path    string
		body    map[string]interface{}
		want    Action
		service string
		wantMsg string
	}{
		// pullCliAllowedTest (#83): the issue's reproduction, as the CLI sends it.
		{"/v1.56/images/create?fromImage=docker.io%2Flibrary%2Falpine&tag=3.19", nil, ActionAllow, "probe", ""},
		// pullShortNameAllowedTest (#84)
		{"/images/create?fromImage=alpine&tag=3.19", nil, ActionAllow, "probe", ""},
		// pullLibraryNameAllowedTest (#84)
		{"/images/create?fromImage=library%2Falpine&tag=latest", nil, ActionAllow, "probe", ""},
		// pullCliOrgAllowedTest (#84): the prefix is written docker.io/chainsafe/lodestar.
		{"/images/create?fromImage=docker.io%2Fchainsafe%2Flodestar&tag=v1", nil, ActionAllow, "beacon", ""},
		// #84: the tag in fromImage, on another Docker Hub host name.
		{"/images/create?fromImage=index.docker.io%2Flibrary%2Falpine%3A3.19", nil, ActionAllow, "probe", ""},
		// #83: the CLI sends a digest in tag.
		{"/images/create?fromImage=alpine&tag=" + url.QueryEscape(testDigest), nil, ActionAllow, "probe", ""},
		// #83: a digest in fromImage.
		{"/images/create?fromImage=" + url.QueryEscape("alpine@"+testDigest), nil, ActionAllow, "probe", ""},
		// #83: image_digest_allowed is false for beacon.
		{"/images/create?fromImage=ghcr.io%2Fchainsafe%2Flodestar&tag=" + url.QueryEscape(testDigest), nil, ActionDeny, "", "image digests not allowed for service beacon"},
		// #84: a registry port is not a tag.
		{"/images/create?fromImage=localhost%3A5000%2Fx%2Fy&tag=2", nil, ActionAllow, "beacon", ""},
		// #84: the registry host is compared lower-cased.
		{"/images/create?fromImage=REGISTRY.example.com%3A443%2Fa&tag=1", nil, ActionAllow, "beacon", ""},
		// #83: the tag pattern applies to pulls.
		{"/images/create?fromImage=chainsafe%2Flodestar&tag=latest", nil, ActionDeny, "", `image tag "latest" does not match pattern "^(v[0-9]+|[0-9]+)$"`},
		// pullDisallowedCliDeniedTest (#83)
		{"/images/create?fromImage=docker.io%2Fattacker%2Fmalware&tag=latest", nil, ActionDeny, "", notAllowed("docker.io/attacker/malware")},
		// pullOtherRegistryDeniedTest (#84): another registry is not Docker Hub's alpine.
		{"/images/create?fromImage=localhost%3A5000%2Falpine&tag=1", nil, ActionDeny, "", notAllowed("localhost:5000/alpine")},
		// #84: the prefix match stays on namespace boundaries.
		{"/images/create?fromImage=alpine-evil&tag=1", nil, ActionDeny, "", notAllowed("alpine-evil")},
		// pullNoFromImageDeniedTest (#83)
		{"/images/create", nil, ActionDeny, "", required},
		// #83: the old contract, fromImage in a JSON body: a pull has no body.
		{"/images/create", map[string]interface{}{"fromImage": "alpine:3.19"}, ActionDeny, "", bodyMsg},
		// pullBodyIgnoredDeniedTest (#83): the daemon would pull the query's image.
		{"/images/create?fromImage=attacker%2Fmalware&tag=latest", alpineBody, ActionDeny, "", bodyMsg},
		// pullJsonBodyDeniedTest (#83): any body is denied, even one that agrees.
		{"/images/create?fromImage=alpine&tag=3.19", alpineBody, ActionDeny, "", bodyMsg},
		// pullImportDeniedTest (#83): the daemon would import the tarball as alpine:latest.
		{"/images/create?fromSrc=http%3A%2F%2Fexample.com%2Fx.tar&repo=alpine&tag=latest", nil, ActionDeny, "", fromSrc},
		// pullImportWithImageDeniedTest (#83)
		{"/images/create?fromImage=alpine&tag=latest&fromSrc=-", nil, ActionDeny, "", fromSrc},
		// #83: a tag in fromImage and in tag is ambiguous.
		{"/images/create?fromImage=alpine%3A3.19&tag=3.20", nil, ActionDeny, "", "fromImage alpine:3.19 already has a tag or digest; the tag query parameter is ambiguous"},
		// #83: no tag and no digest pulls every tag.
		{"/images/create?fromImage=alpine", nil, ActionDeny, "", "image pull without a tag or digest pulls every tag and is not allowed"},
		// #84: upper case in the repository path is invalid.
		{"/images/create?fromImage=Alpine&tag=latest", nil, ActionDeny, "", `invalid image reference "Alpine"`},
		// #83: a repeated parameter could be read two ways.
		{"/images/create?fromImage=alpine&fromImage=attacker%2Fmalware&tag=1", nil, ActionDeny, "", "duplicate fromImage query parameter"},
		// #83: the daemon rejects a malformed query; so does the proxy.
		{"/images/create?fromImage=alpine%zz&tag=1", nil, ActionDeny, "", "invalid query string"},
		// #53 still holds: the percent check reads the path, not the query.
		{"/images/%63reate?fromImage=alpine&tag=1", nil, ActionDeny, "", "percent-encoded path not allowed"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := r.Route("POST", tt.path, tt.body)
			if got.Action != tt.want || got.DenyMsg != tt.wantMsg || got.Service != tt.service {
				t.Errorf("Route(POST, %s) = %v/%q/%q, want %v/%q/%q",
					tt.path, got.Action, got.Service, got.DenyMsg, tt.want, tt.service, tt.wantMsg)
			}
		})
	}
}

// TestRouteImageNormalization is the normalisation table for #84, on the
// create route: each spelling selects the policy its normalised repository
// matches, and a path with upper case is invalid. The same table runs in
// Rust and TypeScript.
func TestRouteImageNormalization(t *testing.T) {
	r := NewRouter(newTestManager(t, pullTestPolicies))
	notAllowed := func(image string) string { return "image " + image + " not allowed by any policy" }

	tests := []struct {
		image   string
		want    Action
		service string
		wantMsg string
	}{
		{"alpine", ActionCreateContainer, "probe", ""},
		{"library/alpine", ActionCreateContainer, "probe", ""},
		{"docker.io/library/alpine", ActionCreateContainer, "probe", ""},
		{"docker.io/alpine", ActionCreateContainer, "probe", ""},
		{"index.docker.io/library/alpine:3.19", ActionCreateContainer, "probe", ""},
		{"docker.io/chainsafe/lodestar:v1", ActionCreateContainer, "beacon", ""},
		{"chainsafe/lodestar:v1", ActionCreateContainer, "beacon", ""},
		{"registry-1.docker.io/chainsafe/lodestar:v1", ActionCreateContainer, "beacon", ""},
		{"ghcr.io/chainsafe/lodestar@" + testDigest, ActionCreateContainer, "beacon", ""},
		{"localhost:5000/x/y:2", ActionCreateContainer, "beacon", ""},
		{"registry.example.com:443/a", ActionCreateContainer, "beacon", ""},
		{"Alpine:latest", ActionDeny, "", `invalid image reference "Alpine:latest"`},
		{"chainsafe/Lodestar:v1", ActionDeny, "", `invalid image reference "chainsafe/Lodestar:v1"`},
		{"alpine-evil", ActionDeny, "", notAllowed("alpine-evil")},
		{"ghcr.io/library/alpine", ActionDeny, "", notAllowed("ghcr.io/library/alpine")},
		{"ghcr.io/chainsafe/lodestar-evil", ActionDeny, "", notAllowed("ghcr.io/chainsafe/lodestar-evil")},
		{"localhost:5000/xy:1", ActionDeny, "", notAllowed("localhost:5000/xy:1")},
	}
	for _, tt := range tests {
		t.Run(tt.image, func(t *testing.T) {
			got := r.Route("POST", "/containers/create", map[string]interface{}{"Image": tt.image})
			if got.Action != tt.want || got.DenyMsg != tt.wantMsg || got.Service != tt.service {
				t.Errorf("create %s = %v/%q/%q, want %v/%q/%q",
					tt.image, got.Action, got.Service, got.DenyMsg, tt.want, tt.service, tt.wantMsg)
			}
		})
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
// sends the request down the lifecycle path, where an unknown container was
// allowed through before #86 — so DELETE /containers/json was allowed in Go
// while Rust and TypeScript denied it.
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
		// A real container name is still routed as a container. No policy
		// covers it, so the daemon is asked which container it is, and the
		// handler denies it (#86).
		// realNameDeleteDeniedTest
		{"DELETE", "/containers/mycontainer", ActionResolveContainer, ""},
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
		// #52: dotted version, container lifecycle delete (uncovered, #86).
		{"DELETE", "/v1.43/containers/foo", nil, ActionResolveContainer},
		// #52: dotted version, container lifecycle start.
		{"POST", "/v1.43/containers/beacon/start", nil, ActionAllow},
		// #52: dotted version, create with a policy-allowed image.
		{"POST", "/v1.43/containers/create", map[string]interface{}{"Image": "chainsafe/lodestar:next"}, ActionCreateContainer},
		// #52: undotted control — stripped correctly everywhere already.
		{"POST", "/v1/containers/beacon/start", nil, ActionAllow},
		// #52: the reserved segment survives the strip (#24 parity).
		{"DELETE", "/v1.43/containers/json", nil, ActionDeny},
		// #57: undotted version, container lifecycle delete (uncovered, #86).
		{"DELETE", "/v1/containers/foo", nil, ActionResolveContainer},
		// #57: multi-digit major version.
		{"DELETE", "/v10.0/containers/foo", nil, ActionResolveContainer},
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
		// #53 control: a plain name is still routed as a container (#86).
		{"DELETE", "/containers/foo", ActionResolveContainer},
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
		// execPrefixNameStartDeniedTest (#49, #86): an uncovered container,
		// routed for resolution; the handler denies it.
		{"POST", "/containers/exec-runner/start", nil, ActionResolveContainer, ""},
		// execPrefixNameDeleteDeniedTest (#49, #86)
		{"DELETE", "/containers/exec-runner", nil, ActionResolveContainer, ""},
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
		{"POST", "/images/create/extra?fromImage=chainsafe/lodestar&tag=next", nil, ActionDeny, ""},
		// A name ending in exec is a plain name (#49, language-only).
		{"GET", "/containers/myexec/json", nil, ActionAllow, ""},
		// A name starting with exec is a plain name (#49, language-only).
		{"DELETE", "/containers/executor", nil, ActionResolveContainer, ""},
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

// TestRouteReadonly is the cross-language parity guard for #75.
//
// With --readonly, every request whose method is not GET or HEAD is denied
// first in the router, for every path. Before #75 the flag only reached the
// middleware chain, which runs on the create route alone, so lifecycle
// POSTs, DELETE /containers/{name} and image pulls were forwarded. Rows
// mirror the readonly* runs in spec/router.qnt.
func TestRouteReadonly(t *testing.T) {
	m := newTestManager(t, map[string]string{
		"beacon.yaml": `
service_name: beacon
allowed_image_prefixes:
  - chainsafe/lodestar
`,
	})
	r := NewRouter(m).WithReadonly(true)
	post := "read-only mode: POST requests are not allowed"
	createBody := map[string]interface{}{"Image": "chainsafe/lodestar:latest"}

	tests := []struct {
		method  string
		path    string
		body    map[string]interface{}
		want    Action
		wantMsg string
	}{
		// readonlyGetAllowedTest (#75)
		{"GET", "/containers/json", nil, ActionAllow, ""},
		// readonlyHeadAllowedTest (#75)
		{"HEAD", "/containers/mycontainer", nil, ActionAllow, ""},
		// #75: the read-only endpoints stay allowed.
		{"GET", "/_ping", nil, ActionAllow, ""},
		// readonlyLifecycleStopDeniedTest (#75)
		{"POST", "/containers/mycontainer/stop", nil, ActionDeny, post},
		// #75: the other lifecycle actions too.
		{"POST", "/containers/mycontainer/start", nil, ActionDeny, post},
		// readonlyDeleteDeniedTest (#75)
		{"DELETE", "/containers/mycontainer", nil, ActionDeny, "read-only mode: DELETE requests are not allowed"},
		// #75: an image pull of an allowed image.
		{"POST", "/images/create?fromImage=chainsafe%2Flodestar&tag=latest", nil, ActionDeny, post},
		// readonlyCreateDeniedTest (#75): an allowed image, so only the flag decides.
		{"POST", "/containers/create", createBody, ActionDeny, post},
		// #75: methods outside the spec's universe.
		{"PUT", "/containers/mycontainer/archive", nil, ActionDeny, "read-only mode: PUT requests are not allowed"},
		// #75: the check runs before the API-version strip.
		{"POST", "/v1.45/containers/mycontainer/stop", nil, ActionDeny, post},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			got := r.Route(tt.method, tt.path, tt.body)
			if got.Action != tt.want || got.DenyMsg != tt.wantMsg {
				t.Fatalf("Route(%s, %s) = %v/%q, want %v/%q",
					tt.method, tt.path, got.Action, got.DenyMsg, tt.want, tt.wantMsg)
			}
		})
	}

	// #75: the flag gates the rule; without it a lifecycle POST is routed as before.
	t.Run("readonly off", func(t *testing.T) {
		got := NewRouter(m).Route("POST", "/containers/mycontainer/stop", nil)
		if got.DenyMsg == post {
			t.Fatalf("Route(POST, /containers/mycontainer/stop) without --readonly = %v/%q", got.Action, got.DenyMsg)
		}
	})
}

// TestRouteAttach is the cross-language parity guard for #76.
//
// attach as a whole segment after /containers/{name} is denied for every
// method, right after the exec check. Before #76 GET .../attach/ws fell
// through to the GET passthrough, and the 101 upgrade gave the caller the
// container's stdin. Rows mirror the attach* runs in spec/router.qnt.
func TestRouteAttach(t *testing.T) {
	m := newTestManager(t, map[string]string{
		"beacon.yaml": `
service_name: beacon
allowed_image_prefixes:
  - chainsafe/lodestar
`,
	})
	r := NewRouter(m)
	attach := "attach is not allowed"

	tests := []struct {
		method  string
		path    string
		want    Action
		wantMsg string
	}{
		// attachGetDeniedTest (#76): the websocket attach endpoint.
		{"GET", "/containers/mycontainer/attach/ws", ActionDeny, attach},
		// attachPostDeniedTest (#76)
		{"POST", "/containers/mycontainer/attach", ActionDeny, attach},
		// attachHeadDeniedTest (#76)
		{"HEAD", "/containers/mycontainer/attach", ActionDeny, attach},
		// #76: the check runs after the API-version strip.
		{"GET", "/v1.45/containers/mycontainer/attach/ws", ActionDeny, attach},
		// #76: every method.
		{"DELETE", "/containers/mycontainer/attach", ActionDeny, attach},
		// #76 control: attach-runner is a name like any other.
		{"GET", "/containers/attach-runner/json", ActionAllow, ""},
		// #76 control: other container reads stay allowed.
		{"GET", "/containers/mycontainer/logs", ActionAllow, ""},
		{"GET", "/containers/json", ActionAllow, ""},
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

// TestRouteReadEndpointMethods is the cross-language parity guard for #78.
//
// /_ping, /version, /info and /events admit only GET and HEAD, through the
// read passthrough; every other method gets the default deny. Before #78 an
// early clause allowed them for every method, and /events as a prefix also
// matched /eventsxyz. Rows mirror the ping* runs in spec/router.qnt.
func TestRouteReadEndpointMethods(t *testing.T) {
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
		// pingPostDeniedTest (#78)
		{"POST", "/_ping", ActionDeny, "endpoint POST /_ping is not allowed"},
		// pingDeleteDeniedTest (#78)
		{"DELETE", "/_ping", ActionDeny, "endpoint DELETE /_ping is not allowed"},
		// #78: every read endpoint, every non-read method.
		{"DELETE", "/version", ActionDeny, "endpoint DELETE /version is not allowed"},
		{"PUT", "/info", ActionDeny, "endpoint PUT /info is not allowed"},
		{"POST", "/events", ActionDeny, "endpoint POST /events is not allowed"},
		{"CONNECT", "/_ping", ActionDeny, "endpoint CONNECT /_ping is not allowed"},
		// #78: the daemon's CORS preflight, denied on purpose.
		{"OPTIONS", "/_ping", ActionDeny, "endpoint OPTIONS /_ping is not allowed"},
		{"PATCH", "/_ping", ActionDeny, "endpoint PATCH /_ping is not allowed"},
		// A lowercase method is an extension method, not CONNECT: the router denies it.
		{"connect", "/_ping", ActionDeny, "endpoint connect /_ping is not allowed"},
		// #78: the old /events prefix match.
		{"POST", "/eventsxyz", ActionDeny, "endpoint POST /eventsxyz is not allowed"},
		// #78: the check runs after the API-version strip.
		{"POST", "/v1.45/_ping", ActionDeny, "endpoint POST /_ping is not allowed"},
		// pingGetAllowedTest (#78)
		{"GET", "/_ping", ActionAllow, ""},
		// pingHeadAllowedTest (#78)
		{"HEAD", "/_ping", ActionAllow, ""},
		{"GET", "/version", ActionAllow, ""},
		{"HEAD", "/version", ActionAllow, ""},
		{"GET", "/info", ActionAllow, ""},
		{"HEAD", "/info", ActionAllow, ""},
		{"GET", "/events", ActionAllow, ""},
		{"HEAD", "/events", ActionAllow, ""},
		{"GET", "/v1.45/_ping", ActionAllow, ""},
		// #78 pin: a read on an unknown path stays on the passthrough.
		{"GET", "/eventsxyz", ActionAllow, ""},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			got := r.Route(tt.method, tt.path, nil)
			if got.Action != tt.want || got.DenyMsg != tt.wantMsg {
				t.Errorf("Route(%s, %s) = %v/%q, want %v/%q",
					tt.method, tt.path, got.Action, got.DenyMsg, tt.want, tt.wantMsg)
			}
		})
	}
}

// TestRouteDotSegments is the cross-language parity guard for #70.
//
// A path with a segment that is exactly . or .. is denied for every method,
// right after the // check and before the API-version strip. Before #70
// GET /./exec/<id>/json had a first segment of ".", so the exec check missed
// it and the GET passthrough forwarded it. Rows mirror the dot* runs in
// spec/router.qnt.
func TestRouteDotSegments(t *testing.T) {
	m := newTestManager(t, map[string]string{
		"beacon.yaml": `
service_name: beacon
allowed_image_prefixes:
  - chainsafe/lodestar
`,
	})
	r := NewRouter(m)
	dot := "dot path segment not allowed"

	tests := []struct {
		method  string
		path    string
		want    Action
		wantMsg string
	}{
		// dotLeadingExecGetDeniedTest (#70): the leading . hid the exec namespace.
		{"GET", "/./exec/abc/json", ActionDeny, dot},
		// dotDotExecGetDeniedTest (#70)
		{"GET", "/x/../exec/abc/json", ActionDeny, dot},
		// dotInContainerPathDeniedTest (#70)
		{"GET", "/containers/x/./exec", ActionDeny, dot},
		// #70: .. climbing out of the container path.
		{"GET", "/containers/x/../../exec/abc/json", ActionDeny, dot},
		// #70: the check runs before the version strip.
		{"GET", "/v1.45/./_ping", ActionDeny, dot},
		// #70: every method.
		{"DELETE", "/containers/..", ActionDeny, dot},
		{"POST", "/containers/x/./start", ActionDeny, dot},
		// #70: the dot hid the attach deny too.
		{"GET", "/containers/./x/attach/ws", ActionDeny, dot},
		// #70 control: names with dots are names.
		{"GET", "/containers/.hidden/json", ActionAllow, ""},
		{"GET", "/containers/a.b/json", ActionAllow, ""},
		{"GET", "/containers/.../json", ActionAllow, ""},
		// #70: the // check runs first.
		{"GET", "//./_ping", ActionDeny, "empty path segment not allowed"},
		// #70: an encoded dot is denied by the percent check (#53).
		{"GET", "/containers/%2e/json", ActionDeny, "percent-encoded path not allowed"},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			got := r.Route(tt.method, tt.path, nil)
			if got.Action != tt.want || got.DenyMsg != tt.wantMsg {
				t.Errorf("Route(%s, %s) = %v/%q, want %v/%q",
					tt.method, tt.path, got.Action, got.DenyMsg, tt.want, tt.wantMsg)
			}
		})
	}
}

// lodestarPolicies is the #85 layout: beacon and validator run one image.
var lodestarPolicies = map[string]string{
	"beacon.yaml": `
service_name: beacon
container_names: [beacon]
allowed_image_prefixes:
  - chainsafe/lodestar
`,
	"validator.yaml": `
service_name: validator
container_names: [validator, validator-2]
allowed_image_prefixes:
  - chainsafe/lodestar
`,
	"monitoring.yaml": `
service_name: monitoring
allowed_image_prefixes:
  - prom/prometheus
`,
}

// TestRouteCreateSelectsByName is the cross-language parity guard for #85.
//
// POST /containers/create selects the one policy whose image prefixes match
// and whose container_names contain ?name=; a policy without container_names
// accepts any name. Before #85 the policy was whichever matched the image
// first in map order (Go, Rust) or load order (TypeScript).
func TestRouteCreateSelectsByName(t *testing.T) {
	r := NewRouter(newTestManager(t, lodestarPolicies))
	lodestar := map[string]interface{}{"Image": "chainsafe/lodestar:v1.20.0"}
	prom := map[string]interface{}{"Image": "prom/prometheus:latest"}

	tests := []struct {
		query   string
		body    map[string]interface{}
		want    Action
		service string
		wantMsg string
	}{
		{"name=beacon", lodestar, ActionCreateContainer, "beacon", ""},
		{"name=validator", lodestar, ActionCreateContainer, "validator", ""},
		{"name=validator-2", lodestar, ActionCreateContainer, "validator", ""},
		// The daemon strips one leading slash, and the name is decoded.
		{"name=/validator", lodestar, ActionCreateContainer, "validator", ""},
		{"name=%2Fbeacon&platform=", lodestar, ActionCreateContainer, "beacon", ""},
		{"platform=linux&name=beacon", lodestar, ActionCreateContainer, "beacon", ""},
		// A name no policy for the image accepts.
		{"name=other", lodestar, ActionDeny, "", "container name other not allowed for image chainsafe/lodestar:v1.20.0 by any policy"},
		// A create without ?name= only matches a policy without container_names.
		{"", lodestar, ActionDeny, "", "image chainsafe/lodestar:v1.20.0 requires a container name"},
		{"name=", lodestar, ActionDeny, "", "image chainsafe/lodestar:v1.20.0 requires a container name"},
		{"", prom, ActionCreateContainer, "monitoring", ""},
		{"name=anything", prom, ActionCreateContainer, "monitoring", ""},
		// The image decides first.
		{"name=beacon", map[string]interface{}{"Image": "alpine:latest"}, ActionDeny, "", "image alpine:latest not allowed by any policy"},
		// An invalid or undecodable name is denied.
		{"name=-beacon", lodestar, ActionDeny, "", "invalid container name"},
		{"name=bea%2Fcon", lodestar, ActionDeny, "", "invalid container name"},
		// Decoded as the daemon's r.Form does.
		{"name=%62eacon", lodestar, ActionCreateContainer, "beacon", ""},
		{"name=validator%2D2", lodestar, ActionCreateContainer, "validator", ""},
		// The daemon takes the first of a repeated name; the proxy denies it.
		{"name=beacon&name=monitoring", lodestar, ActionDeny, "", "duplicate name query parameter"},
		{"name=beacon&n%61me=validator", lodestar, ActionDeny, "", "duplicate name query parameter"},
		// A query the daemon rejects is denied, as for the pull (#83).
		{"name=%zz", lodestar, ActionDeny, "", "invalid query string"},
		{"platform=%zz&name=beacon", lodestar, ActionDeny, "", "invalid query string"},
		{"name=beacon;x=1", lodestar, ActionDeny, "", "invalid query string"},
	}
	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			got := r.Route("POST", "/v1.45/containers/create?"+tt.query, tt.body)
			if got.Action != tt.want {
				t.Fatalf("create ?%s = %v, want %v (deny msg: %q)", tt.query, got.Action, tt.want, got.DenyMsg)
			}
			if got.Service != tt.service {
				t.Fatalf("create ?%s service = %q, want %q", tt.query, got.Service, tt.service)
			}
			if got.DenyMsg != tt.wantMsg {
				t.Fatalf("create ?%s deny msg = %q, want %q", tt.query, got.DenyMsg, tt.wantMsg)
			}
		})
	}
}

// TestRouteCreateSelectionIsStable repeats the #85 reproduction: with two
// policies for one image, every create gets its own policy, every time.
func TestRouteCreateSelectionIsStable(t *testing.T) {
	r := NewRouter(newTestManager(t, lodestarPolicies))
	body := map[string]interface{}{"Image": "chainsafe/lodestar:v1.20.0"}
	for i := 0; i < 50; i++ {
		for _, name := range []string{"beacon", "validator"} {
			got := r.Route("POST", "/containers/create?name="+name, body)
			if got.Action != ActionCreateContainer || got.Service != name {
				t.Fatalf("iteration %d: create ?name=%s got %v service %q (%q)", i, name, got.Action, got.Service, got.DenyMsg)
			}
		}
	}
}

// TestRouteCreateAmbiguous: two policies that both accept one image and name
// are refused at load time; built without that check, the router denies.
func TestRouteCreateAmbiguous(t *testing.T) {
	m := policy.NewManagerFromPolicies(
		&policy.Policy{ServiceName: "b", AllowedImagePrefixes: []string{"chainsafe/lodestar"}},
		&policy.Policy{ServiceName: "a", AllowedImagePrefixes: []string{"chainsafe"}, ContainerNames: []string{"beacon"}},
	)
	r := NewRouter(m)
	body := map[string]interface{}{"Image": "chainsafe/lodestar:v1"}
	got := r.Route("POST", "/containers/create?name=beacon", body)
	want := "ambiguous policy for image chainsafe/lodestar:v1 and name beacon: a, b"
	if got.Action != ActionDeny || got.DenyMsg != want {
		t.Fatalf("got %v %q, want deny %q", got.Action, got.DenyMsg, want)
	}
	got = r.Route("POST", "/containers/create?name=validator", body)
	if got.Action != ActionCreateContainer || got.Service != "b" {
		t.Fatalf("name=validator: got %v %q (%q), want b", got.Action, got.Service, got.DenyMsg)
	}
}

// TestRouteLifecycleCoverage is the cross-language parity guard for #86.
//
// A lifecycle action or DELETE is allowed directly only on a name that
// exactly one policy covers (container_names, or service_name when unset).
// Any other target is routed for resolution: the handler asks the daemon
// which container it is. Rows mirror the covered* and uncovered* runs in
// spec/router.qnt.
func TestRouteLifecycleCoverage(t *testing.T) {
	files := map[string]string{
		"validator.yaml":  lodestarPolicies["validator.yaml"],
		"monitoring.yaml": lodestarPolicies["monitoring.yaml"],
		"vc.yaml": `
service_name: vc-svc
container_names: [vc-1]
allowed_image_prefixes:
  - example/vc
`,
		"cafe.yaml": `
service_name: cafe
allowed_image_prefixes:
  - cafe/app
`,
	}
	r := NewRouter(newTestManager(t, files))

	tests := []struct {
		method  string
		path    string
		want    Action
		service string
	}{
		// coveredNameStartAllowedTest
		{"POST", "/containers/validator/start", ActionAllow, "validator"},
		{"POST", "/v1.45/containers/validator-2/kill", ActionAllow, "validator"},
		{"DELETE", "/containers/validator", ActionAllow, "validator"},
		// A policy without container_names covers its service_name.
		{"POST", "/containers/monitoring/restart", ActionAllow, "monitoring"},
		// With container_names set, service_name is not covered.
		{"POST", "/containers/vc-svc/stop", ActionResolveContainer, ""},
		{"POST", "/containers/vc-1/stop", ActionAllow, "vc-svc"},
		// uncoveredNameStopDeniedTest: an operator container, resolved first.
		{"POST", "/containers/mycontainer/stop", ActionResolveContainer, ""},
		// An ID (full or short) is resolved by the daemon.
		{"POST", "/containers/4f6e1d2c9a7b/kill", ActionResolveContainer, ""},
		{"DELETE", "/containers/4f6e1d2c9a7b8c3d4e5f60718293a4b5c6d7e8f9012345678901234567890abc", ActionResolveContainer, ""},
		// A covered name that could also be an ID prefix is resolved too.
		{"POST", "/containers/cafe/start", ActionResolveContainer, ""},
		// Reads are not lifecycle actions.
		{"GET", "/containers/mycontainer/json", ActionAllow, ""},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			got := r.Route(tt.method, tt.path, nil)
			if got.Action != tt.want {
				t.Fatalf("Route(%s, %s) = %v, want %v (deny msg: %q)", tt.method, tt.path, got.Action, tt.want, got.DenyMsg)
			}
			if got.Service != tt.service {
				t.Fatalf("Route(%s, %s) service = %q, want %q", tt.method, tt.path, got.Service, tt.service)
			}
		})
	}

	// --readonly still denies first (#75).
	ro := NewRouter(newTestManager(t, files)).WithReadonly(true)
	if got := ro.Route("POST", "/containers/validator/start", nil); got.Action != ActionDeny {
		t.Fatalf("readonly start: got %v, want deny", got.Action)
	}
}

// TestRoutePullSharedImage: several policies may allow one image once
// container_names tells their creates apart (#85). A pull creates no
// container, so it is allowed when any policy for the image accepts its tag
// or digest, and denied with the first policy's reason (sorted by
// service_name) when none does.
func TestRoutePullSharedImage(t *testing.T) {
	r := NewRouter(newTestManager(t, map[string]string{
		"vc-b.yaml": "service_name: vc-b\ncontainer_names: [vc-b]\nallowed_image_prefixes: [example/vc]\nimage_tag_pattern: '^v2$'\n",
		"vc-a.yaml": "service_name: vc-a\ncontainer_names: [vc-a]\nallowed_image_prefixes: [example/vc]\nimage_tag_pattern: '^v1$'\n",
	}))
	tests := []struct {
		tag     string
		want    Action
		service string
		wantMsg string
	}{
		{"v1", ActionAllow, "vc-a", ""},
		{"v2", ActionAllow, "vc-b", ""},
		{"v3", ActionDeny, "", `image tag "v3" does not match pattern "^v1$"`},
	}
	for i := 0; i < 50; i++ {
		for _, tt := range tests {
			got := r.Route("POST", "/images/create?fromImage=example%2Fvc&tag="+tt.tag, nil)
			if got.Action != tt.want || got.Service != tt.service || got.DenyMsg != tt.wantMsg {
				t.Fatalf("iteration %d: pull tag %s = %v %q %q, want %v %q %q", i, tt.tag, got.Action, got.Service, got.DenyMsg, tt.want, tt.service, tt.wantMsg)
			}
		}
	}
}
