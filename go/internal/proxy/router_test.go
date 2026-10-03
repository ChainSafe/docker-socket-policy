package proxy

import (
	"os"
	"path/filepath"
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
		method string
		path   string
		want   Action
	}{
		// Reserved: must not be mistaken for a container to remove.
		{"DELETE", "/containers/json", ActionDeny},
		{"DELETE", "/containers/create", ActionDeny},
		// Listing and inspecting stay allowed via the GET/HEAD passthrough.
		{"GET", "/containers/json", ActionAllow},
		// A real container name is still routed as a container.
		{"DELETE", "/containers/mycontainer", ActionAllow},
		{"GET", "/containers/mycontainer", ActionAllow},
		// The reserved word as a *sub*-resource is a normal inspect.
		{"GET", "/containers/mycontainer/json", ActionAllow},
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
