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
