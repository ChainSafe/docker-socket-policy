package proxy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ChainSafe/docker-socket-policy/internal/policy"
	"github.com/ChainSafe/docker-socket-policy/internal/types"
)

func writePolicyFile(t *testing.T, dir, serviceName string, prefixes []string) {
	t.Helper()
	data := "service_name: " + serviceName + "\nallowed_image_prefixes:\n"
	for _, p := range prefixes {
		data += "  - " + p + "\n"
	}
	if err := os.WriteFile(filepath.Join(dir, serviceName+".yaml"), []byte(data), 0644); err != nil {
		t.Fatal(err)
	}
}

func newTestManager(t *testing.T, services map[string][]string) *policy.Manager {
	t.Helper()
	dir := t.TempDir()
	for svc, prefixes := range services {
		writePolicyFile(t, dir, svc, prefixes)
	}
	m, err := policy.NewManager(dir)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}
	return m
}

func TestRouterDenyAuth(t *testing.T) {
	m := newTestManager(t, nil)
	r := NewRouter(m)

	result := r.Route("POST", "/auth", nil)
	if result.Action != types.ActionDeny {
		t.Errorf("expected ActionDeny, got %v", result.Action)
	}
}

func TestRouterAllowPing(t *testing.T) {
	m := newTestManager(t, nil)
	r := NewRouter(m)

	result := r.Route("GET", "/_ping", nil)
	if result.Action != types.ActionAllow {
		t.Errorf("expected ActionAllow, got %v", result.Action)
	}
}

func TestRouterAllowVersion(t *testing.T) {
	m := newTestManager(t, nil)
	r := NewRouter(m)

	result := r.Route("GET", "/v1.41/version", nil)
	if result.Action != types.ActionAllow {
		t.Errorf("expected ActionAllow, got %v", result.Action)
	}
}

func TestRouterDenyExec(t *testing.T) {
	m := newTestManager(t, nil)
	r := NewRouter(m)

	result := r.Route("POST", "/containers/beacon/exec", nil)
	if result.Action != types.ActionDeny {
		t.Errorf("expected ActionDeny, got %v", result.Action)
	}
}

func TestRouterDenyBuild(t *testing.T) {
	m := newTestManager(t, nil)
	r := NewRouter(m)

	result := r.Route("POST", "/build", nil)
	if result.Action != types.ActionDeny {
		t.Errorf("expected ActionDeny, got %v", result.Action)
	}
}

func TestRouterCreateContainerValidImage(t *testing.T) {
	m := newTestManager(t, map[string][]string{"beacon": {"chainsafe/lodestar"}})
	r := NewRouter(m)

	body := []byte(`{"Image": "chainsafe/lodestar:next", "HostConfig": {}}`)
	result := r.Route("POST", "/v1.41/containers/create", body)
	if result.Action != types.ActionCreateContainer {
		t.Errorf("expected ActionCreateContainer, got %v", result.Action)
	}
	if result.Service != "beacon" {
		t.Errorf("expected service beacon, got %s", result.Service)
	}
}

func TestRouterCreateContainerDeniedImage(t *testing.T) {
	m := newTestManager(t, map[string][]string{"beacon": {"chainsafe/lodestar"}})
	r := NewRouter(m)

	body := []byte(`{"Image": "attacker/malware:latest", "HostConfig": {}}`)
	result := r.Route("POST", "/v1.41/containers/create", body)
	if result.Action != types.ActionDeny {
		t.Errorf("expected ActionDeny, got %v", result.Action)
	}
}

func TestRouterContainerLifecycle(t *testing.T) {
	m := newTestManager(t, map[string][]string{"beacon": {"chainsafe/lodestar"}})
	r := NewRouter(m)

	tests := []struct {
		name   string
		method string
		path   string
		want   types.Action
	}{
		{"start", "POST", "/containers/beacon/start", types.ActionAllow},
		{"stop", "POST", "/containers/beacon/stop", types.ActionAllow},
		{"restart", "POST", "/containers/beacon/restart", types.ActionAllow},
		{"kill", "POST", "/containers/beacon/kill", types.ActionAllow},
		{"wait", "POST", "/containers/beacon/wait", types.ActionAllow},
		{"pause", "POST", "/containers/beacon/pause", types.ActionAllow},
		{"unpause", "POST", "/containers/beacon/unpause", types.ActionAllow},
		{"inspect", "GET", "/containers/beacon/json", types.ActionAllow},
		{"logs", "GET", "/containers/beacon/logs", types.ActionAllow},
		{"delete", "DELETE", "/containers/beacon", types.ActionAllow},
		{"rename", "POST", "/containers/beacon/rename", types.ActionDeny},
		{"update", "POST", "/containers/beacon/update", types.ActionDeny},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := r.Route(tt.method, tt.path, nil)
			if result.Action != tt.want {
				t.Errorf("Route(%s, %s) = %v, want %v", tt.method, tt.path, result.Action, tt.want)
			}
		})
	}
}

func TestRouterDefaultDeny(t *testing.T) {
	m := newTestManager(t, nil)
	r := NewRouter(m)

	result := r.Route("POST", "/networks/create", nil)
	if result.Action != types.ActionDeny {
		t.Errorf("expected ActionDeny, got %v", result.Action)
	}
}

func TestRouterAllowInfo(t *testing.T) {
	m := newTestManager(t, nil)
	r := NewRouter(m)
	result := r.Route("GET", "/info", nil)
	if result.Action != types.ActionAllow {
		t.Errorf("expected ActionAllow, got %v", result.Action)
	}
}

func TestRouterAllowEvents(t *testing.T) {
	m := newTestManager(t, nil)
	r := NewRouter(m)
	result := r.Route("GET", "/events", nil)
	if result.Action != types.ActionAllow {
		t.Errorf("expected ActionAllow, got %v", result.Action)
	}
}
