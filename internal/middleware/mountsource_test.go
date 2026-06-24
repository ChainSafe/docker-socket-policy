package middleware

import (
	"net/http"
	"testing"

	"github.com/ChainSafe/docker-socket-policy/internal/policy"
)

func TestMountSourceGate_AllowedVolume(t *testing.T) {
	g := &MountSourceGate{}
	p := &policy.Policy{
		ServiceName: "beacon",
		Volumes: []policy.Volume{
			{HostPath: "/home/beacon", ContainerPath: "/data", ReadWrite: true},
		},
	}
	body := map[string]interface{}{
		"HostConfig": map[string]interface{}{
			"Binds": []interface{}{"/home/beacon:/data"},
		},
	}
	req, _ := http.NewRequest("POST", "/containers/create", nil)

	if err := g.Check(req, p, body); err != nil {
		t.Errorf("expected allowed, got: %v", err)
	}
}

func TestMountSourceGate_DeniedVolume(t *testing.T) {
	g := &MountSourceGate{}
	p := &policy.Policy{
		ServiceName: "beacon",
		Volumes: []policy.Volume{
			{HostPath: "/home/beacon", ContainerPath: "/data", ReadWrite: true},
		},
	}
	body := map[string]interface{}{
		"HostConfig": map[string]interface{}{
			"Binds": []interface{}{"/var/run/docker.sock:/var/run/docker.sock"},
		},
	}
	req, _ := http.NewRequest("POST", "/containers/create", nil)

	if err := g.Check(req, p, body); err == nil {
		t.Errorf("expected denied for /var/run/docker.sock, got nil")
	}
}

func TestMountSourceGate_NoVolumesPolicy(t *testing.T) {
	g := &MountSourceGate{}
	p := &policy.Policy{
		ServiceName: "beacon",
		Volumes:     nil,
	}
	body := map[string]interface{}{
		"HostConfig": map[string]interface{}{
			"Binds": []interface{}{"/any:/any"},
		},
	}
	req, _ := http.NewRequest("POST", "/containers/create", nil)

	if err := g.Check(req, p, body); err != nil {
		t.Errorf("expected allowed when no volume whitelist, got: %v", err)
	}
}

func TestExtractHostPath(t *testing.T) {
	tests := []struct {
		bind string
		want string
	}{
		{"/home/beacon:/data", "/home/beacon"},
		{"/home/beacon:/data:ro", "/home/beacon"},
		{"volume_name:/data", "volume_name"},
	}

	for _, tt := range tests {
		t.Run(tt.bind, func(t *testing.T) {
			if got := extractHostPath(tt.bind); got != tt.want {
				t.Errorf("extractHostPath(%q) = %q, want %q", tt.bind, got, tt.want)
			}
		})
	}
}
