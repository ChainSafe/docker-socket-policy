package middleware

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ChainSafe/docker-socket-policy/internal/policy"
)

func TestRegistryGate_AllowedImage(t *testing.T) {
	g := &RegistryGate{}
	p := &policy.Policy{
		ServiceName:          "beacon",
		AllowedImagePrefixes: []string{"chainsafe/lodestar"},
	}
	body := map[string]interface{}{
		"Image": "chainsafe/lodestar:next",
	}
	req, _ := http.NewRequest("POST", "/containers/create", nil)

	if err := g.Check(req, p, body); err != nil {
		t.Errorf("expected allowed, got: %v", err)
	}
}

func TestRegistryGate_DeniedImage(t *testing.T) {
	g := &RegistryGate{}
	p := &policy.Policy{
		ServiceName:          "beacon",
		AllowedImagePrefixes: []string{"chainsafe/lodestar"},
	}
	body := map[string]interface{}{
		"Image": "attacker/malware:latest",
	}
	req, _ := http.NewRequest("POST", "/containers/create", nil)

	if err := g.Check(req, p, body); err == nil {
		t.Errorf("expected denied, got nil")
	}
}

func TestRegistryGate_TagPattern(t *testing.T) {
	g := &RegistryGate{}
	p := &policy.Policy{
		ServiceName:          "beacon",
		AllowedImagePrefixes: []string{"chainsafe/lodestar"},
		ImageTagPattern:      `^v[0-9]+\.[0-9]+\.[0-9]+$`,
	}

	tests := []struct {
		image string
		allow bool
	}{
		{"chainsafe/lodestar:v1.2.3", true},
		{"chainsafe/lodestar:v1.0.0", true},
		{"chainsafe/lodestar:latest", false},
		{"chainsafe/lodestar:next", false},
	}

	for _, tt := range tests {
		t.Run(tt.image, func(t *testing.T) {
			body := map[string]interface{}{"Image": tt.image}
			req, _ := http.NewRequest("POST", "/containers/create", nil)
			err := g.Check(req, p, body)
			if tt.allow && err != nil {
				t.Errorf("expected allowed for %s, got: %v", tt.image, err)
			}
			if !tt.allow && err == nil {
				t.Errorf("expected denied for %s, got nil", tt.image)
			}
		})
	}
}

func TestRegistryGate_DigestAllowed(t *testing.T) {
	g := &RegistryGate{}
	p := &policy.Policy{
		ServiceName:          "beacon",
		AllowedImagePrefixes: []string{"chainsafe/lodestar"},
		ImageDigestAllowed:   true,
	}

	body := map[string]interface{}{
		"Image": "chainsafe/lodestar@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
	}
	req, _ := http.NewRequest("POST", "/containers/create", nil)

	if err := g.Check(req, p, body); err != nil {
		t.Errorf("expected digest allowed, got: %v", err)
	}
}

func TestRegistryGate_DigestDenied(t *testing.T) {
	g := &RegistryGate{}
	p := &policy.Policy{
		ServiceName:          "beacon",
		AllowedImagePrefixes: []string{"chainsafe/lodestar"},
		ImageDigestAllowed:   false,
	}

	body := map[string]interface{}{
		"Image": "chainsafe/lodestar@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
	}
	req, _ := http.NewRequest("POST", "/containers/create", nil)

	if err := g.Check(req, p, body); err == nil {
		t.Errorf("expected digest denied, got nil")
	}
}

func TestSplitImageRef(t *testing.T) {
	tests := []struct {
		ref           string
		wantName      string
		wantTagOrHash string
	}{
		{"chainsafe/lodestar:next", "chainsafe/lodestar", "next"},
		{"chainsafe/lodestar@sha256:abc", "chainsafe/lodestar", "sha256:abc"},
		{"chainsafe/lodestar", "chainsafe/lodestar", ""},
	}

	for _, tt := range tests {
		t.Run(strings.ReplaceAll(tt.ref, "/", "_"), func(t *testing.T) {
			name, tag := splitImageRef(tt.ref)
			if name != tt.wantName {
				t.Errorf("splitImageRef(%q) name = %q, want %q", tt.ref, name, tt.wantName)
			}
			if tag != tt.wantTagOrHash {
				t.Errorf("splitImageRef(%q) tag = %q, want %q", tt.ref, tag, tt.wantTagOrHash)
			}
		})
	}
}

func TestIsAllowedPrefix(t *testing.T) {
	tests := []struct {
		name     string
		prefixes []string
		want     bool
	}{
		{"chainsafe/lodestar", []string{"chainsafe/lodestar"}, true},
		{"chainsafe/lodestar/beacon", []string{"chainsafe/lodestar"}, true},
		{"attacker/malware", []string{"chainsafe/lodestar"}, false},
		{"chainsafe", []string{"chainsafe/lodestar"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isAllowedPrefix(tt.name, tt.prefixes); got != tt.want {
				t.Errorf("isAllowedPrefix(%q, %v) = %v, want %v", tt.name, tt.prefixes, got, tt.want)
			}
		})
	}
}
