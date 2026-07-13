package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func writePolicyFile(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write policy file: %v", err)
	}
}

func TestNewManager_LoadsValidPolicies(t *testing.T) {
	dir := t.TempDir()
	writePolicyFile(t, dir, "beacon.yaml", `
service_name: beacon
allowed_image_prefixes:
  - chainsafe/lodestar
`)
	writePolicyFile(t, dir, "validator.yaml", `
service_name: validator
allowed_image_prefixes:
  - chainsafe/lodestar
`)

	m, err := NewManager(dir)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	names := m.List()
	if len(names) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(names))
	}

	p, err := m.Get("beacon")
	if err != nil {
		t.Fatalf("Get('beacon') failed: %v", err)
	}
	if p.ServiceName != "beacon" {
		t.Fatalf("expected service_name 'beacon', got '%s'", p.ServiceName)
	}

	if len(p.AllowedImagePrefixes) != 1 || p.AllowedImagePrefixes[0] != "chainsafe/lodestar" {
		t.Fatalf("unexpected allowed_image_prefixes: %v", p.AllowedImagePrefixes)
	}
}

func TestNewManager_RejectsMissingServiceName(t *testing.T) {
	dir := t.TempDir()
	writePolicyFile(t, dir, "bad.yaml", `
allowed_image_prefixes:
  - chainsafe/lodestar
`)

	_, err := NewManager(dir)
	if err == nil {
		t.Fatal("expected error for missing service_name, got nil")
	}
}

func TestNewManager_RejectsEmptyPrefixes(t *testing.T) {
	dir := t.TempDir()
	writePolicyFile(t, dir, "bad.yaml", `
service_name: test
allowed_image_prefixes:
`)

	_, err := NewManager(dir)
	if err == nil {
		t.Fatal("expected error for empty allowed_image_prefixes, got nil")
	}
}

func TestNewManager_SkipsNonYamlFiles(t *testing.T) {
	dir := t.TempDir()
	writePolicyFile(t, dir, "beacon.yaml", `
service_name: beacon
allowed_image_prefixes:
  - chainsafe/lodestar
`)
	writePolicyFile(t, dir, "readme.txt", `this is not a policy`)
	writePolicyFile(t, dir, "notes.md", `not a policy either`)

	m, err := NewManager(dir)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	if len(m.List()) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(m.List()))
	}
}

func TestGetByImage_Match(t *testing.T) {
	dir := t.TempDir()
	writePolicyFile(t, dir, "beacon.yaml", `
service_name: beacon
allowed_image_prefixes:
  - chainsafe/lodestar
`)

	m, err := NewManager(dir)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	p, err := m.GetByImage("chainsafe/lodestar:next")
	if err != nil {
		t.Fatalf("GetByImage failed: %v", err)
	}
	if p.ServiceName != "beacon" {
		t.Fatalf("expected 'beacon', got '%s'", p.ServiceName)
	}
}

func TestGetByImage_NoMatch(t *testing.T) {
	dir := t.TempDir()
	writePolicyFile(t, dir, "beacon.yaml", `
service_name: beacon
allowed_image_prefixes:
  - chainsafe/lodestar
`)

	m, err := NewManager(dir)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	_, err = m.GetByImage("ubuntu:latest")
	if err == nil {
		t.Fatal("expected error for unmatching image, got nil")
	}
}

func TestGetByImage_PrefixMatch(t *testing.T) {
	dir := t.TempDir()
	writePolicyFile(t, dir, "beacon.yaml", `
service_name: beacon
allowed_image_prefixes:
  - chainsafe/lodestar
  - ethpandaops/lodestar
`)

	m, err := NewManager(dir)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	p, err := m.GetByImage("ethpandaops/lodestar:latest")
	if err != nil {
		t.Fatalf("GetByImage failed: %v", err)
	}
	if p.ServiceName != "beacon" {
		t.Fatalf("expected 'beacon', got '%s'", p.ServiceName)
	}
}

func TestGet_UnknownService(t *testing.T) {
	dir := t.TempDir()
	writePolicyFile(t, dir, "beacon.yaml", `
service_name: beacon
allowed_image_prefixes:
  - chainsafe/lodestar
`)

	m, err := NewManager(dir)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	_, err = m.Get("nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown service, got nil")
	}
}

func TestExtractImageName(t *testing.T) {
	tests := []struct {
		ref      string
		expected string
	}{
		{"chainsafe/lodestar:next", "chainsafe/lodestar"},
		{"chainsafe/lodestar@sha256:abc123", "chainsafe/lodestar"},
		{"ubuntu", "ubuntu"},
		{"registry.example.com/image:v1.0", "registry.example.com/image"},
	}

	for _, tc := range tests {
		got := extractImageName(tc.ref)
		if got != tc.expected {
			t.Errorf("extractImageName(%q) = %q, want %q", tc.ref, got, tc.expected)
		}
	}
}
