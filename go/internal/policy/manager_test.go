package policy

import (
	"os"
	"path/filepath"
	"strings"
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

func TestGetByImage_RejectsUnrelatedPrefix(t *testing.T) {
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

	if _, err := m.GetByImage("evilchainsafe-lodestar:latest"); err == nil {
		t.Fatal("expected error for bare-substring prefix match, got nil")
	}
	if _, err := m.GetByImage("chainsafe/lodestar-backup:latest"); err == nil {
		t.Fatal("expected error for sibling image matching prefix, got nil")
	}
	p, err := m.GetByImage("chainsafe/lodestar/beacon:latest")
	if err != nil {
		t.Fatalf("expected nested image under prefix to match: %v", err)
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

// TestParseImageRef is the #84 normalisation table, on the parser itself.
// The same rows run in Rust and TypeScript.
func TestParseImageRef(t *testing.T) {
	const digest = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	tests := []struct {
		in      string
		want    ImageRef
		invalid bool
	}{
		{in: "alpine", want: ImageRef{Name: "alpine"}},
		{in: "library/alpine", want: ImageRef{Name: "alpine"}},
		{in: "docker.io/library/alpine", want: ImageRef{Name: "alpine"}},
		{in: "index.docker.io/library/alpine:3.19", want: ImageRef{Name: "alpine", Tag: "3.19"}},
		{in: "registry-1.docker.io/library/alpine", want: ImageRef{Name: "alpine"}},
		{in: "docker.io/chainsafe/lodestar:v1", want: ImageRef{Name: "chainsafe/lodestar", Tag: "v1"}},
		{in: "ghcr.io/chainsafe/lodestar@" + digest, want: ImageRef{Name: "ghcr.io/chainsafe/lodestar", Digest: digest}},
		{in: "localhost:5000/x/y:2", want: ImageRef{Name: "localhost:5000/x/y", Tag: "2"}},
		{in: "registry.example.com:443/a", want: ImageRef{Name: "registry.example.com:443/a"}},
		{in: "REGISTRY.Example.com:443/a:V1", want: ImageRef{Name: "registry.example.com:443/a", Tag: "V1"}},
		{in: "docker.io/library/a/b", want: ImageRef{Name: "library/a/b"}},
		{in: "ghcr.io/library/alpine", want: ImageRef{Name: "ghcr.io/library/alpine"}},
		{in: "localhost/x", want: ImageRef{Name: "localhost/x"}},
		{in: "localhost", want: ImageRef{Name: "localhost"}},
		{in: "alpine:3.19@" + digest, want: ImageRef{Name: "alpine", Tag: "3.19", Digest: digest}},
		{in: "Alpine", invalid: true},
		{in: "chainsafe/Lodestar", invalid: true},
		{in: "alpine:", invalid: true},
		{in: "alpine@", invalid: true},
		{in: "", invalid: true},
		{in: "a//b", invalid: true},
		{in: "/alpine", invalid: true},
		{in: "alpine/", invalid: true},
		{in: "-alpine", invalid: true},
		{in: "alpine:a/b", invalid: true},
		{in: "a:b/c", invalid: true},
		{in: "alpine:t$g", invalid: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseImageRef(tt.in)
			if tt.invalid {
				want := `invalid image reference "` + tt.in + `"`
				if err == nil || err.Error() != want {
					t.Errorf("ParseImageRef(%q) = %+v, %v; want error %q", tt.in, got, err, want)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Errorf("ParseImageRef(%q) = %+v, %v; want %+v", tt.in, got, err, tt.want)
			}
		})
	}
}

// TestManagerNormalizesPrefixes checks that prefixes are normalised at load
// time, and that a prefix with a tag or an invalid one fails the load (#84).
func TestManagerNormalizesPrefixes(t *testing.T) {
	dir := t.TempDir()
	write := func(content string) {
		if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	write("service_name: a\nallowed_image_prefixes:\n  - docker.io/library/alpine\n  - GHCR.io/team\n")
	m, err := NewManager(dir)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	p, _ := m.Get("a")
	if got := strings.Join(p.AllowedImagePrefixes, ","); got != "alpine,ghcr.io/team" {
		t.Errorf("prefixes = %s, want alpine,ghcr.io/team", got)
	}
	for _, bad := range []string{"alpine:3.19", "Alpine"} {
		write("service_name: a\nallowed_image_prefixes:\n  - \"" + bad + "\"\n")
		if _, err := NewManager(dir); err == nil || !strings.Contains(err.Error(), "invalid allowed_image_prefixes entry") {
			t.Errorf("%s: NewManager error = %v, want an invalid entry error", bad, err)
		}
	}
}
