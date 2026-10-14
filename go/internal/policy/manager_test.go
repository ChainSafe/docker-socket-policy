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
container_names: [beacon]
allowed_image_prefixes:
  - chainsafe/lodestar
`)
	writePolicyFile(t, dir, "validator.yaml", `
service_name: validator
container_names: [validator]
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

// TestNewManager_LoadTimeValidation is the cross-language parity guard for
// the #85 load-time checks. Two policies conflict when their image prefixes
// share a namespace and one has no container_names or their container_names
// intersect. Before #85 every row loaded, and a duplicate service_name
// silently replaced the first file.
func TestNewManager_LoadTimeValidation(t *testing.T) {
	tests := []struct {
		name    string
		files   map[string]string
		wantErr string // "" means it loads
	}{
		{"same prefix, no container_names", map[string]string{
			"a.yaml": "service_name: a\nallowed_image_prefixes: [alpine]\n",
			"b.yaml": "service_name: b\nallowed_image_prefixes: [alpine]\n",
		}, `conflicting policies "a" (a.yaml) and "b" (b.yaml): image prefixes "alpine" and "alpine" overlap and "a" has no container_names`},
		{"one side has no container_names", map[string]string{
			"a.yaml": "service_name: a\ncontainer_names: [x]\nallowed_image_prefixes: [chainsafe/lodestar]\n",
			"b.yaml": "service_name: b\nallowed_image_prefixes: [chainsafe]\n",
		}, `conflicting policies "a" (a.yaml) and "b" (b.yaml): image prefixes "chainsafe/lodestar" and "chainsafe" overlap and "b" has no container_names`},
		{"shared container name", map[string]string{
			"a.yaml": "service_name: a\ncontainer_names: [x, y]\nallowed_image_prefixes: [chainsafe/lodestar]\n",
			"b.yaml": "service_name: b\ncontainer_names: [z, y]\nallowed_image_prefixes: [chainsafe/lodestar]\n",
		}, `conflicting policies "a" (a.yaml) and "b" (b.yaml): image prefixes "chainsafe/lodestar" and "chainsafe/lodestar" overlap and both accept container name "y"`},
		{"disjoint container names", map[string]string{
			"a.yaml": "service_name: a\ncontainer_names: [beacon]\nallowed_image_prefixes: [chainsafe/lodestar]\n",
			"b.yaml": "service_name: b\ncontainer_names: [validator]\nallowed_image_prefixes: [chainsafe/lodestar]\n",
		}, ""},
		{"sibling prefixes do not overlap", map[string]string{
			"a.yaml": "service_name: a\nallowed_image_prefixes: [chainsafe/lodestar]\n",
			"b.yaml": "service_name: b\nallowed_image_prefixes: [chainsafe/lodestar-backup]\n",
		}, ""},
		{"duplicate service_name", map[string]string{
			"a.yaml": "service_name: svc\nallowed_image_prefixes: [alpine]\n",
			"b.yaml": "service_name: svc\nallowed_image_prefixes: [busybox]\n",
		}, `policies in a.yaml and b.yaml both use service_name "svc"`},
		{"invalid container name", map[string]string{
			"a.yaml": "service_name: a\ncontainer_names: [-bad]\nallowed_image_prefixes: [alpine]\n",
		}, `invalid container name "-bad" in container_names`},
		{"container name with a slash", map[string]string{
			"a.yaml": "service_name: a\ncontainer_names: [a/b]\nallowed_image_prefixes: [alpine]\n",
		}, `invalid container name "a/b" in container_names`},
		{"empty container_names", map[string]string{
			"a.yaml": "service_name: a\ncontainer_names: []\nallowed_image_prefixes: [alpine]\n",
		}, `container_names must not be empty`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, content := range tt.files {
				writePolicyFile(t, dir, name, content)
			}
			_, err := NewManager(dir)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("NewManager failed: %v", err)
			case tt.wantErr != "" && err == nil:
				t.Fatalf("NewManager loaded, want error %q", tt.wantErr)
			case tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr):
				t.Fatalf("NewManager error %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// TestSelectForCreate covers #85 selection: the one policy matching the
// image and accepting the name, the nameless create, and ambiguity.
func TestSelectForCreate(t *testing.T) {
	m := NewManagerFromPolicies(
		&Policy{ServiceName: "validator", ContainerNames: []string{"validator"}, AllowedImagePrefixes: []string{"chainsafe/lodestar"}},
		&Policy{ServiceName: "beacon", ContainerNames: []string{"beacon"}, AllowedImagePrefixes: []string{"chainsafe/lodestar"}},
		&Policy{ServiceName: "any", AllowedImagePrefixes: []string{"chainsafe"}},
	)
	for i := 0; i < 50; i++ {
		for _, name := range []string{"beacon", "validator"} {
			_, err := m.SelectForCreate("chainsafe/lodestar:v1", name)
			want := "ambiguous policy for image chainsafe/lodestar:v1 and name " + name + ": any, " + name
			if err == nil || err.Error() != want {
				t.Fatalf("SelectForCreate(%s) error = %v, want %q", name, err, want)
			}
		}
	}
	if p, err := m.SelectForCreate("chainsafe/lodestar:v1", ""); err != nil || p.ServiceName != "any" {
		t.Fatalf("nameless: got %v, %v; want any", p, err)
	}

	m = NewManagerFromPolicies(m.policiesByName["beacon"], m.policiesByName["validator"])
	for i := 0; i < 50; i++ {
		for _, name := range []string{"beacon", "validator"} {
			if p, err := m.SelectForCreate("chainsafe/lodestar:v1", name); err != nil || p.ServiceName != name {
				t.Fatalf("iteration %d: SelectForCreate(%s) = %v, %v", i, name, p, err)
			}
		}
	}
}

func TestCovering(t *testing.T) {
	m := NewManagerFromPolicies(
		&Policy{ServiceName: "beacon", AllowedImagePrefixes: []string{"chainsafe/lodestar"}},
		&Policy{ServiceName: "vc", ContainerNames: []string{"validator"}, AllowedImagePrefixes: []string{"chainsafe/lodestar"}},
	)
	for name, want := range map[string]int{"beacon": 1, "validator": 1, "vc": 0, "other": 0} {
		if got := len(m.Covering(name)); got != want {
			t.Errorf("Covering(%q) = %d policies, want %d", name, got, want)
		}
	}
}
