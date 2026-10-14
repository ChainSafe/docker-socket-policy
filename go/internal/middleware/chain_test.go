package middleware

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/ChainSafe/docker-socket-policy/go/internal/policy"
)

func testRequest(method, path string) *http.Request {
	return &http.Request{
		Method: method,
		URL:    &url.URL{Path: path},
	}
}

func testPolicy(overrides map[string]interface{}) *policy.Policy {
	p := &policy.Policy{
		ServiceName:          "test",
		AllowedImagePrefixes: []string{"chainsafe/lodestar"},
		ImageTagPattern:      `^[A-Za-z0-9._\-]{1,128}$`,
		ImageDigestAllowed:   true,
		EnvFile:              "/test/test.env",
		AllowedCLIFlags:      []string{"--rcConfig", "--dataDir", "--network"},
		DeniedFlags:          []string{"--volume", "--mount", "--privileged"},
		FlagRules: []policy.FlagRule{
			{Flag: "--network", ValuePattern: "^(mainnet|hoodi)$"},
		},
		Volumes: []policy.Volume{
			{HostPath: "/data", ContainerPath: "/data", ReadWrite: true},
		},
		ContainerConfig: policy.ContainerConfig{
			NetworkMode:     "host",
			RestartPolicy:   "unless-stopped",
			SecurityOptions: []string{"no-new-privileges:true"},
			User:            "2001:2001",
			LogDriver:       "json-file",
			LogOptions:      map[string]string{"max-size": "100m"},
		},
	}
	if name, ok := overrides["service_name"].(string); ok {
		p.ServiceName = name
	}
	if prefixes, ok := overrides["allowed_image_prefixes"].([]string); ok {
		p.AllowedImagePrefixes = prefixes
	}
	if ep, ok := overrides["env_file"].(string); ok {
		p.EnvFile = ep
	}
	if denials, ok := overrides["denied_flags"].([]string); ok {
		p.DeniedFlags = denials
	}
	if allows, ok := overrides["allowed_flags"].([]string); ok {
		p.AllowedCLIFlags = allows
	}
	if rules, ok := overrides["flag_rules"].([]policy.FlagRule); ok {
		p.FlagRules = rules
	}
	if vols, ok := overrides["volumes"].([]policy.Volume); ok {
		p.Volumes = vols
	}
	return p
}

func TestRegistryGate_ValidImage(t *testing.T) {
	c := NewChain()
	r := testRequest("POST", "/containers/create")
	body := map[string]interface{}{"Image": "chainsafe/lodestar:next"}
	p := testPolicy(nil)
	result := c.Execute(r, p, body)
	if !result.Allowed {
		t.Fatalf("expected allow, got: %s", result.Reason)
	}
}

func TestRegistryGate_DeniedImage(t *testing.T) {
	c := NewChain()
	r := testRequest("POST", "/containers/create")
	body := map[string]interface{}{"Image": "ubuntu:latest"}
	p := testPolicy(nil)
	result := c.Execute(r, p, body)
	if result.Allowed {
		t.Fatal("expected ubuntu image to be denied")
	}
}

func TestRegistryGate_ValidDigest(t *testing.T) {
	c := NewChain()
	r := testRequest("POST", "/containers/create")
	body := map[string]interface{}{"Image": "chainsafe/lodestar@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"}
	p := testPolicy(nil)
	result := c.Execute(r, p, body)
	if !result.Allowed {
		t.Fatalf("expected digest to be allowed, got: %s", result.Reason)
	}
}

func TestRegistryGate_DigestNotAllowed(t *testing.T) {
	c := NewChain()
	r := testRequest("POST", "/containers/create")
	body := map[string]interface{}{"Image": "chainsafe/lodestar@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"}
	p := testPolicy(map[string]interface{}{
		"allowed_image_prefixes": []string{"chainsafe/lodestar"},
	})
	p.ImageDigestAllowed = false
	result := c.Execute(r, p, body)
	if result.Allowed {
		t.Fatal("expected digest to be denied when ImageDigestAllowed=false")
	}
}

func TestMountSourceGate_AllowedVolume(t *testing.T) {
	c := NewChain()
	r := testRequest("POST", "/containers/create")
	body := map[string]interface{}{
		"Image": "chainsafe/lodestar:next",
		"HostConfig": map[string]interface{}{
			"Binds": []interface{}{"/data:/data:rw"},
		},
	}
	p := testPolicy(nil)
	result := c.Execute(r, p, body)
	if !result.Allowed {
		t.Fatalf("expected allowed volume, got: %s", result.Reason)
	}
}

func TestMountSourceGate_DeniedVolume(t *testing.T) {
	c := NewChain()
	r := testRequest("POST", "/containers/create")
	body := map[string]interface{}{
		"Image": "chainsafe/lodestar:next",
		"HostConfig": map[string]interface{}{
			"Binds": []interface{}{"/etc/passwd:/etc/passwd:ro"},
		},
	}
	p := testPolicy(nil)
	result := c.Execute(r, p, body)
	if result.Allowed {
		t.Fatal("expected non-whitelisted volume to be denied")
	}
}

func TestEnvFileGate_RejectsInlineEnv(t *testing.T) {
	c := NewChain()
	r := testRequest("POST", "/containers/create")
	body := map[string]interface{}{
		"Image": "chainsafe/lodestar:next",
		"Env":   []interface{}{"SECRET=leaked"},
	}
	p := testPolicy(nil)
	result := c.Execute(r, p, body)
	if result.Allowed {
		t.Fatal("expected inline env to be denied when env_file is set")
	}
}

func TestEnvFileGate_AllowsNoEnv(t *testing.T) {
	c := NewChain()
	r := testRequest("POST", "/containers/create")
	body := map[string]interface{}{
		"Image": "chainsafe/lodestar:next",
	}
	p := testPolicy(map[string]interface{}{"env_file": "/test/test.env"})
	result := c.Execute(r, p, body)
	if !result.Allowed {
		t.Fatalf("expected allow when no Env provided, got: %s", result.Reason)
	}
}

func TestEnvFileGate_SkipsWhenNoEnvFile(t *testing.T) {
	c := NewChain()
	r := testRequest("POST", "/containers/create")
	body := map[string]interface{}{
		"Image": "chainsafe/lodestar:next",
		"Env":   []interface{}{"FOO=bar"},
	}
	p := testPolicy(map[string]interface{}{"env_file": ""})
	result := c.Execute(r, p, body)
	if !result.Allowed {
		t.Fatalf("expected allow when env_file not set, got: %s", result.Reason)
	}
}

func TestCmdGate_AllowsAllowedFlag(t *testing.T) {
	c := NewChain()
	r := testRequest("POST", "/containers/create")
	body := map[string]interface{}{
		"Image": "chainsafe/lodestar:next",
		"Cmd":   []interface{}{"--rcConfig", "/data/config.yml"},
	}
	p := testPolicy(nil)
	result := c.Execute(r, p, body)
	if !result.Allowed {
		t.Fatalf("expected allowed flag, got: %s", result.Reason)
	}
}

func TestCmdGate_DeniesDeniedFlag(t *testing.T) {
	c := NewChain()
	r := testRequest("POST", "/containers/create")
	body := map[string]interface{}{
		"Image": "chainsafe/lodestar:next",
		"Cmd":   []interface{}{"--volume", "/data:/data"},
	}
	p := testPolicy(nil)
	result := c.Execute(r, p, body)
	if result.Allowed {
		t.Fatal("expected denied flag to be rejected")
	}
}

func TestCmdGate_DeniesNotAllowedFlag(t *testing.T) {
	c := NewChain()
	r := testRequest("POST", "/containers/create")
	body := map[string]interface{}{
		"Image": "chainsafe/lodestar:next",
		"Cmd":   []interface{}{"--randomFlag"},
	}
	p := testPolicy(nil)
	result := c.Execute(r, p, body)
	if result.Allowed {
		t.Fatal("expected non-allowed flag to be rejected")
	}
}

func TestCmdGate_ValidatesFlagValue(t *testing.T) {
	c := NewChain()
	r := testRequest("POST", "/containers/create")
	body := map[string]interface{}{
		"Image": "chainsafe/lodestar:next",
		"Cmd":   []interface{}{"--network", "mainnet"},
	}
	p := testPolicy(nil)
	result := c.Execute(r, p, body)
	if !result.Allowed {
		t.Fatalf("expected valid flag value, got: %s", result.Reason)
	}
}

func TestCmdGate_RejectsInvalidFlagValue(t *testing.T) {
	c := NewChain()
	r := testRequest("POST", "/containers/create")
	body := map[string]interface{}{
		"Image": "chainsafe/lodestar:next",
		"Cmd":   []interface{}{"--network", "hacker-chan"},
	}
	p := testPolicy(nil)
	result := c.Execute(r, p, body)
	if result.Allowed {
		t.Fatal("expected invalid flag value to be rejected")
	}
}

func TestCmdGate_SafeCharset(t *testing.T) {
	c := NewChain()
	r := testRequest("POST", "/containers/create")
	body := map[string]interface{}{
		"Image": "chainsafe/lodestar:next",
		"Cmd":   []interface{}{"; rm -rf /"},
	}
	p := testPolicy(nil)
	result := c.Execute(r, p, body)
	if result.Allowed {
		t.Fatal("expected unsafe characters in Cmd to be rejected")
	}
}

func TestContainerConfigMutator_SetsNetworkMode(t *testing.T) {
	c := NewChain()
	r := testRequest("POST", "/containers/create")
	body := map[string]interface{}{
		"Image": "chainsafe/lodestar:next",
	}
	p := testPolicy(nil)
	result := c.Execute(r, p, body)
	if !result.Allowed {
		t.Fatalf("expected allow, got: %s", result.Reason)
	}
	if result.ModifiedBody == nil {
		t.Fatal("expected modified body from mutator")
	}
}

func TestContainerConfigMutator_OverridesHostConfig(t *testing.T) {
	c := NewChain()
	r := testRequest("POST", "/containers/create")
	body := map[string]interface{}{
		"Image": "chainsafe/lodestar:next",
		"HostConfig": map[string]interface{}{
			"NetworkMode": "bridge",
			"Privileged":  true,
		},
	}
	p := testPolicy(nil)
	result := c.Execute(r, p, body)
	if !result.Allowed {
		t.Fatalf("expected allow, got: %s", result.Reason)
	}
}

func TestChain_MutatorRunsBeforeGates(t *testing.T) {
	c := NewChain()
	r := testRequest("POST", "/containers/create")
	body := map[string]interface{}{
		"Image": "chainsafe/lodestar:next",
		"HostConfig": map[string]interface{}{
			"Privileged": true,
		},
	}
	p := testPolicy(nil)
	result := c.Execute(r, p, body)
	if !result.Allowed {
		t.Fatalf("expected mutator to strip Privileged before gate check, got: %s", result.Reason)
	}
}

func TestRegistryGate_RejectsInvalidDigestFormat(t *testing.T) {
	c := NewChain()
	r := testRequest("POST", "/containers/create")
	body := map[string]interface{}{"Image": "chainsafe/lodestar@sha256:xyz"}
	p := testPolicy(nil)
	result := c.Execute(r, p, body)
	if result.Allowed {
		t.Fatal("expected invalid digest format to be rejected")
	}
}

func TestRegistryGate_RejectsOversizedTag(t *testing.T) {
	c := NewChain()
	r := testRequest("POST", "/containers/create")
	longTag := strings.Repeat("a", 129)
	body := map[string]interface{}{"Image": "chainsafe/lodestar:" + longTag}
	p := testPolicy(nil)
	result := c.Execute(r, p, body)
	if result.Allowed {
		t.Fatal("expected tag exceeding 128 chars to be rejected")
	}
}

func TestRegistryGate_RejectsTagOutsidePattern(t *testing.T) {
	c := NewChain()
	r := testRequest("POST", "/containers/create")
	body := map[string]interface{}{"Image": "chainsafe/lodestar:2.1"}
	p := testPolicy(nil)
	p.ImageTagPattern = `^v?[0-9]+\.[0-9]+\.[0-9]+$`
	result := c.Execute(r, p, body)
	if result.Allowed {
		t.Fatal("expected tag outside pattern to be rejected")
	}
}

func TestCmdGate_ValidatesInlineFlagValue(t *testing.T) {
	c := NewChain()
	r := testRequest("POST", "/containers/create")
	body := map[string]interface{}{
		"Image": "chainsafe/lodestar:next",
		"Cmd":   []interface{}{"--network=mainnet"},
	}
	p := testPolicy(nil)
	result := c.Execute(r, p, body)
	if !result.Allowed {
		t.Fatalf("expected --flag=value form to be allowed, got: %s", result.Reason)
	}
}

func TestCmdGate_RejectsInvalidInlineFlagValue(t *testing.T) {
	c := NewChain()
	r := testRequest("POST", "/containers/create")
	body := map[string]interface{}{
		"Image": "chainsafe/lodestar:next",
		"Cmd":   []interface{}{"--network=hacker-chan"},
	}
	p := testPolicy(nil)
	result := c.Execute(r, p, body)
	if result.Allowed {
		t.Fatal("expected invalid --flag=value to be rejected")
	}
}

func TestEnvFileGate_RejectsHostConfigEnv(t *testing.T) {
	c := NewChain()
	r := testRequest("POST", "/containers/create")
	body := map[string]interface{}{
		"Image": "chainsafe/lodestar:next",
		"HostConfig": map[string]interface{}{
			"Env": []interface{}{"SECRET=leaked"},
		},
	}
	p := testPolicy(nil)
	result := c.Execute(r, p, body)
	if result.Allowed {
		t.Fatal("expected HostConfig.Env to be denied when env_file is set")
	}
}

func TestMountSourceGate_DeniesTopLevelVolumes(t *testing.T) {
	c := NewChain()
	r := testRequest("POST", "/containers/create")
	body := map[string]interface{}{
		"Image": "chainsafe/lodestar:next",
		"Volumes": map[string]interface{}{
			"/etc/passwd": map[string]interface{}{},
		},
	}
	p := testPolicy(nil)
	result := c.Execute(r, p, body)
	if result.Allowed {
		t.Fatal("expected non-whitelisted top-level Volumes key to be denied")
	}
}

// TestChain_NetworkEndpoints: when the policy forces network_mode, the
// endpoint entries in NetworkingConfig.EndpointsConfig are made consistent
// with it (#87). Before #87 they went through as sent, so the Docker CLI's
// {"default": {}} made the start fail with "network default not found", and
// an extra entry attached the container to a network the policy does not
// allow. Rows mirror the runs in the network_endpoints module of
// spec/docker_socket_policy.qnt; mynet stands for a named network and
// container:beacon for container:x.
func TestChain_NetworkEndpoints(t *testing.T) {
	const aliases = `{"Aliases":["a"]}`
	ec := func(entries string) string { return `{"EndpointsConfig":{` + entries + `}}` }
	extra := func(mode string) string {
		return `network "other" is not allowed for service test; policy forces network_mode ` + mode
	}
	malformed := "NetworkingConfig.EndpointsConfig must be a JSON object; policy forces network_mode host"
	cases := []struct {
		row  string
		mode string // "" means the policy does not force network_mode
		req  string // NetworkingConfig as sent; "" means absent
		want string // NetworkingConfig forwarded, when allowed
		deny string // deny reason substring, when denied
	}{
		{"hostNoEndpoints", "host", "", ec(""), ""},
		{"hostDefaultCleared", "host", ec(`"default":{}`), ec(""), ""},
		{"hostOwnCleared", "host", ec(`"host":` + aliases), ec(""), ""},
		{"hostExtraDenied", "host", ec(`"default":{},"other":{}`), "", extra("host")},
		{"noneNoEndpoints", "none", "", ec(""), ""},
		{"noneDefaultCleared", "none", ec(`"default":{}`), ec(""), ""},
		{"noneOwnCleared", "none", ec(`"none":` + aliases), ec(""), ""},
		{"noneExtraDenied", "none", ec(`"default":{},"other":{}`), "", extra("none")},
		{"containerNoEndpoints", "container:beacon", "", ec(""), ""},
		{"containerDefaultCleared", "container:beacon", ec(`"default":{}`), ec(""), ""},
		{"containerOwnCleared", "container:beacon", ec(`"container:beacon":` + aliases), ec(""), ""},
		{"containerExtraDenied", "container:beacon", ec(`"default":{},"other":{}`), "", extra("container:beacon")},
		{"bridgeNoEndpoints", "bridge", "", ec(`"bridge":{}`), ""},
		{"bridgeDefaultRekeyed", "bridge", ec(`"default":` + aliases), ec(`"bridge":` + aliases), ""},
		{"bridgeOwnKept", "bridge", ec(`"bridge":` + aliases), ec(`"bridge":` + aliases), ""},
		{"bridgeExtraDenied", "bridge", ec(`"default":{},"other":{}`), "", extra("bridge")},
		{"namedNoEndpoints", "mynet", "", ec(`"mynet":{}`), ""},
		{"namedDefaultRekeyed", "mynet", ec(`"default":` + aliases), ec(`"mynet":` + aliases), ""},
		{"namedOwnKept", "mynet", ec(`"mynet":` + aliases), ec(`"mynet":` + aliases), ""},
		{"namedExtraDenied", "mynet", ec(`"default":{},"other":{}`), "", extra("mynet")},
		{"namedOwnOverDefault", "mynet", ec(`"default":` + aliases + `,"mynet":{}`), ec(`"mynet":{}`), ""},
		// #87: a null NetworkingConfig or EndpointsConfig counts as absent.
		{"#87 null NetworkingConfig", "host", "null", ec(""), ""},
		{"#87 null EndpointsConfig", "bridge", `{"EndpointsConfig":null}`, ec(`"bridge":{}`), ""},
		// #87: a NetworkingConfig or EndpointsConfig that is not an object is denied.
		{"#87 EndpointsConfig array", "host", `{"EndpointsConfig":[]}`, "", malformed},
		{"#87 NetworkingConfig string", "host", `"default"`, "", malformed},
		// #87 control: without a forced network_mode, NetworkingConfig is untouched.
		{"#87 no forced mode", "", ec(`"default":{},"other":{}`), ec(`"default":{},"other":{}`), ""},
	}
	var mismatches []string
	for _, tc := range cases {
		p := testPolicy(nil)
		p.ContainerConfig.NetworkMode = tc.mode
		body := map[string]interface{}{"Image": "chainsafe/lodestar:next"}
		if tc.req != "" {
			var nc interface{}
			if err := json.Unmarshal([]byte(tc.req), &nc); err != nil {
				t.Fatalf("%s: bad request JSON: %v", tc.row, err)
			}
			body["NetworkingConfig"] = nc
		}
		result := NewChain().Execute(testRequest("POST", "/containers/create"), p, body)
		if tc.deny != "" {
			if result.Allowed || !strings.Contains(result.Reason, tc.deny) {
				mismatches = append(mismatches, fmt.Sprintf("%s: got allowed=%v %q, want deny %q", tc.row, result.Allowed, result.Reason, tc.deny))
			}
			continue
		}
		if !result.Allowed {
			mismatches = append(mismatches, fmt.Sprintf("%s: got deny %q, want %s", tc.row, result.Reason, tc.want))
			continue
		}
		var out map[string]interface{}
		if err := json.Unmarshal(result.ModifiedBody, &out); err != nil {
			t.Fatalf("%s: bad modified body: %v", tc.row, err)
		}
		var want interface{}
		if err := json.Unmarshal([]byte(tc.want), &want); err != nil {
			t.Fatalf("%s: bad want JSON: %v", tc.row, err)
		}
		if got := out["NetworkingConfig"]; !reflect.DeepEqual(got, want) {
			gotJSON, _ := json.Marshal(got)
			mismatches = append(mismatches, fmt.Sprintf("%s: got %s, want %s", tc.row, gotJSON, tc.want))
		}
	}
	if len(mismatches) > 0 {
		t.Fatalf("%d mismatches:\n%s", len(mismatches), strings.Join(mismatches, "\n"))
	}
}

// TestRegistryGate_ParsesReferences pins the registry gate's reference parser
// (#84): a registry port is not a tag, Docker Hub spellings match the
// normalised prefix, and the tag pattern sees only the tag. The policy's
// prefixes are normalised, as the manager stores them. Same rows in Rust and
// TypeScript.
func TestRegistryGate_ParsesReferences(t *testing.T) {
	gate := &RegistryGate{}
	r := testRequest("POST", "/containers/create")
	p := testPolicy(map[string]interface{}{
		"allowed_image_prefixes": []string{"chainsafe/lodestar", "localhost:5000/team", "registry.example.com:443/a"},
	})
	p.ImageTagPattern = `^(v[0-9]+|[0-9.]+)$`

	tests := []struct {
		image   string
		wantErr string
	}{
		{"localhost:5000/team/app:1.2", ""},
		{"localhost:5000/team/app", ""},
		{"docker.io/chainsafe/lodestar:v1", ""},
		{"registry.example.com:443/a", ""},
		{"Registry.Example.com:443/a:2", ""},
		{"localhost:5000/team/app:latest", `image tag "latest" does not match pattern "^(v[0-9]+|[0-9.]+)$"`},
		{"localhost:5000/other:1", `image "localhost:5000/other" is not in allowed prefixes`},
		{"chainsafe/Lodestar:v1", `invalid image reference "chainsafe/Lodestar:v1"`},
	}
	for _, tt := range tests {
		t.Run(tt.image, func(t *testing.T) {
			err := gate.Check(r, p, map[string]interface{}{"Image": tt.image})
			switch {
			case tt.wantErr == "" && err != nil:
				t.Errorf("Check(%s) = %v, want nil", tt.image, err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Errorf("Check(%s) = %v, want error containing %q", tt.image, err, tt.wantErr)
			}
		})
	}
}
