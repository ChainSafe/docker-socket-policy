package middleware

import (
	"net/http"
	"net/url"
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

func TestExecGate_DeniesExec(t *testing.T) {
	c := NewChain(false)
	r := testRequest("POST", "/containers/test/exec")
	body := map[string]interface{}{}
	p := testPolicy(nil)
	result := c.Execute(r, p, body)
	if result.Allowed {
		t.Fatal("expected exec to be denied")
	}
}

func TestExecGate_AllowsNonExec(t *testing.T) {
	c := NewChain(false)
	r := testRequest("POST", "/containers/create")
	body := map[string]interface{}{"Image": "chainsafe/lodestar:next"}
	p := testPolicy(nil)
	result := c.Execute(r, p, body)
	if !result.Allowed {
		t.Fatalf("expected allow, got: %s", result.Reason)
	}
}

func TestRegistryGate_ValidImage(t *testing.T) {
	c := NewChain(false)
	r := testRequest("POST", "/containers/create")
	body := map[string]interface{}{"Image": "chainsafe/lodestar:next"}
	p := testPolicy(nil)
	result := c.Execute(r, p, body)
	if !result.Allowed {
		t.Fatalf("expected allow, got: %s", result.Reason)
	}
}

func TestRegistryGate_DeniedImage(t *testing.T) {
	c := NewChain(false)
	r := testRequest("POST", "/containers/create")
	body := map[string]interface{}{"Image": "ubuntu:latest"}
	p := testPolicy(nil)
	result := c.Execute(r, p, body)
	if result.Allowed {
		t.Fatal("expected ubuntu image to be denied")
	}
}

func TestRegistryGate_ValidDigest(t *testing.T) {
	c := NewChain(false)
	r := testRequest("POST", "/containers/create")
	body := map[string]interface{}{"Image": "chainsafe/lodestar@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"}
	p := testPolicy(nil)
	result := c.Execute(r, p, body)
	if !result.Allowed {
		t.Fatalf("expected digest to be allowed, got: %s", result.Reason)
	}
}

func TestRegistryGate_DigestNotAllowed(t *testing.T) {
	c := NewChain(false)
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
	c := NewChain(false)
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
	c := NewChain(false)
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
	c := NewChain(false)
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
	c := NewChain(false)
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
	c := NewChain(false)
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
	c := NewChain(false)
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
	c := NewChain(false)
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
	c := NewChain(false)
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
	c := NewChain(false)
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
	c := NewChain(false)
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
	c := NewChain(false)
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
	c := NewChain(false)
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
	c := NewChain(false)
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
	c := NewChain(false)
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
