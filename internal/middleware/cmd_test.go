package middleware

import (
	"net/http"
	"testing"

	"github.com/ChainSafe/docker-socket-policy/internal/policy"
)

func TestCmdGate_AllowedFlags(t *testing.T) {
	g := &CmdGate{}
	p := &policy.Policy{
		ServiceName:     "beacon",
		AllowedCLIFlags: []string{"--rcConfig", "--logLevel"},
	}
	body := map[string]interface{}{
		"Cmd": []interface{}{"--rcConfig", "/data/config.yml", "--logLevel", "info"},
	}
	req, _ := http.NewRequest("POST", "/containers/create", nil)

	if err := g.Check(req, p, body); err != nil {
		t.Errorf("expected allowed, got: %v", err)
	}
}

func TestCmdGate_DeniedFlag(t *testing.T) {
	g := &CmdGate{}
	p := &policy.Policy{
		ServiceName:     "beacon",
		AllowedCLIFlags: []string{"--rcConfig"},
		DeniedFlags:     []string{"--privileged"},
	}
	body := map[string]interface{}{
		"Cmd": []interface{}{"--rcConfig", "/data/config.yml", "--privileged"},
	}
	req, _ := http.NewRequest("POST", "/containers/create", nil)

	if err := g.Check(req, p, body); err == nil {
		t.Errorf("expected denied for --privileged, got nil")
	}
}

func TestCmdGate_FlagNotInAllowlist(t *testing.T) {
	g := &CmdGate{}
	p := &policy.Policy{
		ServiceName:     "beacon",
		AllowedCLIFlags: []string{"--rcConfig"},
	}
	body := map[string]interface{}{
		"Cmd": []interface{}{"--rcConfig", "/data/config.yml", "--unknown-flag", "value"},
	}
	req, _ := http.NewRequest("POST", "/containers/create", nil)

	if err := g.Check(req, p, body); err == nil {
		t.Errorf("expected denied for --unknown-flag, got nil")
	}
}

func TestCmdGate_FlagValuePattern(t *testing.T) {
	g := &CmdGate{}
	p := &policy.Policy{
		ServiceName:     "beacon",
		AllowedCLIFlags: []string{"--rcConfig", "--logLevel"},
		FlagRules: []policy.FlagRule{
			{Flag: "--rcConfig", ValuePattern: `^/data/.*\.yml$`},
			{Flag: "--logLevel", ValuePattern: "^(debug|info|warn|error)$"},
		},
	}

	tests := []struct {
		name  string
		cmd   []interface{}
		allow bool
	}{
		{"valid config path", []interface{}{"--rcConfig", "/data/config.yml"}, true},
		{"invalid config path", []interface{}{"--rcConfig", "/etc/passwd"}, false},
		{"valid log level", []interface{}{"--logLevel", "info"}, true},
		{"invalid log level", []interface{}{"--logLevel", "trace"}, false},
		{"flag equals syntax", []interface{}{"--rcConfig=/data/config.yml"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := map[string]interface{}{"Cmd": tt.cmd}
			req, _ := http.NewRequest("POST", "/containers/create", nil)
			err := g.Check(req, p, body)
			if tt.allow && err != nil {
				t.Errorf("expected allowed, got: %v", err)
			}
			if !tt.allow && err == nil {
				t.Errorf("expected denied, got nil")
			}
		})
	}
}

func TestCmdGate_FlagOrdering(t *testing.T) {
	g := &CmdGate{}
	p := &policy.Policy{
		ServiceName:     "beacon",
		AllowedCLIFlags: []string{"--rcConfig", "--logLevel"},
		FlagRules: []policy.FlagRule{
			{Flag: "--rcConfig", ValuePattern: `^/data/.*\.yml$`},
			{Flag: "--logLevel", ValuePattern: "^(debug|info|warn|error)$"},
		},
	}
	body := map[string]interface{}{
		"Cmd": []interface{}{"--rcConfig", "/data/beacon.yml", "--logLevel", "debug"},
	}
	req, _ := http.NewRequest("POST", "/containers/create", nil)

	if err := g.Check(req, p, body); err != nil {
		t.Errorf("expected allowed, got: %v", err)
	}
}

func TestCmdGate_NoCmd(t *testing.T) {
	g := &CmdGate{}
	p := &policy.Policy{
		ServiceName:     "beacon",
		AllowedCLIFlags: []string{"--rcConfig"},
	}
	body := map[string]interface{}{}
	req, _ := http.NewRequest("POST", "/containers/create", nil)

	if err := g.Check(req, p, body); err != nil {
		t.Errorf("expected allowed when no Cmd, got: %v", err)
	}
}

func TestExtractFlag(t *testing.T) {
	tests := []struct {
		arg  string
		want string
	}{
		{"--rcConfig=/data/config.yml", "--rcConfig"},
		{"--rcConfig", "--rcConfig"},
		{"-v", "-v"},
	}

	for _, tt := range tests {
		t.Run(tt.arg, func(t *testing.T) {
			if got := extractFlag(tt.arg); got != tt.want {
				t.Errorf("extractFlag(%q) = %q, want %q", tt.arg, got, tt.want)
			}
		})
	}
}

func TestExtractFlagValue(t *testing.T) {
	tests := []struct {
		arg  string
		want string
	}{
		{"--rcConfig=/data/config.yml", "/data/config.yml"},
		{"--rcConfig", ""},
		{"--logLevel=info", "info"},
	}

	for _, tt := range tests {
		t.Run(tt.arg, func(t *testing.T) {
			if got := extractFlagValue(tt.arg); got != tt.want {
				t.Errorf("extractFlagValue(%q) = %q, want %q", tt.arg, got, tt.want)
			}
		})
	}
}
