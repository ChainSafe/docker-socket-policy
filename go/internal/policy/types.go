package policy

import (
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v3"
)

type Policy struct {
	ServiceName          string          `yaml:"service_name"`
	ContainerNames       []string        `yaml:"container_names"`
	UserID               string          `yaml:"user_id"`
	GroupID              string          `yaml:"group_id"`
	AllowedImagePrefixes []string        `yaml:"allowed_image_prefixes"`
	ImageTagPattern      string          `yaml:"image_tag_pattern"`
	ImageDigestAllowed   bool            `yaml:"image_digest_allowed"`
	ContainerConfig      ContainerConfig `yaml:"container_config"`
	Volumes              []Volume        `yaml:"volumes"`
	Ports                []string        `yaml:"ports"`
	EnvFile              string          `yaml:"env_file"`
	AllowedCLIFlags      []string        `yaml:"allowed_cli_flags"`
	FlagRules            []FlagRule      `yaml:"flag_rules"`
	DeniedFlags          []string        `yaml:"denied_flags"`
}

// CoveredNames are the container names the policy manages: its
// container_names, or its service_name when container_names is unset (#85,
// #86). Lifecycle actions and DELETE are forwarded only for covered names.
func (p *Policy) CoveredNames() []string {
	if p.ContainerNames != nil {
		return p.ContainerNames
	}
	return []string{p.ServiceName}
}

// AcceptsName reports whether a create named name may use the policy: a
// policy without container_names accepts any name, including none (#85).
func (p *Policy) AcceptsName(name string) bool {
	if p.ContainerNames == nil {
		return true
	}
	for _, n := range p.ContainerNames {
		if n == name {
			return true
		}
	}
	return false
}

type ContainerConfig struct {
	NetworkMode     string            `yaml:"network_mode"`
	RestartPolicy   string            `yaml:"restart_policy"`
	SecurityOptions []string          `yaml:"security_options"`
	User            string            `yaml:"user"`
	LogDriver       string            `yaml:"log_driver"`
	LogOptions      map[string]string `yaml:"log_options"`
	// GroupAdd is forced as HostConfig.GroupAdd (#93). Empty means unset.
	GroupAdd GroupList `yaml:"group_add"`
}

// GroupList is a YAML list of strings. Unlike a plain []string, it refuses
// entries that are not YAML strings, such as an unquoted 64190 or 0x10, so
// Go, Rust and TypeScript read the same text for every entry (#93).
type GroupList []string

func (g *GroupList) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.SequenceNode {
		return fmt.Errorf("line %d: group_add must be a list", node.Line)
	}
	out := make(GroupList, 0, len(node.Content))
	for _, item := range node.Content {
		if item.Kind != yaml.ScalarNode || item.Tag != "!!str" {
			return fmt.Errorf("line %d: group_add entries must be strings (quote GIDs: '64190')", item.Line)
		}
		out = append(out, item.Value)
	}
	*g = out
	return nil
}

type Volume struct {
	HostPath      string `yaml:"host_path"`
	ContainerPath string `yaml:"container_path"`
	ReadWrite     bool   `yaml:"read_write"`
}

type FlagRule struct {
	Flag         string `yaml:"flag"`
	ValuePattern string `yaml:"value_pattern"`
}

func MarshalBody(body map[string]interface{}) ([]byte, error) {
	return json.Marshal(body)
}
