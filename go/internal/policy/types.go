package policy

import "encoding/json"

type Policy struct {
	ServiceName          string          `yaml:"service_name"`
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

type ContainerConfig struct {
	NetworkMode     string            `yaml:"network_mode"`
	RestartPolicy   string            `yaml:"restart_policy"`
	SecurityOptions []string          `yaml:"security_options"`
	User            string            `yaml:"user"`
	LogDriver       string            `yaml:"log_driver"`
	LogOptions      map[string]string `yaml:"log_options"`
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
