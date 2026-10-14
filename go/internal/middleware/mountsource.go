package middleware

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/ChainSafe/docker-socket-policy/go/internal/policy"
)

// MountSourceGate checks every host path a create request mounts against the
// policy's volumes: HostConfig.Binds, HostConfig.Mounts and the top-level
// Volumes keys. A policy with no volumes allows no binds. A volume with
// read_write: false must be mounted read-only (#88).
type MountSourceGate struct{}

// bindModes are the bind options allowed in a Binds entry. The propagation
// modes shared, rshared, slave and rslave are not among them.
var bindModes = map[string]bool{
	"ro": true, "rw": true, "z": true, "Z": true, "nocopy": true,
	"private": true, "rprivate": true,
}

var mountFields = []string{
	"Type", "Source", "Target", "ReadOnly", "Consistency", "BindOptions",
	"VolumeOptions", "ImageOptions", "TmpfsOptions", "ClusterOptions",
}

// mountAnyValue may hold any value in a Mounts entry; Type, Source, ReadOnly
// and BindOptions have their own rules, and every other key must be zero.
var mountAnyValue = map[string]bool{"Target": true, "Consistency": true, "TmpfsOptions": true}

var bindOptionFields = []string{
	"Propagation", "NonRecursive", "CreateMountpoint", "ReadOnlyNonRecursive",
	"ReadOnlyForceRecursive",
}

// bindOptionAnyValue may hold any value in BindOptions; Propagation has its
// own rule, and every other key, ReadOnlyNonRecursive included, must be zero.
var bindOptionAnyValue = map[string]bool{"NonRecursive": true, "CreateMountpoint": true, "ReadOnlyForceRecursive": true}

func (g *MountSourceGate) Check(r *http.Request, p *policy.Policy, body map[string]interface{}) error {
	hostConfig, _ := body["HostConfig"].(map[string]interface{})
	if hostConfig != nil {
		if err := checkBinds(hostConfig["Binds"], p); err != nil {
			return err
		}
		if err := checkMounts(hostConfig["Mounts"], p); err != nil {
			return err
		}
	}

	volumes, _ := body["Volumes"].(map[string]interface{})
	for _, hostPath := range sortedKeys(volumes) {
		if findVolume(hostPath, p.Volumes) == nil {
			return fmt.Errorf("volume %q is not in the whitelist for service %s", hostPath, p.ServiceName)
		}
	}

	return nil
}

func checkBinds(raw interface{}, p *policy.Policy) error {
	if raw == nil {
		return nil
	}
	binds, ok := raw.([]interface{})
	if !ok {
		return fmt.Errorf("HostConfig.Binds must be a list of strings for service %s", p.ServiceName)
	}
	for _, b := range binds {
		bindStr, ok := b.(string)
		if !ok {
			return fmt.Errorf("HostConfig.Binds must be a list of strings for service %s", p.ServiceName)
		}
		parts := splitBind(bindStr)
		if len(parts) == 0 || len(parts) > 3 {
			return fmt.Errorf("bind %q is not a valid bind for service %s", bindStr, p.ServiceName)
		}
		hostPath := parts[0]
		vol := findVolume(hostPath, p.Volumes)
		if vol == nil {
			return fmt.Errorf("volume mount %q is not in the whitelist for service %s", hostPath, p.ServiceName)
		}
		var opts []string
		if len(parts) == 3 && parts[2] != "" {
			opts = strings.Split(parts[2], ",")
		}
		for _, o := range opts {
			if !bindModes[o] {
				return fmt.Errorf("bind option %q on volume mount %q is not allowed for service %s", o, hostPath, p.ServiceName)
			}
		}
		if !vol.ReadWrite && (!containsString(opts, "ro") || containsString(opts, "rw")) {
			return fmt.Errorf("volume mount %q must be read-only (:ro) for service %s", hostPath, p.ServiceName)
		}
	}
	return nil
}

func checkMounts(raw interface{}, p *policy.Policy) error {
	if raw == nil {
		return nil
	}
	mounts, ok := raw.([]interface{})
	if !ok {
		return fmt.Errorf("HostConfig.Mounts must be a list for service %s", p.ServiceName)
	}
	for _, m := range mounts {
		mount, ok := m.(map[string]interface{})
		if !ok {
			return fmt.Errorf("HostConfig.Mounts entry must be an object for service %s", p.ServiceName)
		}
		if err := checkMount(mount, p); err != nil {
			return err
		}
	}
	return nil
}

func checkMount(mount map[string]interface{}, p *policy.Policy) error {
	if err := checkFieldCase("HostConfig.Mounts.", mount, mountFields, p); err != nil {
		return err
	}
	for _, key := range sortedKeys(mount) {
		switch {
		case key == "Type" || key == "Source" || key == "ReadOnly":
		case key == "BindOptions":
			if err := checkBindOptions(mount[key], p); err != nil {
				return err
			}
		case mountAnyValue[key]:
		default:
			if !isZeroValue(mount[key]) {
				return fmt.Errorf("HostConfig.Mounts.%s is not allowed for service %s", key, p.ServiceName)
			}
		}
	}

	mountType, _ := mount["Type"].(string)
	source, _ := mount["Source"].(string)
	switch mountType {
	case "tmpfs":
		if !isZeroValue(mount["Source"]) {
			return fmt.Errorf("tmpfs mount must not have a Source for service %s", p.ServiceName)
		}
		return nil
	case "bind":
		vol := findVolume(source, p.Volumes)
		if vol == nil {
			return fmt.Errorf("mount source %q is not in the whitelist for service %s", source, p.ServiceName)
		}
		readOnly, _ := mount["ReadOnly"].(bool)
		if !vol.ReadWrite && !readOnly {
			return fmt.Errorf("mount of %q must be read-only (ReadOnly: true) for service %s", source, p.ServiceName)
		}
		return nil
	default:
		return fmt.Errorf("mount type %q is not allowed for service %s", mountType, p.ServiceName)
	}
}

func checkBindOptions(raw interface{}, p *policy.Policy) error {
	if raw == nil {
		return nil
	}
	opts, ok := raw.(map[string]interface{})
	if !ok {
		return fmt.Errorf("HostConfig.Mounts.BindOptions must be an object for service %s", p.ServiceName)
	}
	if err := checkFieldCase("HostConfig.Mounts.BindOptions.", opts, bindOptionFields, p); err != nil {
		return err
	}
	for _, key := range sortedKeys(opts) {
		value := opts[key]
		switch {
		case key == "Propagation":
			if value == nil {
				continue
			}
			s, isStr := value.(string)
			if !isStr {
				return fmt.Errorf("mount propagation %v is not allowed for service %s", value, p.ServiceName)
			}
			if s != "" && s != "private" && s != "rprivate" {
				return fmt.Errorf("mount propagation %q is not allowed for service %s", s, p.ServiceName)
			}
		case bindOptionAnyValue[key]:
		default:
			if !isZeroValue(value) {
				return fmt.Errorf("HostConfig.Mounts.BindOptions.%s is not allowed for service %s", key, p.ServiceName)
			}
		}
	}
	return nil
}

func splitBind(bind string) []string {
	var parts []string
	var current []byte
	escaped := false

	for i := 0; i < len(bind); i++ {
		ch := bind[i]
		if escaped {
			current = append(current, ch)
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		if ch == ':' {
			parts = append(parts, string(current))
			current = nil
			continue
		}
		current = append(current, ch)
	}
	if len(current) > 0 {
		parts = append(parts, string(current))
	}

	return parts
}

func findVolume(hostPath string, volumes []policy.Volume) *policy.Volume {
	for i := range volumes {
		if volumes[i].HostPath == hostPath {
			return &volumes[i]
		}
	}
	return nil
}
