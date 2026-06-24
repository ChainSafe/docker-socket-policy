package middleware

import (
	"fmt"
	"net/http"

	"github.com/ChainSafe/docker-socket-policy/internal/policy"
)

// MountSourceGate validates volume mounts against the policy's whitelist.
type MountSourceGate struct{}

func (g *MountSourceGate) Check(r *http.Request, p *policy.Policy, body map[string]interface{}) error {
	if len(p.Volumes) == 0 {
		return nil
	}

	// Check HostConfig.Binds (array of "host:container:mode" strings)
	hostConfig, _ := body["HostConfig"].(map[string]interface{})
	if hostConfig != nil {
		binds, _ := hostConfig["Binds"].([]interface{})
		for _, b := range binds {
			bindStr, ok := b.(string)
			if !ok {
				continue
			}
			hostPath := extractHostPath(bindStr)
			if !isVolumeAllowed(hostPath, p.Volumes) {
				return fmt.Errorf("volume mount %q is not in the whitelist for service %s", hostPath, p.ServiceName)
			}
		}
	}

	// Check Volumes (deprecated but still used by some clients)
	volumes, _ := body["Volumes"].(map[string]interface{})
	if volumes != nil {
		for hostPath := range volumes {
			if !isVolumeAllowed(hostPath, p.Volumes) {
				return fmt.Errorf("volume %q is not in the whitelist for service %s", hostPath, p.ServiceName)
			}
		}
	}

	return nil
}

func extractHostPath(bind string) string {
	parts := splitBind(bind)
	if len(parts) >= 1 {
		return parts[0]
	}
	return bind
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

func isVolumeAllowed(hostPath string, volumes []policy.Volume) bool {
	for _, v := range volumes {
		if v.HostPath == hostPath {
			return true
		}
	}
	return false
}
