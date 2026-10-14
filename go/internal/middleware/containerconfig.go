package middleware

import (
	"net/http"

	"github.com/ChainSafe/docker-socket-policy/go/internal/policy"
)

// ContainerConfigMutator overwrites the fields the policy's container_config
// sets. It forces HostConfig.Privileged to false on every create, even when
// container_config is empty (#88). A HostConfig that is not an object is left
// alone for HostConfigGate to deny.
type ContainerConfigMutator struct{}

func (m *ContainerConfigMutator) Mutate(r *http.Request, p *policy.Policy, body map[string]interface{}) {
	cc := p.ContainerConfig

	if raw, ok := body["HostConfig"]; ok && raw != nil {
		if _, isObj := raw.(map[string]interface{}); !isObj {
			return
		}
	}
	hostConfig, _ := body["HostConfig"].(map[string]interface{})
	if hostConfig == nil {
		hostConfig = make(map[string]interface{})
		body["HostConfig"] = hostConfig
	}

	if cc.NetworkMode != "" {
		hostConfig["NetworkMode"] = cc.NetworkMode
		forceEndpoints(cc.NetworkMode, body)
	}

	if cc.RestartPolicy != "" {
		restartPolicy := make(map[string]interface{})
		restartPolicy["Name"] = cc.RestartPolicy
		hostConfig["RestartPolicy"] = restartPolicy
	}

	if len(cc.SecurityOptions) > 0 {
		// Stored as a generic JSON list, like a parsed body, so that
		// HostConfigGate reads it the same way.
		opts := make([]interface{}, len(cc.SecurityOptions))
		for i, o := range cc.SecurityOptions {
			opts[i] = o
		}
		hostConfig["SecurityOpt"] = opts
	}

	hostConfig["Privileged"] = false

	if cc.User != "" {
		body["User"] = cc.User
	}

	if cc.LogDriver != "" {
		hostConfig["LogConfig"] = map[string]interface{}{
			"Type":   cc.LogDriver,
			"Config": cc.LogOptions,
		}
	}
}
