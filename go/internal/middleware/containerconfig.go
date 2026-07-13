package middleware

import (
	"net/http"

	"github.com/ChainSafe/docker-socket-policy/go/internal/policy"
)

type ContainerConfigMutator struct{}

func (m *ContainerConfigMutator) Mutate(r *http.Request, p *policy.Policy, body map[string]interface{}) {
	cc := p.ContainerConfig
	if cc.NetworkMode == "" && cc.RestartPolicy == "" && len(cc.SecurityOptions) == 0 && cc.User == "" && cc.LogDriver == "" {
		return
	}

	hostConfig, _ := body["HostConfig"].(map[string]interface{})
	if hostConfig == nil {
		hostConfig = make(map[string]interface{})
		body["HostConfig"] = hostConfig
	}

	if cc.NetworkMode != "" {
		hostConfig["NetworkMode"] = cc.NetworkMode
	}

	if cc.RestartPolicy != "" {
		restartPolicy := make(map[string]interface{})
		restartPolicy["Name"] = cc.RestartPolicy
		hostConfig["RestartPolicy"] = restartPolicy
	}

	if len(cc.SecurityOptions) > 0 {
		hostConfig["SecurityOpt"] = cc.SecurityOptions
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
