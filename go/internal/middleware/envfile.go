package middleware

import (
	"fmt"
	"net/http"

	"github.com/ChainSafe/docker-socket-policy/go/internal/policy"
)

type EnvFileGate struct{}

func (g *EnvFileGate) Check(r *http.Request, p *policy.Policy, body map[string]interface{}) error {
	if p.EnvFile == "" {
		return nil
	}

	if envRaw, hasEnv := body["Env"]; hasEnv {
		envList, ok := envRaw.([]interface{})
		if ok && len(envList) > 0 {
			return fmt.Errorf("inline environment variables are not allowed for service %s; use env_file: %s", p.ServiceName, p.EnvFile)
		}
		delete(body, "Env")
	}

	hostConfig, _ := body["HostConfig"].(map[string]interface{})
	if hostConfig != nil {
		if envRaw, hasEnv := hostConfig["Env"]; hasEnv {
			envList, ok := envRaw.([]interface{})
			if ok && len(envList) > 0 {
				return fmt.Errorf("inline environment variables in HostConfig are not allowed for service %s; use env_file: %s", p.ServiceName, p.EnvFile)
			}
			delete(hostConfig, "Env")
		}
	}

	return nil
}
