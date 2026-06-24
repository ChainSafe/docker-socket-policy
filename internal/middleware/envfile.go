package middleware

import (
	"fmt"
	"net/http"

	"github.com/ChainSafe/docker-socket-policy/internal/policy"
)

// EnvFileGate rejects requests that provide inline environment variables
// when the policy requires an env_file. All environment variables must come
// from the locked env_file.
//
// As defense-in-depth, the Env field is stripped from the body even on
// allowed requests, ensuring Docker never sees inline env vars.
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
		// Strip empty Env field for defense-in-depth
		delete(body, "Env")
	}

	hostConfig, _ := body["HostConfig"].(map[string]interface{})
	if hostConfig != nil {
		if envRaw, hasEnv := hostConfig["Env"]; hasEnv {
			envList, ok := envRaw.([]interface{})
			if ok && len(envList) > 0 {
				return fmt.Errorf("inline environment variables in HostConfig are not allowed for service %s; use env_file: %s", p.ServiceName, p.EnvFile)
			}
			delete(body, "HostConfig")
			delete(hostConfig, "Env")
			body["HostConfig"] = hostConfig
		}
	}

	return nil
}
