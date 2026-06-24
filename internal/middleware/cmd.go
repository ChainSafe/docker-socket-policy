package middleware

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/ChainSafe/docker-socket-policy/internal/policy"
)

var safeCharset = regexp.MustCompile(`^[A-Za-z0-9._=:/,\-]{1,256}$`)

// CmdGate validates the Cmd array from the container create body
// against the policy's allowed and denied flags.
type CmdGate struct{}

func (g *CmdGate) Check(r *http.Request, p *policy.Policy, body map[string]interface{}) error {
	cmdRaw, ok := body["Cmd"]
	if !ok || cmdRaw == nil {
		return nil
	}

	cmd, ok := cmdRaw.([]interface{})
	if !ok {
		return nil
	}

	for i := 0; i < len(cmd); i++ {
		arg, ok := cmd[i].(string)
		if !ok {
			return fmt.Errorf("Cmd element is not a string: %v", cmdRaw)
		}

		if !safeCharset.MatchString(arg) {
			return fmt.Errorf("Cmd argument %q contains invalid characters", arg)
		}

		if !strings.HasPrefix(arg, "-") {
			continue
		}

		flag := extractFlag(arg)

		for _, denied := range p.DeniedFlags {
			if flag == denied {
				return fmt.Errorf("flag %q is denied for service %s", flag, p.ServiceName)
			}
		}

		allowed := false
		for _, allowedFlag := range p.AllowedCLIFlags {
			if flag == allowedFlag {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("flag %q is not in the allowlist for service %s", flag, p.ServiceName)
		}

		// Extract the value: either from --flag=value syntax or the next Cmd element
		value := extractFlagValue(arg)
		if value == "" && i+1 < len(cmd) {
			next, ok := cmd[i+1].(string)
			if ok && !strings.HasPrefix(next, "-") {
				value = next
				i++ // Skip the next element as it's a value, not a flag
			}
		}

		if value != "" {
			for _, rule := range p.FlagRules {
				if rule.Flag == flag {
					matched, err := regexp.MatchString(rule.ValuePattern, value)
					if err != nil {
						return fmt.Errorf("invalid value pattern regex for flag %s: %w", flag, err)
					}
					if !matched {
						return fmt.Errorf("flag %s value %q does not match pattern %q", flag, value, rule.ValuePattern)
					}
					break
				}
			}
		}
	}

	return nil
}

func extractFlag(arg string) string {
	eqIdx := strings.Index(arg, "=")
	if eqIdx == -1 {
		return arg
	}
	return arg[:eqIdx]
}

func extractFlagValue(arg string) string {
	eqIdx := strings.Index(arg, "=")
	if eqIdx == -1 {
		return ""
	}
	return arg[eqIdx+1:]
}
