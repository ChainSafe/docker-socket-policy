package middleware

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/ChainSafe/docker-socket-policy/internal/policy"
)

// RegistryGate validates image references against the policy's allowed prefixes.
type RegistryGate struct{}

func (g *RegistryGate) Check(r *http.Request, p *policy.Policy, body map[string]interface{}) error {
	image, _ := body["Image"].(string)
	if image == "" {
		return nil
	}

	imageName, tagOrDigest := splitImageRef(image)

	if !isAllowedPrefix(imageName, p.AllowedImagePrefixes) {
		return fmt.Errorf("image %q is not in allowed prefixes: %v", imageName, p.AllowedImagePrefixes)
	}

	if tagOrDigest != "" {
		if len(tagOrDigest) > 128 {
			return fmt.Errorf("image tag/digest exceeds 128 characters")
		}

		if strings.HasPrefix(tagOrDigest, "sha256:") {
			if !p.ImageDigestAllowed {
				return fmt.Errorf("image digests not allowed for service %s", p.ServiceName)
			}
			matched, _ := regexp.MatchString(`^sha256:[a-f0-9]{64}$`, tagOrDigest)
			if !matched {
				return fmt.Errorf("invalid digest format: %s", tagOrDigest)
			}
		} else if p.ImageTagPattern != "" {
			matched, err := regexp.MatchString(p.ImageTagPattern, tagOrDigest)
			if err != nil {
				return fmt.Errorf("invalid tag pattern regex: %w", err)
			}
			if !matched {
				return fmt.Errorf("image tag %q does not match pattern %q", tagOrDigest, p.ImageTagPattern)
			}
		}
	}

	return nil
}

func splitImageRef(ref string) (name, tagOrDigest string) {
	for i, ch := range ref {
		if ch == ':' || ch == '@' {
			return ref[:i], ref[i+1:]
		}
	}
	return ref, ""
}

func isAllowedPrefix(imageName string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if imageName == prefix || strings.HasPrefix(imageName, prefix+"/") {
			return true
		}
	}
	return false
}
