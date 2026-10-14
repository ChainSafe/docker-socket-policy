package middleware

import (
	"fmt"
	"net/http"

	"github.com/ChainSafe/docker-socket-policy/go/internal/policy"
)

type RegistryGate struct{}

func (g *RegistryGate) Check(r *http.Request, p *policy.Policy, body map[string]interface{}) error {
	image, _ := body["Image"].(string)
	if image == "" {
		return nil
	}

	// The same parser as the router, so a registry port is not a tag (#84).
	ref, err := policy.ParseImageRef(image)
	if err != nil {
		return err
	}

	if !policy.MatchesImagePrefix(ref.Name, p.AllowedImagePrefixes) {
		return fmt.Errorf("image %q is not in allowed prefixes: %v", ref.Name, p.AllowedImagePrefixes)
	}

	return policy.CheckImageTag(p, ref)
}
