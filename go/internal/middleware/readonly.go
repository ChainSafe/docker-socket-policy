package middleware

import (
	"fmt"
	"net/http"

	"github.com/ChainSafe/docker-socket-policy/go/internal/policy"
)

type ReadonlyGate struct{}

func (g *ReadonlyGate) Check(r *http.Request, p *policy.Policy, body map[string]interface{}) error {
	switch r.Method {
	case "POST", "PUT", "DELETE", "PATCH":
		return fmt.Errorf("read-only mode: %s requests are not allowed", r.Method)
	}
	return nil
}
