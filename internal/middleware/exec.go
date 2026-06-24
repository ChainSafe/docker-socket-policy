package middleware

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/ChainSafe/docker-socket-policy/internal/policy"
)

// ExecGate denies POST /containers/*/exec and POST /exec/*/start.
type ExecGate struct{}

func (g *ExecGate) Check(r *http.Request, p *policy.Policy, body map[string]interface{}) error {
	path := r.URL.Path
	if strings.Contains(path, "/exec") && r.Method == "POST" {
		return fmt.Errorf("exec is not allowed: docker exec provides a shell escape vector")
	}
	return nil
}
