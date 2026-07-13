package middleware

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/ChainSafe/docker-socket-policy/go/internal/policy"
)

type ExecGate struct{}

func (g *ExecGate) Check(r *http.Request, p *policy.Policy, body map[string]interface{}) error {
	if strings.Contains(r.URL.Path, "/exec") && r.Method == "POST" {
		return fmt.Errorf("exec is not allowed: docker exec provides a shell escape vector")
	}
	return nil
}
