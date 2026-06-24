package middleware

import (
	"fmt"
	"net/http"

	"github.com/ChainSafe/docker-socket-policy/internal/policy"
	"github.com/ChainSafe/docker-socket-policy/internal/types"
)

// Gate is a validation step that can deny a request.
type Gate interface {
	Check(r *http.Request, p *policy.Policy, body map[string]interface{}) error
}

// Mutator modifies the request body before validation.
type Mutator interface {
	Mutate(r *http.Request, p *policy.Policy, body map[string]interface{})
}

// Result is returned by Chain.Execute.
type Result struct {
	Allowed      bool
	Reason       string
	ModifiedBody []byte
}

// Chain holds the middleware pipeline.
type Chain struct {
	readonly bool
	gates    []Gate
	mutators []Mutator
}

// NewChain creates a middleware chain with default gates and mutators.
func NewChain(readonly bool) *Chain {
	c := &Chain{readonly: readonly}

	if readonly {
		c.gates = append(c.gates, &ReadonlyGate{})
	}
	c.gates = append(c.gates, &ExecGate{})
	c.gates = append(c.gates, &RegistryGate{})
	c.gates = append(c.gates, &MountSourceGate{})
	c.gates = append(c.gates, &EnvFileGate{})
	c.gates = append(c.gates, &CmdGate{})

	c.mutators = append(c.mutators, &ContainerConfigMutator{})

	return c
}

// Execute runs the middleware pipeline against a request.
// route is the pre-computed routing result.
// It returns the validation result, including a modified body if mutators ran.
func (c *Chain) Execute(r *http.Request, route *types.RouteResult) *Result {
	switch route.Action {
	case types.ActionDeny:
		return &Result{Allowed: false, Reason: route.DenyMsg}

	case types.ActionCreateContainer:
		if route.Policy == nil {
			return &Result{Allowed: false, Reason: "no matching policy found for container creation"}
		}

		for _, m := range c.mutators {
			m.Mutate(r, route.Policy, route.Body)
		}

		for _, g := range c.gates {
			if err := g.Check(r, route.Policy, route.Body); err != nil {
				return &Result{Allowed: false, Reason: fmt.Sprintf("validation failed: %v", err)}
			}
		}

		modifiedBody := marshalBody(route.Body)
		return &Result{
			Allowed:      true,
			Reason:       "container create allowed",
			ModifiedBody: modifiedBody,
		}

	case types.ActionAllow:
		if route.Policy != nil {
			for _, g := range c.gates {
				if err := g.Check(r, route.Policy, nil); err != nil {
					return &Result{Allowed: false, Reason: fmt.Sprintf("validation failed: %v", err)}
				}
			}
		}
		return &Result{Allowed: true, Reason: "request allowed"}
	}

	return &Result{Allowed: false, Reason: "unknown route action"}
}

func marshalBody(body map[string]interface{}) []byte {
	if body == nil {
		return nil
	}
	data, _ := policy.Marshal(body)
	return data
}
