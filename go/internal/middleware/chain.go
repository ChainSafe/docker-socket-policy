package middleware

import (
	"fmt"
	"net/http"

	"github.com/ChainSafe/docker-socket-policy/go/internal/policy"
)

type Gate interface {
	Check(r *http.Request, p *policy.Policy, body map[string]interface{}) error
}

type Mutator interface {
	Mutate(r *http.Request, p *policy.Policy, body map[string]interface{})
}

type Result struct {
	Allowed      bool
	Reason       string
	ModifiedBody []byte
}

type Chain struct {
	gates    []Gate
	mutators []Mutator
}

func NewChain(readonly bool) *Chain {
	c := &Chain{}

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

func (c *Chain) Execute(r *http.Request, p *policy.Policy, body map[string]interface{}) *Result {
	if p == nil || body == nil {
		return &Result{Allowed: true, Reason: "no policy or body, skipping validation"}
	}

	for _, m := range c.mutators {
		m.Mutate(r, p, body)
	}

	for _, g := range c.gates {
		if err := g.Check(r, p, body); err != nil {
			return &Result{Allowed: false, Reason: fmt.Sprintf("validation failed: %v", err)}
		}
	}

	modifiedBody, err := policy.MarshalBody(body)
	if err != nil {
		return &Result{Allowed: false, Reason: fmt.Sprintf("failed to marshal modified body: %v", err)}
	}

	return &Result{
		Allowed:      true,
		Reason:       "container create allowed",
		ModifiedBody: modifiedBody,
	}
}
