package types

import "github.com/ChainSafe/docker-socket-policy/internal/policy"

// Action describes what to do with a matched request.
type Action int

const (
	ActionDeny            Action = iota
	ActionAllow                  // Read-only or container lifecycle
	ActionCreateContainer        // Container create (needs full validation)
)

// RouteResult describes the result of routing a request.
type RouteResult struct {
	Action    Action
	Service   string
	Policy    *policy.Policy
	Body      map[string]interface{}
	Container string
	Image     string
	DenyMsg   string
}
