package proxy

import (
	"fmt"
	"strings"

	"github.com/ChainSafe/docker-socket-policy/go/internal/policy"
)

type Action int

const (
	ActionDeny            Action = iota
	ActionAllow
	ActionCreateContainer
)

type RouteResult struct {
	Action    Action
	Service   string
	Policy    *policy.Policy
	Body      map[string]interface{}
	Container string
	Image     string
	DenyMsg   string
}

type Router struct {
	manager *policy.Manager
}

func NewRouter(manager *policy.Manager) *Router {
	return &Router{manager: manager}
}

func (r *Router) Route(method, path string, body map[string]interface{}) *RouteResult {
	// The daemon decodes the path before routing, so deny any escape (#53).
	if strings.Contains(path, "%") {
		return &RouteResult{Action: ActionDeny, DenyMsg: "percent-encoded path not allowed"}
	}

	path = stripAPIVersion(path)

	if path == "/_ping" || path == "/version" || path == "/info" || strings.HasPrefix(path, "/events") {
		return &RouteResult{Action: ActionAllow}
	}

	if strings.HasPrefix(path, "/auth") {
		return &RouteResult{Action: ActionDeny, DenyMsg: "auth endpoint is not allowed"}
	}

	if matchEndpoint(path, "containers", "exec") {
		return &RouteResult{Action: ActionDeny, DenyMsg: "exec is not allowed"}
	}

	if strings.HasPrefix(path, "/build") {
		return &RouteResult{Action: ActionDeny, DenyMsg: "build is not allowed"}
	}

	if strings.HasPrefix(path, "/commit") {
		return &RouteResult{Action: ActionDeny, DenyMsg: "commit is not allowed"}
	}

	if matchEndpoint(path, "containers", "create") && method == "POST" {
		return r.routeCreate(body)
	}

	if containerName := extractContainerName(path); containerName != "" {
		switch {
		case strings.HasSuffix(path, "/start") && method == "POST":
			return r.routeByContainerName(containerName, "start")
		case strings.HasSuffix(path, "/stop") && method == "POST":
			return r.routeByContainerName(containerName, "stop")
		case strings.HasSuffix(path, "/restart") && method == "POST":
			return r.routeByContainerName(containerName, "restart")
		case strings.HasSuffix(path, "/kill") && method == "POST":
			return r.routeByContainerName(containerName, "kill")
		case strings.HasSuffix(path, "/wait") && method == "POST":
			return r.routeByContainerName(containerName, "wait")
		case strings.HasSuffix(path, "/pause") && method == "POST":
			return r.routeByContainerName(containerName, "pause")
		case strings.HasSuffix(path, "/unpause") && method == "POST":
			return r.routeByContainerName(containerName, "unpause")
		case strings.HasSuffix(path, "/rename") && method == "POST":
			return &RouteResult{Action: ActionDeny, DenyMsg: "rename is not allowed"}
		case strings.HasSuffix(path, "/update") && method == "POST":
			return &RouteResult{Action: ActionDeny, DenyMsg: "update is not allowed"}
		case method == "DELETE":
			return r.routeByContainerName(containerName, "rm")
		default:
			if method == "GET" {
				return &RouteResult{Action: ActionAllow}
			}
		}
	}

	if matchEndpoint(path, "images", "create") && method == "POST" {
		return r.routeImagePull(body)
	}

	if method == "GET" || method == "HEAD" {
		return &RouteResult{Action: ActionAllow}
	}

	return &RouteResult{
		Action:  ActionDeny,
		DenyMsg: fmt.Sprintf("endpoint %s %s is not allowed", method, path),
	}
}

func (r *Router) routeCreate(body map[string]interface{}) *RouteResult {
	if len(body) == 0 {
		return &RouteResult{Action: ActionDeny, DenyMsg: "empty request body"}
	}

	image, _ := body["Image"].(string)
	if image == "" {
		return &RouteResult{Action: ActionDeny, DenyMsg: "image field is required"}
	}

	p, err := r.manager.GetByImage(image)
	if err != nil {
		return &RouteResult{Action: ActionDeny, DenyMsg: fmt.Sprintf("image %s not allowed by any policy", image)}
	}

	return &RouteResult{
		Action:  ActionCreateContainer,
		Service: p.ServiceName,
		Policy:  p,
		Body:    body,
		Image:   image,
	}
}

func (r *Router) routeByContainerName(containerName, action string) *RouteResult {
	if p, err := r.manager.Get(containerName); err == nil {
		return &RouteResult{
			Action:  ActionAllow,
			Service: p.ServiceName,
			Policy:  p,
		}
	}
	return &RouteResult{
		Action:    ActionAllow,
		Container: containerName,
	}
}

func (r *Router) routeImagePull(body map[string]interface{}) *RouteResult {
	if len(body) == 0 {
		return &RouteResult{Action: ActionDeny, DenyMsg: "empty request body"}
	}

	fromImage, _ := body["fromImage"].(string)
	if fromImage == "" {
		return &RouteResult{Action: ActionDeny, DenyMsg: "fromImage field is required for image pull"}
	}

	if _, err := r.manager.GetByImage(fromImage); err != nil {
		return &RouteResult{Action: ActionDeny, DenyMsg: fmt.Sprintf("image %s not allowed by any policy", fromImage)}
	}

	return &RouteResult{Action: ActionAllow, Image: fromImage}
}

// stripAPIVersion strips one leading /v<N>/ or /v<N>.<M>/ (ASCII digits only), else returns path unchanged (#57).
func stripAPIVersion(path string) string {
	if !strings.HasPrefix(path, "/v") {
		return path
	}
	i := scanDigits(path, 2)
	if i == 2 {
		return path
	}
	if i < len(path) && path[i] == '.' {
		j := scanDigits(path, i+1)
		if j == i+1 {
			return path
		}
		i = j
	}
	if i < len(path) && path[i] == '/' {
		return path[i:]
	}
	return path
}

func scanDigits(s string, i int) int {
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return i
}

func matchEndpoint(path, resource, endpoint string) bool {
	path = strings.TrimPrefix(path, "/")
	parts := strings.SplitN(path, "/", 3)
	if len(parts) < 2 {
		return false
	}
	return parts[0] == resource && parts[1] == endpoint
}

// reservedContainerSegments are Docker endpoints that sit where a container
// name would: /containers/json lists, /containers/create creates. Treating one
// as a container name routes the request down the lifecycle path, where an
// unknown container is allowed through — so DELETE /containers/json would be
// allowed rather than denied. Rust (rs/src/proxy.rs) and TypeScript
// (ts/src/proxy.ts) exclude the same set.
var reservedContainerSegments = map[string]bool{
	"create": true,
	"json":   true,
	"exec":   true,
}

func extractContainerName(path string) string {
	path = strings.TrimPrefix(path, "/")
	parts := strings.Split(path, "/")
	if len(parts) >= 2 && parts[0] == "containers" && !reservedContainerSegments[parts[1]] {
		return parts[1]
	}
	return ""
}
