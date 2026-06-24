package proxy

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ChainSafe/docker-socket-policy/internal/policy"
	"github.com/ChainSafe/docker-socket-policy/internal/types"
)

// Router matches incoming Docker API requests to policies.
type Router struct {
	manager *policy.Manager
}

// NewRouter creates a new Router.
func NewRouter(manager *policy.Manager) *Router {
	return &Router{manager: manager}
}

// Route matches a Docker API request to a policy and action.
func (r *Router) Route(method, path string, body []byte) *types.RouteResult {
	path = stripAPIVersion(path)

	if path == "/_ping" || path == "/version" || path == "/info" || strings.HasPrefix(path, "/events") {
		return &types.RouteResult{Action: types.ActionAllow}
	}

	if strings.HasPrefix(path, "/auth") {
		return &types.RouteResult{Action: types.ActionDeny, DenyMsg: "auth endpoint is not allowed"}
	}

	if matchEndpoint(path, "containers", "exec") {
		return &types.RouteResult{Action: types.ActionDeny, DenyMsg: "exec is not allowed"}
	}

	if strings.HasPrefix(path, "/build") {
		return &types.RouteResult{Action: types.ActionDeny, DenyMsg: "build is not allowed"}
	}

	if strings.HasPrefix(path, "/commit") {
		return &types.RouteResult{Action: types.ActionDeny, DenyMsg: "commit is not allowed"}
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
			return &types.RouteResult{Action: types.ActionDeny, DenyMsg: "rename is not allowed"}
		case strings.HasSuffix(path, "/update") && method == "POST":
			return &types.RouteResult{Action: types.ActionDeny, DenyMsg: "update is not allowed"}
		case method == "DELETE":
			return r.routeByContainerName(containerName, "rm")
		default:
			if method == "GET" {
				return &types.RouteResult{Action: types.ActionAllow}
			}
		}
	}

	if matchEndpoint(path, "images", "create") && method == "POST" {
		return r.routeImagePull(body)
	}

	if method == "GET" || method == "HEAD" {
		return &types.RouteResult{Action: types.ActionAllow}
	}

	return &types.RouteResult{
		Action:  types.ActionDeny,
		DenyMsg: fmt.Sprintf("endpoint %s %s is not allowed", method, path),
	}
}

func (r *Router) routeCreate(body []byte) *types.RouteResult {
	if len(body) == 0 {
		return &types.RouteResult{Action: types.ActionDeny, DenyMsg: "empty request body"}
	}

	var req map[string]interface{}
	if err := json.Unmarshal(body, &req); err != nil {
		return &types.RouteResult{Action: types.ActionDeny, DenyMsg: fmt.Sprintf("invalid JSON body: %v", err)}
	}

	image, _ := req["Image"].(string)
	if image == "" {
		return &types.RouteResult{Action: types.ActionDeny, DenyMsg: "image field is required"}
	}

	p, err := r.manager.GetByImage(image)
	if err != nil {
		return &types.RouteResult{Action: types.ActionDeny, DenyMsg: fmt.Sprintf("image %s not allowed by any policy", image)}
	}

	return &types.RouteResult{
		Action:  types.ActionCreateContainer,
		Service: p.ServiceName,
		Policy:  p,
		Body:    req,
		Image:   image,
	}
}

func (r *Router) routeByContainerName(containerName, action string) *types.RouteResult {
	if p, err := r.manager.Get(containerName); err == nil {
		return &types.RouteResult{
			Action:  types.ActionAllow,
			Service: p.ServiceName,
			Policy:  p,
		}
	}
	return &types.RouteResult{
		Action:    types.ActionAllow,
		Container: containerName,
	}
}

func (r *Router) routeImagePull(body []byte) *types.RouteResult {
	if len(body) == 0 {
		return &types.RouteResult{Action: types.ActionDeny, DenyMsg: "empty request body"}
	}

	var req map[string]interface{}
	if err := json.Unmarshal(body, &req); err != nil {
		return &types.RouteResult{Action: types.ActionDeny, DenyMsg: fmt.Sprintf("invalid JSON body: %v", err)}
	}

	fromImage, _ := req["fromImage"].(string)
	if fromImage == "" {
		return &types.RouteResult{Action: types.ActionDeny, DenyMsg: "fromImage field is required for image pull"}
	}

	if _, err := r.manager.GetByImage(fromImage); err != nil {
		return &types.RouteResult{Action: types.ActionDeny, DenyMsg: fmt.Sprintf("image %s not allowed by any policy", fromImage)}
	}

	return &types.RouteResult{Action: types.ActionAllow, Image: fromImage}
}

func stripAPIVersion(path string) string {
	if strings.HasPrefix(path, "/v") {
		parts := strings.SplitN(path, "/", 3)
		if len(parts) >= 3 {
			return "/" + parts[2]
		}
	}
	return path
}

func matchEndpoint(path, resource, endpoint string) bool {
	path = strings.TrimPrefix(path, "/")
	parts := strings.SplitN(path, "/", 3)
	if len(parts) < 2 {
		return false
	}
	return parts[0] == resource && parts[1] == endpoint
}

func extractContainerName(path string) string {
	path = strings.TrimPrefix(path, "/")
	parts := strings.Split(path, "/")
	if len(parts) >= 2 && parts[0] == "containers" {
		return parts[1]
	}
	return ""
}
