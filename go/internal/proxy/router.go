package proxy

import (
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/ChainSafe/docker-socket-policy/go/internal/policy"
)

type Action int

const (
	ActionDeny Action = iota
	ActionAllow
	ActionCreateContainer
	// ActionResolveContainer: a lifecycle action or DELETE on a container
	// that is not directly a covered name. The handler asks the daemon which
	// container it is and allows the request only if its name is covered (#86).
	ActionResolveContainer
)

type RouteResult struct {
	Action    Action
	Service   string
	Policy    *policy.Policy
	Body      map[string]interface{}
	Container string
	// ResolvedName is the daemon's name for Container, set when the handler
	// resolved it (#86).
	ResolvedName string
	Image        string
	DenyMsg      string
}

type Router struct {
	manager  *policy.Manager
	readonly bool
}

func NewRouter(manager *policy.Manager) *Router {
	return &Router{manager: manager}
}

// WithReadonly sets read-only mode (--readonly) and returns the router.
func (r *Router) WithReadonly(readonly bool) *Router {
	r.readonly = readonly
	return r
}

// Route routes a request whose body, if any, is the parsed JSON body. It is
// RouteRequest with hasBody set when body is non-nil.
func (r *Router) Route(method, target string, body map[string]interface{}) *RouteResult {
	return r.RouteRequest(method, target, body != nil, body)
}

// RouteRequest routes a request. target is the raw request target: the path,
// still percent-encoded, and the query string, if any. The path checks read
// the path only; the image pull reads the query (#83). hasBody reports a
// non-empty raw body of any Content-Type; body is that body parsed as JSON,
// or nil.
func (r *Router) RouteRequest(method, target string, hasBody bool, body map[string]interface{}) *RouteResult {
	// Read-only mode denies every write, for every path (#75).
	if r.readonly && method != "GET" && method != "HEAD" {
		return &RouteResult{Action: ActionDeny, DenyMsg: fmt.Sprintf("read-only mode: %s requests are not allowed", method)}
	}

	path, rawQuery, _ := strings.Cut(target, "?")

	// The daemon decodes the path before routing, so deny any escape (#53).
	if strings.Contains(path, "%") {
		return &RouteResult{Action: ActionDeny, DenyMsg: "percent-encoded path not allowed"}
	}

	// An empty interior segment can hide a denied prefix such as /exec (#55).
	if strings.Contains(path, "//") {
		return &RouteResult{Action: ActionDeny, DenyMsg: "empty path segment not allowed"}
	}

	// A . or .. segment can hide a denied prefix the same way (#70).
	if hasDotSegment(path) {
		return &RouteResult{Action: ActionDeny, DenyMsg: "dot path segment not allowed"}
	}

	path = stripAPIVersion(path)

	if strings.HasPrefix(path, "/auth") {
		return &RouteResult{Action: ActionDeny, DenyMsg: "auth endpoint is not allowed"}
	}

	if isExecPath(path) {
		return &RouteResult{Action: ActionDeny, DenyMsg: "exec is not allowed"}
	}

	if isAttachPath(path) {
		return &RouteResult{Action: ActionDeny, DenyMsg: "attach is not allowed"}
	}

	if strings.HasPrefix(path, "/build") {
		return &RouteResult{Action: ActionDeny, DenyMsg: "build is not allowed"}
	}

	if strings.HasPrefix(path, "/commit") {
		return &RouteResult{Action: ActionDeny, DenyMsg: "commit is not allowed"}
	}

	if path == "/containers/create" && method == "POST" {
		return r.routeCreate(body, rawQuery)
	}

	if containerName := extractContainerName(path); containerName != "" {
		switch {
		case strings.HasSuffix(path, "/start") && method == "POST":
			return r.routeByContainerName(containerName)
		case strings.HasSuffix(path, "/stop") && method == "POST":
			return r.routeByContainerName(containerName)
		case strings.HasSuffix(path, "/restart") && method == "POST":
			return r.routeByContainerName(containerName)
		case strings.HasSuffix(path, "/kill") && method == "POST":
			return r.routeByContainerName(containerName)
		case strings.HasSuffix(path, "/wait") && method == "POST":
			return r.routeByContainerName(containerName)
		case strings.HasSuffix(path, "/pause") && method == "POST":
			return r.routeByContainerName(containerName)
		case strings.HasSuffix(path, "/unpause") && method == "POST":
			return r.routeByContainerName(containerName)
		case strings.HasSuffix(path, "/rename") && method == "POST":
			return &RouteResult{Action: ActionDeny, DenyMsg: "rename is not allowed"}
		case strings.HasSuffix(path, "/update") && method == "POST":
			return &RouteResult{Action: ActionDeny, DenyMsg: "update is not allowed"}
		case method == "DELETE":
			return r.routeByContainerName(containerName)
		default:
			if method == "GET" {
				return &RouteResult{Action: ActionAllow}
			}
		}
	}

	if path == "/images/create" && method == "POST" {
		return r.routeImagePull(rawQuery, hasBody)
	}

	if method == "GET" || method == "HEAD" {
		return &RouteResult{Action: ActionAllow}
	}

	return &RouteResult{
		Action:  ActionDeny,
		DenyMsg: fmt.Sprintf("endpoint %s %s is not allowed", method, path),
	}
}

func (r *Router) routeCreate(body map[string]interface{}, rawQuery string) *RouteResult {
	if len(body) == 0 {
		return &RouteResult{Action: ActionDeny, DenyMsg: "empty request body"}
	}

	image, _ := body["Image"].(string)
	if image == "" {
		return &RouteResult{Action: ActionDeny, DenyMsg: "image field is required"}
	}
	if _, err := policy.ParseImageRef(image); err != nil {
		return &RouteResult{Action: ActionDeny, DenyMsg: err.Error()}
	}

	name, msg := createName(rawQuery)
	if msg != "" {
		return &RouteResult{Action: ActionDeny, DenyMsg: msg}
	}

	p, err := r.manager.SelectForCreate(image, name)
	if err != nil {
		return &RouteResult{Action: ActionDeny, DenyMsg: err.Error()}
	}

	return &RouteResult{
		Action:    ActionCreateContainer,
		Service:   p.ServiceName,
		Policy:    p,
		Body:      body,
		Container: name,
		Image:     image,
	}
}

// createName returns the ?name= of a create, without the one leading slash
// the daemon also strips, or "" when there is none. The query is parsed as the
// daemon parses it, with url.ParseQuery, as the image pull does (#83). msg is
// the deny message for a query the daemon would reject or an invalid name
// (#85).
func createName(rawQuery string) (name, msg string) {
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		return "", "invalid query string"
	}
	name = strings.TrimPrefix(q.Get("name"), "/")
	if name != "" && !policy.ValidContainerName(name) {
		return "", "invalid container name"
	}
	return name, ""
}

// routeByContainerName allows a lifecycle action or DELETE on a name that
// exactly one policy covers. Anything else, including a name that could also
// be an ID prefix, needs the daemon to say which container it is (#86).
func (r *Router) routeByContainerName(containerName string) *RouteResult {
	if ps := r.manager.Covering(containerName); len(ps) == 1 && !couldBeID(containerName) {
		return &RouteResult{
			Action:    ActionAllow,
			Service:   ps[0].ServiceName,
			Policy:    ps[0],
			Container: containerName,
		}
	}
	return &RouteResult{
		Action:    ActionResolveContainer,
		Container: containerName,
	}
}

// couldBeID reports a name of lowercase hex digits only. The daemon looks up
// an ID, then a name, then an ID prefix, so if no container has this name it
// would act on the container whose ID starts with it (#86).
func couldBeID(name string) bool {
	for _, c := range name {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return name != ""
}

// routeImagePull routes an image pull (#83). The Docker CLI sends fromImage
// and tag in the query string and no body. The image then gets the create checks: a policy prefix on the
// normalised repository (#84), and that policy's tag and digest rules.
func (r *Router) routeImagePull(rawQuery string, hasBody bool) *RouteResult {
	deny := func(msg string) *RouteResult { return &RouteResult{Action: ActionDeny, DenyMsg: msg} }

	// The daemon reads a form body's fromImage over the query's, so a body
	// could name any image: a pull has no body, whatever its Content-Type.
	if hasBody {
		return deny("image pull must not have a request body")
	}

	// The daemon parses the query with url.ParseQuery too, and rejects it on error.
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		return deny("invalid query string")
	}
	for _, key := range []string{"fromImage", "tag", "fromSrc"} {
		if len(q[key]) > 1 {
			return deny(fmt.Sprintf("duplicate %s query parameter", key))
		}
	}
	if q.Has("fromSrc") {
		return deny("image import (fromSrc) is not allowed")
	}
	fromImage := q.Get("fromImage")
	if fromImage == "" {
		return deny("fromImage query parameter is required for image pull")
	}
	ref, err := policy.ParseImageRef(fromImage)
	if err != nil {
		return deny(err.Error())
	}
	if tag := q.Get("tag"); tag != "" {
		if ref.Tag != "" || ref.Digest != "" {
			return deny(fmt.Sprintf("fromImage %s already has a tag or digest; the tag query parameter is ambiguous", fromImage))
		}
		// The CLI sends a digest in tag; a tag never contains ':'.
		sep := ":"
		if strings.Contains(tag, ":") {
			sep = "@"
		}
		if ref, err = policy.ParseImageRef(fromImage + sep + tag); err != nil {
			return deny(err.Error())
		}
	}
	// With neither, the daemon pulls every tag of the repository.
	if ref.Tag == "" && ref.Digest == "" {
		return deny("image pull without a tag or digest pulls every tag and is not allowed")
	}

	// Several policies may allow the image once container_names tells their
	// creates apart (#85). A pull creates no container, so any of them may
	// accept the tag or digest; with none, the first one's reason is given.
	matching := r.manager.MatchingImage(ref.Name)
	if len(matching) == 0 {
		return deny(fmt.Sprintf("image %s not allowed by any policy", fromImage))
	}
	var firstErr error
	for _, p := range matching {
		err := policy.CheckImageTag(p, ref)
		if err == nil {
			return &RouteResult{Action: ActionAllow, Service: p.ServiceName, Image: fromImage}
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return deny(firstErr.Error())
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

// hasDotSegment reports a segment that is exactly . or ..; names such as
// .hidden or a.b are not dot segments (#70).
func hasDotSegment(path string) bool {
	for _, seg := range strings.Split(path, "/") {
		if seg == "." || seg == ".." {
			return true
		}
	}
	return false
}

// isExecPath matches exec on whole segments, so a name like exec-runner is not exec (#49).
func isExecPath(path string) bool {
	segs := strings.Split(strings.TrimPrefix(path, "/"), "/")
	return segs[0] == "exec" || (segs[0] == "containers" && slices.Contains(segs[1:], "exec"))
}

// isAttachPath matches attach on whole segments after /containers, so a name
// like attach-runner is not attach (#76).
func isAttachPath(path string) bool {
	segs := strings.Split(strings.TrimPrefix(path, "/"), "/")
	return segs[0] == "containers" && slices.Contains(segs[1:], "attach")
}

// reservedContainerSegments are Docker endpoints that sit where a container
// name would: /containers/json lists, /containers/create creates. Treating one
// as a container name routes the request down the lifecycle path, where
// DELETE /containers/json would be treated as a container removal rather than
// denied. Rust (rs/src/proxy.rs) and TypeScript
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
