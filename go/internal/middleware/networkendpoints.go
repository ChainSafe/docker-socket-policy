package middleware

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/ChainSafe/docker-socket-policy/go/internal/policy"
)

// endpointsConfig returns NetworkingConfig.EndpointsConfig of a create body:
// nil when absent or null, ok=false when NetworkingConfig or EndpointsConfig
// is not an object.
func endpointsConfig(body map[string]interface{}) (eps map[string]interface{}, ok bool) {
	nc, present := body["NetworkingConfig"]
	if !present || nc == nil {
		return nil, true
	}
	ncMap, isMap := nc.(map[string]interface{})
	if !isMap {
		return nil, false
	}
	raw, present := ncMap["EndpointsConfig"]
	if !present || raw == nil {
		return nil, true
	}
	eps, isMap = raw.(map[string]interface{})
	return eps, isMap
}

// detachedNetworkMode reports a network mode in which the container joins no
// network of its own.
func detachedNetworkMode(mode string) bool {
	return mode == "host" || mode == "none" || strings.HasPrefix(mode, "container:")
}

// NetworkEndpointsGate: when the policy forces network_mode M, every key in
// NetworkingConfig.EndpointsConfig must be "default" or M (#87). Any other key
// would attach the container to a network the policy does not allow.
// ContainerConfigMutator leaves such a request unchanged, so this gate sees
// what the caller sent.
type NetworkEndpointsGate struct{}

func (g *NetworkEndpointsGate) Check(r *http.Request, p *policy.Policy, body map[string]interface{}) error {
	mode := p.ContainerConfig.NetworkMode
	if mode == "" {
		return nil
	}
	eps, ok := endpointsConfig(body)
	if !ok {
		return fmt.Errorf("NetworkingConfig.EndpointsConfig must be a JSON object; policy forces network_mode %s", mode)
	}
	keys := make([]string, 0, len(eps))
	for k := range eps {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if k != "default" && k != mode {
			return fmt.Errorf("network %q is not allowed for service %s; policy forces network_mode %s", k, p.ServiceName, mode)
		}
	}
	return nil
}

// forceEndpoints makes NetworkingConfig.EndpointsConfig consistent with the
// forced network mode (#87): no entries for host, none and container:<id>;
// otherwise exactly one entry keyed by the mode, with the settings of the
// caller's entry for the mode, else of its "default" entry, else {}. A request
// that NetworkEndpointsGate denies is left unchanged.
func forceEndpoints(mode string, body map[string]interface{}) {
	eps, ok := endpointsConfig(body)
	if !ok {
		return
	}
	for k := range eps {
		if k != "default" && k != mode {
			return
		}
	}
	forced := map[string]interface{}{}
	if !detachedNetworkMode(mode) {
		entry, present := eps[mode]
		if !present {
			entry, present = eps["default"]
		}
		if !present {
			entry = map[string]interface{}{}
		}
		forced[mode] = entry
	}
	nc, isMap := body["NetworkingConfig"].(map[string]interface{})
	if !isMap {
		nc = map[string]interface{}{}
		body["NetworkingConfig"] = nc
	}
	nc["EndpointsConfig"] = forced
}
