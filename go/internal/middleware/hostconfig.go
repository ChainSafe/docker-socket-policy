package middleware

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/ChainSafe/docker-socket-policy/go/internal/policy"
)

// HostConfigGate is the default-deny check on HostConfig (#88). It runs after
// ContainerConfigMutator, on the body that is forwarded, so values the policy
// forces (Privileged, NetworkMode, SecurityOpt, ...) are what it sees.
//
// A key in hostConfigAnyValue may hold any value. A key in hostConfigRules has
// its own rule. Binds and Mounts are checked by MountSourceGate. Every other
// key, known or not, must be absent or hold a zero value (null, false, 0, "",
// [] or {}); MaskedPaths and ReadonlyPaths must be absent or null, because an
// empty list unmasks /proc.
//
// The daemon matches JSON keys without regard to case, and the last match
// wins, so "privileged": true would set Privileged and "securityopt": null
// would clear a forced SecurityOpt. A key that folds to a known field name but
// is not spelled exactly like it is denied, here and at the top level.
type HostConfigGate struct{}

// hostConfigFields is every HostConfig field of the Docker Engine API (v1.44
// and later, including the embedded Resources fields), plus a few removed
// ones. It is used only to catch case variants of field names.
var hostConfigFields = []string{
	"Binds", "ContainerIDFile", "LogConfig", "NetworkMode", "PortBindings",
	"RestartPolicy", "AutoRemove", "VolumeDriver", "VolumesFrom", "Mounts",
	"ConsoleSize", "Annotations", "CapAdd", "CapDrop", "CgroupnsMode", "Dns",
	"DnsOptions", "DnsSearch", "ExtraHosts", "GroupAdd", "IpcMode", "Cgroup",
	"Links", "OomScoreAdj", "PidMode", "Privileged", "PublishAllPorts",
	"ReadonlyRootfs", "SecurityOpt", "StorageOpt", "Tmpfs", "UTSMode",
	"UsernsMode", "ShmSize", "Sysctls", "Runtime", "Isolation", "MaskedPaths",
	"ReadonlyPaths", "Init", "Capabilities",
	"CpuShares", "Memory", "CgroupParent", "BlkioWeight", "BlkioWeightDevice",
	"BlkioDeviceReadBps", "BlkioDeviceWriteBps", "BlkioDeviceReadIOps",
	"BlkioDeviceWriteIOps", "CpuPeriod", "CpuQuota", "CpuRealtimePeriod",
	"CpuRealtimeRuntime", "CpusetCpus", "CpusetMems", "Devices",
	"DeviceCgroupRules", "DeviceRequests", "KernelMemory", "KernelMemoryTCP",
	"MemoryReservation", "MemorySwap", "MemorySwappiness", "NanoCpus",
	"OomKillDisable", "PidsLimit", "Ulimits", "CpuCount", "CpuPercent",
	"IOMaximumIOps", "IOMaximumBandwidth",
}

// createBodyFields is every top-level field of the create body (the container
// Config, HostConfig and NetworkingConfig), used to catch case variants.
var createBodyFields = []string{
	"Hostname", "Domainname", "User", "AttachStdin", "AttachStdout",
	"AttachStderr", "ExposedPorts", "Tty", "OpenStdin", "StdinOnce", "Env",
	"Cmd", "Healthcheck", "ArgsEscaped", "Image", "Volumes", "WorkingDir",
	"Entrypoint", "NetworkDisabled", "MacAddress", "OnBuild", "Labels",
	"StopSignal", "StopTimeout", "Shell", "HostConfig", "NetworkingConfig",
}

// networkingConfigFields is every field of NetworkingConfig.
var networkingConfigFields = []string{"EndpointsConfig"}

// hostConfigAnyValue may hold any value. NetworkMode, RestartPolicy and
// LogConfig are overwritten by the mutator when the policy sets them.
var hostConfigAnyValue = map[string]bool{
	"NetworkMode": true, "RestartPolicy": true, "LogConfig": true,
	"CapDrop": true, "ReadonlyRootfs": true, "Init": true, "AutoRemove": true,
	"ConsoleSize": true, "ShmSize": true, "PortBindings": true,
	"PublishAllPorts": true, "Dns": true, "DnsOptions": true, "DnsSearch": true,
	"ExtraHosts": true, "Tmpfs": true, "Ulimits": true, "Memory": true,
	"MemoryReservation": true, "MemorySwap": true, "MemorySwappiness": true,
	"NanoCpus": true, "CpuShares": true, "CpuPeriod": true, "CpuQuota": true,
	"CpusetCpus": true, "CpusetMems": true, "PidsLimit": true,
	"BlkioWeight": true, "ContainerIDFile": true,
}

// hostConfigModes lists the values a namespace field may take; "" is always
// allowed. "host" and "container:<id>" are denied.
var hostConfigModes = map[string][]string{
	"PidMode":      {},
	"IpcMode":      {"private", "shareable", "none"},
	"UTSMode":      {},
	"UsernsMode":   {},
	"CgroupnsMode": {"private"},
	"Cgroup":       {},
	"Isolation":    {"default"},
}

var noNewPrivileges = map[string]bool{"no-new-privileges": true, "no-new-privileges:true": true}

func (g *HostConfigGate) Check(r *http.Request, p *policy.Policy, body map[string]interface{}) error {
	if err := checkFieldCase("", body, createBodyFields, p); err != nil {
		return err
	}
	// NetworkEndpointsGate and the mutator read NetworkingConfig.EndpointsConfig
	// by its exact name; the daemon would also read "endpointsconfig".
	if nc, isObj := body["NetworkingConfig"].(map[string]interface{}); isObj {
		if err := checkFieldCase("NetworkingConfig.", nc, networkingConfigFields, p); err != nil {
			return err
		}
	}

	raw, ok := body["HostConfig"]
	if !ok || raw == nil {
		return nil
	}
	hc, ok := raw.(map[string]interface{})
	if !ok {
		return fmt.Errorf("HostConfig must be an object for service %s", p.ServiceName)
	}
	if err := checkFieldCase("HostConfig.", hc, hostConfigFields, p); err != nil {
		return err
	}

	for _, key := range sortedKeys(hc) {
		value := hc[key]
		switch {
		case key == "Binds" || key == "Mounts":
			// MountSourceGate.
		case hostConfigAnyValue[key]:
		case key == "MaskedPaths" || key == "ReadonlyPaths":
			if value != nil {
				return fmt.Errorf("HostConfig.%s is not allowed for service %s", key, p.ServiceName)
			}
		case key == "GroupAdd":
			// Zero, or exactly the policy's group_add, which the mutator
			// forces (#93). Checked here too so that the gate does not open
			// up if the mutator ever stops forcing it.
			if !isZeroValue(value) && !equalsStringList(value, p.ContainerConfig.GroupAdd) {
				return fmt.Errorf("HostConfig.GroupAdd is not allowed for service %s", p.ServiceName)
			}
		case key == "SecurityOpt":
			if err := checkSecurityOpt(value, p); err != nil {
				return err
			}
		case key == "OomScoreAdj":
			if value == nil {
				continue
			}
			n, isNum := value.(float64)
			if !isNum || n < 0 {
				return fmt.Errorf("HostConfig.OomScoreAdj value %v is not allowed for service %s", value, p.ServiceName)
			}
		default:
			if modes, isMode := hostConfigModes[key]; isMode {
				if err := checkMode(key, value, modes, p); err != nil {
					return err
				}
				continue
			}
			if !isZeroValue(value) {
				return fmt.Errorf("HostConfig.%s is not allowed for service %s", key, p.ServiceName)
			}
		}
	}
	return nil
}

func checkSecurityOpt(value interface{}, p *policy.Policy) error {
	if value == nil {
		return nil
	}
	list, ok := value.([]interface{})
	if !ok {
		return fmt.Errorf("HostConfig.SecurityOpt must be a list for service %s", p.ServiceName)
	}
	for _, e := range list {
		s, isStr := e.(string)
		if !isStr {
			return fmt.Errorf("HostConfig.SecurityOpt entry %v is not allowed for service %s", e, p.ServiceName)
		}
		if noNewPrivileges[s] || containsString(p.ContainerConfig.SecurityOptions, s) {
			continue
		}
		return fmt.Errorf("HostConfig.SecurityOpt entry %q is not allowed for service %s", s, p.ServiceName)
	}
	return nil
}

func checkMode(key string, value interface{}, allowed []string, p *policy.Policy) error {
	if value == nil {
		return nil
	}
	s, ok := value.(string)
	if ok && (s == "" || containsString(allowed, s)) {
		return nil
	}
	if ok {
		return fmt.Errorf("HostConfig.%s value %q is not allowed for service %s", key, s, p.ServiceName)
	}
	return fmt.Errorf("HostConfig.%s value %v is not allowed for service %s", key, value, p.ServiceName)
}

// checkFieldCase denies a key that the daemon would read as one of fields but
// that is not spelled exactly like it.
func checkFieldCase(prefix string, obj map[string]interface{}, fields []string, p *policy.Policy) error {
	for _, key := range sortedKeys(obj) {
		folded := foldKey(key)
		for _, f := range fields {
			if key != f && folded == foldKey(f) {
				return fmt.Errorf("%s%s is not allowed for service %s (the daemon reads it as %s%s)", prefix, key, p.ServiceName, prefix, f)
			}
		}
	}
	return nil
}

// foldKey folds a key the way the daemon's JSON decoder matches field names:
// ASCII case, plus the Kelvin sign (U+212A) as k and the long s (U+017F) as s.
func foldKey(s string) string {
	var b strings.Builder
	for len(s) > 0 {
		r, size := utf8.DecodeRuneInString(s)
		s = s[size:]
		switch {
		case r >= 'A' && r <= 'Z':
			r += 'a' - 'A'
		case r == 'K':
			r = 'k'
		case r == 'ſ':
			r = 's'
		}
		b.WriteRune(r)
	}
	return b.String()
}

// isZeroValue reports null, false, 0, "", [] and {}.
func isZeroValue(v interface{}) bool {
	switch x := v.(type) {
	case nil:
		return true
	case bool:
		return !x
	case float64:
		return x == 0
	case string:
		return x == ""
	case []interface{}:
		return len(x) == 0
	case map[string]interface{}:
		return len(x) == 0
	}
	return false
}

// equalsStringList reports whether v is a JSON list of strings equal to want,
// in order. An empty want matches nothing.
func equalsStringList(v interface{}, want []string) bool {
	list, ok := v.([]interface{})
	if !ok || len(want) == 0 || len(list) != len(want) {
		return false
	}
	for i, e := range list {
		if s, isStr := e.(string); !isStr || s != want[i] {
			return false
		}
	}
	return true
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
