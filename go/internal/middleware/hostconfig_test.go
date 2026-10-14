package middleware

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/ChainSafe/docker-socket-policy/go/internal/policy"
)

// HostConfig default-deny, Mounts and bind-mode rows (#88). The same rows, by
// name, are in rs/src/middleware.rs and ts/src/middleware.test.ts.
//
// Policies: "std" has volumes /data (read_write) and /ro (read-only) and
// forces network_mode host; "secopt" is "std" plus security_options
// [no-new-privileges:true]; "bare" has no volumes and no container_config.
// want is "" for an allowed create, or a substring of the deny reason. fwd,
// when set, lists HostConfig fields the forwarded body must hold.
type hostConfigRow struct {
	name   string
	policy string
	body   string
	want   string
	fwd    string
}

func hostConfigRowPolicy(name string) *policy.Policy {
	p := &policy.Policy{
		ServiceName:          "svc",
		AllowedImagePrefixes: []string{"chainsafe/lodestar"},
	}
	if name == "bare" {
		return p
	}
	p.Volumes = []policy.Volume{
		{HostPath: "/data", ContainerPath: "/data", ReadWrite: true},
		{HostPath: "/ro", ContainerPath: "/ro", ReadWrite: false},
	}
	p.ContainerConfig.NetworkMode = "host"
	if name == "secopt" {
		p.ContainerConfig.SecurityOptions = []string{"no-new-privileges:true"}
	}
	return p
}

func TestHostConfigRows(t *testing.T) {
	for _, row := range hostConfigRows {
		t.Run(row.name, func(t *testing.T) {
			var body map[string]interface{}
			if err := json.Unmarshal([]byte(row.body), &body); err != nil {
				t.Fatalf("bad row body: %v", err)
			}
			result := NewChain().Execute(testRequest("POST", "/containers/create"), hostConfigRowPolicy(row.policy), body)
			if row.want == "" {
				if !result.Allowed {
					t.Fatalf("expected allow, got: %s", result.Reason)
				}
			} else {
				if result.Allowed {
					t.Fatalf("expected deny with %q, got allow", row.want)
				}
				if !strings.Contains(result.Reason, row.want) {
					t.Fatalf("expected deny with %q, got: %s", row.want, result.Reason)
				}
				return
			}
			if row.fwd == "" {
				return
			}
			var want, forwarded map[string]interface{}
			if err := json.Unmarshal([]byte(row.fwd), &want); err != nil {
				t.Fatalf("bad row fwd: %v", err)
			}
			if err := json.Unmarshal(result.ModifiedBody, &forwarded); err != nil {
				t.Fatalf("forwarded body: %v", err)
			}
			hc, _ := forwarded["HostConfig"].(map[string]interface{})
			for k, v := range want {
				if !reflect.DeepEqual(hc[k], v) {
					t.Fatalf("forwarded HostConfig.%s = %v, want %v", k, hc[k], v)
				}
			}
		})
	}
}

var hostConfigRows = []hostConfigRow{
	{name: "capAddDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"CapAdd":["SYS_ADMIN"]}}`, want: "HostConfig.CapAdd is not allowed for service svc", fwd: ``},
	{name: "devicesDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Devices":[{"PathOnHost":"/dev/sda","PathInContainer":"/dev/sda","CgroupPermissions":"rwm"}]}}`, want: "HostConfig.Devices is not allowed for service svc", fwd: ``},
	{name: "deviceRequestsDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"DeviceRequests":[{"Driver":"","Count":-1,"Capabilities":[["gpu"]]}]}}`, want: "HostConfig.DeviceRequests is not allowed for service svc", fwd: ``},
	{name: "deviceCgroupRulesDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"DeviceCgroupRules":["b 8:* rmw"]}}`, want: "HostConfig.DeviceCgroupRules is not allowed for service svc", fwd: ``},
	{name: "groupAddDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"GroupAdd":["docker"]}}`, want: "HostConfig.GroupAdd is not allowed for service svc", fwd: ``},
	{name: "volumesFromDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"VolumesFrom":["other"]}}`, want: "HostConfig.VolumesFrom is not allowed for service svc", fwd: ``},
	{name: "linksDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Links":["other:alias"]}}`, want: "HostConfig.Links is not allowed for service svc", fwd: ``},
	{name: "sysctlsDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Sysctls":{"kernel.shm_rmid_forced":"1"}}}`, want: "HostConfig.Sysctls is not allowed for service svc", fwd: ``},
	{name: "cgroupParentDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"CgroupParent":"/"}}`, want: "HostConfig.CgroupParent is not allowed for service svc", fwd: ``},
	{name: "runtimeDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Runtime":"other"}}`, want: "HostConfig.Runtime is not allowed for service svc", fwd: ``},
	{name: "volumeDriverDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"VolumeDriver":"local"}}`, want: "HostConfig.VolumeDriver is not allowed for service svc", fwd: ``},
	{name: "oomKillDisableDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"OomKillDisable":true}}`, want: "HostConfig.OomKillDisable is not allowed for service svc", fwd: ``},
	{name: "annotationsDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Annotations":{"a":"b"}}}`, want: "HostConfig.Annotations is not allowed for service svc", fwd: ``},
	{name: "storageOptDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"StorageOpt":{"size":"1G"}}}`, want: "HostConfig.StorageOpt is not allowed for service svc", fwd: ``},
	{name: "blkioDeviceReadBpsDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"BlkioDeviceReadBps":[{"Path":"/dev/sda","Rate":1}]}}`, want: "HostConfig.BlkioDeviceReadBps is not allowed for service svc", fwd: ``},
	{name: "cpuRealtimeRuntimeDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"CpuRealtimeRuntime":1000}}`, want: "HostConfig.CpuRealtimeRuntime is not allowed for service svc", fwd: ``},
	{name: "unknownFieldDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"FutureField":true}}`, want: "HostConfig.FutureField is not allowed for service svc", fwd: ``},
	{name: "maskedPathsEmptyDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"MaskedPaths":[]}}`, want: "HostConfig.MaskedPaths is not allowed for service svc", fwd: ``},
	{name: "readonlyPathsEmptyDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"ReadonlyPaths":[]}}`, want: "HostConfig.ReadonlyPaths is not allowed for service svc", fwd: ``},
	{name: "maskedPathsListDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"MaskedPaths":["/proc/kcore"]}}`, want: "HostConfig.MaskedPaths is not allowed for service svc", fwd: ``},
	{name: "zeroValuesAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"CapAdd":null,"Devices":[],"GroupAdd":null,"Sysctls":{},"CgroupParent":"","OomKillDisable":false,"Runtime":"","VolumeDriver":"","FutureField":0,"MaskedPaths":null,"ReadonlyPaths":null,"PidMode":"","IpcMode":"","SecurityOpt":null,"OomScoreAdj":0,"Privileged":false}}`, want: "", fwd: ``},
	{name: "pidModeHostDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"PidMode":"host"}}`, want: "HostConfig.PidMode value \"host\" is not allowed for service svc", fwd: ``},
	{name: "pidModeContainerDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"PidMode":"container:abc"}}`, want: "HostConfig.PidMode value \"container:abc\" is not allowed", fwd: ``},
	{name: "ipcModeHostDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"IpcMode":"host"}}`, want: "HostConfig.IpcMode value \"host\" is not allowed", fwd: ``},
	{name: "ipcModeContainerDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"IpcMode":"container:abc"}}`, want: "HostConfig.IpcMode value \"container:abc\" is not allowed", fwd: ``},
	{name: "utsModeHostDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"UTSMode":"host"}}`, want: "HostConfig.UTSMode value \"host\" is not allowed", fwd: ``},
	{name: "usernsModeHostDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"UsernsMode":"host"}}`, want: "HostConfig.UsernsMode value \"host\" is not allowed", fwd: ``},
	{name: "cgroupnsModeHostDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"CgroupnsMode":"host"}}`, want: "HostConfig.CgroupnsMode value \"host\" is not allowed", fwd: ``},
	{name: "cgroupContainerDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Cgroup":"container:abc"}}`, want: "HostConfig.Cgroup value \"container:abc\" is not allowed", fwd: ``},
	{name: "isolationHypervDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Isolation":"hyperv"}}`, want: "HostConfig.Isolation value \"hyperv\" is not allowed", fwd: ``},
	{name: "ipcModePrivateAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"IpcMode":"private"}}`, want: "", fwd: ``},
	{name: "ipcModeShareableAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"IpcMode":"shareable"}}`, want: "", fwd: ``},
	{name: "ipcModeNoneAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"IpcMode":"none"}}`, want: "", fwd: ``},
	{name: "cgroupnsModePrivateAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"CgroupnsMode":"private"}}`, want: "", fwd: ``},
	{name: "isolationDefaultAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Isolation":"default"}}`, want: "", fwd: ``},
	{name: "oomScoreAdjNegativeDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"OomScoreAdj":-1000}}`, want: "HostConfig.OomScoreAdj value -1000 is not allowed", fwd: ``},
	{name: "oomScoreAdjPositiveAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"OomScoreAdj":500}}`, want: "", fwd: ``},
	{name: "securityOptSeccompUnconfinedDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"SecurityOpt":["seccomp=unconfined"]}}`, want: "HostConfig.SecurityOpt entry \"seccomp=unconfined\" is not allowed", fwd: ``},
	{name: "securityOptApparmorUnconfinedDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"SecurityOpt":["apparmor=unconfined"]}}`, want: "HostConfig.SecurityOpt entry \"apparmor=unconfined\" is not allowed", fwd: ``},
	{name: "securityOptLabelDisableDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"SecurityOpt":["label=disable"]}}`, want: "HostConfig.SecurityOpt entry \"label=disable\" is not allowed", fwd: ``},
	{name: "securityOptNoNewPrivilegesFalseDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"SecurityOpt":["no-new-privileges:false"]}}`, want: "HostConfig.SecurityOpt entry \"no-new-privileges:false\" is not allowed", fwd: ``},
	{name: "securityOptNoNewPrivilegesAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"SecurityOpt":["no-new-privileges"]}}`, want: "", fwd: ``},
	{name: "securityOptNoNewPrivilegesTrueAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"SecurityOpt":["no-new-privileges:true"]}}`, want: "", fwd: ``},
	{name: "securityOptOverwrittenByPolicy", policy: "secopt", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"SecurityOpt":["seccomp=unconfined"]}}`, want: "", fwd: `{"SecurityOpt":["no-new-privileges:true"]}`},
	{name: "caseVariantPrivilegedDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"privileged":true}}`, want: "HostConfig.privileged is not allowed for service svc (the daemon reads it as HostConfig.Privileged)", fwd: ``},
	{name: "caseVariantZeroSecurityOptDenied", policy: "secopt", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"securityopt":null}}`, want: "HostConfig.securityopt is not allowed", fwd: ``},
	{name: "caseVariantBindsDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"binds":["/:/host"]}}`, want: "HostConfig.binds is not allowed", fwd: ``},
	{name: "caseVariantLongSDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"\u017fecurityOpt":["seccomp=unconfined"]}}`, want: "(the daemon reads it as HostConfig.SecurityOpt)", fwd: ``},
	{name: "caseVariantKelvinDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Lin\u212as":["other:alias"]}}`, want: "(the daemon reads it as HostConfig.Links)", fwd: ``},
	{name: "topLevelHostConfigVariantDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","hostConfig":{"Privileged":true}}`, want: "hostConfig is not allowed for service svc (the daemon reads it as HostConfig)", fwd: ``},
	{name: "topLevelUserVariantDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","user":"root"}`, want: "user is not allowed for service svc (the daemon reads it as User)", fwd: ``},
	{name: "topLevelImageVariantDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","image":"alpine:3.20"}`, want: "image is not allowed for service svc (the daemon reads it as Image)", fwd: ``},
	{name: "networkingConfigVariantDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","NetworkingConfig":{"EndpointsConfig":{"default":{}},"endpointsconfig":{"evil-net":{}}}}`, want: "NetworkingConfig.endpointsconfig is not allowed for service svc (the daemon reads it as NetworkingConfig.EndpointsConfig)", fwd: ``},
	{name: "networkingConfigVariantBareDenied", policy: "bare", body: `{"Image":"chainsafe/lodestar:v1","NetworkingConfig":{"EndpointsConfig":{"default":{}},"endpointsconfig":{"evil-net":{}}}}`, want: "NetworkingConfig.endpointsconfig is not allowed for service svc", fwd: ``},
	{name: "networkingConfigVariantLongSDenied", policy: "bare", body: `{"Image":"chainsafe/lodestar:v1","NetworkingConfig":{"Endpoint\u017fConfig":{"evil-net":{}}}}`, want: "(the daemon reads it as NetworkingConfig.EndpointsConfig)", fwd: ``},
	{name: "networkingConfigUnforcedAllowed", policy: "bare", body: `{"Image":"chainsafe/lodestar:v1","NetworkingConfig":{"EndpointsConfig":{"default":{},"other":{}}}}`, want: "", fwd: ``},
	{name: "hostConfigNotObjectDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":"x"}`, want: "HostConfig must be an object", fwd: ``},
	{name: "capDropAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"CapDrop":["ALL"]}}`, want: "", fwd: ``},
	{name: "readonlyRootfsAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"ReadonlyRootfs":true}}`, want: "", fwd: ``},
	{name: "initAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Init":true}}`, want: "", fwd: ``},
	{name: "autoRemoveAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"AutoRemove":true}}`, want: "", fwd: ``},
	{name: "consoleSizeAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"ConsoleSize":[24,80]}}`, want: "", fwd: ``},
	{name: "shmSizeAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"ShmSize":67108864}}`, want: "", fwd: ``},
	{name: "portBindingsAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"PortBindings":{"8080/tcp":[{"HostIp":"127.0.0.1","HostPort":"8080"}]}}}`, want: "", fwd: ``},
	{name: "publishAllPortsAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"PublishAllPorts":true}}`, want: "", fwd: ``},
	{name: "dnsAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Dns":["1.1.1.1"]}}`, want: "", fwd: ``},
	{name: "dnsOptionsAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"DnsOptions":["ndots:1"]}}`, want: "", fwd: ``},
	{name: "dnsSearchAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"DnsSearch":["example.com"]}}`, want: "", fwd: ``},
	{name: "extraHostsAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"ExtraHosts":["host:10.0.0.1"]}}`, want: "", fwd: ``},
	{name: "tmpfsAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Tmpfs":{"/run":"rw,noexec"}}}`, want: "", fwd: ``},
	{name: "ulimitsAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Ulimits":[{"Name":"nofile","Soft":1024,"Hard":2048}]}}`, want: "", fwd: ``},
	{name: "memoryAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Memory":268435456}}`, want: "", fwd: ``},
	{name: "memoryReservationAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"MemoryReservation":134217728}}`, want: "", fwd: ``},
	{name: "memorySwapAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"MemorySwap":-1}}`, want: "", fwd: ``},
	{name: "memorySwappinessAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"MemorySwappiness":-1}}`, want: "", fwd: ``},
	{name: "nanoCpusAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"NanoCpus":500000000}}`, want: "", fwd: ``},
	{name: "cpuSharesAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"CpuShares":512}}`, want: "", fwd: ``},
	{name: "cpuPeriodAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"CpuPeriod":100000}}`, want: "", fwd: ``},
	{name: "cpuQuotaAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"CpuQuota":50000}}`, want: "", fwd: ``},
	{name: "cpusetCpusAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"CpusetCpus":"0-1"}}`, want: "", fwd: ``},
	{name: "cpusetMemsAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"CpusetMems":"0"}}`, want: "", fwd: ``},
	{name: "pidsLimitAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"PidsLimit":100}}`, want: "", fwd: ``},
	{name: "blkioWeightAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"BlkioWeight":10}}`, want: "", fwd: ``},
	{name: "containerIdFileAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"ContainerIDFile":"/tmp/cid"}}`, want: "", fwd: ``},
	{name: "networkModeAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"NetworkMode":"bridge"}}`, want: "", fwd: ``},
	{name: "restartPolicyAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"RestartPolicy":{"Name":"always","MaximumRetryCount":0}}}`, want: "", fwd: ``},
	{name: "logConfigAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"LogConfig":{"Type":"json-file","Config":{"max-size":"10m"}}}}`, want: "", fwd: ``},
	{name: "privilegedNeutralised", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Privileged":true}}`, want: "", fwd: `{"Privileged":false}`},
	{name: "privilegedNeutralisedEmptyContainerConfig", policy: "bare", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Privileged":true}}`, want: "", fwd: `{"Privileged":false}`},
	{name: "emptyContainerConfigForcesPrivilegedFalse", policy: "bare", body: `{"Image":"chainsafe/lodestar:v1"}`, want: "", fwd: `{"Privileged":false}`},
	{name: "mountBindRootDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"bind","Source":"/","Target":"/host"}]}}`, want: "mount source \"/\" is not in the whitelist for service svc", fwd: ``},
	{name: "mountBindAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"bind","Source":"/data","Target":"/data"}]}}`, want: "", fwd: ``},
	{name: "mountBindReadOnlyVolumeWritableDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"bind","Source":"/ro","Target":"/ro"}]}}`, want: "mount of \"/ro\" must be read-only (ReadOnly: true) for service svc", fwd: ``},
	{name: "mountBindReadOnlyVolumeReadOnlyFalseDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"bind","Source":"/ro","Target":"/ro","ReadOnly":false}]}}`, want: "mount of \"/ro\" must be read-only", fwd: ``},
	{name: "mountBindReadOnlyVolumeReadOnlyAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"bind","Source":"/ro","Target":"/ro","ReadOnly":true}]}}`, want: "", fwd: ``},
	{name: "mountVolumeTypeDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"volume","Source":"myvol","Target":"/v"}]}}`, want: "mount type \"volume\" is not allowed for service svc", fwd: ``},
	{name: "mountImageTypeDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"image","Source":"alpine:3.20","Target":"/i"}]}}`, want: "mount type \"image\" is not allowed", fwd: ``},
	{name: "mountNpipeTypeDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"npipe","Source":"//./pipe/docker_engine","Target":"/p"}]}}`, want: "mount type \"npipe\" is not allowed", fwd: ``},
	{name: "mountMissingTypeDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Source":"/data","Target":"/data"}]}}`, want: "mount type \"\" is not allowed", fwd: ``},
	{name: "mountTmpfsAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"tmpfs","Target":"/run","TmpfsOptions":{"SizeBytes":1048576}}]}}`, want: "", fwd: ``},
	{name: "mountTmpfsWithSourceDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"tmpfs","Source":"/","Target":"/run"}]}}`, want: "tmpfs mount must not have a Source", fwd: ``},
	{name: "mountPropagationRsharedDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"bind","Source":"/data","Target":"/data","BindOptions":{"Propagation":"rshared"}}]}}`, want: "mount propagation \"rshared\" is not allowed", fwd: ``},
	{name: "mountPropagationSlaveDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"bind","Source":"/data","Target":"/data","BindOptions":{"Propagation":"slave"}}]}}`, want: "mount propagation \"slave\" is not allowed", fwd: ``},
	{name: "mountPropagationRprivateAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"bind","Source":"/data","Target":"/data","BindOptions":{"Propagation":"rprivate"}}]}}`, want: "", fwd: ``},
	{name: "mountCreateMountpointAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"bind","Source":"/data","Target":"/data","BindOptions":{"CreateMountpoint":true}}]}}`, want: "", fwd: ``},
	{name: "mountReadOnlyNonRecursiveDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"bind","Source":"/ro","Target":"/ro","ReadOnly":true,"BindOptions":{"ReadOnlyNonRecursive":true}}]}}`, want: "HostConfig.Mounts.BindOptions.ReadOnlyNonRecursive is not allowed", fwd: ``},
	{name: "mountVolumeOptionsDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"bind","Source":"/data","Target":"/data","VolumeOptions":{"NoCopy":true}}]}}`, want: "HostConfig.Mounts.VolumeOptions is not allowed", fwd: ``},
	{name: "mountCaseVariantDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"tmpfs","Target":"/x","type":"bind","source":"/"}]}}`, want: "HostConfig.Mounts.source is not allowed", fwd: ``},
	{name: "mountNoVolumesDenied", policy: "bare", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"bind","Source":"/data","Target":"/data"}]}}`, want: "mount source \"/data\" is not in the whitelist", fwd: ``},
	{name: "mountsNotListDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":{}}}`, want: "HostConfig.Mounts must be a list", fwd: ``},
	{name: "bindAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Binds":["/data:/data"]}}`, want: "", fwd: ``},
	{name: "bindReadOnlyVolumeRwDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Binds":["/ro:/ro:rw"]}}`, want: "volume mount \"/ro\" must be read-only (:ro) for service svc", fwd: ``},
	{name: "bindReadOnlyVolumeNoModeDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Binds":["/ro:/ro"]}}`, want: "volume mount \"/ro\" must be read-only (:ro)", fwd: ``},
	{name: "bindReadOnlyVolumeRoAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Binds":["/ro:/ro:ro"]}}`, want: "", fwd: ``},
	{name: "bindReadOnlyVolumeRoZAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Binds":["/ro:/ro:ro,Z"]}}`, want: "", fwd: ``},
	{name: "bindReadOnlyVolumeRoRwDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Binds":["/ro:/ro:ro,rw"]}}`, want: "volume mount \"/ro\" must be read-only (:ro)", fwd: ``},
	{name: "bindRsharedDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Binds":["/data:/data:rshared"]}}`, want: "bind option \"rshared\" on volume mount \"/data\" is not allowed for service svc", fwd: ``},
	{name: "bindRslaveDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Binds":["/data:/data:rw,rslave"]}}`, want: "bind option \"rslave\" on volume mount \"/data\" is not allowed", fwd: ``},
	{name: "bindConsistencyModeDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Binds":["/data:/data:cached"]}}`, want: "bind option \"cached\" on volume mount \"/data\" is not allowed", fwd: ``},
	{name: "bindRprivateAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Binds":["/data:/data:rw,rprivate"]}}`, want: "", fwd: ``},
	{name: "bindPrivateZAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Binds":["/data:/data:z,private"]}}`, want: "", fwd: ``},
	{name: "bindNocopyAllowed", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Binds":["/data:/data:nocopy"]}}`, want: "", fwd: ``},
	{name: "bindUnlistedDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Binds":["/etc:/etc:ro"]}}`, want: "volume mount \"/etc\" is not in the whitelist for service svc", fwd: ``},
	{name: "bindNoVolumesDenied", policy: "bare", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Binds":["/data:/data"]}}`, want: "volume mount \"/data\" is not in the whitelist", fwd: ``},
	{name: "bindNotStringDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Binds":[1]}}`, want: "HostConfig.Binds must be a list of strings", fwd: ``},
	{name: "bindTooManyPartsDenied", policy: "std", body: `{"Image":"chainsafe/lodestar:v1","HostConfig":{"Binds":["/data:/data:ro:x"]}}`, want: "bind \"/data:/data:ro:x\" is not a valid bind", fwd: ``},
	{name: "topLevelVolumesNoVolumesDenied", policy: "bare", body: `{"Image":"chainsafe/lodestar:v1","Volumes":{"/data":{}}}`, want: "volume \"/data\" is not in the whitelist", fwd: ``},
	{name: "topLevelVolumesEmptyAllowed", policy: "bare", body: `{"Image":"chainsafe/lodestar:v1","Volumes":{}}`, want: "", fwd: ``},
	{name: "dockerCliCreateBodyAllowed", policy: "std", body: `{"Hostname":"","Domainname":"","User":"","AttachStdin":false,"AttachStdout":true,"AttachStderr":true,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":null,"Cmd":["true"],"Image":"chainsafe/lodestar:v1","Volumes":{},"WorkingDir":"","Entrypoint":null,"Labels":{},"HostConfig":{"Binds":null,"ContainerIDFile":"","LogConfig":{"Type":"","Config":{}},"NetworkMode":"default","PortBindings":{},"RestartPolicy":{"Name":"no","MaximumRetryCount":0},"AutoRemove":false,"VolumeDriver":"","VolumesFrom":null,"ConsoleSize":[0,0],"CapAdd":null,"CapDrop":null,"CgroupnsMode":"","Dns":null,"DnsOptions":[],"DnsSearch":[],"ExtraHosts":null,"GroupAdd":null,"IpcMode":"","Cgroup":"","Links":null,"OomScoreAdj":0,"PidMode":"","Privileged":false,"PublishAllPorts":false,"ReadonlyRootfs":false,"SecurityOpt":null,"UTSMode":"","UsernsMode":"","ShmSize":0,"Isolation":"","CpuShares":0,"Memory":0,"NanoCpus":0,"CgroupParent":"","BlkioWeight":0,"BlkioWeightDevice":[],"BlkioDeviceReadBps":[],"BlkioDeviceWriteBps":[],"BlkioDeviceReadIOps":[],"BlkioDeviceWriteIOps":[],"CpuPeriod":0,"CpuQuota":0,"CpuRealtimePeriod":0,"CpuRealtimeRuntime":0,"CpusetCpus":"","CpusetMems":"","Devices":[],"DeviceCgroupRules":null,"DeviceRequests":null,"MemoryReservation":0,"MemorySwap":0,"MemorySwappiness":-1,"OomKillDisable":false,"PidsLimit":0,"Ulimits":null,"CpuCount":0,"CpuPercent":0,"IOMaximumIOps":0,"IOMaximumBandwidth":0,"MaskedPaths":null,"ReadonlyPaths":null},"NetworkingConfig":{"EndpointsConfig":{"default":{"IPAMConfig":null,"Links":null,"Aliases":null,"DriverOpts":null,"GwPriority":0,"NetworkID":"","EndpointID":"","Gateway":"","IPAddress":"","MacAddress":"","IPPrefixLen":0,"IPv6Gateway":"","GlobalIPv6Address":"","GlobalIPv6PrefixLen":0,"DNSNames":null}}}}`, want: "", fwd: ``},
	{name: "dockerCliCreateBodyBareAllowed", policy: "bare", body: `{"Hostname":"","Domainname":"","User":"","AttachStdin":false,"AttachStdout":true,"AttachStderr":true,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":null,"Cmd":["true"],"Image":"chainsafe/lodestar:v1","Volumes":{},"WorkingDir":"","Entrypoint":null,"Labels":{},"HostConfig":{"Binds":null,"ContainerIDFile":"","LogConfig":{"Type":"","Config":{}},"NetworkMode":"default","PortBindings":{},"RestartPolicy":{"Name":"no","MaximumRetryCount":0},"AutoRemove":false,"VolumeDriver":"","VolumesFrom":null,"ConsoleSize":[0,0],"CapAdd":null,"CapDrop":null,"CgroupnsMode":"","Dns":null,"DnsOptions":[],"DnsSearch":[],"ExtraHosts":null,"GroupAdd":null,"IpcMode":"","Cgroup":"","Links":null,"OomScoreAdj":0,"PidMode":"","Privileged":false,"PublishAllPorts":false,"ReadonlyRootfs":false,"SecurityOpt":null,"UTSMode":"","UsernsMode":"","ShmSize":0,"Isolation":"","CpuShares":0,"Memory":0,"NanoCpus":0,"CgroupParent":"","BlkioWeight":0,"BlkioWeightDevice":[],"BlkioDeviceReadBps":[],"BlkioDeviceWriteBps":[],"BlkioDeviceReadIOps":[],"BlkioDeviceWriteIOps":[],"CpuPeriod":0,"CpuQuota":0,"CpuRealtimePeriod":0,"CpuRealtimeRuntime":0,"CpusetCpus":"","CpusetMems":"","Devices":[],"DeviceCgroupRules":null,"DeviceRequests":null,"MemoryReservation":0,"MemorySwap":0,"MemorySwappiness":-1,"OomKillDisable":false,"PidsLimit":0,"Ulimits":null,"CpuCount":0,"CpuPercent":0,"IOMaximumIOps":0,"IOMaximumBandwidth":0,"MaskedPaths":null,"ReadonlyPaths":null},"NetworkingConfig":{"EndpointsConfig":{"default":{"IPAMConfig":null,"Links":null,"Aliases":null,"DriverOpts":null,"GwPriority":0,"NetworkID":"","EndpointID":"","Gateway":"","IPAddress":"","MacAddress":"","IPPrefixLen":0,"IPv6Gateway":"","GlobalIPv6Address":"","GlobalIPv6PrefixLen":0,"DNSNames":null}}}}`, want: "", fwd: ``},
	{name: "ansibleCreateBodyAllowed", policy: "secopt", body: `{"Image":"chainsafe/lodestar:v1","Cmd":["beacon"],"Env":[],"Labels":{"app":"beacon"},"HostConfig":{"Binds":["/data:/data:rw","/ro:/ro:ro"],"NetworkMode":"host","RestartPolicy":{"Name":"unless-stopped","MaximumRetryCount":0},"LogConfig":{"Type":"json-file","Config":{"max-size":"100m"}},"SecurityOpt":["no-new-privileges:true"],"Init":false,"AutoRemove":false,"Privileged":false,"ReadonlyRootfs":false,"CapDrop":["ALL"],"Memory":0}}`, want: "", fwd: ``},
}
