// ─── Module: policy ──────────────────────────────────────────────────────

module policy {
  type FlagRule = { flag: str, valuePattern: str }

  type ContainerConfig = {
    networkMode: str,
    restartPolicy: str,
    securityOptions: Set[str],
    user: str
  }

  // containerNames is the policy's container_names (#85). The empty set
  // stands for "unset": an empty container_names list is a load error, so
  // the two cannot be confused.
  type Policy = {
    serviceName: str,
    containerNames: Set[str],
    allowedImagePrefixes: Set[str],
    imageTagPattern: str,
    imageDigestAllowed: bool,
    containerConfig: ContainerConfig,
    volumes: Set[str],
    // The volumes with read_write: false (#88).
    readOnlyVolumes: Set[str],
    envFile: str,
    privileged: bool,
    allowedCliFlags: Set[str],
    flagRules: List[FlagRule],
    deniedFlags: Set[str]
  }

  pure def imageNameAllowed(name: str, policy: Policy): bool = {
    policy.allowedImagePrefixes.contains(name)
  }

  // A create named `name` may use the policy: a policy without
  // container_names accepts any name, including none (#85).
  pure def acceptsName(name: str, policy: Policy): bool = {
    policy.containerNames.size() == 0 or policy.containerNames.contains(name)
  }

  // The policies a create of `image` named `name` could use. The proxy
  // forwards a create only when this is exactly one policy, and applies that
  // one (#85). Before #85 any policy that matched the image could be applied.
  pure def selectPolicies(ps: Set[Policy], image: str, name: str): Set[Policy] = {
    ps.filter(p => imageNameAllowed(image, p) and acceptsName(name, p))
  }

  pure def flagAllowed(flag: str, policy: Policy): bool = {
    policy.allowedCliFlags.contains(flag)
      and not(policy.deniedFlags.contains(flag))
  }

  pure def volumeAllowed(volume: str, policy: Policy): bool = {
    policy.volumes.contains(volume)
  }

  pure def envAllowed(envVars: Set[str], policy: Policy): bool = {
    policy.envFile == "" or envVars.size() == 0
  }
}

// ─── Module: network_endpoints_model ────────────────────────────────────
//
// How ContainerConfigMutator and NetworkEndpointsGate treat
// NetworkingConfig.EndpointsConfig when the policy forces
// container_config.network_mode (#87). The state machine below records the
// forced HostConfig.NetworkMode (`alwaysHostNetwork`); this module adds the
// endpoint entries, which the daemon reads alongside it.
//
// EndpointsConfig is a map from network name to that entry's settings: ""
// stands for `{}` and "a" for an entry with settings such as Aliases. An
// absent NetworkingConfig and an empty EndpointsConfig are both `Map()`.
// `container:x` stands for every `container:<name|id>` mode.
//
// ENFORCE_ENDPOINTS = false models all three before #87: the mutator forced
// HostConfig.NetworkMode and forwarded EndpointsConfig as the caller sent
// it. Without `--network` the Docker CLI sends {"default": {}}, so the
// create succeeded and the start failed with `network default not found`.
// true models all three after the fix: a key other than "default" and the
// forced mode M is denied; otherwise host, none and container:x get no
// entries, and bridge or a named network gets exactly one entry keyed M,
// with the settings of the caller's M entry, else of its "default" entry,
// else `{}`.

module network_endpoints_model {
  const ENFORCE_ENDPOINTS: bool

  type Endpoints = str -> str
  type EndpointsOutcome = { allowed: bool, endpoints: Endpoints }

  pure val NETWORK_MODES = Set("host", "none", "container:x", "bridge", "mynet")
  pure val ENDPOINT_KEYS = Set("default", "host", "none", "container:x", "bridge", "mynet", "other")
  pure val ENDPOINT_SETTINGS = Set("", "a")

  // Every EndpointsConfig over ENDPOINT_KEYS and ENDPOINT_SETTINGS.
  pure val ENDPOINT_REQUESTS: Set[Endpoints] =
    ENDPOINT_KEYS.powerset().fold(Set(), (acc, ks) => acc.union(ks.setOfMaps(ENDPOINT_SETTINGS)))

  // Modes in which the container joins no network of its own.
  pure def detachedMode(m: str): bool =
    m == "host" or m == "none" or m == "container:x"

  pure def forcedEntry(m: str, eps: Endpoints): str =
    if (eps.keys().contains(m)) eps.get(m)
    else if (eps.keys().contains("default")) eps.get("default")
    else ""

  pure def forceEndpoints(m: str, eps: Endpoints): Endpoints =
    if (detachedMode(m)) Map() else Map(m -> forcedEntry(m, eps))

  // The create request's endpoints after the gate and the mutator, for a
  // policy that forces network mode m.
  pure def handleEndpoints(m: str, eps: Endpoints): EndpointsOutcome =
    if (not(ENFORCE_ENDPOINTS)) { allowed: true, endpoints: eps }
    else if (eps.keys().forall(k => k == "default" or k == m))
      { allowed: true, endpoints: forceEndpoints(m, eps) }
    else { allowed: false, endpoints: eps }

  // The daemon starts the container only when every endpoint key names its
  // NetworkMode. Checked on Engine 29.8.2, API 1.41 to 1.56: with NetworkMode
  // host, none or bridge, a "default" entry fails the start with
  // `network default not found`, and an empty EndpointsConfig starts.
  pure def daemonStarts(m: str, eps: Endpoints): bool =
    eps.keys().forall(k => k == m)

  // Rule: an endpoint key other than "default" and the forced mode is denied.
  val extraNetworkDenied = NETWORK_MODES.forall(m => ENDPOINT_REQUESTS.forall(eps =>
    eps.keys().exists(k => k != "default" and k != m) implies not(handleEndpoints(m, eps).allowed)
  ))

  // Security: an allowed create names no network but the forced one.
  val onlyForcedNetwork = NETWORK_MODES.forall(m => ENDPOINT_REQUESTS.forall(eps =>
    val o = handleEndpoints(m, eps)
    o.allowed implies o.endpoints.keys().subseteq(Set(m))
  ))

  // The bug: every allowed create also starts.
  val allowedCreatesStart = NETWORK_MODES.forall(m => ENDPOINT_REQUESTS.forall(eps =>
    val o = handleEndpoints(m, eps)
    o.allowed implies daemonStarts(m, o.endpoints)
  ))
}

module network_endpoints {
  import network_endpoints_model(ENFORCE_ENDPOINTS = true).*

  pure def allowedWith(m: str, eps: Endpoints, want: Endpoints): bool =
    handleEndpoints(m, eps) == { allowed: true, endpoints: want }

  pure def denied(m: str, eps: Endpoints): bool =
    not(handleEndpoints(m, eps).allowed)

  run endpointsSoundTest =
    assert(and { extraNetworkDenied, onlyForcedNetwork, allowedCreatesStart })

  run hostNoEndpointsTest = assert(allowedWith("host", Map(), Map()))
  run hostDefaultClearedTest = assert(allowedWith("host", Map("default" -> ""), Map()))
  run hostOwnClearedTest = assert(allowedWith("host", Map("host" -> "a"), Map()))
  run hostExtraDeniedTest = assert(denied("host", Map("default" -> "", "other" -> "")))

  run noneNoEndpointsTest = assert(allowedWith("none", Map(), Map()))
  run noneDefaultClearedTest = assert(allowedWith("none", Map("default" -> ""), Map()))
  run noneOwnClearedTest = assert(allowedWith("none", Map("none" -> "a"), Map()))
  run noneExtraDeniedTest = assert(denied("none", Map("default" -> "", "other" -> "")))

  run containerNoEndpointsTest = assert(allowedWith("container:x", Map(), Map()))
  run containerDefaultClearedTest = assert(allowedWith("container:x", Map("default" -> ""), Map()))
  run containerOwnClearedTest = assert(allowedWith("container:x", Map("container:x" -> "a"), Map()))
  run containerExtraDeniedTest = assert(denied("container:x", Map("default" -> "", "other" -> "")))

  run bridgeNoEndpointsTest = assert(allowedWith("bridge", Map(), Map("bridge" -> "")))
  run bridgeDefaultRekeyedTest = assert(allowedWith("bridge", Map("default" -> "a"), Map("bridge" -> "a")))
  run bridgeOwnKeptTest = assert(allowedWith("bridge", Map("bridge" -> "a"), Map("bridge" -> "a")))
  run bridgeExtraDeniedTest = assert(denied("bridge", Map("default" -> "", "other" -> "")))

  run namedNoEndpointsTest = assert(allowedWith("mynet", Map(), Map("mynet" -> "")))
  run namedDefaultRekeyedTest = assert(allowedWith("mynet", Map("default" -> "a"), Map("mynet" -> "a")))
  run namedOwnKeptTest = assert(allowedWith("mynet", Map("mynet" -> "a"), Map("mynet" -> "a")))
  run namedExtraDeniedTest = assert(denied("mynet", Map("default" -> "", "other" -> "")))
  run namedOwnOverDefaultTest = assert(allowedWith("mynet", Map("default" -> "a", "mynet" -> ""), Map("mynet" -> "")))
}

// All three before #87: EndpointsConfig went through as the caller sent it.
// The Docker CLI's {"default": {}} was allowed with network_mode host, and
// the daemon then refused to start the container; an extra entry was allowed
// too.
module network_endpoints_pre87 {
  import network_endpoints_model(ENFORCE_ENDPOINTS = false).*

  run pre87UnsoundTest =
    assert(and {
      not(extraNetworkDenied),
      not(onlyForcedNetwork),
      not(allowedCreatesStart),
      handleEndpoints("host", Map("default" -> "")) == { allowed: true, endpoints: Map("default" -> "") },
      not(daemonStarts("host", Map("default" -> ""))),
      handleEndpoints("host", Map("default" -> "", "other" -> "")).allowed,
    })
}

// ─── Module: create_model ───────────────────────────────────────────────
//
// The HostConfig check on POST /containers/create (#88): what of a create
// request's HostConfig reaches the daemon. Mirrors ContainerConfigMutator,
// MountSourceGate and HostConfigGate in go/internal/middleware,
// rs/src/middleware.rs and ts/src/middleware.ts.
//
// A HostConfig field is a key, spelled as the caller spelled it, and an atom
// standing for its value. "null" is an absent or null field, "zero" any other
// zero value (false, 0, "", {}), and "[]" an empty list; every other atom is
// a non-zero value. A list field holds one entry, the atom. The model's field
// names stand for the classes in the README table: CapAdd, Devices and
// GroupAdd for the fields that must be zero, FutureField for a field the
// proxy does not know, CapDrop and MemorySwappiness for the fields that may
// hold any value, PidMode and IpcMode for the namespace modes.
//
// The daemon matches field names without regard to case, and the last match
// in the body wins. CASE_FOLD lists the variants in the model; the daemon
// reads a variant under its canonical name, and when a name appears twice,
// either value may be the one it keeps. The same holds inside
// NetworkingConfig, whose only field is EndpointsConfig: a request's
// `networking` entries are its NetworkingConfig keys, each with one network
// name as value, and NetworkEndpointsGate (#87) reads the exact key only.
//
// LEGACY_CREATE = true models all three before #88: the only check was that
// each Binds host path is a policy volume, skipped when the policy has no
// volumes; Mounts, bind options and every other field went through; and the
// mutator did not force Privileged when the policy has no container_config.
// NetworkEndpointsGate (#87) is in both instances, as it is on main before
// #88. false models all three after the fix.

module create_model {
  import policy.*

  const LEGACY_CREATE: bool

  type Field = { key: str, value: str }
  // A HostConfig.Binds entry: host path and bind options.
  type Bind = { source: str, opts: Set[str] }
  // A HostConfig.Mounts entry. kind is its Type; propagation is
  // BindOptions.Propagation.
  type MountEntry = { kind: str, source: str, readOnly: bool, propagation: str }
  type CreateReq = { entries: Set[Field], binds: Set[Bind], mounts: Set[MountEntry], networking: Set[Field] }
  // A host path the daemon mounts into the container.
  type HostMount = { source: str, writable: bool, privatePropagation: bool }

  pure val ZERO_VALUES = Set("null", "zero", "[]")
  pure def isZero(v: str): bool = ZERO_VALUES.contains(v)

  pure val CASE_FOLD: str -> str = Map(
    "privileged" -> "Privileged",
    "securityopt" -> "SecurityOpt",
    "networkmode" -> "NetworkMode",
    "endpointsconfig" -> "EndpointsConfig",
  )
  pure def canon(k: str): str = if (CASE_FOLD.keys().contains(k)) CASE_FOLD.get(k) else k
  pure def isVariant(k: str): bool = canon(k) != k

  pure val ANY_VALUE = Set("NetworkMode", "CapDrop", "MemorySwappiness")
  pure val MODES: str -> Set[str] = Map(
    "PidMode" -> Set(),
    "IpcMode" -> Set("private", "shareable", "none"),
  )
  pure val NULL_ONLY = Set("MaskedPaths")
  pure val NO_NEW_PRIVILEGES = Set("no-new-privileges", "no-new-privileges:true")
  // The value the mutator writes for SecurityOpt: the policy's list.
  pure val POLICY_SECURITY_OPT = "policySecurityOptions"

  pure val BIND_OPTS = Set("ro", "rw", "Z", "rprivate")
  pure val PRIVATE_PROPAGATION = Set("", "private", "rprivate")
  pure val SHARED_PROPAGATION = Set("shared", "rshared", "slave", "rslave")

  // The value a field may hold when it reaches the daemon, under its
  // canonical name.
  pure def valueAllowed(p: Policy, k: str, v: str): bool =
    if (NULL_ONLY.contains(k)) v == "null"
    else if (isZero(v)) true
    else if (ANY_VALUE.contains(k)) true
    else if (MODES.keys().contains(k)) MODES.get(k).contains(v)
    else if (k == "OomScoreAdj") v != "-1000"
    else if (k == "SecurityOpt")
      NO_NEW_PRIVILEGES.contains(v) or p.containerConfig.securityOptions.contains(v) or v == POLICY_SECURITY_OPT
    else false

  pure def hasContainerConfig(p: Policy): bool = or {
    p.containerConfig.networkMode != "",
    p.containerConfig.restartPolicy != "",
    p.containerConfig.securityOptions.size() > 0,
    p.containerConfig.user != "",
  }

  pure def forcesPrivileged(p: Policy): bool = not(LEGACY_CREATE) or hasContainerConfig(p)

  // ContainerConfigMutator. It writes canonical names only.
  pure def mutate(p: Policy, fs: Set[Field]): Set[Field] = {
    val nm = p.containerConfig.networkMode
    val forcesSecOpt = p.containerConfig.securityOptions.size() > 0
    val kept = fs.filter(f => not(or {
      f.key == "Privileged" and forcesPrivileged(p),
      f.key == "NetworkMode" and nm != "",
      f.key == "SecurityOpt" and forcesSecOpt,
    }))
    kept
      .union(if (forcesPrivileged(p)) Set({ key: "Privileged", value: "zero" }) else Set())
      .union(if (nm != "") Set({ key: "NetworkMode", value: nm }) else Set())
      .union(if (forcesSecOpt) Set({ key: "SecurityOpt", value: POLICY_SECURITY_OPT }) else Set())
  }

  // HostConfigGate, on the mutated fields.
  pure def fieldOk(p: Policy, f: Field): bool =
    not(isVariant(f.key)) and valueAllowed(p, f.key, f.value)

  // MountSourceGate on a Binds entry.
  pure def bindOk(p: Policy, b: Bind): bool = and {
    p.volumes.contains(b.source),
    b.opts.subseteq(BIND_OPTS),
    p.readOnlyVolumes.contains(b.source) implies (b.opts.contains("ro") and not(b.opts.contains("rw"))),
  }

  // MountSourceGate on a Mounts entry.
  pure def mountOk(p: Policy, m: MountEntry): bool = or {
    m.kind == "tmpfs" and m.source == "",
    and {
      m.kind == "bind",
      p.volumes.contains(m.source),
      p.readOnlyVolumes.contains(m.source) implies m.readOnly,
      PRIVATE_PROPAGATION.contains(m.propagation),
    },
  }

  // NetworkEndpointsGate (#87): when the policy forces network_mode, every
  // network under the exact key EndpointsConfig is "default" or the mode.
  pure def endpointsOk(p: Policy, r: CreateReq): bool = {
    val nm = p.containerConfig.networkMode
    nm == "" or r.networking.forall(f => f.key == "EndpointsConfig" implies Set("default", nm).contains(f.value))
  }

  pure def createAllowed(p: Policy, r: CreateReq): bool = and {
    endpointsOk(p, r),
    if (LEGACY_CREATE)
      p.volumes.size() == 0 or r.binds.forall(b => p.volumes.contains(b.source))
    else and {
      mutate(p, r.entries).forall(f => fieldOk(p, f)),
      r.networking.forall(f => not(isVariant(f.key))),
      r.binds.forall(b => bindOk(p, b)),
      r.mounts.forall(m => mountOk(p, m)),
    },
  }

  // ─── What the daemon reads ──────────────────────────────────────────

  pure def daemonFields(p: Policy, r: CreateReq): Set[Field] =
    mutate(p, r.entries).map(f => { key: canon(f.key), value: f.value })

  // The networks the daemon attaches: every EndpointsConfig entry, under any
  // spelling of the key.
  pure def daemonNetworks(r: CreateReq): Set[str] =
    r.networking.filter(f => canon(f.key) == "EndpointsConfig").map(f => f.value)

  pure def daemonPrivileged(p: Policy, r: CreateReq): bool =
    daemonFields(p, r).exists(f => f.key == "Privileged" and not(isZero(f.value)))

  // Every host path the daemon mounts. A volume mount stands for host
  // storage named by its source; tmpfs mounts nothing from the host.
  pure def daemonMounts(r: CreateReq): Set[HostMount] =
    r.binds.map(b => {
      source: b.source,
      writable: not(b.opts.contains("ro")),
      privatePropagation: b.opts.intersect(SHARED_PROPAGATION).size() == 0,
    }).union(r.mounts.filter(m => m.kind != "tmpfs").map(m => {
      source: m.source,
      writable: not(m.readOnly),
      privatePropagation: PRIVATE_PROPAGATION.contains(m.propagation),
    }))

  // ─── Universe ───────────────────────────────────────────────────────

  pure val BEACON: Policy = {
    serviceName: "beacon",
    containerNames: Set(),
    allowedImagePrefixes: Set("chainsafe/lodestar"),
    imageTagPattern: "",
    imageDigestAllowed: false,
    containerConfig: {
      networkMode: "host",
      restartPolicy: "unless-stopped",
      securityOptions: Set("no-new-privileges:true"),
      user: "2001:2001",
    },
    volumes: Set("/home/beacon", "/etc/jwt_dir"),
    readOnlyVolumes: Set("/etc/jwt_dir"),
    envFile: "",
    privileged: false,
    allowedCliFlags: Set(),
    flagRules: List(),
    deniedFlags: Set(),
  }

  // No volumes and no container_config.
  pure val TOOLS: Policy = {
    serviceName: "tools",
    containerNames: Set(),
    allowedImagePrefixes: Set("example/tools"),
    imageTagPattern: "",
    imageDigestAllowed: false,
    containerConfig: { networkMode: "", restartPolicy: "", securityOptions: Set(), user: "" },
    volumes: Set(),
    readOnlyVolumes: Set(),
    envFile: "",
    privileged: false,
    allowedCliFlags: Set(),
    flagRules: List(),
    deniedFlags: Set(),
  }

  pure val MODEL_POLICIES = Set(BEACON, TOOLS)

  pure val KEYS = Set(
    "Privileged", "privileged", "SecurityOpt", "securityopt", "NetworkMode", "networkmode",
    "CapAdd", "Devices", "GroupAdd", "FutureField", "MaskedPaths", "CapDrop",
    "MemorySwappiness", "PidMode", "IpcMode", "OomScoreAdj",
  )
  pure val VALUES = Set(
    "null", "zero", "[]", "true", "host", "private", "container:x", "SYS_ADMIN",
    "-1000", "500", "no-new-privileges", "seccomp=unconfined", "bridge",
  )
  pure val SOURCES = Set("/home/beacon", "/etc/jwt_dir", "/")

  pure def fieldsReq(fs: Set[Field]): CreateReq = { entries: fs, binds: Set(), mounts: Set(), networking: Set() }
  pure def bindReq(source: str, opts: Set[str]): CreateReq =
    { entries: Set(), binds: Set({ source: source, opts: opts }), mounts: Set(), networking: Set() }
  pure def mountReq(kind: str, source: str, readOnly: bool, propagation: str): CreateReq =
    { entries: Set(), binds: Set(), mounts: Set({ kind: kind, source: source, readOnly: readOnly, propagation: propagation }), networking: Set() }
  pure def netReq(fs: Set[Field]): CreateReq = { entries: Set(), binds: Set(), mounts: Set(), networking: fs }

  // Every single-field request, every single-bind request, every
  // single-mount request, and every NetworkingConfig with the CLI's
  // {"default"} plus one more entry, over the model's atoms.
  pure val REQS: Set[CreateReq] =
    tuples(KEYS, VALUES).map(((k, v)) => fieldsReq(Set({ key: k, value: v })))
      .union(tuples(SOURCES, Set("ro", "rw", "rshared", "Z").powerset()).map(((s, o)) => bindReq(s, o)))
      .union(tuples(Set("bind", "tmpfs", "volume"), SOURCES.union(Set("")), Set(true, false), Set("", "rprivate", "rshared"))
        .map(((k, s, ro, prop)) => mountReq(k, s, ro, prop)))
      .union(tuples(Set("EndpointsConfig", "endpointsconfig"), Set("default", "host", "evil-net"))
        .map(((k, n)) => netReq(Set({ key: "EndpointsConfig", value: "default" }, { key: k, value: n })))
      )

  // ─── Properties ─────────────────────────────────────────────────────

  // The rule: an allowed create has only fields spelled as the daemon names
  // them, each with a value its rule allows, and only binds and mounts the
  // policy allows. Close to a tautology on `create`, since createAllowed
  // tests exactly this.
  pure val createChecksEveryField: bool =
    MODEL_POLICIES.forall(p => REQS.forall(r =>
      createAllowed(p, r) implies and {
        r.entries.forall(f => not(isVariant(f.key))),
        r.networking.forall(f => not(isVariant(f.key))),
        mutate(p, r.entries).forall(f => valueAllowed(p, f.key, f.value)),
        r.binds.forall(b => bindOk(p, b)),
        r.mounts.forall(m => mountOk(p, m)),
      }
    ))

  // The security claim, on what the daemon reads: only allowlisted fields
  // with allowed values, Privileged false, and every value the policy forces
  // kept. It does not mention createAllowed's rules or LEGACY_CREATE, so
  // that create_pre88 fails it.
  pure val daemonSeesOnlyAllowlistedHostConfig: bool =
    MODEL_POLICIES.forall(p => REQS.forall(r =>
      createAllowed(p, r) implies daemonFields(p, r).forall(f => and {
        valueAllowed(p, f.key, f.value),
        f.key == "Privileged" implies isZero(f.value),
        (f.key == "NetworkMode" and p.containerConfig.networkMode != "")
          implies f.value == p.containerConfig.networkMode,
        (f.key == "SecurityOpt" and p.containerConfig.securityOptions.size() > 0)
          implies f.value == POLICY_SECURITY_OPT,
      })
    ))

  // The security claim on mounts: every host path the daemon mounts is a
  // policy volume, a read-only volume is never writable, and no mount
  // propagates. With no volumes, nothing is mounted.
  pure val daemonMountsOnlyWhitelisted: bool =
    MODEL_POLICIES.forall(p => REQS.forall(r =>
      createAllowed(p, r) implies daemonMounts(r).forall(m => and {
        p.volumes.contains(m.source),
        m.writable implies not(p.readOnlyVolumes.contains(m.source)),
        m.privatePropagation,
      })
    ))

  // The security claim on networks: when the policy forces network_mode,
  // the daemon attaches no network but the mode (or the CLI's "default",
  // which the mutator rewrites). #87 checked the exact key only.
  pure val daemonAttachesOnlyForcedNetwork: bool =
    MODEL_POLICIES.forall(p => REQS.forall(r =>
      (createAllowed(p, r) and p.containerConfig.networkMode != "")
        implies daemonNetworks(r).subseteq(Set("default", p.containerConfig.networkMode))
    ))

  pure def one(k: str, v: str): CreateReq = fieldsReq(Set({ key: k, value: v }))
  pure def withVariantEndpoints(n: str): CreateReq =
    netReq(Set({ key: "EndpointsConfig", value: "default" }, { key: "endpointsconfig", value: n }))
  pure val NO_HOST_CONFIG: CreateReq = fieldsReq(Set())
}

// After #88, all three.
module create {
  import create_model(LEGACY_CREATE = false).*

  // ─── Tests: one run per table row ───────────────────────────────────
  //
  // Rows shared with the language tables (same names), on `create` only:
  // most deny rows are allowed on create_pre88.

  run capAddDeniedTest = assert(not(createAllowed(BEACON, one("CapAdd", "SYS_ADMIN"))))
  run devicesDeniedTest = assert(not(createAllowed(BEACON, one("Devices", "/dev/sda"))))
  run groupAddDeniedTest = assert(not(createAllowed(BEACON, one("GroupAdd", "true"))))
  run unknownFieldDeniedTest = assert(not(createAllowed(BEACON, one("FutureField", "true"))))
  run maskedPathsEmptyDeniedTest = assert(not(createAllowed(BEACON, one("MaskedPaths", "[]"))))
  run pidModeHostDeniedTest = assert(not(createAllowed(BEACON, one("PidMode", "host"))))
  run pidModeContainerDeniedTest = assert(not(createAllowed(BEACON, one("PidMode", "container:x"))))
  run ipcModeHostDeniedTest = assert(not(createAllowed(BEACON, one("IpcMode", "host"))))
  run ipcModePrivateAllowedTest = assert(createAllowed(BEACON, one("IpcMode", "private")))
  run oomScoreAdjNegativeDeniedTest = assert(not(createAllowed(BEACON, one("OomScoreAdj", "-1000"))))
  run oomScoreAdjPositiveAllowedTest = assert(createAllowed(BEACON, one("OomScoreAdj", "500")))
  run capDropAllowedTest = assert(createAllowed(BEACON, one("CapDrop", "SYS_ADMIN")))
  run memorySwappinessAllowedTest = assert(createAllowed(BEACON, one("MemorySwappiness", "-1000")))
  run networkModeAllowedTest = assert(createAllowed(TOOLS, one("NetworkMode", "bridge")))
  run zeroValuesAllowedTest =
    assert(createAllowed(BEACON, fieldsReq(Set(
      { key: "CapAdd", value: "null" }, { key: "Devices", value: "[]" },
      { key: "FutureField", value: "zero" }, { key: "MaskedPaths", value: "null" },
      { key: "PidMode", value: "zero" }, { key: "Privileged", value: "zero" },
    ))))
  run securityOptSeccompUnconfinedDeniedTest =
    assert(not(createAllowed(TOOLS, one("SecurityOpt", "seccomp=unconfined"))))
  run securityOptNoNewPrivilegesAllowedTest =
    assert(createAllowed(TOOLS, one("SecurityOpt", "no-new-privileges")))
  run securityOptOverwrittenByPolicyTest =
    assert(and {
      createAllowed(BEACON, one("SecurityOpt", "seccomp=unconfined")),
      daemonFields(BEACON, one("SecurityOpt", "seccomp=unconfined"))
        == Set({ key: "SecurityOpt", value: POLICY_SECURITY_OPT }, { key: "Privileged", value: "zero" },
               { key: "NetworkMode", value: "host" }),
    })
  run caseVariantPrivilegedDeniedTest = assert(not(createAllowed(BEACON, one("privileged", "true"))))
  run caseVariantZeroSecurityOptDeniedTest = assert(not(createAllowed(BEACON, one("securityopt", "null"))))
  run networkingConfigVariantDeniedTest = assert(not(createAllowed(BEACON, withVariantEndpoints("evil-net"))))
  run networkingConfigVariantBareDeniedTest = assert(not(createAllowed(TOOLS, withVariantEndpoints("evil-net"))))
  run privilegedNeutralisedTest =
    assert(createAllowed(BEACON, one("Privileged", "true")) and not(daemonPrivileged(BEACON, one("Privileged", "true"))))
  run privilegedNeutralisedEmptyContainerConfigTest =
    assert(createAllowed(TOOLS, one("Privileged", "true")) and not(daemonPrivileged(TOOLS, one("Privileged", "true"))))
  run mountBindRootDeniedTest = assert(not(createAllowed(BEACON, mountReq("bind", "/", false, ""))))
  run mountBindAllowedTest = assert(createAllowed(BEACON, mountReq("bind", "/home/beacon", false, "")))
  run mountBindReadOnlyVolumeWritableDeniedTest =
    assert(not(createAllowed(BEACON, mountReq("bind", "/etc/jwt_dir", false, ""))))
  run mountBindReadOnlyVolumeReadOnlyAllowedTest =
    assert(createAllowed(BEACON, mountReq("bind", "/etc/jwt_dir", true, "")))
  run mountVolumeTypeDeniedTest = assert(not(createAllowed(BEACON, mountReq("volume", "/home/beacon", false, ""))))
  run mountTmpfsAllowedTest = assert(createAllowed(BEACON, mountReq("tmpfs", "", false, "")))
  run mountTmpfsWithSourceDeniedTest = assert(not(createAllowed(BEACON, mountReq("tmpfs", "/", false, ""))))
  run mountPropagationRsharedDeniedTest =
    assert(not(createAllowed(BEACON, mountReq("bind", "/home/beacon", false, "rshared"))))
  run mountPropagationRprivateAllowedTest =
    assert(createAllowed(BEACON, mountReq("bind", "/home/beacon", false, "rprivate")))
  run mountNoVolumesDeniedTest = assert(not(createAllowed(TOOLS, mountReq("bind", "/home/beacon", false, ""))))
  run bindAllowedTest = assert(createAllowed(BEACON, bindReq("/home/beacon", Set())))
  run bindReadOnlyVolumeRwDeniedTest = assert(not(createAllowed(BEACON, bindReq("/etc/jwt_dir", Set("rw")))))
  run bindReadOnlyVolumeNoModeDeniedTest = assert(not(createAllowed(BEACON, bindReq("/etc/jwt_dir", Set()))))
  run bindReadOnlyVolumeRoAllowedTest = assert(createAllowed(BEACON, bindReq("/etc/jwt_dir", Set("ro"))))
  run bindReadOnlyVolumeRoZAllowedTest = assert(createAllowed(BEACON, bindReq("/etc/jwt_dir", Set("ro", "Z"))))
  run bindReadOnlyVolumeRoRwDeniedTest = assert(not(createAllowed(BEACON, bindReq("/etc/jwt_dir", Set("ro", "rw")))))
  run bindRsharedDeniedTest = assert(not(createAllowed(BEACON, bindReq("/home/beacon", Set("rshared")))))
  run bindUnlistedDeniedTest = assert(not(createAllowed(BEACON, bindReq("/", Set("ro")))))
  run bindNoVolumesDeniedTest = assert(not(createAllowed(TOOLS, bindReq("/home/beacon", Set()))))

  run createSoundTest =
    assert(and {
      createChecksEveryField,
      daemonSeesOnlyAllowlistedHostConfig,
      daemonMountsOnlyWhitelisted,
      daemonAttachesOnlyForcedNetwork,
    })
}

// All three before #88: only the Binds host paths were checked, and not at
// all for a policy with no volumes; the mutator did not force Privileged
// without a container_config.
module create_pre88 {
  import create_model(LEGACY_CREATE = true).*

  run pre88UnsoundTest =
    assert(and {
      not(daemonSeesOnlyAllowlistedHostConfig),
      not(daemonMountsOnlyWhitelisted),
      // The reproductions in #88.
      createAllowed(BEACON, mountReq("bind", "/", false, "")),
      createAllowed(BEACON, bindReq("/etc/jwt_dir", Set("rw"))),
      createAllowed(BEACON, bindReq("/etc/jwt_dir", Set())),
      createAllowed(BEACON, one("CapAdd", "SYS_ADMIN")),
      createAllowed(BEACON, one("PidMode", "host")),
      // A policy with no volumes let any bind through.
      createAllowed(TOOLS, bindReq("/", Set())),
      // Without a container_config, Privileged reached the daemon.
      createAllowed(TOOLS, one("Privileged", "true")) and daemonPrivileged(TOOLS, one("Privileged", "true")),
      // A zero-valued case variant cleared a forced field.
      createAllowed(BEACON, one("securityopt", "null")),
      // NetworkEndpointsGate (#87) read only the exact key, so a variant
      // attached another network.
      not(daemonAttachesOnlyForcedNetwork),
      createAllowed(BEACON, withVariantEndpoints("evil-net")),
    })
}

// ─── Module: docker_socket_policy ───────────────────────────────────────

module docker_socket_policy {
  import policy.*
  // The create check after #88: createAllowed, daemonFields, daemonMounts.
  import create_model(LEGACY_CREATE = false).*

  // ─── Image Reference Types ──────────────────────────────────────────
  //
  // Models the split-then-validate pipeline for Docker image references.
  // At runtime the proxy splits "image:tag" into name + tag/digest, then
  // validates each part against the policy. Quint can't do string splitting
  // or regex, so we model the EFFECT: only ValidImage reaches the container.

  type ImageRef = {
    kind: str,
    imageName: str,
    tag: str,
    digest: str
  }

  // ─── Container State ────────────────────────────────────────────────

  type ContainerState = Running | Paused | Exited

  // ─── Container Type ──────────────────────────────────────────────────

  type Container = {
    name: str,
    serviceName: str,
    imageRef: ImageRef,
    state: ContainerState,
    privileged: bool,
    volumes: Set[str],
    envVars: Set[str],
    flags: Set[str],
    networkMode: str,
    // The HostConfig fields and host mounts the daemon read (#88).
    hostConfig: Set[Field],
    hostMounts: Set[HostMount]
  }

  pure def setState(c: Container, s: ContainerState): Container = {
    { ...c, state: s }
  }

  // ─── Policy Constants ─────────────────────────────────────────────────

  val policies: Set[Policy] = Set(
    {
      serviceName: "beacon",
      // The #88 create scenarios below are named for beacon too, so they
      // reach the HostConfig checks rather than stopping at selection (#85).
      containerNames: Set("beacon-0", "beacon-1", "beacon-2", "beacon-privileged", "beacon-jwt-ro",
                          "mount-root", "jwt-rw", "cap-add", "pid-host", "lower-privileged"),
      allowedImagePrefixes: Set(
        "chainsafe/lodestar",
        "ethpandaops/lodestar"
      ),
      imageTagPattern: "",
      imageDigestAllowed: false,
      containerConfig: {
        networkMode: "host",
        restartPolicy: "unless-stopped",
        securityOptions: Set("no-new-privileges:true"),
        user: "2001:2001"
      },
      volumes: Set("/home/beacon", "/etc/jwt_dir"),
      readOnlyVolumes: Set("/etc/jwt_dir"),
      envFile: "/etc/docker/env/beacon.env",
      privileged: false,
      allowedCliFlags: Set("--rcConfig", "--logLevel", "--dataDir", "--network"),
      flagRules: List(
        { flag: "--rcConfig", valuePattern: "^/data/.*\\.yml$" },
        { flag: "--logLevel", valuePattern: "^(debug|info|warn|error)$" }
      ),
      deniedFlags: Set("--privileged", "--volume", "--mount",
                       "--cap-add", "--cap-drop", "--device",
                       "--security-opt", "--user", "--network")
    },
    {
      serviceName: "validator",
      containerNames: Set("validator-0", "validator-1", "validator-2"),
      allowedImagePrefixes: Set(
        "chainsafe/lodestar"
      ),
      imageTagPattern: "",
      imageDigestAllowed: false,
      containerConfig: {
        networkMode: "host",
        restartPolicy: "unless-stopped",
        securityOptions: Set("no-new-privileges:true"),
        user: "2002:2002"
      },
      volumes: Set("/home/validator"),
      readOnlyVolumes: Set(),
      envFile: "/etc/docker/env/validator.env",
      privileged: false,
      allowedCliFlags: Set("--rcConfig", "--logLevel", "--dataDir", "--network"),
      flagRules: List(
        { flag: "--rcConfig", valuePattern: "^/data/.*\\.yml$" }
      ),
      deniedFlags: Set("--privileged", "--volume", "--mount",
                       "--cap-add", "--cap-drop", "--device",
                       "--security-opt", "--user", "--network")
    },
    // No volumes and no container_config (#88).
    TOOLS
  )

  // ─── State Variables ──────────────────────────────────────────────────

  var containers: Set[Container]
  var proxyRunning: bool

  // ─── Endpoint Routing Table (for completeness check) ──────────────────

  type Endpoint = { method: str, path: str, kind: str }

  val endpointsTable: Set[Endpoint] = Set(
    { method: "GET",  path: "/_ping",                 kind: "allowRead" },
    { method: "GET",  path: "/version",               kind: "allowRead" },
    { method: "GET",  path: "/info",                  kind: "allowRead" },
    { method: "GET",  path: "/events",                kind: "allowRead" },
    { method: "GET",  path: "/containers/json",       kind: "allowRead" },
    { method: "GET",  path: "/containers/:name/json", kind: "allowRead" },
    { method: "GET",  path: "/containers/:name/logs", kind: "allowRead" },
    { method: "POST", path: "/containers/create",     kind: "create" },
    { method: "POST", path: "/containers/:name/start",kind: "allowAction" },
    { method: "POST", path: "/containers/:name/stop", kind: "allowAction" },
    { method: "POST", path: "/containers/:name/restart",kind: "allowAction" },
    { method: "POST", path: "/containers/:name/kill", kind: "allowAction" },
    { method: "POST", path: "/containers/:name/wait", kind: "allowAction" },
    { method: "POST", path: "/containers/:name/pause",kind: "allowAction" },
    { method: "POST", path: "/containers/:name/unpause",kind: "allowAction" },
    { method: "DELETE", path: "/containers/:name",    kind: "allowAction" },
    { method: "POST", path: "/images/create",         kind: "pullImage" },
    { method: "POST", path: "/auth",                  kind: "deny" },
    { method: "POST", path: "/build",                 kind: "deny" },
    { method: "POST", path: "/commit",                kind: "deny" },
    { method: "*",    path: "/containers/:name/exec", kind: "deny" },
    { method: "*",    path: "/exec/*",                kind: "deny" },
    { method: "POST", path: "/containers/:name/rename",kind: "deny" },
    { method: "POST", path: "/containers/:name/update",kind: "deny" },
    { method: "*",    path: "/containers/:name/attach",kind: "deny" },
    { method: "*",    path: "/containers/:name/attach/ws",kind: "deny" },
    { method: "POST", path: "/containers/:name/prune", kind: "deny" },
    { method: "POST", path: "/networks/create",       kind: "deny" },
    { method: "POST", path: "/volumes/create",        kind: "deny" }
  )

  // ─── Initial State ──────────────────────────────────────────────────

  action init: bool = all {
    containers' = Set(),
    proxyRunning' = true
  }

  // ─── Helpers ──────────────────────────────────────────────────────────

  def containerExists(name: str): bool = {
    containers.exists(c => c.name == name)
  }

  // ─── Container Lifecycle Actions ─────────────────────────────────────

  action createContainer(
    name: str, imageRef: ImageRef, flags: Set[str],
    volumes: Set[str], envVars: Set[str],
    hc: CreateReq
  ): bool = {
    if (imageRef.kind == "valid") {
      // The one policy that matches the image and accepts the name (#85):
      // zero or several candidates deny the create.
      val candidates = selectPolicies(policies, imageRef.imageName, name)
      nondet matched = oneOf(candidates)
      all {
        candidates.size() == 1,
        flags.forall(f => flagAllowed(f, matched)),
        volumes.forall(v => volumeAllowed(v, matched)),
        envAllowed(envVars, matched),
        not(matched.privileged),
        createAllowed(matched, hc),

        containers' = containers.union(
          Set({
            name: name,
            serviceName: matched.serviceName,
            imageRef: imageRef,
            state: Running,
            privileged: daemonPrivileged(matched, hc),
            volumes: volumes.intersect(matched.volumes),
            envVars: if (matched.envFile != "") Set() else envVars,
            flags: flags.intersect(matched.allowedCliFlags),
            networkMode: matched.containerConfig.networkMode,
            hostConfig: daemonFields(matched, hc),
            hostMounts: daemonMounts(hc)
          })
        ),
        proxyRunning' = proxyRunning
      }
    } else all {
      false,
      containers' = containers,
      proxyRunning' = proxyRunning
    }
  }

  action startContainer(name: str): bool = all {
    containerExists(name),
    containers' = containers.map(c =>
      if (c.name == name) setState(c, Running) else c
    ),
    proxyRunning' = proxyRunning
  }

  action stopContainer(name: str): bool = all {
    containerExists(name),
    containers' = containers.map(c =>
      if (c.name == name) setState(c, Exited) else c
    ),
    proxyRunning' = proxyRunning
  }

  action restartContainer(name: str): bool = all {
    containerExists(name),
    containers' = containers.map(c =>
      if (c.name == name) setState(c, Running) else c
    ),
    proxyRunning' = proxyRunning
  }

  action killContainer(name: str): bool = all {
    containerExists(name),
    containers' = containers.map(c =>
      if (c.name == name) setState(c, Exited) else c
    ),
    proxyRunning' = proxyRunning
  }

  action waitContainer(name: str): bool = all {
    containerExists(name),
    containers' = containers,
    proxyRunning' = proxyRunning
  }

  action pauseContainer(name: str): bool = all {
    containerExists(name),
    containers' = containers.map(c =>
      if (c.name == name) setState(c, Paused) else c
    ),
    proxyRunning' = proxyRunning
  }

  action unpauseContainer(name: str): bool = all {
    containerExists(name),
    containers' = containers.map(c =>
      if (c.name == name) setState(c, Running) else c
    ),
    proxyRunning' = proxyRunning
  }

  action removeContainer(name: str): bool = all {
    containerExists(name),
    containers' = containers.exclude(containers.filter(c => c.name == name)),
    proxyRunning' = proxyRunning
  }

  action pullImage(image: str): bool = {
    nondet matched = oneOf(policies.filter(p => imageNameAllowed(image, p)))
    all {
      containers' = containers,
      proxyRunning' = proxyRunning
    }
  }

  action readOnlyRequest(method: str, path: str): bool = all {
    containers' = containers,
    proxyRunning' = proxyRunning
  }

  // ─── Step Action (for model checker) ──────────────────────────────────
  //
  // Ordering note: At runtime, mutators (ContainerConfigMutator) run BEFORE
  // gates (MountSourceGate, RegistryGate). The mutated body is what gates
  // validate. In the spec, guards and state updates are combined in all {}
  // blocks — this models the end-to-end invariant, not the pipeline ordering.
  //
  // Non-deterministically picks one transition per step. Entry guards
  // (imageNameAllowed, flagAllowed, volumeAllowed, envAllowed, etc.)
  // naturally filter out invalid transitions. execContainer is modeled as
  // an endpointsTable deny entry, not a separate action.
  //
  // Create actions are weighted higher (3x) to quickly populate the container
  // set so lifecycle operations become productive.

  action step: bool = any {
    // --- Create actions (weighted 3x to seed containers early) ---
    createContainer("beacon-0",
      { kind: "valid", imageName: "chainsafe/lodestar", tag: "beacon", digest: "" },
      Set("--rcConfig", "--dataDir"),
      Set("/home/beacon"), Set(), NO_HOST_CONFIG),
    createContainer("beacon-1",
      { kind: "valid", imageName: "chainsafe/lodestar", tag: "beacon", digest: "" },
      Set("--rcConfig", "--logLevel"),
      Set("/home/beacon"), Set(), NO_HOST_CONFIG),
    createContainer("beacon-2",
      { kind: "valid", imageName: "chainsafe/lodestar", tag: "beacon", digest: "" },
      Set("--network", "--rcConfig"),
      Set("/home/beacon"), Set(), NO_HOST_CONFIG),
    createContainer("validator-0",
      { kind: "valid", imageName: "chainsafe/lodestar", tag: "validator", digest: "" },
      Set("--dataDir", "/data/validator"),
      Set("/home/validator"), Set(), NO_HOST_CONFIG),
    createContainer("validator-1",
      { kind: "valid", imageName: "chainsafe/lodestar", tag: "validator", digest: "" },
      Set("--dataDir", "/data/validator"),
      Set("/home/validator"), Set(), NO_HOST_CONFIG),
    createContainer("validator-2",
      { kind: "valid", imageName: "chainsafe/lodestar", tag: "validator", digest: "" },
      Set("--dataDir", "/data/validator"),
      Set("/home/validator"), Set(), NO_HOST_CONFIG),
    // --- Rejected create attempts (always fail, test coverage) ---
    createContainer("evil",
      { kind: "invalidTag", imageName: "attacker/malware", tag: "latest", digest: "" },
      Set("--privileged"), Set(), Set(), one("Privileged", "true")),
    createContainer("bad-digest",
      { kind: "invalidDigest", imageName: "", tag: "", digest: "sha256:badbadbad" },
      Set(), Set(), Set(), NO_HOST_CONFIG),
    // --- HostConfig (#88): allowed, with Privileged neutralised ---
    createContainer("beacon-privileged",
      { kind: "valid", imageName: "chainsafe/lodestar", tag: "beacon", digest: "" },
      Set("--rcConfig"), Set("/home/beacon"), Set(), one("Privileged", "true")),
    createContainer("tools-privileged",
      { kind: "valid", imageName: "example/tools", tag: "latest", digest: "" },
      Set(), Set(), Set(), one("Privileged", "true")),
    createContainer("beacon-jwt-ro",
      { kind: "valid", imageName: "chainsafe/lodestar", tag: "beacon", digest: "" },
      Set("--rcConfig"), Set("/home/beacon"), Set(), bindReq("/etc/jwt_dir", Set("ro"))),
    // --- HostConfig (#88): rejected ---
    createContainer("mount-root",
      { kind: "valid", imageName: "chainsafe/lodestar", tag: "beacon", digest: "" },
      Set("--rcConfig"), Set("/home/beacon"), Set(), mountReq("bind", "/", false, "")),
    createContainer("jwt-rw",
      { kind: "valid", imageName: "chainsafe/lodestar", tag: "beacon", digest: "" },
      Set("--rcConfig"), Set("/home/beacon"), Set(), bindReq("/etc/jwt_dir", Set("rw"))),
    createContainer("cap-add",
      { kind: "valid", imageName: "chainsafe/lodestar", tag: "beacon", digest: "" },
      Set("--rcConfig"), Set("/home/beacon"), Set(), one("CapAdd", "SYS_ADMIN")),
    createContainer("pid-host",
      { kind: "valid", imageName: "chainsafe/lodestar", tag: "beacon", digest: "" },
      Set("--rcConfig"), Set("/home/beacon"), Set(), one("PidMode", "host")),
    createContainer("lower-privileged",
      { kind: "valid", imageName: "chainsafe/lodestar", tag: "beacon", digest: "" },
      Set("--rcConfig"), Set("/home/beacon"), Set(), one("privileged", "true")),
    createContainer("tools-bind",
      { kind: "valid", imageName: "example/tools", tag: "latest", digest: "" },
      Set(), Set(), Set(), bindReq("/home/beacon", Set())),
    // --- Lifecycle actions (conditional on container existence) ---
    startContainer("beacon-0"),
    stopContainer("beacon-0"),
    restartContainer("beacon-0"),
    killContainer("beacon-0"),
    waitContainer("beacon-0"),
    pauseContainer("beacon-0"),
    unpauseContainer("beacon-0"),
    removeContainer("beacon-0"),
    // --- Read-only & image pull (always productive) ---
    pullImage("chainsafe/lodestar"),
    pullImage("chainsafe/lodestar"),
    readOnlyRequest("GET", "/_ping"),
    readOnlyRequest("GET", "/containers/json")
  }

  // ─── Invariants ───────────────────────────────────────────────────────
  //
  // P0 — must never fail under any action sequence.
  // P1 — should never fail under normal operation.

  val noPrivilegedAccess = containers.forall(c => not(c.privileged))

  // Every HostConfig field the daemon read is one the policy allows, with an
  // allowed value (#88).
  val hostConfigInAllowlist = containers.forall(c =>
    policies.exists(p =>
      p.serviceName == c.serviceName
        and c.hostConfig.forall(f => valueAllowed(p, f.key, f.value))
    )
  )

  // Every host path the daemon mounted is a policy volume, never writable
  // when the volume is read-only, and never propagating (#88).
  val hostMountsInWhitelist = containers.forall(c =>
    policies.exists(p =>
      p.serviceName == c.serviceName
        and c.hostMounts.forall(m => and {
          p.volumes.contains(m.source),
          m.writable implies not(p.readOnlyVolumes.contains(m.source)),
          m.privatePropagation,
        })
    )
  )

  // Every container's network mode is exactly what its matched policy
  // configures — the caller cannot override it via the create request.
  // (Not a hardcoded "host" check: the security property is that the
  // policy YAML controls networkMode, not the untrusted request body.)
  val alwaysHostNetwork = containers.forall(c =>
    policies.exists(p =>
      p.serviceName == c.serviceName
        and c.networkMode == p.containerConfig.networkMode
    )
  )

  val imagesAlwaysAllowed = containers.forall(c =>
    if (c.imageRef.kind == "valid")
      policies.exists(p => imageNameAllowed(c.imageRef.imageName, p))
    else
      false
  )

  val validImagesOnly = containers.forall(c =>
    c.imageRef.kind == "valid"
  )

  val envOnlyFromFile = containers.forall(c =>
    policies.exists(p =>
      p.serviceName == c.serviceName
        and (p.envFile == "" or c.envVars.size() == 0)
    )
  )

  val proxyLives = proxyRunning

  // Every container was created under the one policy that matches its image
  // and accepts its name (#85): selection is unique, never a choice.
  val policySelectionUnique = containers.forall(c =>
    selectPolicies(policies, c.imageRef.imageName, c.name).map(p => p.serviceName) == Set(c.serviceName)
  )

  val volumesInWhitelist = containers.forall(c =>
    policies.exists(p =>
      p.serviceName == c.serviceName
        and c.volumes.subseteq(p.volumes)
    )
  )

  val flagsInAllowlist = containers.forall(c =>
    policies.exists(p =>
      p.serviceName == c.serviceName
        and c.flags.forall(f => flagAllowed(f, p))
    )
  )

  val routingTableComplete = all {
    endpointsTable.contains({ method: "GET",  path: "/_ping",                 kind: "allowRead" }),
    endpointsTable.contains({ method: "GET",  path: "/version",               kind: "allowRead" }),
    endpointsTable.contains({ method: "GET",  path: "/info",                  kind: "allowRead" }),
    endpointsTable.contains({ method: "GET",  path: "/events",                kind: "allowRead" }),
    endpointsTable.contains({ method: "GET",  path: "/containers/json",       kind: "allowRead" }),
    endpointsTable.contains({ method: "GET",  path: "/containers/:name/json", kind: "allowRead" }),
    endpointsTable.contains({ method: "GET",  path: "/containers/:name/logs", kind: "allowRead" }),

    endpointsTable.contains({ method: "POST", path: "/containers/create",     kind: "create" }),
    endpointsTable.contains({ method: "POST", path: "/containers/:name/start",kind: "allowAction" }),
    endpointsTable.contains({ method: "POST", path: "/containers/:name/stop", kind: "allowAction" }),
    endpointsTable.contains({ method: "POST", path: "/containers/:name/restart",kind: "allowAction" }),
    endpointsTable.contains({ method: "POST", path: "/containers/:name/kill", kind: "allowAction" }),
    endpointsTable.contains({ method: "POST", path: "/containers/:name/wait", kind: "allowAction" }),
    endpointsTable.contains({ method: "POST", path: "/containers/:name/pause",kind: "allowAction" }),
    endpointsTable.contains({ method: "POST", path: "/containers/:name/unpause",kind: "allowAction" }),
    endpointsTable.contains({ method: "DELETE", path: "/containers/:name",    kind: "allowAction" }),

    endpointsTable.contains({ method: "POST", path: "/images/create",         kind: "pullImage" }),

    endpointsTable.contains({ method: "POST", path: "/auth",                  kind: "deny" }),
    endpointsTable.contains({ method: "POST", path: "/build",                 kind: "deny" }),
    endpointsTable.contains({ method: "POST", path: "/commit",                kind: "deny" }),
    endpointsTable.contains({ method: "*",    path: "/containers/:name/exec", kind: "deny" }),
    endpointsTable.contains({ method: "*",    path: "/exec/*",                kind: "deny" }),
    endpointsTable.contains({ method: "POST", path: "/containers/:name/rename",kind: "deny" }),
    endpointsTable.contains({ method: "POST", path: "/containers/:name/update",kind: "deny" }),
    endpointsTable.contains({ method: "*",    path: "/containers/:name/attach",kind: "deny" }),
    endpointsTable.contains({ method: "*",    path: "/containers/:name/attach/ws",kind: "deny" }),
    endpointsTable.contains({ method: "POST", path: "/containers/:name/prune", kind: "deny" }),
    endpointsTable.contains({ method: "POST", path: "/networks/create",       kind: "deny" }),
    endpointsTable.contains({ method: "POST", path: "/volumes/create",        kind: "deny" })
  }

  val allP0Invariants = all {
    noPrivilegedAccess,
    alwaysHostNetwork,
    imagesAlwaysAllowed,
    validImagesOnly,
    envOnlyFromFile,
    proxyLives,
    hostConfigInAllowlist,
    hostMountsInWhitelist,
    policySelectionUnique
  }

  val allInvariants = allP0Invariants.and(all {
    volumesInWhitelist,
    flagsInAllowlist,
    routingTableComplete
  })

  // Attack scenarios are documented in spec/README.md.

  // ─── Policy selection (#85) ──────────────────────────────────────────
  //
  // Beacon and validator run one image. Without container_names (the
  // policies before #85) both match every lodestar create, and the proxy
  // applied whichever it found first.
  pure val PRE85_POLICIES: Set[Policy] = policies.map(p => { ...p, containerNames: Set() })

  run pre85AmbiguousTest =
    assert(and {
      selectPolicies(PRE85_POLICIES, "chainsafe/lodestar", "validator-0").size() == 2,
      selectPolicies(policies, "chainsafe/lodestar", "validator-0").map(p => p.serviceName) == Set("validator"),
      selectPolicies(policies, "chainsafe/lodestar", "beacon-0").map(p => p.serviceName) == Set("beacon"),
    })

  // A create named for a policy gets that policy.
  run createSelectsByNameTest =
    init
      .then(createContainer("validator-0",
        { kind: "valid", imageName: "chainsafe/lodestar", tag: "validator", digest: "" },
        Set("--dataDir"), Set("/home/validator"), Set(), NO_HOST_CONFIG))
      .then(all {
        assert(containers.map(c => c.serviceName) == Set("validator")),
        assert(policySelectionUnique),
        containers' = containers,
        proxyRunning' = proxyRunning,
      })

  // A name no policy for the image accepts is denied, as is a create without
  // a name ("") when every matching policy sets container_names.
  run createUnknownNameDeniedTest =
    init
      .then(createContainer("monitoring",
        { kind: "valid", imageName: "chainsafe/lodestar", tag: "beacon", digest: "" },
        Set(), Set(), Set(), NO_HOST_CONFIG))
      .fail()

  run createNamelessDeniedTest =
    init
      .then(createContainer("",
        { kind: "valid", imageName: "chainsafe/lodestar", tag: "beacon", digest: "" },
        Set(), Set(), Set(), NO_HOST_CONFIG))
      .fail()

  // P0 invariants must never fail under any sequence of actions.
  // P1 invariants should never fail under normal operation.
  // The quint verify command checks all invariants across all
  // possible action sequences up to max-steps.
}
