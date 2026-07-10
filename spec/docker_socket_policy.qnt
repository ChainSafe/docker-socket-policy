// ─── Module: policy ──────────────────────────────────────────────────────

module policy {
  type FlagRule = { flag: str, valuePattern: str }

  type ContainerConfig = {
    networkMode: str,
    restartPolicy: str,
    securityOptions: Set[str],
    user: str
  }

  type Policy = {
    serviceName: str,
    allowedImagePrefixes: Set[str],
    imageTagPattern: str,
    imageDigestAllowed: bool,
    containerConfig: ContainerConfig,
    volumes: Set[str],
    envFile: str,
    privileged: bool,
    allowedCliFlags: Set[str],
    flagRules: List[FlagRule],
    deniedFlags: Set[str]
  }

  pure def imageNameAllowed(name: str, policy: Policy): bool = {
    policy.allowedImagePrefixes.contains(name)
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

// ─── Module: docker_socket_policy ───────────────────────────────────────

module docker_socket_policy {
  import policy.*

  // ─── Image Reference Types ──────────────────────────────────────────
  //
  // Models the split-then-validate pipeline for Docker image references.
  // At runtime the proxy splits "image:tag" into name + tag/digest, then
  // validates each part against the policy. Quint can't do string splitting
  // or regex, so we model the EFFECT: only ValidImage reaches the container.

  type ImageRef =
    | ValidImage(name: str, tag: str)
    | InvalidTag(name: str, tag: str)
    | InvalidDigest(digest: str)

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
    networkMode: str
  }

  pure def setState(c: Container, s: ContainerState): Container = {
    {
      name: c.name,
      serviceName: c.serviceName,
      imageRef: c.imageRef,
      state: s,
      privileged: c.privileged,
      volumes: c.volumes,
      envVars: c.envVars,
      flags: c.flags,
      networkMode: c.networkMode
    }
  }

  // ─── Policy Constants ─────────────────────────────────────────────────

  val policies: Set[Policy] = Set(
    {
      serviceName: "beacon",
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
      envFile: "/etc/docker/env/validator.env",
      privileged: false,
      allowedCliFlags: Set("--rcConfig", "--logLevel", "--dataDir", "--network"),
      flagRules: List(
        { flag: "--rcConfig", valuePattern: "^/data/.*\\.yml$" }
      ),
      deniedFlags: Set("--privileged", "--volume", "--mount",
                       "--cap-add", "--cap-drop", "--device",
                       "--security-opt", "--user", "--network")
    }
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
    { method: "POST", path: "/containers/:name/unpause",kind: "allowAction" },
    { method: "DELETE", path: "/containers/:name",    kind: "allowAction" },
    { method: "POST", path: "/images/create",         kind: "pullImage" },
    { method: "POST", path: "/auth",                  kind: "deny" },
    { method: "POST", path: "/build",                 kind: "deny" },
    { method: "POST", path: "/commit",                kind: "deny" },
    { method: "POST", path: "/containers/:name/exec", kind: "deny" },
    { method: "POST", path: "/containers/:name/rename",kind: "deny" },
    { method: "POST", path: "/containers/:name/update",kind: "deny" },
    { method: "POST", path: "/containers/:name/pause",kind: "deny" },
    { method: "POST", path: "/containers/:name/attach",kind: "deny" },
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
    name: str, image: str, flags: Set[str],
    volumes: Set[str], envVars: Set[str],
    privileged: bool
  ): bool = {
    nondet matched = oneOf(policies.filter(p => imageNameAllowed(image, p)))
    all {
      flags.forall(f => flagAllowed(f, matched)),
      volumes.forall(v => volumeAllowed(v, matched)),
      envAllowed(envVars, matched),
      not(privileged),

      containers' = containers.union(
        Set({
          name: name,
          serviceName: matched.serviceName,
          image: image,
          privileged: false,
          volumes: volumes.intersect(matched.volumes),
          envVars: if (matched.envFile != "") Set() else envVars,
          flags: flags.intersect(matched.allowedCliFlags),
          networkMode: matched.containerConfig.networkMode,
          running: true
        })
      ),
      proxyRunning' = proxyRunning
    }
  }

  action startContainer(name: str): bool = all {
    containerExists(name),
    containers' = containers.map(c =>
      if (c.name == name) setRunning(c, true) else c
    ),
    proxyRunning' = proxyRunning
  }

  action stopContainer(name: str): bool = all {
    containerExists(name),
    containers' = containers.map(c =>
      if (c.name == name) setRunning(c, false) else c
    ),
    proxyRunning' = proxyRunning
  }

  action removeContainer(name: str): bool = all {
    containerExists(name),
    containers' = containers.exclude(containers.filter(c => c.name == name)),
    proxyRunning' = proxyRunning
  }

  action execContainer(name: str): bool = all {
    false,
    containers' = containers,
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
  // Non-deterministically picks one transition per step. Entry guards
  // (imageAllowed, flagAllowed, volumeAllowed, envAllowed, etc.) naturally
  // filter out invalid transitions. Actions that always fail (execContainer)
  // are excluded — they contribute no state-space coverage.
  //
  // Create actions are weighted higher (3x) to quickly populate the container
  // set so lifecycle operations (start/stop/remove) become productive.

  action step: bool = any {
    // --- Create actions (weighted 3x to seed containers early) ---
    createContainer("beacon-0", "chainsafe/lodestar:beacon",
      Set("--rcConfig", "--dataDir"),
      Set("/home/beacon"), Set(), false),
    createContainer("beacon-1", "chainsafe/lodestar:beacon",
      Set("--rcConfig", "--logLevel"),
      Set("/home/beacon"), Set(), false),
    createContainer("beacon-2", "chainsafe/lodestar:beacon",
      Set("--network", "--rcConfig"),
      Set("/home/beacon"), Set(), false),
    createContainer("validator-0", "chainsafe/lodestar:validator",
      Set("--dataDir", "/data/validator"),
      Set("/home/validator"), Set(), false),
    createContainer("validator-1", "chainsafe/lodestar:validator",
      Set("--dataDir", "/data/validator"),
      Set("/home/validator"), Set(), false),
    createContainer("validator-2", "chainsafe/lodestar:validator",
      Set("--dataDir", "/data/validator"),
      Set("/home/validator"), Set(), false),
    createContainer("evil", "attacker/malware:latest",
      Set("--privileged"), Set(), Set(), true),
    // --- Lifecycle actions (conditional on container existence) ---
    startContainer("beacon-0"),
    stopContainer("beacon-0"),
    removeContainer("beacon-0"),
    // --- Read-only & image pull (always productive) ---
    pullImage("chainsafe/lodestar:beacon"),
    pullImage("chainsafe/lodestar:validator"),
    readOnlyRequest("GET", "/_ping"),
    readOnlyRequest("GET", "/containers/json")
  }

  // ─── Invariants ───────────────────────────────────────────────────────

  val noPrivileged = containers.forall(c => not(c.privileged))

  val networkModeEnforced = containers.forall(c => c.networkMode == "host")

  val allImagesAllowlisted = containers.forall(c =>
    policies.exists(p => imageNameAllowed(c.image, p))
  )

  val envFromFileOnly = containers.forall(c =>
    policies.exists(p =>
      p.serviceName == c.serviceName
        and (p.envFile == "" or c.envVars.size() == 0)
    )
  )

  val proxyAlwaysRunning = proxyRunning

  val volumesWhitelisted = containers.forall(c =>
    policies.exists(p =>
      p.serviceName == c.serviceName
        and c.volumes.subseteq(p.volumes)
    )
  )

  val flagsAllowlisted = containers.forall(c =>
    policies.exists(p =>
      p.serviceName == c.serviceName
        and c.flags.forall(f => flagAllowed(f, p))
    )
  )

  val allEndpointsMatched = all {
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
    endpointsTable.contains({ method: "DELETE", path: "/containers/:name",    kind: "allowAction" }),

    endpointsTable.contains({ method: "POST", path: "/images/create",         kind: "pullImage" }),

    endpointsTable.contains({ method: "POST", path: "/auth",                  kind: "deny" }),
    endpointsTable.contains({ method: "POST", path: "/build",                 kind: "deny" }),
    endpointsTable.contains({ method: "POST", path: "/commit",                kind: "deny" }),
    endpointsTable.contains({ method: "POST", path: "/containers/:name/exec", kind: "deny" }),
    endpointsTable.contains({ method: "POST", path: "/containers/:name/rename",kind: "deny" }),
    endpointsTable.contains({ method: "POST", path: "/containers/:name/update",kind: "deny" }),
    endpointsTable.contains({ method: "POST", path: "/containers/:name/kill", kind: "deny" }),
    endpointsTable.contains({ method: "POST", path: "/containers/:name/attach",kind: "deny" }),
    endpointsTable.contains({ method: "POST", path: "/containers/:name/prune", kind: "deny" }),
    endpointsTable.contains({ method: "POST", path: "/networks/create",       kind: "deny" }),
    endpointsTable.contains({ method: "POST", path: "/volumes/create",        kind: "deny" })
  }

  val allP0Invariants = all {
    noPrivileged,
    networkModeEnforced,
    allImagesAllowlisted,
    envFromFileOnly,
    proxyAlwaysRunning
  }

  val allInvariants = allP0Invariants.and(all {
    volumesWhitelisted,
    flagsAllowlisted,
    allEndpointsMatched
  })

  // Attack scenarios are documented in spec/README.md.

  // P0 invariants must never fail under any sequence of actions.
  // P1 invariants should never fail under normal operation.
  // The quint verify command checks all invariants across all
  // possible action sequences up to max-steps.
}
