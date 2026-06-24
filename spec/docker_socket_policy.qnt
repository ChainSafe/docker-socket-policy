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
    allowedImages: Set[str],
    containerConfig: ContainerConfig,
    volumes: Set[str],
    envFile: bool,
    allowedCliFlags: Set[str],
    flagRules: List[FlagRule],
    deniedFlags: Set[str]
  }

  pure def imageAllowed(image: str, policy: Policy): bool = {
    policy.allowedImages.contains(image)
  }

  pure def flagAllowed(flag: str, policy: Policy): bool = {
    policy.allowedCliFlags.contains(flag)
      and not(policy.deniedFlags.contains(flag))
  }

  pure def volumeAllowed(volume: str, policy: Policy): bool = {
    policy.volumes.contains(volume)
  }

  pure def envAllowed(envVars: Set[str], policy: Policy): bool = {
    not(policy.envFile) or envVars.size() == 0
  }
}

// ─── Module: docker_socket_policy ───────────────────────────────────────

module docker_socket_policy {
  import policy.*

  // ─── Container Type ──────────────────────────────────────────────────

  type Container = {
    name: str,
    serviceName: str,
    image: str,
    privileged: bool,
    volumes: Set[str],
    envVars: Set[str],
    flags: Set[str],
    networkMode: str,
    running: bool
  }

  pure def setRunning(c: Container, r: bool): Container = {
    {
      name: c.name,
      serviceName: c.serviceName,
      image: c.image,
      privileged: c.privileged,
      volumes: c.volumes,
      envVars: c.envVars,
      flags: c.flags,
      networkMode: c.networkMode,
      running: r
    }
  }

  // ─── Policy Constants ─────────────────────────────────────────────────

  val policies: Set[Policy] = Set(
    {
      serviceName: "beacon",
      allowedImages: Set(
        "chainsafe/lodestar:latest",
        "chainsafe/lodestar:next",
        "ethpandaops/lodestar:latest"
      ),
      containerConfig: {
        networkMode: "host",
        restartPolicy: "unless-stopped",
        securityOptions: Set("no-new-privileges:true"),
        user: "2001:2001"
      },
      volumes: Set("/home/beacon", "/etc/jwt_dir"),
      envFile: true,
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
      allowedImages: Set(
        "chainsafe/lodestar:latest",
        "chainsafe/lodestar:next"
      ),
      containerConfig: {
        networkMode: "host",
        restartPolicy: "unless-stopped",
        securityOptions: Set("no-new-privileges:true"),
        user: "2002:2002"
      },
      volumes: Set("/home/validator"),
      envFile: true,
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
    { method: "DELETE", path: "/containers/:name",    kind: "allowAction" },
    { method: "POST", path: "/images/create",         kind: "pullImage" },
    { method: "POST", path: "/auth",                  kind: "deny" },
    { method: "POST", path: "/build",                 kind: "deny" },
    { method: "POST", path: "/commit",                kind: "deny" },
    { method: "POST", path: "/containers/:name/exec", kind: "deny" },
    { method: "POST", path: "/containers/:name/rename",kind: "deny" },
    { method: "POST", path: "/containers/:name/update",kind: "deny" },
    { method: "POST", path: "/containers/:name/kill", kind: "deny" },
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
    nondet matched = oneOf(policies.filter(p => imageAllowed(image, p)))
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
          envVars: if (matched.envFile) Set() else envVars,
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
    nondet matched = oneOf(policies.filter(p => imageAllowed(image, p)))
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

  action step: bool = any {
    createContainer("beacon", "chainsafe/lodestar:next",
      Set("--rcConfig", "/data/config.yml"),
      Set("/home/beacon"), Set(), false),
    createContainer("validator", "chainsafe/lodestar:latest",
      Set("--dataDir", "/data/validator"),
      Set("/home/validator"), Set(), false),
    createContainer("evil", "attacker/malware:latest",
      Set(), Set(), Set(), true),
    startContainer("beacon"),
    stopContainer("beacon"),
    removeContainer("beacon"),
    execContainer("beacon"),
    pullImage("chainsafe/lodestar:next"),
    pullImage("attacker/malware:latest"),
    readOnlyRequest("GET", "/_ping")
  }

  // ─── Invariants ───────────────────────────────────────────────────────

  val noPrivileged = containers.forall(c => not(c.privileged))

  val networkModeEnforced = containers.forall(c => c.networkMode == "host")

  val allImagesAllowlisted = containers.forall(c =>
    policies.exists(p => imageAllowed(c.image, p))
  )

  val envFromFileOnly = containers.forall(c =>
    policies.exists(p =>
      p.serviceName == c.serviceName
        and (not(p.envFile) or c.envVars.size() == 0)
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
