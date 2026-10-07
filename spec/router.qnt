// ─── Module: router_model ───────────────────────────────────────────────
//
// How the router extracts a container name from a request path, and how
// the container-lifecycle branch routes on it (#48). Mirrors
// `extract_container_name` and the lifecycle branch of `Router::route` in
// rs/src/proxy.rs. This is not the full router: checks that run before the
// lifecycle branch (exec, build, commit, POST /containers/create) are left
// out. Go (`extractContainerName`) and TypeScript (`extractContainerName`)
// have the same lifecycle branch for GET, POST and DELETE. HEAD differs:
// Go and TypeScript allow it through the passthrough, Rust denies it. HEAD
// is outside METHODS.
//
// A path is a list of segments: `DELETE /containers/` is
// ["containers", ""], `POST /containers//start` is ["containers", "", "start"].
//
// ALLOW_EMPTY_NAME = true models Rust before #48, where an empty second
// segment counted as a container name. false models Go, TypeScript, and
// Rust after the fix.

module router_model {
  const ALLOW_EMPTY_NAME: bool

  pure val RESERVED = Set("create", "json", "exec")
  pure val KNOWN_SERVICES = Set("beacon")

  pure val BY_NAME_ACTIONS = Set("start", "stop", "restart", "kill", "wait", "pause", "unpause")
  pure val DENIED_ACTIONS = Set("rename", "update")

  // Kept apart from containerNameOf so that, under ALLOW_EMPTY_NAME, "the
  // name is empty" and "there is no name" stay distinct.
  pure def hasContainerName(segs: List[str]): bool =
    if (segs.length() < 2) false
    else and {
      segs[0] == "containers",
      not(RESERVED.contains(segs[1])),
      segs[1] != "" or ALLOW_EMPTY_NAME,
    }

  pure def containerNameOf(segs: List[str]): str =
    if (hasContainerName(segs)) segs[1] else ""

  pure def lastSeg(segs: List[str]): str =
    if (segs.length() == 0) "" else segs[segs.length() - 1]

  pure def routeByName(name: str): str =
    if (KNOWN_SERVICES.contains(name)) "allowKnown" else "allowUnknown"

  pure def route(method: str, segs: List[str]): str =
    if (hasContainerName(segs)) {
      val name = containerNameOf(segs)
      if (method == "POST" and BY_NAME_ACTIONS.contains(lastSeg(segs))) routeByName(name)
      else if (method == "POST" and DENIED_ACTIONS.contains(lastSeg(segs))) "deny"
      else if (method == "DELETE") routeByName(name)
      else if (method == "GET") "allowRead"
      else "deny"
    }
    else if (method == "GET" or method == "HEAD") "allowRead"
    else "deny"

  // ─── Path universe ──────────────────────────────────────────────────

  pure val WORDS = Set("containers", "", "json", "create", "exec", "mycontainer", "beacon", "start")
  pure val METHODS = Set("GET", "POST", "DELETE")

  pure val PATHS: Set[List[str]] =
    WORDS.map(a => [a])
      .union(tuples(WORDS, WORDS).map(t => [t._1, t._2]))
      .union(tuples(WORDS, WORDS, WORDS).map(t => [t._1, t._2, t._3]))

  // ─── Property ───────────────────────────────────────────────────────

  // A lifecycle allow only ever targets a real, non-reserved name.
  pure val lifecycleOnlyTargetsRealNames: bool =
    METHODS.forall(m => PATHS.forall(segs =>
      Set("allowKnown", "allowUnknown").contains(route(m, segs)) implies and {
        segs.length() >= 2,
        segs[1] != "",
        not(RESERVED.contains(segs[1])),
      }
    ))

  // ─── Tests: one run per table row ───────────────────────────────────
  //
  // Rows whose outcome does not depend on ALLOW_EMPTY_NAME run on both
  // instances. The two rows that do, and soundTest, live in `router`.

  run emptyNameGetAllowedTest =
    assert(route("GET", ["containers", ""]) == "allowRead")

  run reservedJsonDeleteDeniedTest =
    assert(route("DELETE", ["containers", "json"]) == "deny")

  run reservedCreateDeleteDeniedTest =
    assert(route("DELETE", ["containers", "create"]) == "deny")

  run reservedExecDeleteDeniedTest =
    assert(route("DELETE", ["containers", "exec"]) == "deny")

  run realNameDeleteAllowedTest =
    assert(route("DELETE", ["containers", "mycontainer"]) == "allowUnknown")

  run reservedInSubpathAllowedTest =
    assert(route("GET", ["containers", "mycontainer", "json"]) == "allowRead")
}

// ─── Instances ──────────────────────────────────────────────────────────

// The extraction rule of Go, TypeScript, and Rust after #48: an empty
// segment is not a name.
module router {
  import router_model(ALLOW_EMPTY_NAME = false).*

  run emptyNameDeleteDeniedTest =
    assert(route("DELETE", ["containers", ""]) == "deny")

  run emptyNameStartDeniedTest =
    assert(route("POST", ["containers", "", "start"]) == "deny")

  run soundTest =
    assert(lifecycleOnlyTargetsRealNames)
}

// Rust before #48: `/containers/` and `/containers//start` reach
// route_by_name("") and are allowed as an unknown container.
module router_pre48 {
  import router_model(ALLOW_EMPTY_NAME = true).*

  run pre48UnsoundTest =
    assert(and {
      not(lifecycleOnlyTargetsRealNames),
      route("DELETE", ["containers", ""]) == "allowUnknown",
      route("POST", ["containers", "", "start"]) == "allowUnknown",
    })
}
