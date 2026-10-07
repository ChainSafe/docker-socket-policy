// ─── Module: router_model ───────────────────────────────────────────────
//
// How the router extracts a container name from a request path, how the
// container-lifecycle branch routes on it (#48), and the percent-encoded
// path deny that runs first in the router (#53). Mirrors
// `extract_container_name` and the lifecycle branch of `Router::route` in
// rs/src/proxy.rs. This is not the full router: the percent check is
// modeled, but the API-version strip and the checks that run between the
// percent check and the lifecycle branch (exec, build, commit,
// POST /containers/create) are left out. Go (`extractContainerName`) and
// TypeScript (`extractContainerName`) have the same lifecycle branch for
// GET, POST and DELETE. HEAD differs: Go and TypeScript allow it through
// the passthrough, Rust denies it. HEAD is outside METHODS.
//
// A path is a list of raw (still percent-encoded) segments, with the query
// string removed: `DELETE /containers/` is ["containers", ""],
// `POST /containers//start` is ["containers", "", "start"], and
// `DELETE /containers/%2F` is ["containers", "%2F"].
//
// The daemon percent-decodes the path before it routes. The model cannot
// inspect characters, so decoding is a fixed table (DAEMON_DECODING) from
// encoded tokens to the segments the daemon sees: `/containers/%2F` reaches
// the daemon as `/containers//`, i.e. ["containers", "", ""].
//
// ALLOW_EMPTY_NAME = true models Rust before #48, where an empty second
// segment counted as a container name. false models Go, TypeScript, and
// Rust after the fix.
//
// ALLOW_PERCENT = true models Rust and TypeScript before #53, which routed
// on the raw path and let encoded segments through. false models all three
// after the fix: any `%` in the path is denied, for every method.
//
// No instance models Go before #53. Go decoded before routing, which is
// route(m, decodePath(segs)); with this table that agrees with the daemon
// by construction, so the property cannot express Go's risk: decoding that
// differs from the daemon's, such as encoded version segments (#57). Go's
// change is covered by the language handler tests.

module router_model {
  const ALLOW_EMPTY_NAME: bool
  const ALLOW_PERCENT: bool

  // ─── Daemon decoding ────────────────────────────────────────────────

  // Every encoded token in the universe, and the segments the daemon reads
  // it as. A segment is encoded iff it is a key; any other segment decodes
  // to itself.
  pure val DAEMON_DECODING: str -> List[str] = Map(
    "%2F" -> ["", ""],
    "%2f" -> ["", ""],
    "%6A%73%6F%6E" -> ["json"],
    "beacon%2Fstart" -> ["beacon", "start"],
  )

  pure def isEncoded(seg: str): bool =
    DAEMON_DECODING.keys().contains(seg)

  pure def hasEncodedSeg(segs: List[str]): bool =
    segs.indices().exists(i => isEncoded(segs[i]))

  pure def decodeSeg(seg: str): List[str] =
    if (isEncoded(seg)) DAEMON_DECODING.get(seg) else [seg]

  pure def decodePath(segs: List[str]): List[str] =
    segs.foldl([], (acc, s) => acc.concat(decodeSeg(s)))

  // ─── Router ─────────────────────────────────────────────────────────

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

  // The percent check (#53) comes first, before the GET passthrough.
  pure def route(method: str, segs: List[str]): str =
    if (not(ALLOW_PERCENT) and hasEncodedSeg(segs)) "deny"
    else if (hasContainerName(segs)) {
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

  pure val WORDS = Set(
    "containers", "", "json", "create", "exec", "mycontainer", "beacon", "start",
    "%2F", "%2f", "%6A%73%6F%6E", "beacon%2Fstart",
  )
  pure val METHODS = Set("GET", "POST", "DELETE")

  pure val PATHS: Set[List[str]] =
    WORDS.map(a => [a])
      .union(tuples(WORDS, WORDS).map(t => [t._1, t._2]))
      .union(tuples(WORDS, WORDS, WORDS).map(t => [t._1, t._2, t._3]))

  // ─── Properties ─────────────────────────────────────────────────────

  // A lifecycle allow only ever targets a real, non-reserved name.
  pure val lifecycleOnlyTargetsRealNames: bool =
    METHODS.forall(m => PATHS.forall(segs =>
      Set("allowKnown", "allowUnknown").contains(route(m, segs)) implies and {
        segs.length() >= 2,
        segs[1] != "",
        not(RESERVED.contains(segs[1])),
      }
    ))

  // Any request the router does not deny reads the same to the daemon:
  // decoding leaves its path unchanged (#53). Ranges over GET too.
  pure val routerSeesWhatDaemonSees: bool =
    METHODS.forall(m => PATHS.forall(segs =>
      route(m, segs) != "deny" implies decodePath(segs) == segs
    ))

  // ─── Tests: one run per table row ───────────────────────────────────
  //
  // Rows whose outcome depends on neither ALLOW_EMPTY_NAME nor
  // ALLOW_PERCENT run on every instance. The rows that do, soundTest and
  // percentSoundTest live in `router`.

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

// Go, TypeScript, and Rust after #48 and #53: an empty segment is not a
// name, and a percent-encoded path is denied.
module router {
  import router_model(ALLOW_EMPTY_NAME = false, ALLOW_PERCENT = false).*

  run emptyNameDeleteDeniedTest =
    assert(route("DELETE", ["containers", ""]) == "deny")

  run emptyNameStartDeniedTest =
    assert(route("POST", ["containers", "", "start"]) == "deny")

  run percentSlashDeleteDeniedTest =
    assert(route("DELETE", ["containers", "%2F"]) == "deny")

  run percentLowerSlashDeleteDeniedTest =
    assert(route("DELETE", ["containers", "%2f"]) == "deny")

  run percentReservedDeleteDeniedTest =
    assert(route("DELETE", ["containers", "%6A%73%6F%6E"]) == "deny")

  run percentNameStartDeniedTest =
    assert(route("POST", ["containers", "%2F", "start"]) == "deny")

  // A pin, not a discriminator: routing on the raw path already denies it,
  // since `beacon%2Fstart` is not an action. Only Go's decode-first handler
  // before #53 would have allowed it, as the daemon reads
  // `POST /containers/beacon/start`.
  run percentSubpathStartDeniedTest =
    assert(route("POST", ["containers", "beacon%2Fstart"]) == "deny")

  run percentGetDeniedTest =
    assert(route("GET", ["containers", "%2F"]) == "deny")

  run soundTest =
    assert(lifecycleOnlyTargetsRealNames)

  run percentSoundTest =
    assert(routerSeesWhatDaemonSees)
}

// Rust before #48: `/containers/` and `/containers//start` reach
// route_by_name("") and are allowed as an unknown container. The percent
// check is on, so that this instance isolates #48.
module router_pre48 {
  import router_model(ALLOW_EMPTY_NAME = true, ALLOW_PERCENT = false).*

  run pre48UnsoundTest =
    assert(and {
      not(lifecycleOnlyTargetsRealNames),
      route("DELETE", ["containers", ""]) == "allowUnknown",
      route("POST", ["containers", "", "start"]) == "allowUnknown",
    })
}

// Rust and TypeScript before #53: they routed on the raw path, so an
// encoded name such as `%2F` counted as an unknown container and the
// request was forwarded. The daemon decodes it and reads a different path.
module router_pre53 {
  import router_model(ALLOW_EMPTY_NAME = false, ALLOW_PERCENT = true).*

  run pre53UnsoundTest =
    assert(and {
      not(routerSeesWhatDaemonSees),
      route("DELETE", ["containers", "%2F"]) == "allowUnknown",
      route("POST", ["containers", "%2F", "start"]) == "allowUnknown",
      route("GET", ["containers", "%2F"]) == "allowRead",
    })
}
