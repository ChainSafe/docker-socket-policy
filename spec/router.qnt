// ─── Module: router_model ───────────────────────────────────────────────
//
// How the router extracts a container name from a request path, how the
// container-lifecycle branch routes on it (#48), the percent-encoded
// path deny that runs first in the router (#53), the empty interior segment
// deny that follows it (#55), and the segment-exact exec deny and
// POST /containers/create route (#49). Mirrors
// `extract_container_name` and the lifecycle branch of `Router::route` in
// rs/src/proxy.rs. This is not the full router: the API-version strip and
// the other checks that run between the percent check and the lifecycle
// branch (build, commit, the read-only endpoints, auth) are left out, as is
// POST /images/create. Go (`extractContainerName`) and
// TypeScript (`extractContainerName`) have the same lifecycle branch.
// HEAD is routed like GET in all three (#55).
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
// ALLOW_EMPTY_INTERIOR = true models all three before #55, which let an
// empty segment before the last one through. false models all three after
// the fix: a path with `//` in it is denied, for every method. A single
// trailing slash, as in `/containers/`, is not interior.
//
// No instance models Go before #53. Go decoded before routing, which is
// route(m, decodePath(segs)); with this table that agrees with the daemon
// by construction, so the property cannot express Go's risk: decoding that
// differs from the daemon's, such as encoded version segments (#57). Go's
// change is covered by the language handler tests.

module router_model {
  const ALLOW_EMPTY_NAME: bool
  const ALLOW_PERCENT: bool
  const ALLOW_EMPTY_INTERIOR: bool

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

  // Exec matches whole segments only (#49): the `/exec/<id>/…` namespace,
  // or `exec` anywhere after `containers`. A segment such as `exec-runner`
  // is a name like any other.
  pure def isExecPath(segs: List[str]): bool =
    if (segs.length() == 0) false
    else or {
      segs[0] == "exec",
      segs[0] == "containers" and segs.indices().exists(i => i >= 1 and segs[i] == "exec"),
    }

  // An empty segment before the last one, i.e. `//` in the path. A trailing
  // empty segment (`/containers/`) is not interior.
  pure def hasEmptyInterior(segs: List[str]): bool =
    segs.indices().exists(i => i < segs.length() - 1 and segs[i] == "")

  pure def isDenied(outcome: str): bool =
    outcome == "deny" or outcome == "denyExec"

  // The percent check (#53) comes first, then the empty interior segment
  // check (#55). The exec check (#49) follows, before
  // the create route, the lifecycle branch and the GET passthrough, so it
  // denies every method. POST /containers/create matches only the exact
  // segments; a longer path falls through.
  pure def route(method: str, segs: List[str]): str =
    if (not(ALLOW_PERCENT) and hasEncodedSeg(segs)) "deny"
    else if (not(ALLOW_EMPTY_INTERIOR) and hasEmptyInterior(segs)) "deny"
    else if (isExecPath(segs)) "denyExec"
    else if (method == "POST" and segs == ["containers", "create"]) "routeCreate"
    else if (hasContainerName(segs)) {
      val name = containerNameOf(segs)
      if (method == "POST" and BY_NAME_ACTIONS.contains(lastSeg(segs))) routeByName(name)
      else if (method == "POST" and DENIED_ACTIONS.contains(lastSeg(segs))) "deny"
      else if (method == "DELETE") routeByName(name)
      else if (method == "GET" or method == "HEAD") "allowRead"
      else "deny"
    }
    else if (method == "GET" or method == "HEAD") "allowRead"
    else "deny"

  // ─── Path universe ──────────────────────────────────────────────────

  pure val WORDS = Set(
    "containers", "", "json", "create", "exec", "mycontainer", "beacon", "start",
    "%2F", "%2f", "%6A%73%6F%6E", "beacon%2Fstart",
    "exec-runner", "abc", "extra",
  )
  pure val METHODS = Set("GET", "HEAD", "POST", "DELETE")

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
      not(isDenied(route(m, segs))) implies decodePath(segs) == segs
    ))

  // A path with `exec` in an exec position is denied for every method (#49).
  // Ranges over GET too. The exec positions are written out here rather
  // than taken from isExecPath, so that a narrower rule in `route` fails it.
  pure val execNeverAllowed: bool =
    METHODS.forall(m => PATHS.forall(segs =>
      segs.indices().exists(i => and {
        segs[i] == "exec",
        i == 0 or segs[0] == "containers",
      }) implies isDenied(route(m, segs))
    ))

  // `exec-runner` only starts with `exec`. Renaming it to the plain unknown
  // name `mycontainer`, wherever it appears, never changes the outcome (#49).
  pure def renameExecLike(segs: List[str]): List[str] =
    segs.foldl([], (acc, s) => acc.append(if (s == "exec-runner") "mycontainer" else s))

  pure val execPrefixNamesRoute: bool =
    METHODS.forall(m => PATHS.forall(segs =>
      route(m, segs) == route(m, renameExecLike(segs))
    ))

  // The create route is taken for exactly POST /containers/create (#49).
  pure val createOnlyExact: bool =
    METHODS.forall(m => PATHS.forall(segs =>
      (route(m, segs) == "routeCreate") iff (m == "POST" and segs == ["containers", "create"])
    ))

  // A path with an empty segment before the last one is denied for every
  // method (#55). Ranges over GET too.
  pure val emptyInteriorDenied: bool =
    METHODS.forall(m => PATHS.forall(segs =>
      hasEmptyInterior(segs) implies isDenied(route(m, segs))
    ))

  // The security claim behind emptyInteriorDenied: a path that is an exec
  // path once its empty segments are dropped, as the daemon's redirect to
  // the clean path does, is denied for every method (#55).
  pure val emptySegmentsHideNoExec: bool =
    METHODS.forall(m => PATHS.forall(segs =>
      isExecPath(segs.select(s => s != "")) implies isDenied(route(m, segs))
    ))

  // ─── Tests: one run per table row ───────────────────────────────────
  //
  // Rows whose outcome depends on none of ALLOW_EMPTY_NAME, ALLOW_PERCENT
  // and ALLOW_EMPTY_INTERIOR run on every instance. The rows that do and the
  // property tests (soundTest, percentSoundTest, execSoundTest,
  // execPrefixSoundTest, createExactSoundTest, emptyInteriorSoundTest) live
  // in `router`.

  run emptyNameGetAllowedTest =
    assert(route("GET", ["containers", ""]) == "allowRead")

  run reservedJsonDeleteDeniedTest =
    assert(route("DELETE", ["containers", "json"]) == "deny")

  run reservedCreateDeleteDeniedTest =
    assert(route("DELETE", ["containers", "create"]) == "deny")

  // Decided by the exec check, as in all three implementations.
  run reservedExecDeleteDeniedTest =
    assert(route("DELETE", ["containers", "exec"]) == "denyExec")

  run realNameDeleteAllowedTest =
    assert(route("DELETE", ["containers", "mycontainer"]) == "allowUnknown")

  run reservedInSubpathAllowedTest =
    assert(route("GET", ["containers", "mycontainer", "json"]) == "allowRead")

  // Segment-exact exec and create matching (#49).

  run execSubpathDeleteDeniedTest =
    assert(route("DELETE", ["containers", "mycontainer", "exec"]) == "denyExec")

  run execSubpathPostDeniedTest =
    assert(route("POST", ["containers", "mycontainer", "exec"]) == "denyExec")

  run execPrefixNameStartAllowedTest =
    assert(route("POST", ["containers", "exec-runner", "start"]) == "allowUnknown")

  run execPrefixNameDeleteAllowedTest =
    assert(route("DELETE", ["containers", "exec-runner"]) == "allowUnknown")

  run execPrefixNameGetAllowedTest =
    assert(route("GET", ["containers", "exec-runner", "json"]) == "allowRead")

  run execNamespaceGetDeniedTest =
    assert(route("GET", ["exec", "abc", "json"]) == "denyExec")

  run execNamespacePostDeniedTest =
    assert(route("POST", ["exec", "abc", "start"]) == "denyExec")

  run createSubpathDeniedTest =
    assert(route("POST", ["containers", "create", "extra"]) == "deny")

  // HEAD is routed like GET (#55).

  run headNamedContainerAllowedTest =
    assert(route("HEAD", ["containers", "mycontainer"]) == "allowRead")
}

// ─── Instances ──────────────────────────────────────────────────────────

// Go, TypeScript, and Rust after #48, #53, #49 and #55: an empty segment is
// not a name, and a percent-encoded path or one with an empty interior
// segment is denied.
module router {
  import router_model(ALLOW_EMPTY_NAME = false, ALLOW_PERCENT = false, ALLOW_EMPTY_INTERIOR = false).*

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

  run execSoundTest =
    assert(execNeverAllowed)

  run execPrefixSoundTest =
    assert(execPrefixNamesRoute)

  run createExactSoundTest =
    assert(createOnlyExact)

  // Empty interior segments (#55). `GET //exec/abc/json`: the leading empty
  // segment hid the exec namespace from the exec check.

  run emptyLeadingExecGetDeniedTest =
    assert(route("GET", ["", "exec", "abc"]) == "deny")

  run emptyInteriorGetDeniedTest =
    assert(route("GET", ["containers", "", "json"]) == "deny")

  run emptyInteriorSoundTest =
    assert(emptyInteriorDenied)

  run emptySegmentsHideNoExecTest =
    assert(emptySegmentsHideNoExec)
}

// Rust before #48: `/containers/` and `/containers//start` reach
// route_by_name("") and are allowed as an unknown container. The percent
// check is on, so that this instance isolates #48. The empty interior check
// is off: with it on, `/containers//start` would be denied before it reached
// the name branch, and the instance could not show #48.
module router_pre48 {
  import router_model(ALLOW_EMPTY_NAME = true, ALLOW_PERCENT = false, ALLOW_EMPTY_INTERIOR = true).*

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
  import router_model(ALLOW_EMPTY_NAME = false, ALLOW_PERCENT = true, ALLOW_EMPTY_INTERIOR = false).*

  run pre53UnsoundTest =
    assert(and {
      not(routerSeesWhatDaemonSees),
      route("DELETE", ["containers", "%2F"]) == "allowUnknown",
      route("POST", ["containers", "%2F", "start"]) == "allowUnknown",
      route("GET", ["containers", "%2F"]) == "allowRead",
    })
}

// All three before #55: an empty interior segment went through. In
// `GET //exec/abc/json` the first segment is empty, not `exec`, so the exec
// check missed it and the GET passthrough forwarded it. The daemon answers
// with a 301 to the clean path, so nothing leaked, but the router allowed it.
module router_pre55 {
  import router_model(ALLOW_EMPTY_NAME = false, ALLOW_PERCENT = false, ALLOW_EMPTY_INTERIOR = true).*

  run pre55UnsoundTest =
    assert(and {
      not(emptyInteriorDenied),
      not(emptySegmentsHideNoExec),
      route("GET", ["", "exec", "abc"]) == "allowRead",
    })
}
