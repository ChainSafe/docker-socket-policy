// ─── Module: router_model ───────────────────────────────────────────────
//
// How the router extracts a container name from a request path, how the
// container-lifecycle branch routes on it (#48), the percent-encoded
// path deny that runs first in the router (#53), the empty interior segment
// deny that follows it (#55), the segment-exact exec deny and
// POST /containers/create route (#49), and the segment-exact attach deny
// (#76), that the read passthrough admits only GET and HEAD, with
// `/_ping` standing for the read endpoints (#78), and the dot segment deny
// that follows the empty interior segment deny (#70). Mirrors
// `extract_container_name` and the lifecycle branch of `Router::route` in
// rs/src/proxy.rs. This is not the full router: the API-version strip and
// the other checks that run between the percent check and the lifecycle
// branch (build, commit, auth) are left out, as is
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
// READONLY = true models `--readonly` (#75): every request whose method is
// not GET or HEAD is denied, for every path, before any other check.
// false models the proxy without the flag. Before #75 the flag only reached
// the middleware chain, which runs on the create route alone; that was
// handler wiring, not routing, so no instance models it.
//
// ALLOW_ATTACH = true models all three before #76, where attach fell
// through to the GET passthrough (and, for other methods, the lifecycle
// branch's default deny). false models all three after the fix: a path
// whose first segment is `containers` with `attach` as any later segment
// is denied, for every method, right after the exec check.
//
// ALLOW_ANY_METHOD_PING = true models all three before #78, where an early
// clause allowed `/_ping`, `/version`, `/info` and `/events…` for every
// method, right after the empty interior segment check. false models all
// three after the fix: those paths reach the GET/HEAD passthrough like any
// other read, and every other method is denied by default. `/_ping` stands
// for all four.
//
// ALLOW_DOT_SEGMENTS = true models all three before #70, which let a `.`
// or `..` segment through. false models all three after the fix: a path
// with a segment that is exactly `.` or `..` is denied, for every method,
// right after the empty interior segment check. `.hidden`, `...` and `a.b`
// are names like any other.
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
  const READONLY: bool
  const ALLOW_ATTACH: bool
  const ALLOW_ANY_METHOD_PING: bool
  const ALLOW_DOT_SEGMENTS: bool

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

  // Attach matches whole segments only (#76), as exec does under
  // `containers`: `attach` anywhere after `containers`. A segment such as
  // `attach-runner` is a name like any other.
  pure def isAttachPath(segs: List[str]): bool =
    if (segs.length() == 0) false
    else segs[0] == "containers" and segs.indices().exists(i => i >= 1 and segs[i] == "attach")

  // An empty segment before the last one, i.e. `//` in the path. A trailing
  // empty segment (`/containers/`) is not interior.
  pure def hasEmptyInterior(segs: List[str]): bool =
    segs.indices().exists(i => i < segs.length() - 1 and segs[i] == "")

  // A segment that is exactly `.` or `..` (#70).
  pure def hasDotSegment(segs: List[str]): bool =
    segs.indices().exists(i => segs[i] == "." or segs[i] == "..")

  pure def isDenied(outcome: str): bool =
    outcome == "deny" or outcome == "denyExec"

  // The read-only check (#75) comes first, then the percent check (#53),
  // then the empty interior segment check (#55), then the dot segment
  // check (#70). Before #78 the read
  // endpoints were allowed next, for every method. The exec check (#49)
  // and the attach check (#76) follow, before
  // the create route, the lifecycle branch and the GET passthrough, so it
  // denies every method. POST /containers/create matches only the exact
  // segments; a longer path falls through.
  pure def route(method: str, segs: List[str]): str =
    if (READONLY and not(method == "GET" or method == "HEAD")) "deny"
    else if (not(ALLOW_PERCENT) and hasEncodedSeg(segs)) "deny"
    else if (not(ALLOW_EMPTY_INTERIOR) and hasEmptyInterior(segs)) "deny"
    else if (not(ALLOW_DOT_SEGMENTS) and hasDotSegment(segs)) "deny"
    else if (ALLOW_ANY_METHOD_PING and segs == ["_ping"]) "allowRead"
    else if (isExecPath(segs)) "denyExec"
    else if (not(ALLOW_ATTACH) and isAttachPath(segs)) "deny"
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
    "containers", "", "json", "create", "exec", "mycontainer", "beacon", "start", "stop",
    "%2F", "%2f", "%6A%73%6F%6E", "beacon%2Fstart",
    "exec-runner", "abc", "extra", "attach", "ws", "_ping", ".", "..",
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

  // A path whose first segment is `containers` with `attach` at some later
  // segment is denied for every method (#76). Ranges over GET too. Written
  // out rather than taken from isAttachPath, as execNeverAllowed is.
  pure val attachNeverAllowed: bool =
    METHODS.forall(m => PATHS.forall(segs =>
      (segs.length() > 0 and segs[0] == "containers"
        and segs.indices().exists(i => i >= 1 and segs[i] == "attach"))
        implies isDenied(route(m, segs))
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

  // A path with a `.` or `..` segment is denied for every method (#70).
  // Ranges over GET too.
  pure val dotSegmentsDenied: bool =
    METHODS.forall(m => PATHS.forall(segs =>
      hasDotSegment(segs) implies isDenied(route(m, segs))
    ))

  // The path a client that resolves dot segments reads, as the daemon's
  // redirect to the clean path does: `.` is dropped, and `..` removes the
  // segment before it, if any, and is dropped.
  pure def resolveDots(segs: List[str]): List[str] =
    segs.foldl([], (acc, s) =>
      if (s == ".") acc
      else if (s == "..") (if (acc.length() == 0) acc else acc.slice(0, acc.length() - 1))
      else acc.append(s))

  // The security claim behind dotSegmentsDenied: a path that is an exec or
  // attach path once its dot segments are resolved is denied for every
  // method (#70). It does not mention hasDotSegment or ALLOW_DOT_SEGMENTS,
  // so that router_pre70 fails it.
  pure val dotSegmentsHideNoExec: bool =
    METHODS.forall(m => PATHS.forall(segs =>
      (isExecPath(resolveDots(segs)) or isAttachPath(resolveDots(segs)))
        implies isDenied(route(m, segs))
    ))

  // Every request that is not GET or HEAD is denied, for every path (#75).
  // The read-only claim: it holds only on `router_readonly`. It does not
  // mention READONLY, so that the instance with the flag off fails it
  // rather than passing it vacuously.
  pure val readonlyAllowsOnlyReads: bool =
    METHODS.forall(m => PATHS.forall(segs =>
      not(m == "GET" or m == "HEAD") implies isDenied(route(m, segs))
    ))

  // The read passthrough is taken only by GET and HEAD (#78): every other
  // method on a path that no earlier rule allows is denied. It does not
  // mention ALLOW_ANY_METHOD_PING, so that router_pre78 fails it.
  pure val readPassthroughOnlyForReads: bool =
    METHODS.forall(m => PATHS.forall(segs =>
      route(m, segs) == "allowRead" implies (m == "GET" or m == "HEAD")
    ))

  // ─── Tests: one run per table row ───────────────────────────────────
  //
  // Rows whose outcome depends on none of ALLOW_EMPTY_NAME, ALLOW_PERCENT,
  // ALLOW_EMPTY_INTERIOR, ALLOW_ATTACH, ALLOW_ANY_METHOD_PING and
  // ALLOW_DOT_SEGMENTS run on every READONLY = false instance. The rows
  // that do and the
  // property tests (soundTest, percentSoundTest, execSoundTest,
  // execPrefixSoundTest, createExactSoundTest, emptyInteriorSoundTest,
  // attachSoundTest, readPassthroughSoundTest, dotSoundTest) live
  // in `router`. `router_readonly` runs only its own `readonly*` tests
  // (`--match`): with READONLY = true the write rows here are denied.

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

  // The read endpoints stay readable (#78).

  run pingGetAllowedTest =
    assert(route("GET", ["_ping"]) == "allowRead")

  run pingHeadAllowedTest =
    assert(route("HEAD", ["_ping"]) == "allowRead")
}

// ─── Instances ──────────────────────────────────────────────────────────

// Go, TypeScript, and Rust after #48, #53, #49, #55, #76, #78 and #70: an
// empty segment is not a name, a percent-encoded path or one with an empty
// interior segment or a dot segment is denied, attach is denied, and the
// read endpoints are read-only.
module router {
  import router_model(ALLOW_EMPTY_NAME = false, ALLOW_PERCENT = false, ALLOW_EMPTY_INTERIOR = false, READONLY = false, ALLOW_ATTACH = false, ALLOW_ANY_METHOD_PING = false, ALLOW_DOT_SEGMENTS = false).*

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

  // Attach is denied for every method (#76). The model has at most three
  // segments, so `/containers/mycontainer/attach/ws` is not expressible;
  // `/containers/mycontainer/attach` stands for it.

  run attachGetDeniedTest =
    assert(route("GET", ["containers", "mycontainer", "attach"]) == "deny")

  // A pin, not a discriminator: with ALLOW_ATTACH = true the lifecycle
  // branch still denies it, since `attach` is not an action.
  run attachPostDeniedTest =
    assert(route("POST", ["containers", "mycontainer", "attach"]) == "deny")

  run attachHeadDeniedTest =
    assert(route("HEAD", ["containers", "mycontainer", "attach"]) == "deny")

  // A container literally named `attach` is denied too, as
  // `/containers/exec/...` is for exec.
  run attachNamedContainerDeniedTest =
    assert(route("GET", ["containers", "attach", "ws"]) == "deny")

  run attachSoundTest =
    assert(attachNeverAllowed)

  // The read endpoints admit only GET and HEAD (#78). Before #78 the early
  // clause allowed them for every method.

  run pingPostDeniedTest =
    assert(route("POST", ["_ping"]) == "deny")

  run pingDeleteDeniedTest =
    assert(route("DELETE", ["_ping"]) == "deny")

  run readPassthroughSoundTest =
    assert(readPassthroughOnlyForReads)

  // Dot segments (#70). `GET /./exec/abc/json`: the leading `.` hid the
  // exec namespace from the exec check.

  run dotLeadingExecGetDeniedTest =
    assert(route("GET", [".", "exec", "abc"]) == "deny")

  run dotDotExecGetDeniedTest =
    assert(route("GET", ["mycontainer", "..", "exec"]) == "deny")

  run dotInContainerPathDeniedTest =
    assert(route("GET", ["containers", "mycontainer", "."]) == "deny")

  run dotSoundTest =
    assert(and {
      dotSegmentsDenied,
      dotSegmentsHideNoExec,
    })
}

// Rust before #48: `/containers/` and `/containers//start` reach
// route_by_name("") and are allowed as an unknown container. The percent
// check is on, so that this instance isolates #48. The empty interior check
// is off: with it on, `/containers//start` would be denied before it reached
// the name branch, and the instance could not show #48.
module router_pre48 {
  import router_model(ALLOW_EMPTY_NAME = true, ALLOW_PERCENT = false, ALLOW_EMPTY_INTERIOR = true, READONLY = false, ALLOW_ATTACH = false, ALLOW_ANY_METHOD_PING = false, ALLOW_DOT_SEGMENTS = false).*

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
  import router_model(ALLOW_EMPTY_NAME = false, ALLOW_PERCENT = true, ALLOW_EMPTY_INTERIOR = false, READONLY = false, ALLOW_ATTACH = false, ALLOW_ANY_METHOD_PING = false, ALLOW_DOT_SEGMENTS = false).*

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
  import router_model(ALLOW_EMPTY_NAME = false, ALLOW_PERCENT = false, ALLOW_EMPTY_INTERIOR = true, READONLY = false, ALLOW_ATTACH = false, ALLOW_ANY_METHOD_PING = false, ALLOW_DOT_SEGMENTS = false).*

  run pre55UnsoundTest =
    assert(and {
      not(emptyInteriorDenied),
      not(emptySegmentsHideNoExec),
      route("GET", ["", "exec", "abc"]) == "allowRead",
    })
}

// `--readonly` (#75): as `router`, plus the read-only check. Run with
// `--match='^readonly.*Test$'`; the shared write rows in router_model assume the
// flag is off.
module router_readonly {
  import router_model(ALLOW_EMPTY_NAME = false, ALLOW_PERCENT = false, ALLOW_EMPTY_INTERIOR = false, READONLY = true, ALLOW_ATTACH = false, ALLOW_ANY_METHOD_PING = false, ALLOW_DOT_SEGMENTS = false).*

  run readonlySoundTest =
    assert(readonlyAllowsOnlyReads)

  run readonlyLifecycleStopDeniedTest =
    assert(route("POST", ["containers", "mycontainer", "stop"]) == "deny")

  run readonlyDeleteDeniedTest =
    assert(route("DELETE", ["containers", "mycontainer"]) == "deny")

  run readonlyCreateDeniedTest =
    assert(route("POST", ["containers", "create"]) == "deny")

  run readonlyGetAllowedTest =
    assert(route("GET", ["containers", "json"]) == "allowRead")

  run readonlyHeadAllowedTest =
    assert(route("HEAD", ["containers", "mycontainer"]) == "allowRead")
}

// All three before #76: attach fell through to the GET passthrough, so
// `GET /containers/{name}/attach/ws` with `Upgrade: websocket` was forwarded
// and Go relayed the 101, giving the caller the container's stdin. Other
// flags as `router`.
module router_pre76 {
  import router_model(ALLOW_EMPTY_NAME = false, ALLOW_PERCENT = false, ALLOW_EMPTY_INTERIOR = false, READONLY = false, ALLOW_ATTACH = true, ALLOW_ANY_METHOD_PING = false, ALLOW_DOT_SEGMENTS = false).*

  run pre76UnsoundTest =
    assert(and {
      not(attachNeverAllowed),
      route("GET", ["containers", "mycontainer", "attach"]) == "allowRead",
    })
}

// All three before #78: an early clause allowed `/_ping`, `/version`,
// `/info` and `/events…` for every method, so `POST /_ping` and
// `DELETE /version` reached the daemon. Other flags as `router`.
module router_pre78 {
  import router_model(ALLOW_EMPTY_NAME = false, ALLOW_PERCENT = false, ALLOW_EMPTY_INTERIOR = false, READONLY = false, ALLOW_ATTACH = false, ALLOW_ANY_METHOD_PING = true, ALLOW_DOT_SEGMENTS = false).*

  run pre78UnsoundTest =
    assert(and {
      not(readPassthroughOnlyForReads),
      route("POST", ["_ping"]) == "allowRead",
      route("DELETE", ["_ping"]) == "allowRead",
    })
}

// All three before #70: a `.` or `..` segment went through. In
// `GET /./exec/abc/json` the first segment is `.`, not `exec`, so the exec
// check missed it and the GET passthrough forwarded it. The daemon answers
// with a 301 to the clean path, so nothing leaked, but the router allowed it.
// Other flags as `router`.
module router_pre70 {
  import router_model(ALLOW_EMPTY_NAME = false, ALLOW_PERCENT = false, ALLOW_EMPTY_INTERIOR = false, READONLY = false, ALLOW_ATTACH = false, ALLOW_ANY_METHOD_PING = false, ALLOW_DOT_SEGMENTS = true).*

  run pre70UnsoundTest =
    assert(and {
      not(dotSegmentsDenied),
      not(dotSegmentsHideNoExec),
      route("GET", [".", "exec", "abc"]) == "allowRead",
    })
}
