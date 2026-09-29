// ─── Module: listener ────────────────────────────────────────────────────
//
// Startup of the listening socket, as designed in spec/listener-design.md.
// Each instance moves through
//   idle → started → locked → probed → unlinked → bound → chowned → serving
// one step per transition, so the steps of different instances interleave.
// Any instance can crash at any step: the kernel releases its lock and its
// socket file stays at the path as a stale socket.
//
// LOCK_HELD = true models Go and Rust (flock on <path>.lock); false models
// TypeScript, where the lock step does nothing (#46).

module listener {
  const LOCK_HELD: bool

  type Config = {
    listenArg: str,
    groupArg: str,
    defaultGroupExists: bool
  }

  // kind: "absent" | "socket" | "file"; id identifies the socket inode.
  type PathObj = { kind: str, id: int }

  pure val INSTANCES = Set("I1", "I2", "I3")

  pure val LISTEN_ARGS = Set("unix", "fd3", "tcp", "http")
  pure val GROUP_ARGS = Set("absent", "existing", "missing", "empty")
  pure val INITIAL_PATHS = Set("absent", "stale", "live", "file")

  // Socket inodes present before any instance starts. The live one belongs
  // to a process outside the model (v0.2.21, a TypeScript instance, …) and
  // keeps accepting connections.
  pure val STALE_ID = 0
  pure val EXTERNAL_LIVE_ID = 1
  pure val FIRST_OWN_ID = 2

  pure val MODE_BOUND = 384   // 0600: umask(0177) around bind(2)
  pure val MODE_FINAL = 432   // 0660

  pure val DEFAULT_GROUP = "docker-socket-policy"
  pure val EXPLICIT_GROUP = "explicit-group"
  pure val OWN_GROUP = "egid"
  pure val GROUP_ERROR = "error"

  // The group-selection table from spec/listener-design.md, one row per
  // (groupArg, defaultGroupExists). `=""` ignores the default group, so it
  // appears for both values.
  pure val groupSelectionTable = Set(
    { groupArg: "absent",   defaultExists: true,  group: DEFAULT_GROUP,  warn: false },
    { groupArg: "absent",   defaultExists: false, group: OWN_GROUP,      warn: true  },
    { groupArg: "existing", defaultExists: true,  group: EXPLICIT_GROUP, warn: false },
    { groupArg: "existing", defaultExists: false, group: EXPLICIT_GROUP, warn: false },
    { groupArg: "missing",  defaultExists: true,  group: GROUP_ERROR,    warn: false },
    { groupArg: "missing",  defaultExists: false, group: GROUP_ERROR,    warn: false },
    { groupArg: "empty",    defaultExists: true,  group: OWN_GROUP,      warn: false },
    { groupArg: "empty",    defaultExists: false, group: OWN_GROUP,      warn: false },
  )

  // Group resolution as the implementations do it (moby's listeners_linux.go
  // order): explicit value first, then the default name with a fallback.
  pure def resolveGroup(c: Config): (str, bool) =
    if (c.groupArg == "empty") (OWN_GROUP, false)
    else if (c.groupArg == "existing") (EXPLICIT_GROUP, false)
    else if (c.groupArg == "missing") (GROUP_ERROR, false)
    else if (c.defaultGroupExists) (DEFAULT_GROUP, false)
    else (OWN_GROUP, true)

  pure def hasGroupBits(mode: int): bool = (mode / 8) % 8 != 0

  // ─── State ──────────────────────────────────────────────────────────

  var config: Config
  var initPathKind: str
  var pathObj: PathObj
  var sockGroup: str
  var sockMode: int
  var lockOwner: str
  var phase: str -> str
  var ownSock: str -> int
  var exitCode: str -> int
  var selectedGroup: str   // "" until the first start resolves it
  var warned: bool
  var nextId: int

  // A socket accepts connections while its inode is held open by a process
  // that has bound it and not exited, whether or not it is still at the path.
  def isLive(id: int): bool =
    id == EXTERNAL_LIVE_ID or INSTANCES.exists(j =>
      ownSock.get(j) == id and Set("bound", "chowned", "serving").contains(phase.get(j))
    )

  def serving(i: str): bool = phase.get(i) == "serving"

  // ─── Init ───────────────────────────────────────────────────────────

  action initWith(c: Config, initialPath: str): bool = all {
    config' = c,
    initPathKind' = if (initialPath == "file") "file"
                    else if (initialPath == "absent") "absent"
                    else "socket",
    pathObj' = if (initialPath == "stale") { kind: "socket", id: STALE_ID }
               else if (initialPath == "live") { kind: "socket", id: EXTERNAL_LIVE_ID }
               else if (initialPath == "file") { kind: "file", id: -1 }
               else { kind: "absent", id: -1 },
    sockGroup' = if (initialPath == "stale" or initialPath == "live") "other" else "",
    sockMode' = if (initialPath == "stale" or initialPath == "live") MODE_BOUND else 0,
    lockOwner' = "",
    phase' = INSTANCES.mapBy(_ => "idle"),
    ownSock' = INSTANCES.mapBy(_ => -1),
    exitCode' = INSTANCES.mapBy(_ => 0),
    selectedGroup' = "",
    warned' = false,
    nextId' = FIRST_OWN_ID,
  }

  action init = {
    nondet listenArg = LISTEN_ARGS.oneOf()
    nondet groupArg = GROUP_ARGS.oneOf()
    nondet defaultGroupExists = Set(true, false).oneOf()
    nondet initialPath = INITIAL_PATHS.oneOf()
    initWith({ listenArg: listenArg, groupArg: groupArg, defaultGroupExists: defaultGroupExists }, initialPath)
  }

  // ─── Actions ────────────────────────────────────────────────────────

  action exitWith(i: str, code: int): bool = all {
    phase' = phase.set(i, "exited"),
    exitCode' = exitCode.set(i, code),
    lockOwner' = if (lockOwner == i) "" else lockOwner,
  }

  // Flag parsing and group resolution. Anything but a Unix path, and an
  // explicit group that doesn't resolve, is a usage error (exit 2).
  action start(i: str): bool = all {
    phase.get(i) == "idle",
    if (config.listenArg != "unix") all {
      exitWith(i, 2),
      selectedGroup' = selectedGroup,
      warned' = warned,
    } else {
      val g = resolveGroup(config)
      all {
        selectedGroup' = g._1,
        warned' = g._2,
        if (g._1 == GROUP_ERROR) exitWith(i, 2)
        else all {
          phase' = phase.set(i, "started"),
          exitCode' = exitCode,
          lockOwner' = lockOwner,
        },
      }
    },
    config' = config, initPathKind' = initPathKind, pathObj' = pathObj,
    sockGroup' = sockGroup, sockMode' = sockMode, ownSock' = ownSock, nextId' = nextId,
  }

  // flock(LOCK_EX|LOCK_NB) on <path>.lock; a pass-through without the lock.
  action lock(i: str): bool = all {
    phase.get(i) == "started",
    if (not(LOCK_HELD)) all {
      phase' = phase.set(i, "locked"),
      exitCode' = exitCode,
      lockOwner' = lockOwner,
    } else if (lockOwner == "") all {
      phase' = phase.set(i, "locked"),
      exitCode' = exitCode,
      lockOwner' = i,
    } else exitWith(i, 1),
    config' = config, initPathKind' = initPathKind, pathObj' = pathObj,
    sockGroup' = sockGroup, sockMode' = sockMode, ownSock' = ownSock,
    selectedGroup' = selectedGroup, warned' = warned, nextId' = nextId,
  }

  // The existing-path table: stat, then connect(2) to a socket.
  action probe(i: str): bool = all {
    phase.get(i) == "locked",
    if (pathObj.kind == "absent") all {
      phase' = phase.set(i, "probed"), exitCode' = exitCode, lockOwner' = lockOwner,
    } else if (pathObj.kind == "file") exitWith(i, 1)
    else if (isLive(pathObj.id)) exitWith(i, 1)
    else all {
      phase' = phase.set(i, "probed"), exitCode' = exitCode, lockOwner' = lockOwner,
    },
    config' = config, initPathKind' = initPathKind, pathObj' = pathObj,
    sockGroup' = sockGroup, sockMode' = sockMode, ownSock' = ownSock,
    selectedGroup' = selectedGroup, warned' = warned, nextId' = nextId,
  }

  // unlink(2) acts on whatever is at the path now, not on what probe saw.
  action unlink(i: str): bool = all {
    phase.get(i) == "probed",
    phase' = phase.set(i, "unlinked"),
    pathObj' = { kind: "absent", id: -1 },
    sockGroup' = "",
    sockMode' = 0,
    config' = config, initPathKind' = initPathKind, lockOwner' = lockOwner,
    ownSock' = ownSock, exitCode' = exitCode,
    selectedGroup' = selectedGroup, warned' = warned, nextId' = nextId,
  }

  // bind(2)+listen(2) under umask(0177): a fresh inode at 0600, process group.
  action bind(i: str): bool = all {
    phase.get(i) == "unlinked",
    if (pathObj.kind != "absent") all {
      exitWith(i, 1),   // EADDRINUSE
      pathObj' = pathObj, sockGroup' = sockGroup, sockMode' = sockMode,
      ownSock' = ownSock, nextId' = nextId,
    } else all {
      phase' = phase.set(i, "bound"),
      exitCode' = exitCode,
      lockOwner' = lockOwner,
      pathObj' = { kind: "socket", id: nextId },
      sockGroup' = OWN_GROUP,
      sockMode' = MODE_BOUND,
      ownSock' = ownSock.set(i, nextId),
      nextId' = nextId + 1,
    },
    config' = config, initPathKind' = initPathKind,
    selectedGroup' = selectedGroup, warned' = warned,
  }

  // chown(path, -1, gid) — by path, like the implementations.
  action chown(i: str): bool = all {
    phase.get(i) == "bound",
    if (pathObj.kind != "socket") all {
      exitWith(i, 1), sockGroup' = sockGroup,
    } else all {
      phase' = phase.set(i, "chowned"),
      exitCode' = exitCode,
      lockOwner' = lockOwner,
      sockGroup' = selectedGroup,
    },
    config' = config, initPathKind' = initPathKind, pathObj' = pathObj,
    sockMode' = sockMode, ownSock' = ownSock,
    selectedGroup' = selectedGroup, warned' = warned, nextId' = nextId,
  }

  // chmod(path, 0660) — by path; the instance then serves.
  action chmod(i: str): bool = all {
    phase.get(i) == "chowned",
    if (pathObj.kind != "socket") all {
      exitWith(i, 1), sockMode' = sockMode,
    } else all {
      phase' = phase.set(i, "serving"),
      exitCode' = exitCode,
      lockOwner' = lockOwner,
      sockMode' = MODE_FINAL,
    },
    config' = config, initPathKind' = initPathKind, pathObj' = pathObj,
    sockGroup' = sockGroup, ownSock' = ownSock,
    selectedGroup' = selectedGroup, warned' = warned, nextId' = nextId,
  }

  // SIGKILL at any step: the kernel drops the flock; the socket file stays.
  action crash(i: str): bool = all {
    not(Set("idle", "exited").contains(phase.get(i))),
    exitWith(i, 137),
    config' = config, initPathKind' = initPathKind, pathObj' = pathObj,
    sockGroup' = sockGroup, sockMode' = sockMode, ownSock' = ownSock,
    selectedGroup' = selectedGroup, warned' = warned, nextId' = nextId,
  }

  action stutter: bool = all {
    config' = config, initPathKind' = initPathKind, pathObj' = pathObj,
    sockGroup' = sockGroup, sockMode' = sockMode, lockOwner' = lockOwner,
    phase' = phase, ownSock' = ownSock, exitCode' = exitCode,
    selectedGroup' = selectedGroup, warned' = warned, nextId' = nextId,
  }

  action advance(i: str): bool =
    any { start(i), lock(i), probe(i), unlink(i), bind(i), chown(i), chmod(i) }

  // `fault` only biases the simulator: with a plain `any { …, crash(i) }`
  // half of all steps crash and random runs almost never interleave two
  // live instances. Every crash is still reachable from every phase, and
  // stuttering adds no states, so the reachable state space is unchanged.
  pure val FAULT_ODDS = 0.to(9)

  action step = {
    val active = INSTANCES.filter(i => phase.get(i) != "exited")
    if (active == Set()) stutter
    else {
      nondet i = active.oneOf()
      nondet fault = FAULT_ODDS.oneOf()
      if (fault == 0 and phase.get(i) != "idle") crash(i)
      else if (serving(i)) stutter
      else advance(i)
    }
  }

  // ─── Invariants ─────────────────────────────────────────────────────

  val neverListensOnTcp: bool =
    INSTANCES.forall(i => serving(i) implies config.listenArg == "unix")

  val groupBeforeMode: bool =
    hasGroupBits(sockMode) implies sockGroup == selectedGroup

  val neverWorldWritable: bool = sockMode % 8 < 2

  val neverUnlinksNonSocket: bool =
    initPathKind == "file" implies pathObj.kind == "file"

  val noLiveTakeover: bool =
    INSTANCES.forall(i => serving(i) implies
      (pathObj.kind == "socket" and pathObj.id == ownSock.get(i)))

  val groupSelectionMatchesTable: bool =
    selectedGroup == "" or groupSelectionTable.contains({
      groupArg: config.groupArg,
      defaultExists: config.defaultGroupExists,
      group: selectedGroup,
      warn: warned,
    })

  val allListenerInvariants: bool = and {
    neverListensOnTcp,
    groupBeforeMode,
    neverWorldWritable,
    neverUnlinksNonSocket,
    noLiveTakeover,
    groupSelectionMatchesTable,
  }

  // ─── Tests: one run per spec table row ──────────────────────────────

  pure def unixCfg(groupArg: str, defaultGroupExists: bool): Config =
    { listenArg: "unix", groupArg: groupArg, defaultGroupExists: defaultGroupExists }

  action toServing(i: str): bool =
    start(i).then(lock(i)).then(probe(i)).then(unlink(i))
      .then(bind(i)).then(chown(i)).then(chmod(i))

  run groupDefaultPresentTest =
    initWith(unixCfg("absent", true), "absent")
      .then(toServing("I1"))
      .expect(and {
        serving("I1"),
        sockGroup == DEFAULT_GROUP,
        sockMode == MODE_FINAL,
        not(warned),
        allListenerInvariants,
      })

  run groupDefaultMissingWarnsTest =
    initWith(unixCfg("absent", false), "absent")
      .then(toServing("I1"))
      .expect(and {
        serving("I1"),
        sockGroup == OWN_GROUP,
        sockMode == MODE_FINAL,
        warned,
        allListenerInvariants,
      })

  run groupExplicitPresentTest =
    initWith(unixCfg("existing", false), "absent")
      .then(toServing("I1"))
      .expect(and {
        serving("I1"),
        sockGroup == EXPLICIT_GROUP,
        sockMode == MODE_FINAL,
        not(warned),
        allListenerInvariants,
      })

  run groupExplicitMissingFailsTest =
    initWith(unixCfg("missing", true), "absent")
      .then(start("I1"))
      .expect(and {
        phase.get("I1") == "exited",
        exitCode.get("I1") == 2,
        pathObj.kind == "absent",
        allListenerInvariants,
      })

  run groupEmptyUsesOwnTest =
    initWith(unixCfg("empty", true), "absent")
      .then(toServing("I1"))
      .expect(and {
        serving("I1"),
        sockGroup == OWN_GROUP,
        sockMode == MODE_FINAL,
        not(warned),
        allListenerInvariants,
      })

  run pathAbsentBindsTest =
    initWith(unixCfg("absent", true), "absent")
      .then(toServing("I1"))
      .expect(and {
        serving("I1"),
        pathObj == { kind: "socket", id: ownSock.get("I1") },
        allListenerInvariants,
      })

  run pathStaleReplacedTest =
    initWith(unixCfg("absent", true), "stale")
      .then(toServing("I1"))
      .expect(and {
        serving("I1"),
        pathObj == { kind: "socket", id: ownSock.get("I1") },
        ownSock.get("I1") != STALE_ID,
        sockMode == MODE_FINAL,
        allListenerInvariants,
      })

  run pathLiveRefusedTest =
    initWith(unixCfg("absent", true), "live")
      .then(start("I1")).then(lock("I1")).then(probe("I1"))
      .expect(and {
        phase.get("I1") == "exited",
        exitCode.get("I1") == 1,
        pathObj == { kind: "socket", id: EXTERNAL_LIVE_ID },
        allListenerInvariants,
      })

  run pathNotSocketRefusedTest =
    initWith(unixCfg("absent", true), "file")
      .then(start("I1")).then(lock("I1")).then(probe("I1"))
      .expect(and {
        phase.get("I1") == "exited",
        exitCode.get("I1") == 1,
        pathObj.kind == "file",
        allListenerInvariants,
      })
}

// ─── Instances ──────────────────────────────────────────────────────────

// Go and Rust: the single-instance lock is taken before the path is touched.
module listener_locked {
  import listener(LOCK_HELD = true).*

  run secondInstanceLockRefusedTest =
    initWith(unixCfg("absent", true), "absent")
      .then(start("I1")).then(lock("I1"))
      .then(start("I2")).then(lock("I2"))
      .expect(and {
        lockOwner == "I1",
        phase.get("I1") == "locked",
        phase.get("I2") == "exited",
        exitCode.get("I2") == 1,
        allListenerInvariants,
      })

  run crashReleasesLockTest =
    initWith(unixCfg("absent", true), "absent")
      .then(toServing("I1"))
      .then(crash("I1"))
      .expect(lockOwner == "")
      .then(toServing("I2"))
      .expect(and {
        lockOwner == "I2",
        serving("I2"),
        pathObj == { kind: "socket", id: ownSock.get("I2") },
        allListenerInvariants,
      })
}

// TypeScript: no flock in Node, so only the connect check guards the path.
module listener_unlocked {
  import listener(LOCK_HELD = false).*

  // The four-step race from spec/listener-design.md §TypeScript exception:
  // both probe a stale socket, I1 binds and serves, I2 unlinks I1's live
  // socket and binds its own. I1 keeps serving on an inode nobody can reach.
  run raceWithoutLockTest =
    initWith(unixCfg("absent", true), "stale")
      .then(start("I1")).then(lock("I1"))
      .then(start("I2")).then(lock("I2"))
      .then(probe("I1"))
      .then(probe("I2"))
      .then(unlink("I1")).then(bind("I1")).then(chown("I1")).then(chmod("I1"))
      .expect(serving("I1") and noLiveTakeover)
      .then(unlink("I2"))
      .expect(serving("I1") and not(noLiveTakeover))
      .then(bind("I2"))
      .expect(and {
        serving("I1"),
        pathObj.kind == "socket",
        pathObj.id == ownSock.get("I2"),
        pathObj.id != ownSock.get("I1"),
        not(noLiveTakeover),
      })
}
