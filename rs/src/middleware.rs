use crate::policy::{check_image_tag, matches_image_prefix, parse_image_ref, Policy};
use std::collections::HashMap;

#[cfg(test)]
use crate::policy::{ContainerConfig, FlagRule, Volume};

pub trait Gate: Send + Sync {
    fn check(
        &self,
        _method: &str,
        _path: &str,
        _policy: &Policy,
        _body: &HashMap<String, serde_json::Value>,
    ) -> std::result::Result<(), String> {
        Ok(())
    }
}

pub trait Mutator: Send + Sync {
    fn mutate(&self, _policy: &Policy, _body: &mut HashMap<String, serde_json::Value>) {}
}

pub struct Chain {
    gates: Vec<Box<dyn Gate>>,
    mutators: Vec<Box<dyn Mutator>>,
}

pub struct GateResult {
    pub allowed: bool,
    pub reason: String,
    pub modified_body: Option<Vec<u8>>,
}

impl Chain {
    pub fn new() -> Self {
        let mut gates: Vec<Box<dyn Gate>> = Vec::new();
        gates.push(Box::new(RegistryGate));
        gates.push(Box::new(MountSourceGate));
        gates.push(Box::new(EnvFileGate));
        gates.push(Box::new(HostConfigGate));
        gates.push(Box::new(CmdGate));
        gates.push(Box::new(NetworkEndpointsGate));

        let mutators: Vec<Box<dyn Mutator>> = vec![Box::new(ContainerConfigMutator)];

        Chain { gates, mutators }
    }

    pub fn execute(
        &self,
        method: &str,
        path: &str,
        policy: &Policy,
        body: &HashMap<String, serde_json::Value>,
    ) -> GateResult {
        let mut body = body.clone();

        for m in &self.mutators {
            m.mutate(policy, &mut body);
        }

        for g in &self.gates {
            if let Err(reason) = g.check(method, path, policy, &body) {
                return GateResult {
                    allowed: false,
                    reason,
                    modified_body: None,
                };
            }
        }

        let modified = serde_json::to_vec(&body).ok();
        GateResult {
            allowed: true,
            reason: "container create allowed".into(),
            modified_body: modified,
        }
    }
}

fn charset_check(s: &str) -> bool {
    s.len() <= 256
        && s.chars()
            .all(|c| matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '.' | '_' | '=' | ':' | '/' | ',' | '-'))
}

pub struct RegistryGate;
impl Gate for RegistryGate {
    fn check(
        &self,
        _method: &str,
        _path: &str,
        policy: &Policy,
        body: &HashMap<String, serde_json::Value>,
    ) -> std::result::Result<(), String> {
        let image = body.get("Image").and_then(|v| v.as_str());
        let image = match image {
            Some(s) if !s.is_empty() => s,
            _ => return Ok(()),
        };

        // The same parser as the router, so a registry port is not a tag (#84).
        let image_ref = parse_image_ref(image)?;
        if !matches_image_prefix(&image_ref.name, &policy.allowed_image_prefixes) {
            return Err(format!("image {:?} is not in allowed prefixes", image_ref.name));
        }
        check_image_tag(policy, &image_ref)?;

        Ok(())
    }
}

type JsonObject = serde_json::Map<String, serde_json::Value>;

/// MountSourceGate checks every host path a create request mounts against the
/// policy's volumes: `HostConfig.Binds`, `HostConfig.Mounts` and the top-level
/// `Volumes` keys. A policy with no volumes allows no binds. A volume with
/// `read_write: false` must be mounted read-only (#88).
pub struct MountSourceGate;

/// The bind options allowed in a `Binds` entry. The propagation modes
/// shared, rshared, slave and rslave are not among them.
const BIND_MODES: &[&str] = &["ro", "rw", "z", "Z", "nocopy", "private", "rprivate"];

const MOUNT_FIELDS: &[&str] = &[
    "Type",
    "Source",
    "Target",
    "ReadOnly",
    "Consistency",
    "BindOptions",
    "VolumeOptions",
    "ImageOptions",
    "TmpfsOptions",
    "ClusterOptions",
];

/// May hold any value in a `Mounts` entry; Type, Source, ReadOnly and
/// BindOptions have their own rules, and every other key must be zero.
const MOUNT_ANY_VALUE: &[&str] = &["Target", "Consistency", "TmpfsOptions"];

const BIND_OPTION_FIELDS: &[&str] = &[
    "Propagation",
    "NonRecursive",
    "CreateMountpoint",
    "ReadOnlyNonRecursive",
    "ReadOnlyForceRecursive",
];

/// May hold any value in `BindOptions`; Propagation has its own rule, and
/// every other key, ReadOnlyNonRecursive included, must be zero.
const BIND_OPTION_ANY_VALUE: &[&str] = &["NonRecursive", "CreateMountpoint", "ReadOnlyForceRecursive"];

fn find_volume<'a>(host_path: &str, policy: &'a Policy) -> Option<&'a crate::policy::Volume> {
    policy.volumes.as_ref()?.iter().find(|v| v.host_path == host_path)
}

fn check_binds(raw: Option<&serde_json::Value>, policy: &Policy) -> std::result::Result<(), String> {
    let raw = match raw {
        None | Some(serde_json::Value::Null) => return Ok(()),
        Some(r) => r,
    };
    let not_list = || {
        format!(
            "HostConfig.Binds must be a list of strings for service {}",
            policy.service_name
        )
    };
    let binds = raw.as_array().ok_or_else(not_list)?;
    for bind in binds {
        let bind_str = bind.as_str().ok_or_else(not_list)?;
        let parts: Vec<&str> = bind_str.split(':').collect();
        if bind_str.is_empty() || parts.len() > 3 {
            return Err(format!(
                "bind {:?} is not a valid bind for service {}",
                bind_str, policy.service_name
            ));
        }
        let host_path = parts[0];
        let vol = find_volume(host_path, policy).ok_or_else(|| {
            format!(
                "volume mount {:?} is not in the whitelist for service {}",
                host_path, policy.service_name
            )
        })?;
        let opts: Vec<&str> = if parts.len() == 3 && !parts[2].is_empty() {
            parts[2].split(',').collect()
        } else {
            Vec::new()
        };
        for o in &opts {
            if !BIND_MODES.contains(o) {
                return Err(format!(
                    "bind option {:?} on volume mount {:?} is not allowed for service {}",
                    o, host_path, policy.service_name
                ));
            }
        }
        if !vol.read_write && (!opts.contains(&"ro") || opts.contains(&"rw")) {
            return Err(format!(
                "volume mount {:?} must be read-only (:ro) for service {}",
                host_path, policy.service_name
            ));
        }
    }
    Ok(())
}

fn check_mounts(raw: Option<&serde_json::Value>, policy: &Policy) -> std::result::Result<(), String> {
    let raw = match raw {
        None | Some(serde_json::Value::Null) => return Ok(()),
        Some(r) => r,
    };
    let mounts = raw
        .as_array()
        .ok_or_else(|| format!("HostConfig.Mounts must be a list for service {}", policy.service_name))?;
    for m in mounts {
        let mount = m.as_object().ok_or_else(|| {
            format!(
                "HostConfig.Mounts entry must be an object for service {}",
                policy.service_name
            )
        })?;
        check_mount(mount, policy)?;
    }
    Ok(())
}

fn check_mount(mount: &JsonObject, policy: &Policy) -> std::result::Result<(), String> {
    check_field_case("HostConfig.Mounts.", mount.keys(), MOUNT_FIELDS, policy)?;
    for key in sorted_keys(mount.keys()) {
        let value = &mount[key.as_str()];
        match key.as_str() {
            "Type" | "Source" | "ReadOnly" => {}
            "BindOptions" => check_bind_options(value, policy)?,
            k if MOUNT_ANY_VALUE.contains(&k) => {}
            k => {
                if !is_zero_value(value) {
                    return Err(format!(
                        "HostConfig.Mounts.{} is not allowed for service {}",
                        k, policy.service_name
                    ));
                }
            }
        }
    }

    let mount_type = mount.get("Type").and_then(|v| v.as_str()).unwrap_or("");
    let source = mount.get("Source").and_then(|v| v.as_str()).unwrap_or("");
    match mount_type {
        "tmpfs" => {
            if !mount.get("Source").map_or(true, is_zero_value) {
                return Err(format!(
                    "tmpfs mount must not have a Source for service {}",
                    policy.service_name
                ));
            }
            Ok(())
        }
        "bind" => {
            let vol = find_volume(source, policy).ok_or_else(|| {
                format!(
                    "mount source {:?} is not in the whitelist for service {}",
                    source, policy.service_name
                )
            })?;
            let read_only = mount.get("ReadOnly").and_then(|v| v.as_bool()).unwrap_or(false);
            if !vol.read_write && !read_only {
                return Err(format!(
                    "mount of {:?} must be read-only (ReadOnly: true) for service {}",
                    source, policy.service_name
                ));
            }
            Ok(())
        }
        t => Err(format!(
            "mount type {:?} is not allowed for service {}",
            t, policy.service_name
        )),
    }
}

fn check_bind_options(raw: &serde_json::Value, policy: &Policy) -> std::result::Result<(), String> {
    if raw.is_null() {
        return Ok(());
    }
    let opts = raw.as_object().ok_or_else(|| {
        format!(
            "HostConfig.Mounts.BindOptions must be an object for service {}",
            policy.service_name
        )
    })?;
    check_field_case(
        "HostConfig.Mounts.BindOptions.",
        opts.keys(),
        BIND_OPTION_FIELDS,
        policy,
    )?;
    for key in sorted_keys(opts.keys()) {
        let value = &opts[key.as_str()];
        match key.as_str() {
            "Propagation" => match value {
                serde_json::Value::Null => {}
                serde_json::Value::String(s) if s.is_empty() || s == "private" || s == "rprivate" => {}
                serde_json::Value::String(s) => {
                    return Err(format!(
                        "mount propagation {:?} is not allowed for service {}",
                        s, policy.service_name
                    ))
                }
                v => {
                    return Err(format!(
                        "mount propagation {} is not allowed for service {}",
                        v, policy.service_name
                    ))
                }
            },
            k if BIND_OPTION_ANY_VALUE.contains(&k) => {}
            k => {
                if !is_zero_value(value) {
                    return Err(format!(
                        "HostConfig.Mounts.BindOptions.{} is not allowed for service {}",
                        k, policy.service_name
                    ));
                }
            }
        }
    }
    Ok(())
}

impl Gate for MountSourceGate {
    fn check(
        &self,
        _method: &str,
        _path: &str,
        policy: &Policy,
        body: &HashMap<String, serde_json::Value>,
    ) -> std::result::Result<(), String> {
        if let Some(host_config) = body.get("HostConfig").and_then(|v| v.as_object()) {
            check_binds(host_config.get("Binds"), policy)?;
            check_mounts(host_config.get("Mounts"), policy)?;
        }

        if let Some(body_volumes) = body.get("Volumes").and_then(|v| v.as_object()) {
            for host_path in sorted_keys(body_volumes.keys()) {
                if find_volume(&host_path, policy).is_none() {
                    return Err(format!(
                        "volume {:?} is not in the whitelist for service {}",
                        host_path, policy.service_name
                    ));
                }
            }
        }

        Ok(())
    }
}

/// HostConfigGate is the default-deny check on `HostConfig` (#88). It runs
/// after ContainerConfigMutator, on the body that is forwarded, so values the
/// policy forces (Privileged, NetworkMode, SecurityOpt, ...) are what it sees.
///
/// A key in `HOST_CONFIG_ANY_VALUE` may hold any value. SecurityOpt,
/// OomScoreAdj and the namespace modes have their own rules. Binds and Mounts
/// are checked by MountSourceGate. Every other key, known or not, must be
/// absent or hold a zero value (null, false, 0, "", [] or {}); MaskedPaths and
/// ReadonlyPaths must be absent or null, because an empty list unmasks /proc.
///
/// The daemon matches JSON keys without regard to case, and the last match
/// wins, so `"privileged": true` would set Privileged and `"securityopt": null`
/// would clear a forced SecurityOpt. A key that folds to a known field name
/// but is not spelled exactly like it is denied, here and at the top level.
pub struct HostConfigGate;

/// Every HostConfig field of the Docker Engine API (v1.44 and later,
/// including the embedded Resources fields), plus a few removed ones. Used
/// only to catch case variants of field names.
const HOST_CONFIG_FIELDS: &[&str] = &[
    "Binds",
    "ContainerIDFile",
    "LogConfig",
    "NetworkMode",
    "PortBindings",
    "RestartPolicy",
    "AutoRemove",
    "VolumeDriver",
    "VolumesFrom",
    "Mounts",
    "ConsoleSize",
    "Annotations",
    "CapAdd",
    "CapDrop",
    "CgroupnsMode",
    "Dns",
    "DnsOptions",
    "DnsSearch",
    "ExtraHosts",
    "GroupAdd",
    "IpcMode",
    "Cgroup",
    "Links",
    "OomScoreAdj",
    "PidMode",
    "Privileged",
    "PublishAllPorts",
    "ReadonlyRootfs",
    "SecurityOpt",
    "StorageOpt",
    "Tmpfs",
    "UTSMode",
    "UsernsMode",
    "ShmSize",
    "Sysctls",
    "Runtime",
    "Isolation",
    "MaskedPaths",
    "ReadonlyPaths",
    "Init",
    "Capabilities",
    "CpuShares",
    "Memory",
    "CgroupParent",
    "BlkioWeight",
    "BlkioWeightDevice",
    "BlkioDeviceReadBps",
    "BlkioDeviceWriteBps",
    "BlkioDeviceReadIOps",
    "BlkioDeviceWriteIOps",
    "CpuPeriod",
    "CpuQuota",
    "CpuRealtimePeriod",
    "CpuRealtimeRuntime",
    "CpusetCpus",
    "CpusetMems",
    "Devices",
    "DeviceCgroupRules",
    "DeviceRequests",
    "KernelMemory",
    "KernelMemoryTCP",
    "MemoryReservation",
    "MemorySwap",
    "MemorySwappiness",
    "NanoCpus",
    "OomKillDisable",
    "PidsLimit",
    "Ulimits",
    "CpuCount",
    "CpuPercent",
    "IOMaximumIOps",
    "IOMaximumBandwidth",
];

/// Every top-level field of the create body (the container Config,
/// HostConfig and NetworkingConfig), used to catch case variants.
const CREATE_BODY_FIELDS: &[&str] = &[
    "Hostname",
    "Domainname",
    "User",
    "AttachStdin",
    "AttachStdout",
    "AttachStderr",
    "ExposedPorts",
    "Tty",
    "OpenStdin",
    "StdinOnce",
    "Env",
    "Cmd",
    "Healthcheck",
    "ArgsEscaped",
    "Image",
    "Volumes",
    "WorkingDir",
    "Entrypoint",
    "NetworkDisabled",
    "MacAddress",
    "OnBuild",
    "Labels",
    "StopSignal",
    "StopTimeout",
    "Shell",
    "HostConfig",
    "NetworkingConfig",
];

/// Every field of NetworkingConfig.
const NETWORKING_CONFIG_FIELDS: &[&str] = &["EndpointsConfig"];

/// May hold any value. NetworkMode, RestartPolicy and LogConfig are
/// overwritten by the mutator when the policy sets them.
const HOST_CONFIG_ANY_VALUE: &[&str] = &[
    "NetworkMode",
    "RestartPolicy",
    "LogConfig",
    "CapDrop",
    "ReadonlyRootfs",
    "Init",
    "AutoRemove",
    "ConsoleSize",
    "ShmSize",
    "PortBindings",
    "PublishAllPorts",
    "Dns",
    "DnsOptions",
    "DnsSearch",
    "ExtraHosts",
    "Tmpfs",
    "Ulimits",
    "Memory",
    "MemoryReservation",
    "MemorySwap",
    "MemorySwappiness",
    "NanoCpus",
    "CpuShares",
    "CpuPeriod",
    "CpuQuota",
    "CpusetCpus",
    "CpusetMems",
    "PidsLimit",
    "BlkioWeight",
    "ContainerIDFile",
];

/// The values a namespace field may take besides "". "host" and
/// "container:<id>" are denied.
fn host_config_modes(key: &str) -> Option<&'static [&'static str]> {
    match key {
        "PidMode" | "UTSMode" | "UsernsMode" | "Cgroup" => Some(&[]),
        "IpcMode" => Some(&["private", "shareable", "none"]),
        "CgroupnsMode" => Some(&["private"]),
        "Isolation" => Some(&["default"]),
        _ => None,
    }
}

const NO_NEW_PRIVILEGES: &[&str] = &["no-new-privileges", "no-new-privileges:true"];

/// Folds a key the way the daemon's JSON decoder matches field names: ASCII
/// case, plus the Kelvin sign (U+212A) as k and the long s (U+017F) as s.
fn fold_key(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '\u{212a}' => 'k',
            '\u{17f}' => 's',
            c => c.to_ascii_lowercase(),
        })
        .collect()
}

fn sorted_keys<'a, I: Iterator<Item = &'a String>>(keys: I) -> Vec<String> {
    let mut v: Vec<String> = keys.cloned().collect();
    v.sort();
    v
}

/// Denies a key that the daemon would read as one of `fields` but that is
/// not spelled exactly like it.
fn check_field_case<'a, I: Iterator<Item = &'a String>>(
    prefix: &str,
    keys: I,
    fields: &[&str],
    policy: &Policy,
) -> std::result::Result<(), String> {
    for key in sorted_keys(keys) {
        let folded = fold_key(&key);
        for f in fields {
            if key != *f && folded == fold_key(f) {
                return Err(format!(
                    "{}{} is not allowed for service {} (the daemon reads it as {}{})",
                    prefix, key, policy.service_name, prefix, f
                ));
            }
        }
    }
    Ok(())
}

/// null, false, 0, "", [] and {}.
fn is_zero_value(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::Null => true,
        serde_json::Value::Bool(b) => !b,
        serde_json::Value::Number(n) => n.as_f64() == Some(0.0),
        serde_json::Value::String(s) => s.is_empty(),
        serde_json::Value::Array(a) => a.is_empty(),
        serde_json::Value::Object(o) => o.is_empty(),
    }
}

/// Whether `value` is a JSON list of strings equal, in order, to the
/// policy's non-empty `group_add` (#93).
fn equals_forced_groups(value: &serde_json::Value, policy: &Policy) -> bool {
    let forced = match policy.container_config.as_ref().and_then(|c| c.group_add.as_ref()) {
        Some(g) if !g.is_empty() => g,
        _ => return false,
    };
    value.as_array().is_some_and(|list| {
        list.len() == forced.len() && list.iter().zip(forced).all(|(v, f)| v.as_str() == Some(f.as_str()))
    })
}

fn check_security_opt(value: &serde_json::Value, policy: &Policy) -> std::result::Result<(), String> {
    if value.is_null() {
        return Ok(());
    }
    let list = value.as_array().ok_or_else(|| {
        format!(
            "HostConfig.SecurityOpt must be a list for service {}",
            policy.service_name
        )
    })?;
    let policy_opts = policy
        .container_config
        .as_ref()
        .and_then(|c| c.security_options.as_ref());
    for e in list {
        let s = match e.as_str() {
            Some(s) => s,
            None => {
                return Err(format!(
                    "HostConfig.SecurityOpt entry {} is not allowed for service {}",
                    e, policy.service_name
                ))
            }
        };
        if NO_NEW_PRIVILEGES.contains(&s) || policy_opts.is_some_and(|o| o.iter().any(|x| x == s)) {
            continue;
        }
        return Err(format!(
            "HostConfig.SecurityOpt entry {:?} is not allowed for service {}",
            s, policy.service_name
        ));
    }
    Ok(())
}

fn check_mode(
    key: &str,
    value: &serde_json::Value,
    allowed: &[&str],
    policy: &Policy,
) -> std::result::Result<(), String> {
    match value {
        serde_json::Value::Null => Ok(()),
        serde_json::Value::String(s) if s.is_empty() || allowed.contains(&s.as_str()) => Ok(()),
        serde_json::Value::String(s) => Err(format!(
            "HostConfig.{} value {:?} is not allowed for service {}",
            key, s, policy.service_name
        )),
        v => Err(format!(
            "HostConfig.{} value {} is not allowed for service {}",
            key, v, policy.service_name
        )),
    }
}

impl Gate for HostConfigGate {
    fn check(
        &self,
        _method: &str,
        _path: &str,
        policy: &Policy,
        body: &HashMap<String, serde_json::Value>,
    ) -> std::result::Result<(), String> {
        check_field_case("", body.keys(), CREATE_BODY_FIELDS, policy)?;
        // NetworkEndpointsGate and the mutator read
        // NetworkingConfig.EndpointsConfig by its exact name; the daemon would
        // also read "endpointsconfig".
        if let Some(nc) = body.get("NetworkingConfig").and_then(|v| v.as_object()) {
            check_field_case("NetworkingConfig.", nc.keys(), NETWORKING_CONFIG_FIELDS, policy)?;
        }

        let hc = match body.get("HostConfig") {
            None | Some(serde_json::Value::Null) => return Ok(()),
            Some(serde_json::Value::Object(hc)) => hc,
            Some(_) => {
                return Err(format!(
                    "HostConfig must be an object for service {}",
                    policy.service_name
                ))
            }
        };
        check_field_case("HostConfig.", hc.keys(), HOST_CONFIG_FIELDS, policy)?;

        for key in sorted_keys(hc.keys()) {
            let value = &hc[key.as_str()];
            match key.as_str() {
                // MountSourceGate.
                "Binds" | "Mounts" => {}
                k if HOST_CONFIG_ANY_VALUE.contains(&k) => {}
                "MaskedPaths" | "ReadonlyPaths" => {
                    if !value.is_null() {
                        return Err(format!(
                            "HostConfig.{} is not allowed for service {}",
                            key, policy.service_name
                        ));
                    }
                }
                "SecurityOpt" => check_security_opt(value, policy)?,
                // Zero, or exactly the policy's group_add, which the mutator
                // forces (#93). Checked here too so that the gate does not
                // open up if the mutator ever stops forcing it.
                "GroupAdd" => {
                    if !is_zero_value(value) && !equals_forced_groups(value, policy) {
                        return Err(format!(
                            "HostConfig.GroupAdd is not allowed for service {}",
                            policy.service_name
                        ));
                    }
                }
                "OomScoreAdj" => {
                    if !value.is_null() && !value.as_f64().is_some_and(|n| n >= 0.0) {
                        return Err(format!(
                            "HostConfig.OomScoreAdj value {} is not allowed for service {}",
                            value, policy.service_name
                        ));
                    }
                }
                k => {
                    if let Some(modes) = host_config_modes(k) {
                        check_mode(k, value, modes, policy)?;
                    } else if !is_zero_value(value) {
                        return Err(format!(
                            "HostConfig.{} is not allowed for service {}",
                            k, policy.service_name
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}

pub struct EnvFileGate;
impl Gate for EnvFileGate {
    fn check(
        &self,
        _method: &str,
        _path: &str,
        policy: &Policy,
        body: &HashMap<String, serde_json::Value>,
    ) -> std::result::Result<(), String> {
        let env_file = match &policy.env_file {
            Some(e) if !e.is_empty() => e,
            _ => return Ok(()),
        };

        if let Some(env) = body.get("Env").and_then(|v| v.as_array()) {
            if !env.is_empty() {
                return Err(format!(
                    "inline environment variables are not allowed for service {}; use env_file: {}",
                    policy.service_name, env_file
                ));
            }
        }

        if let Some(host_config) = body.get("HostConfig").and_then(|v| v.as_object()) {
            if let Some(env) = host_config.get("Env").and_then(|v| v.as_array()) {
                if !env.is_empty() {
                    return Err(format!(
                        "inline environment variables in HostConfig are not allowed for service {}; use env_file: {}",
                        policy.service_name, env_file
                    ));
                }
            }
        }

        Ok(())
    }
}

pub struct CmdGate;
impl Gate for CmdGate {
    fn check(
        &self,
        _method: &str,
        _path: &str,
        policy: &Policy,
        body: &HashMap<String, serde_json::Value>,
    ) -> std::result::Result<(), String> {
        let cmd = match body.get("Cmd").and_then(|v| v.as_array()) {
            Some(c) => c,
            None => return Ok(()),
        };

        let mut i = 0;
        while i < cmd.len() {
            let arg = cmd[i].as_str().unwrap_or("");
            if !charset_check(arg) {
                return Err(format!("Cmd argument {:?} contains invalid characters", arg));
            }
            if !arg.starts_with('-') {
                i += 1;
                continue;
            }
            let flag = arg.split('=').next().unwrap_or(arg);

            if let Some(denied) = &policy.denied_flags {
                if denied.contains(&flag.to_string()) {
                    return Err(format!("flag {:?} is denied for service {}", flag, policy.service_name));
                }
            }
            if let Some(allowed) = &policy.allowed_cli_flags {
                if !allowed.contains(&flag.to_string()) {
                    return Err(format!(
                        "flag {:?} is not in the allowlist for service {}",
                        flag, policy.service_name
                    ));
                }
            }

            let value = if let Some(eq_idx) = arg.find('=') {
                arg[eq_idx + 1..].to_string()
            } else if i + 1 < cmd.len() {
                let next = cmd[i + 1].as_str().unwrap_or("");
                if !next.starts_with('-') {
                    i += 1;
                    next.to_string()
                } else {
                    String::new()
                }
            } else {
                String::new()
            };

            if !value.is_empty() {
                if let Some(ref rules) = policy.flag_rules {
                    for rule in rules {
                        if rule.flag == flag {
                            let re = regex::Regex::new(&rule.value_pattern)
                                .map_err(|e| format!("invalid flag rule regex: {}", e))?;
                            if !re.is_match(&value) {
                                return Err(format!(
                                    "flag {} value {:?} does not match pattern {:?}",
                                    flag, value, rule.value_pattern
                                ));
                            }
                        }
                    }
                }
            }

            i += 1;
        }

        Ok(())
    }
}

/// The network mode the policy forces, if any (#87).
fn forced_network_mode(policy: &Policy) -> Option<&str> {
    policy
        .container_config
        .as_ref()
        .and_then(|cc| cc.network_mode.as_deref())
        .filter(|m| !m.is_empty())
}

/// NetworkingConfig.EndpointsConfig of a create body: Ok(None) when absent
/// or null, Err when NetworkingConfig or EndpointsConfig is not an object.
fn endpoints_config(
    body: &HashMap<String, serde_json::Value>,
) -> std::result::Result<Option<&serde_json::Map<String, serde_json::Value>>, ()> {
    match body.get("NetworkingConfig") {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Object(nc)) => match nc.get("EndpointsConfig") {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(serde_json::Value::Object(eps)) => Ok(Some(eps)),
            Some(_) => Err(()),
        },
        Some(_) => Err(()),
    }
}

/// A network mode in which the container joins no network of its own.
fn detached_network_mode(mode: &str) -> bool {
    mode == "host" || mode == "none" || mode.starts_with("container:")
}

/// When the policy forces network_mode M, every key in
/// NetworkingConfig.EndpointsConfig must be "default" or M (#87). Any other
/// key would attach the container to a network the policy does not allow.
/// ContainerConfigMutator leaves such a request unchanged, so this gate
/// sees what the caller sent.
pub struct NetworkEndpointsGate;
impl Gate for NetworkEndpointsGate {
    fn check(
        &self,
        _method: &str,
        _path: &str,
        policy: &Policy,
        body: &HashMap<String, serde_json::Value>,
    ) -> std::result::Result<(), String> {
        let mode = match forced_network_mode(policy) {
            Some(m) => m,
            None => return Ok(()),
        };
        let eps = match endpoints_config(body) {
            Ok(Some(eps)) => eps,
            Ok(None) => return Ok(()),
            Err(()) => {
                return Err(format!(
                    "NetworkingConfig.EndpointsConfig must be a JSON object; policy forces network_mode {}",
                    mode
                ))
            }
        };
        if let Some(k) = eps.keys().find(|k| k.as_str() != "default" && k.as_str() != mode) {
            return Err(format!(
                "network {:?} is not allowed for service {}; policy forces network_mode {}",
                k, policy.service_name, mode
            ));
        }
        Ok(())
    }
}

/// Make NetworkingConfig.EndpointsConfig consistent with the forced network
/// mode (#87): no entries for host, none and container:<id>; otherwise
/// exactly one entry keyed by the mode, with the settings of the caller's
/// entry for the mode, else of its "default" entry, else {}. A request that
/// NetworkEndpointsGate denies is left unchanged.
fn force_endpoints(mode: &str, body: &mut HashMap<String, serde_json::Value>) {
    let eps = match endpoints_config(body) {
        Ok(Some(eps)) => eps.clone(),
        Ok(None) => serde_json::Map::new(),
        Err(()) => return,
    };
    if eps.keys().any(|k| k.as_str() != "default" && k.as_str() != mode) {
        return;
    }
    let mut forced = serde_json::Map::new();
    if !detached_network_mode(mode) {
        let entry = eps
            .get(mode)
            .or_else(|| eps.get("default"))
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));
        forced.insert(mode.to_string(), entry);
    }
    let nc = body
        .entry("NetworkingConfig".to_string())
        .or_insert_with(|| serde_json::json!({}));
    if !nc.is_object() {
        *nc = serde_json::json!({});
    }
    if let Some(nc) = nc.as_object_mut() {
        nc.insert("EndpointsConfig".to_string(), serde_json::Value::Object(forced));
    }
}

/// ContainerConfigMutator overwrites the fields the policy's
/// `container_config` sets. It forces `HostConfig.Privileged` to false on
/// every create, even without a `container_config` (#88), and
/// `HostConfig.GroupAdd` to the policy's `group_add` when set (#93). A
/// `HostConfig` that
/// is not an object is left alone for HostConfigGate to deny.
pub struct ContainerConfigMutator;
impl Mutator for ContainerConfigMutator {
    fn mutate(&self, policy: &Policy, body: &mut HashMap<String, serde_json::Value>) {
        let host_config = body
            .entry("HostConfig".to_string())
            .or_insert_with(|| serde_json::Value::Object(Default::default()));
        if host_config.is_null() {
            *host_config = serde_json::Value::Object(Default::default());
        }
        let hc = match host_config.as_object_mut() {
            Some(hc) => hc,
            None => return,
        };
        hc.insert("Privileged".to_string(), serde_json::Value::Bool(false));

        let cc = match &policy.container_config {
            Some(c) => c,
            None => return,
        };

        if let Some(nm) = &cc.network_mode {
            hc.insert("NetworkMode".to_string(), serde_json::Value::String(nm.clone()));
        }
        if let Some(rp) = &cc.restart_policy {
            let rp_obj = serde_json::json!({"Name": rp});
            hc.insert("RestartPolicy".to_string(), rp_obj);
        }
        if let Some(so) = &cc.security_options {
            hc.insert(
                "SecurityOpt".to_string(),
                serde_json::Value::Array(so.iter().map(|s| serde_json::Value::String(s.clone())).collect()),
            );
        }
        if let Some(driver) = &cc.log_driver {
            hc.insert(
                "LogConfig".to_string(),
                serde_json::json!({"Type": driver, "Config": cc.log_options.clone().unwrap_or_default()}),
            );
        }
        // Overwritten like User (#93); HostConfigGate allows exactly this list.
        if let Some(groups) = cc.group_add.as_ref().filter(|g| !g.is_empty()) {
            hc.insert(
                "GroupAdd".to_string(),
                serde_json::Value::Array(groups.iter().map(|g| serde_json::Value::String(g.clone())).collect()),
            );
        }
        if let Some(u) = &cc.user {
            body.insert("User".to_string(), serde_json::Value::String(u.clone()));
        }
        if let Some(mode) = forced_network_mode(policy) {
            force_endpoints(mode, body);
        }
    }
}

fn make_policy(name: &str, prefixes: Vec<&str>) -> Policy {
    Policy {
        service_name: name.to_string(),
        container_names: None,
        user_id: None,
        group_id: None,
        allowed_image_prefixes: prefixes.iter().map(|s| s.to_string()).collect(),
        image_tag_pattern: None,
        image_digest_allowed: false,
        container_config: None,
        volumes: None,
        ports: None,
        env_file: None,
        allowed_cli_flags: None,
        flag_rules: None,
        denied_flags: None,
    }
}

fn body_from_json(json: serde_json::Value) -> HashMap<String, serde_json::Value> {
    serde_json::from_value(json).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_gate_allows_allowed_image() {
        let gate = RegistryGate;
        let policy = make_policy("test", vec!["alpine", "ubuntu"]);
        let body = body_from_json(serde_json::json!({"Image": "alpine:latest"}));
        assert!(gate.check("POST", "/containers/create", &policy, &body).is_ok());
    }

    #[test]
    fn test_registry_gate_allows_prefix_match() {
        let gate = RegistryGate;
        let policy = make_policy("test", vec!["myreg.io/team"]);
        let body = body_from_json(serde_json::json!({"Image": "myreg.io/team/myapp:v1"}));
        assert!(gate.check("POST", "/containers/create", &policy, &body).is_ok());
    }

    #[test]
    fn test_registry_gate_denies_unknown_image() {
        let gate = RegistryGate;
        let policy = make_policy("test", vec!["alpine"]);
        let body = body_from_json(serde_json::json!({"Image": "ubuntu:latest"}));
        let result = gate.check("POST", "/containers/create", &policy, &body);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not in allowed prefixes"));
    }

    #[test]
    fn test_registry_gate_no_image_field() {
        let gate = RegistryGate;
        let policy = make_policy("test", vec!["alpine"]);
        let body = HashMap::new();
        assert!(gate.check("POST", "/containers/create", &policy, &body).is_ok());
    }

    #[test]
    fn test_mount_source_gate_allows_allowed_volume() {
        let gate = MountSourceGate;
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.volumes = Some(vec![Volume {
            host_path: "/data".into(),
            container_path: "/data".into(),
            read_write: true,
        }]);
        let body = body_from_json(serde_json::json!({
            "HostConfig": {"Binds": ["/data:/data:rw"]}
        }));
        assert!(gate.check("POST", "/containers/create", &policy, &body).is_ok());
    }

    #[test]
    fn test_mount_source_gate_denies_unknown_volume() {
        let gate = MountSourceGate;
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.volumes = Some(vec![Volume {
            host_path: "/data".into(),
            container_path: "/data".into(),
            read_write: true,
        }]);
        let body = body_from_json(serde_json::json!({
            "HostConfig": {"Binds": ["/other:/other:rw"]}
        }));
        let result = gate.check("POST", "/containers/create", &policy, &body);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not in the whitelist"));
    }

    #[test]
    fn test_mount_source_gate_no_volumes_in_policy() {
        // A policy with no volumes allows no binds (#88); before #88 the gate
        // returned early and let every bind through.
        let gate = MountSourceGate;
        let policy = make_policy("test", vec!["alpine"]);
        let body = body_from_json(serde_json::json!({
            "HostConfig": {"Binds": ["/data:/data"]}
        }));
        let result = gate.check("POST", "/containers/create", &policy, &body);
        assert!(result.unwrap_err().contains("not in the whitelist"));
    }

    #[test]
    fn test_mount_source_gate_no_body_binds() {
        let gate = MountSourceGate;
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.volumes = Some(vec![Volume {
            host_path: "/data".into(),
            container_path: "/data".into(),
            read_write: true,
        }]);
        let body = HashMap::new();
        assert!(gate.check("POST", "/containers/create", &policy, &body).is_ok());
    }

    #[test]
    fn test_env_file_gate_allows_no_env_in_body() {
        let gate = EnvFileGate;
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.env_file = Some("/etc/env".into());
        let body = HashMap::new();
        assert!(gate.check("POST", "/containers/create", &policy, &body).is_ok());
    }

    #[test]
    fn test_env_file_gate_denies_inline_env() {
        let gate = EnvFileGate;
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.env_file = Some("/etc/env".into());
        let body = body_from_json(serde_json::json!({
            "Env": ["FOO=bar"]
        }));
        let result = gate.check("POST", "/containers/create", &policy, &body);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("env_file"));
    }

    #[test]
    fn test_env_file_gate_no_env_file_in_policy() {
        let gate = EnvFileGate;
        let policy = make_policy("test", vec!["alpine"]);
        let body = body_from_json(serde_json::json!({
            "Env": ["FOO=bar"]
        }));
        assert!(gate.check("POST", "/containers/create", &policy, &body).is_ok());
    }

    #[test]
    fn test_cmd_gate_valid_args() {
        let gate = CmdGate;
        let policy = make_policy("test", vec!["alpine"]);
        let body = body_from_json(serde_json::json!({
            "Cmd": ["nginx", "-g", "daemon_off"]
        }));
        assert!(gate.check("POST", "/containers/create", &policy, &body).is_ok());
    }

    #[test]
    fn test_cmd_gate_invalid_chars() {
        let gate = CmdGate;
        let policy = make_policy("test", vec!["alpine"]);
        let body = body_from_json(serde_json::json!({
            "Cmd": ["valid", "invalid\x00char"]
        }));
        let result = gate.check("POST", "/containers/create", &policy, &body);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid characters"));
    }

    #[test]
    fn test_cmd_gate_denied_flag() {
        let gate = CmdGate;
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.denied_flags = Some(vec!["--privileged".into()]);
        let body = body_from_json(serde_json::json!({
            "Cmd": ["--privileged"]
        }));
        let result = gate.check("POST", "/containers/create", &policy, &body);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("denied"));
    }

    #[test]
    fn test_cmd_gate_allowlisted_flag() {
        let gate = CmdGate;
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.allowed_cli_flags = Some(vec!["--cap-drop".into()]);
        let body = body_from_json(serde_json::json!({
            "Cmd": ["--cap-drop=ALL"]
        }));
        assert!(gate.check("POST", "/containers/create", &policy, &body).is_ok());
    }

    #[test]
    fn test_cmd_gate_not_in_allowlist() {
        let gate = CmdGate;
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.allowed_cli_flags = Some(vec!["--cap-drop".into()]);
        let body = body_from_json(serde_json::json!({
            "Cmd": ["--memory=256m"]
        }));
        let result = gate.check("POST", "/containers/create", &policy, &body);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not in the allowlist"));
    }

    #[test]
    fn test_cmd_gate_no_cmd_in_body() {
        let gate = CmdGate;
        let policy = make_policy("test", vec!["alpine"]);
        let body = HashMap::new();
        assert!(gate.check("POST", "/containers/create", &policy, &body).is_ok());
    }

    #[test]
    fn test_container_config_mutator_sets_network_mode() {
        let mutator = ContainerConfigMutator;
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.container_config = Some(ContainerConfig {
            network_mode: Some("host".into()),
            restart_policy: None,
            security_options: None,
            user: None,
            log_driver: None,
            log_options: None,
            group_add: None,
        });
        let mut body: HashMap<String, serde_json::Value> = HashMap::new();
        mutator.mutate(&policy, &mut body);
        let hc = body.get("HostConfig").unwrap().as_object().unwrap();
        assert_eq!(hc.get("NetworkMode").unwrap(), "host");
        assert_eq!(hc.get("Privileged").unwrap(), false);
    }

    #[test]
    fn test_container_config_mutator_sets_restart_policy() {
        let mutator = ContainerConfigMutator;
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.container_config = Some(ContainerConfig {
            network_mode: None,
            restart_policy: Some("unless-stopped".into()),
            security_options: None,
            user: None,
            log_driver: None,
            log_options: None,
            group_add: None,
        });
        let mut body = body_from_json(serde_json::json!({"HostConfig": {}}));
        mutator.mutate(&policy, &mut body);
        let hc = body.get("HostConfig").unwrap().as_object().unwrap();
        let rp = hc.get("RestartPolicy").unwrap();
        assert_eq!(rp.get("Name").unwrap(), "unless-stopped");
    }

    #[test]
    fn test_container_config_mutator_sets_user() {
        let mutator = ContainerConfigMutator;
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.container_config = Some(ContainerConfig {
            network_mode: None,
            restart_policy: None,
            security_options: None,
            user: Some("appuser".into()),
            log_driver: None,
            log_options: None,
            group_add: None,
        });
        let mut body = HashMap::new();
        mutator.mutate(&policy, &mut body);
        assert_eq!(body.get("User").unwrap(), "appuser");
    }

    #[test]
    fn test_container_config_mutator_noop_when_no_config() {
        // Without container_config the mutator still forces Privileged to
        // false, and sets nothing else (#88).
        let mutator = ContainerConfigMutator;
        let policy = make_policy("test", vec!["alpine"]);
        let mut body = HashMap::new();
        mutator.mutate(&policy, &mut body);
        assert_eq!(body.len(), 1);
        assert_eq!(
            body.get("HostConfig").unwrap(),
            &serde_json::json!({"Privileged": false})
        );
    }

    #[test]
    fn test_chain_execute_allows() {
        let chain = Chain::new();
        let policy = make_policy("test", vec!["alpine"]);
        let body = body_from_json(serde_json::json!({"Image": "alpine"}));
        let result = chain.execute("POST", "/containers/create", &policy, &body);
        assert!(result.allowed);
        assert_eq!(result.reason, "container create allowed");
    }

    #[test]
    fn test_chain_execute_denies_unknown_image_via_registry_gate() {
        let chain = Chain::new();
        let policy = make_policy("test", vec!["alpine"]);
        let body = body_from_json(serde_json::json!({"Image": "ubuntu"}));
        let result = chain.execute("POST", "/containers/create", &policy, &body);
        assert!(!result.allowed);
        assert!(result.reason.contains("not in allowed prefixes"));
    }

    #[test]
    fn test_chain_execute_with_mutator_sets_hostconfig() {
        let chain = Chain::new();
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.container_config = Some(ContainerConfig {
            network_mode: Some("bridge".into()),
            restart_policy: None,
            security_options: None,
            user: None,
            log_driver: None,
            log_options: None,
            group_add: None,
        });
        let body = body_from_json(serde_json::json!({"Image": "alpine"}));
        let result = chain.execute("POST", "/containers/create", &policy, &body);
        assert!(result.allowed);
        assert!(result.modified_body.is_some());
        let modified: HashMap<String, serde_json::Value> =
            serde_json::from_slice(&result.modified_body.unwrap()).unwrap();
        let hc = modified.get("HostConfig").unwrap().as_object().unwrap();
        assert_eq!(hc.get("NetworkMode").unwrap(), "bridge");
    }

    #[test]
    fn test_charset_check_valid() {
        assert!(charset_check("valid-string_123"));
        assert!(charset_check("a"));
    }

    #[test]
    fn test_charset_check_invalid() {
        assert!(!charset_check("string with spaces"));
        assert!(!charset_check("string\nwith\nnewlines"));
    }

    #[test]
    fn test_charset_check_too_long() {
        let long = "a".repeat(257);
        assert!(!charset_check(&long));
    }

    #[test]
    fn test_registry_gate_allows_tag_matching_pattern() {
        let gate = RegistryGate;
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.image_tag_pattern = Some("^v\\d+\\.\\d+$".into());
        let body = body_from_json(serde_json::json!({"Image": "alpine:v1.0"}));
        assert!(gate.check("POST", "/containers/create", &policy, &body).is_ok());
    }

    #[test]
    fn test_registry_gate_denies_tag_not_matching_pattern() {
        let gate = RegistryGate;
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.image_tag_pattern = Some("^v\\d+\\.\\d+$".into());
        let body = body_from_json(serde_json::json!({"Image": "alpine:latest"}));
        let result = gate.check("POST", "/containers/create", &policy, &body);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("does not match pattern"));
    }

    #[test]
    fn test_registry_gate_allows_digest_when_allowed() {
        let gate = RegistryGate;
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.image_digest_allowed = true;
        let body = body_from_json(
            serde_json::json!({"Image": "alpine@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"}),
        );
        assert!(gate.check("POST", "/containers/create", &policy, &body).is_ok());
    }

    #[test]
    fn test_registry_gate_denies_digest_when_not_allowed() {
        let gate = RegistryGate;
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.image_digest_allowed = false;
        let body = body_from_json(serde_json::json!({"Image": "alpine@sha256:abc123"}));
        let result = gate.check("POST", "/containers/create", &policy, &body);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("image digest"));
    }

    #[test]
    fn test_registry_gate_denies_invalid_digest_format() {
        let gate = RegistryGate;
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.image_digest_allowed = true;
        let body = body_from_json(serde_json::json!({"Image": "alpine@sha256:xyz"}));
        let result = gate.check("POST", "/containers/create", &policy, &body);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid digest"));
    }

    #[test]
    fn test_registry_gate_denies_tag_exceeds_128_chars() {
        let gate = RegistryGate;
        let policy = make_policy("test", vec!["alpine"]);
        let long_tag = "a".repeat(129);
        let body = body_from_json(serde_json::json!({"Image": format!("alpine:{}", long_tag)}));
        let result = gate.check("POST", "/containers/create", &policy, &body);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("128"));
    }

    #[test]
    fn test_cmd_gate_flag_rule_matches() {
        let gate = CmdGate;
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.flag_rules = Some(vec![FlagRule {
            flag: "--memory".into(),
            value_pattern: "^\\d+m$".into(),
        }]);
        let body = body_from_json(serde_json::json!({
            "Cmd": ["--memory=256m"]
        }));
        assert!(gate.check("POST", "/containers/create", &policy, &body).is_ok());
    }

    #[test]
    fn test_cmd_gate_flag_rule_does_not_match() {
        let gate = CmdGate;
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.flag_rules = Some(vec![FlagRule {
            flag: "--memory".into(),
            value_pattern: "^\\d+m$".into(),
        }]);
        let body = body_from_json(serde_json::json!({
            "Cmd": ["--memory=256g"]
        }));
        let result = gate.check("POST", "/containers/create", &policy, &body);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("does not match pattern"));
    }

    #[test]
    fn test_cmd_gate_flag_rule_with_next_arg_value() {
        let gate = CmdGate;
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.flag_rules = Some(vec![FlagRule {
            flag: "--memory".into(),
            value_pattern: "^\\d+m$".into(),
        }]);
        let body = body_from_json(serde_json::json!({
            "Cmd": ["--memory", "256m"]
        }));
        assert!(gate.check("POST", "/containers/create", &policy, &body).is_ok());
    }

    #[test]
    fn test_cmd_gate_flag_rule_skips_next_arg() {
        let gate = CmdGate;
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.flag_rules = Some(vec![FlagRule {
            flag: "--memory".into(),
            value_pattern: "^\\d+m$".into(),
        }]);
        let body = body_from_json(serde_json::json!({
            "Cmd": ["--memory", "256m", "--cap-drop=ALL"]
        }));
        assert!(gate.check("POST", "/containers/create", &policy, &body).is_ok());
    }

    #[test]
    fn test_mount_source_gate_denies_unknown_volume_in_top_level_volumes() {
        let gate = MountSourceGate;
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.volumes = Some(vec![Volume {
            host_path: "/data".into(),
            container_path: "/data".into(),
            read_write: true,
        }]);
        let body = body_from_json(serde_json::json!({
            "Volumes": {"/other": {}}
        }));
        let result = gate.check("POST", "/containers/create", &policy, &body);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not in the whitelist"));
    }

    #[test]
    fn test_mount_source_gate_allows_volume_in_top_level_volumes() {
        let gate = MountSourceGate;
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.volumes = Some(vec![Volume {
            host_path: "/data".into(),
            container_path: "/data".into(),
            read_write: true,
        }]);
        let body = body_from_json(serde_json::json!({
            "Volumes": {"/data": {}}
        }));
        assert!(gate.check("POST", "/containers/create", &policy, &body).is_ok());
    }

    #[test]
    fn test_env_file_gate_denies_host_config_env() {
        let gate = EnvFileGate;
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.env_file = Some("/etc/env".into());
        let body = body_from_json(serde_json::json!({
            "HostConfig": {"Env": ["FOO=bar"]}
        }));
        let result = gate.check("POST", "/containers/create", &policy, &body);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("HostConfig"));
    }

    #[test]
    fn test_env_file_gate_allows_empty_host_config_env() {
        let gate = EnvFileGate;
        let mut policy = make_policy("test", vec!["alpine"]);
        policy.env_file = Some("/etc/env".into());
        let body = body_from_json(serde_json::json!({
            "HostConfig": {"Env": []}
        }));
        assert!(gate.check("POST", "/containers/create", &policy, &body).is_ok());
    }

    /// When the policy forces network_mode, the endpoint entries in
    /// NetworkingConfig.EndpointsConfig are made consistent with it (#87).
    /// Before #87 they went through as sent, so the Docker CLI's
    /// {"default": {}} made the start fail with "network default not found",
    /// and an extra entry attached the container to a network the policy does
    /// not allow. Rows mirror the runs in the network_endpoints module of
    /// spec/docker_socket_policy.qnt; mynet stands for a named network and
    /// container:beacon for container:x.
    #[test]
    fn test_chain_network_endpoints() {
        let aliases = r#"{"Aliases":["a"]}"#;
        let ec = |entries: &str| format!(r#"{{"EndpointsConfig":{{{}}}}}"#, entries);
        let extra = |mode: &str| {
            format!(
                r#"network "other" is not allowed for service test; policy forces network_mode {}"#,
                mode
            )
        };
        let malformed = "NetworkingConfig.EndpointsConfig must be a JSON object; policy forces network_mode host";
        let both = ec(r#""default":{},"other":{}"#);
        // (row, forced mode ("" = none), NetworkingConfig sent ("" = absent),
        //  NetworkingConfig forwarded when allowed, deny reason when denied)
        let cases: Vec<(&str, &str, String, String, String)> = vec![
            ("hostNoEndpoints", "host", String::new(), ec(""), String::new()),
            (
                "hostDefaultCleared",
                "host",
                ec(r#""default":{}"#),
                ec(""),
                String::new(),
            ),
            (
                "hostOwnCleared",
                "host",
                ec(&format!(r#""host":{}"#, aliases)),
                ec(""),
                String::new(),
            ),
            ("hostExtraDenied", "host", both.clone(), String::new(), extra("host")),
            ("noneNoEndpoints", "none", String::new(), ec(""), String::new()),
            (
                "noneDefaultCleared",
                "none",
                ec(r#""default":{}"#),
                ec(""),
                String::new(),
            ),
            (
                "noneOwnCleared",
                "none",
                ec(&format!(r#""none":{}"#, aliases)),
                ec(""),
                String::new(),
            ),
            ("noneExtraDenied", "none", both.clone(), String::new(), extra("none")),
            (
                "containerNoEndpoints",
                "container:beacon",
                String::new(),
                ec(""),
                String::new(),
            ),
            (
                "containerDefaultCleared",
                "container:beacon",
                ec(r#""default":{}"#),
                ec(""),
                String::new(),
            ),
            (
                "containerOwnCleared",
                "container:beacon",
                ec(&format!(r#""container:beacon":{}"#, aliases)),
                ec(""),
                String::new(),
            ),
            (
                "containerExtraDenied",
                "container:beacon",
                both.clone(),
                String::new(),
                extra("container:beacon"),
            ),
            (
                "bridgeNoEndpoints",
                "bridge",
                String::new(),
                ec(r#""bridge":{}"#),
                String::new(),
            ),
            (
                "bridgeDefaultRekeyed",
                "bridge",
                ec(&format!(r#""default":{}"#, aliases)),
                ec(&format!(r#""bridge":{}"#, aliases)),
                String::new(),
            ),
            (
                "bridgeOwnKept",
                "bridge",
                ec(&format!(r#""bridge":{}"#, aliases)),
                ec(&format!(r#""bridge":{}"#, aliases)),
                String::new(),
            ),
            (
                "bridgeExtraDenied",
                "bridge",
                both.clone(),
                String::new(),
                extra("bridge"),
            ),
            (
                "namedNoEndpoints",
                "mynet",
                String::new(),
                ec(r#""mynet":{}"#),
                String::new(),
            ),
            (
                "namedDefaultRekeyed",
                "mynet",
                ec(&format!(r#""default":{}"#, aliases)),
                ec(&format!(r#""mynet":{}"#, aliases)),
                String::new(),
            ),
            (
                "namedOwnKept",
                "mynet",
                ec(&format!(r#""mynet":{}"#, aliases)),
                ec(&format!(r#""mynet":{}"#, aliases)),
                String::new(),
            ),
            ("namedExtraDenied", "mynet", both.clone(), String::new(), extra("mynet")),
            (
                "namedOwnOverDefault",
                "mynet",
                ec(&format!(r#""default":{},"mynet":{{}}"#, aliases)),
                ec(r#""mynet":{}"#),
                String::new(),
            ),
            // #87: a null NetworkingConfig or EndpointsConfig counts as absent.
            (
                "#87 null NetworkingConfig",
                "host",
                "null".into(),
                ec(""),
                String::new(),
            ),
            (
                "#87 null EndpointsConfig",
                "bridge",
                r#"{"EndpointsConfig":null}"#.into(),
                ec(r#""bridge":{}"#),
                String::new(),
            ),
            // #87: a NetworkingConfig or EndpointsConfig that is not an object is denied.
            (
                "#87 EndpointsConfig array",
                "host",
                r#"{"EndpointsConfig":[]}"#.into(),
                String::new(),
                malformed.into(),
            ),
            (
                "#87 NetworkingConfig string",
                "host",
                r#""default""#.into(),
                String::new(),
                malformed.into(),
            ),
            // #87 control: without a forced network_mode, NetworkingConfig is untouched.
            ("#87 no forced mode", "", both.clone(), both.clone(), String::new()),
        ];
        let chain = Chain::new();
        let mut mismatches = Vec::new();
        for (row, mode, req, want, deny) in cases {
            let mut policy = make_policy("test", vec!["alpine"]);
            policy.container_config = Some(ContainerConfig {
                network_mode: if mode.is_empty() { None } else { Some(mode.into()) },
                restart_policy: Some("unless-stopped".into()),
                security_options: None,
                user: None,
                log_driver: None,
                log_options: None,
                group_add: None,
            });
            let mut body = body_from_json(serde_json::json!({"Image": "alpine:3.20"}));
            if !req.is_empty() {
                body.insert("NetworkingConfig".into(), serde_json::from_str(&req).unwrap());
            }
            let result = chain.execute("POST", "/containers/create", &policy, &body);
            if !deny.is_empty() {
                if result.allowed || !result.reason.contains(&deny) {
                    mismatches.push(format!(
                        "{}: got allowed={} {:?}, want deny {:?}",
                        row, result.allowed, result.reason, deny
                    ));
                }
                continue;
            }
            if !result.allowed {
                mismatches.push(format!("{}: got deny {:?}, want {}", row, result.reason, want));
                continue;
            }
            let out: HashMap<String, serde_json::Value> =
                serde_json::from_slice(&result.modified_body.unwrap()).unwrap();
            let want_v: serde_json::Value = serde_json::from_str(&want).unwrap();
            let got = out.get("NetworkingConfig").cloned().unwrap_or(serde_json::Value::Null);
            if got != want_v {
                mismatches.push(format!("{}: got {}, want {}", row, got, want));
            }
        }
        assert!(
            mismatches.is_empty(),
            "{} mismatches:\n{}",
            mismatches.len(),
            mismatches.join("\n")
        );
    }

    /// Pins the registry gate's reference parser (#84): a registry port is
    /// not a tag, Docker Hub spellings match the normalised prefix, and the
    /// tag pattern sees only the tag. The policy's prefixes are normalised,
    /// as the manager stores them. Same rows in Go and TypeScript.
    #[test]
    fn test_registry_gate_parses_references() {
        let gate = RegistryGate;
        let mut policy = make_policy(
            "test",
            vec![
                "chainsafe/lodestar",
                "localhost:5000/team",
                "registry.example.com:443/a",
            ],
        );
        policy.image_tag_pattern = Some("^(v[0-9]+|[0-9.]+)$".into());
        let cases = [
            ("localhost:5000/team/app:1.2", None),
            ("localhost:5000/team/app", None),
            ("docker.io/chainsafe/lodestar:v1", None),
            ("registry.example.com:443/a", None),
            ("Registry.Example.com:443/a:2", None),
            (
                "localhost:5000/team/app:latest",
                Some(r#"image tag "latest" does not match pattern "^(v[0-9]+|[0-9.]+)$""#),
            ),
            (
                "localhost:5000/other:1",
                Some(r#"image "localhost:5000/other" is not in allowed prefixes"#),
            ),
            (
                "chainsafe/Lodestar:v1",
                Some(r#"invalid image reference "chainsafe/Lodestar:v1""#),
            ),
        ];
        let mut mismatches = Vec::new();
        for (image, want_err) in cases {
            let body = body_from_json(serde_json::json!({ "Image": image }));
            let got = gate.check("POST", "/containers/create", &policy, &body);
            let ok = match (&got, want_err) {
                (Ok(()), None) => true,
                (Err(e), Some(want)) => e.contains(want),
                _ => false,
            };
            if !ok {
                mismatches.push(format!("{}: got {:?}, want {:?}", image, got, want_err));
            }
        }
        assert!(
            mismatches.is_empty(),
            "registry gate mismatches:\n{}",
            mismatches.join("\n")
        );
    }
    // HostConfig default-deny, Mounts and bind-mode rows (#88). The same rows,
    // by name, are in go/internal/middleware/hostconfig_test.go and
    // ts/src/middleware.test.ts.
    //
    // Policies: "std" has volumes /data (read_write) and /ro (read-only) and
    // forces network_mode host; "secopt" is "std" plus security_options
    // [no-new-privileges:true]; "bare" has no volumes and no
    // container_config; "groups" is "std" plus group_add ["64190", "jwt"]
    // (#93). `want` is "" for an allowed create, or a substring of
    // the deny reason. `fwd`, when set, lists HostConfig fields the forwarded
    // body must hold.
    struct HostConfigRow {
        name: &'static str,
        policy: &'static str,
        body: &'static str,
        want: &'static str,
        fwd: &'static str,
    }

    fn host_config_row_policy(name: &str) -> Policy {
        let mut p = make_policy("svc", vec!["chainsafe/lodestar"]);
        if name == "bare" {
            return p;
        }
        p.volumes = Some(vec![
            Volume {
                host_path: "/data".into(),
                container_path: "/data".into(),
                read_write: true,
            },
            Volume {
                host_path: "/ro".into(),
                container_path: "/ro".into(),
                read_write: false,
            },
        ]);
        p.container_config = Some(ContainerConfig {
            network_mode: Some("host".into()),
            restart_policy: None,
            security_options: if name == "secopt" {
                Some(vec!["no-new-privileges:true".into()])
            } else {
                None
            },
            user: None,
            log_driver: None,
            log_options: None,
            group_add: if name == "groups" {
                Some(vec!["64190".into(), "jwt".into()])
            } else {
                None
            },
        });
        p
    }

    #[test]
    fn test_host_config_rows() {
        let chain = Chain::new();
        let mut failures = Vec::new();
        for row in HOST_CONFIG_ROWS {
            let body: HashMap<String, serde_json::Value> = serde_json::from_str(row.body).unwrap();
            let result = chain.execute("POST", "/containers/create", &host_config_row_policy(row.policy), &body);
            if row.want.is_empty() {
                if !result.allowed {
                    failures.push(format!("{}: expected allow, got: {}", row.name, result.reason));
                    continue;
                }
            } else {
                if result.allowed || !result.reason.contains(row.want) {
                    failures.push(format!(
                        "{}: expected deny with {:?}, got allowed={} {}",
                        row.name, row.want, result.allowed, result.reason
                    ));
                }
                continue;
            }
            if row.fwd.is_empty() {
                continue;
            }
            let want: serde_json::Map<String, serde_json::Value> = serde_json::from_str(row.fwd).unwrap();
            let forwarded: serde_json::Value = serde_json::from_slice(&result.modified_body.unwrap()).unwrap();
            for (k, v) in &want {
                if forwarded["HostConfig"].get(k) != Some(v) {
                    failures.push(format!(
                        "{}: forwarded HostConfig.{} = {:?}, want {}",
                        row.name,
                        k,
                        forwarded["HostConfig"].get(k),
                        v
                    ));
                }
            }
        }
        assert!(
            failures.is_empty(),
            "{} rows failed:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    // HostConfigGate alone, on the "groups" policy (#93): as if the mutator
    // stopped forcing the list. Only the policy's list, exactly, or a zero
    // value passes. The same rows, by name, are in
    // go/internal/middleware/hostconfig_test.go and ts/src/middleware.test.ts.
    #[test]
    fn test_group_add_gate_rows() {
        let rows: &[(&str, &str, &str)] = &[
            (
                "groupAddGateForcedListAllowed",
                r##"{"HostConfig":{"GroupAdd":["64190","jwt"]}}"##,
                "",
            ),
            ("groupAddGateEmptyAllowed", r##"{"HostConfig":{"GroupAdd":[]}}"##, ""),
            ("groupAddGateNullAllowed", r##"{"HostConfig":{"GroupAdd":null}}"##, ""),
            (
                "groupAddGateOtherListDenied",
                r##"{"HostConfig":{"GroupAdd":["docker"]}}"##,
                "HostConfig.GroupAdd is not allowed for service svc",
            ),
            (
                "groupAddGateReorderedDenied",
                r##"{"HostConfig":{"GroupAdd":["jwt","64190"]}}"##,
                "HostConfig.GroupAdd is not allowed for service svc",
            ),
            (
                "groupAddGateSubsetDenied",
                r##"{"HostConfig":{"GroupAdd":["64190"]}}"##,
                "HostConfig.GroupAdd is not allowed for service svc",
            ),
            (
                "groupAddGateSupersetDenied",
                r##"{"HostConfig":{"GroupAdd":["64190","jwt","0"]}}"##,
                "HostConfig.GroupAdd is not allowed for service svc",
            ),
            (
                "groupAddGateNumberDenied",
                r##"{"HostConfig":{"GroupAdd":[64190,"jwt"]}}"##,
                "HostConfig.GroupAdd is not allowed for service svc",
            ),
            (
                "groupAddGateStringDenied",
                r##"{"HostConfig":{"GroupAdd":"64190"}}"##,
                "HostConfig.GroupAdd is not allowed for service svc",
            ),
        ];
        let policy = host_config_row_policy("groups");
        let mut failures = Vec::new();
        for (name, body, want) in rows {
            let body: HashMap<String, serde_json::Value> = serde_json::from_str(body).unwrap();
            match (
                HostConfigGate.check("POST", "/containers/create", &policy, &body),
                *want,
            ) {
                (Ok(()), "") => {}
                (Ok(()), want) => failures.push(format!("{name}: expected deny with {want:?}, got allow")),
                (Err(e), "") => failures.push(format!("{name}: expected allow, got: {e}")),
                (Err(e), want) if !e.contains(want) => {
                    failures.push(format!("{name}: expected deny with {want:?}, got: {e}"))
                }
                _ => {}
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    const HOST_CONFIG_ROWS: &[HostConfigRow] = &[
        HostConfigRow {
            name: "capAddDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"CapAdd":["SYS_ADMIN"]}}"##,
            want: "HostConfig.CapAdd is not allowed for service svc",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "devicesDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Devices":[{"PathOnHost":"/dev/sda","PathInContainer":"/dev/sda","CgroupPermissions":"rwm"}]}}"##,
            want: "HostConfig.Devices is not allowed for service svc",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "deviceRequestsDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"DeviceRequests":[{"Driver":"","Count":-1,"Capabilities":[["gpu"]]}]}}"##,
            want: "HostConfig.DeviceRequests is not allowed for service svc",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "deviceCgroupRulesDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"DeviceCgroupRules":["b 8:* rmw"]}}"##,
            want: "HostConfig.DeviceCgroupRules is not allowed for service svc",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "groupAddDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"GroupAdd":["docker"]}}"##,
            want: "HostConfig.GroupAdd is not allowed for service svc",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "groupAddPolicyListWithoutGroupAddDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"GroupAdd":["64190","jwt"]}}"##,
            want: "HostConfig.GroupAdd is not allowed for service svc",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "groupAddForced",
            policy: "groups",
            body: r##"{"Image":"chainsafe/lodestar:v1"}"##,
            want: "",
            fwd: r##"{"GroupAdd":["64190","jwt"]}"##,
        },
        HostConfigRow {
            name: "groupAddForcedNullHostConfig",
            policy: "groups",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":null}"##,
            want: "",
            fwd: r##"{"GroupAdd":["64190","jwt"]}"##,
        },
        HostConfigRow {
            name: "groupAddCallerReplaced",
            policy: "groups",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"GroupAdd":["docker","0"]}}"##,
            want: "",
            fwd: r##"{"GroupAdd":["64190","jwt"]}"##,
        },
        HostConfigRow {
            name: "groupAddCallerNullReplaced",
            policy: "groups",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"GroupAdd":null}}"##,
            want: "",
            fwd: r##"{"GroupAdd":["64190","jwt"]}"##,
        },
        HostConfigRow {
            name: "groupAddSameListUnchanged",
            policy: "groups",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"GroupAdd":["64190","jwt"]}}"##,
            want: "",
            fwd: r##"{"GroupAdd":["64190","jwt"]}"##,
        },
        HostConfigRow {
            name: "groupAddCaseVariantDenied",
            policy: "groups",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"groupadd":["0"]}}"##,
            want: "HostConfig.groupadd is not allowed for service svc",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "groupAddNonObjectHostConfigDenied",
            policy: "groups",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":["GroupAdd"]}"##,
            want: "HostConfig must be an object for service svc",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "volumesFromDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"VolumesFrom":["other"]}}"##,
            want: "HostConfig.VolumesFrom is not allowed for service svc",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "linksDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Links":["other:alias"]}}"##,
            want: "HostConfig.Links is not allowed for service svc",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "sysctlsDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Sysctls":{"kernel.shm_rmid_forced":"1"}}}"##,
            want: "HostConfig.Sysctls is not allowed for service svc",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "cgroupParentDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"CgroupParent":"/"}}"##,
            want: "HostConfig.CgroupParent is not allowed for service svc",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "runtimeDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Runtime":"other"}}"##,
            want: "HostConfig.Runtime is not allowed for service svc",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "volumeDriverDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"VolumeDriver":"local"}}"##,
            want: "HostConfig.VolumeDriver is not allowed for service svc",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "oomKillDisableDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"OomKillDisable":true}}"##,
            want: "HostConfig.OomKillDisable is not allowed for service svc",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "annotationsDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Annotations":{"a":"b"}}}"##,
            want: "HostConfig.Annotations is not allowed for service svc",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "storageOptDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"StorageOpt":{"size":"1G"}}}"##,
            want: "HostConfig.StorageOpt is not allowed for service svc",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "blkioDeviceReadBpsDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"BlkioDeviceReadBps":[{"Path":"/dev/sda","Rate":1}]}}"##,
            want: "HostConfig.BlkioDeviceReadBps is not allowed for service svc",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "cpuRealtimeRuntimeDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"CpuRealtimeRuntime":1000}}"##,
            want: "HostConfig.CpuRealtimeRuntime is not allowed for service svc",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "unknownFieldDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"FutureField":true}}"##,
            want: "HostConfig.FutureField is not allowed for service svc",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "maskedPathsEmptyDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"MaskedPaths":[]}}"##,
            want: "HostConfig.MaskedPaths is not allowed for service svc",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "readonlyPathsEmptyDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"ReadonlyPaths":[]}}"##,
            want: "HostConfig.ReadonlyPaths is not allowed for service svc",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "maskedPathsListDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"MaskedPaths":["/proc/kcore"]}}"##,
            want: "HostConfig.MaskedPaths is not allowed for service svc",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "zeroValuesAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"CapAdd":null,"Devices":[],"GroupAdd":null,"Sysctls":{},"CgroupParent":"","OomKillDisable":false,"Runtime":"","VolumeDriver":"","FutureField":0,"MaskedPaths":null,"ReadonlyPaths":null,"PidMode":"","IpcMode":"","SecurityOpt":null,"OomScoreAdj":0,"Privileged":false}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "pidModeHostDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"PidMode":"host"}}"##,
            want: "HostConfig.PidMode value \"host\" is not allowed for service svc",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "pidModeContainerDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"PidMode":"container:abc"}}"##,
            want: "HostConfig.PidMode value \"container:abc\" is not allowed",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "ipcModeHostDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"IpcMode":"host"}}"##,
            want: "HostConfig.IpcMode value \"host\" is not allowed",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "ipcModeContainerDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"IpcMode":"container:abc"}}"##,
            want: "HostConfig.IpcMode value \"container:abc\" is not allowed",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "utsModeHostDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"UTSMode":"host"}}"##,
            want: "HostConfig.UTSMode value \"host\" is not allowed",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "usernsModeHostDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"UsernsMode":"host"}}"##,
            want: "HostConfig.UsernsMode value \"host\" is not allowed",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "cgroupnsModeHostDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"CgroupnsMode":"host"}}"##,
            want: "HostConfig.CgroupnsMode value \"host\" is not allowed",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "cgroupContainerDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Cgroup":"container:abc"}}"##,
            want: "HostConfig.Cgroup value \"container:abc\" is not allowed",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "isolationHypervDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Isolation":"hyperv"}}"##,
            want: "HostConfig.Isolation value \"hyperv\" is not allowed",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "ipcModePrivateAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"IpcMode":"private"}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "ipcModeShareableAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"IpcMode":"shareable"}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "ipcModeNoneAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"IpcMode":"none"}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "cgroupnsModePrivateAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"CgroupnsMode":"private"}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "isolationDefaultAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Isolation":"default"}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "oomScoreAdjNegativeDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"OomScoreAdj":-1000}}"##,
            want: "HostConfig.OomScoreAdj value -1000 is not allowed",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "oomScoreAdjPositiveAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"OomScoreAdj":500}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "securityOptSeccompUnconfinedDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"SecurityOpt":["seccomp=unconfined"]}}"##,
            want: "HostConfig.SecurityOpt entry \"seccomp=unconfined\" is not allowed",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "securityOptApparmorUnconfinedDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"SecurityOpt":["apparmor=unconfined"]}}"##,
            want: "HostConfig.SecurityOpt entry \"apparmor=unconfined\" is not allowed",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "securityOptLabelDisableDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"SecurityOpt":["label=disable"]}}"##,
            want: "HostConfig.SecurityOpt entry \"label=disable\" is not allowed",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "securityOptNoNewPrivilegesFalseDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"SecurityOpt":["no-new-privileges:false"]}}"##,
            want: "HostConfig.SecurityOpt entry \"no-new-privileges:false\" is not allowed",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "securityOptNoNewPrivilegesAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"SecurityOpt":["no-new-privileges"]}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "securityOptNoNewPrivilegesTrueAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"SecurityOpt":["no-new-privileges:true"]}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "securityOptOverwrittenByPolicy",
            policy: "secopt",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"SecurityOpt":["seccomp=unconfined"]}}"##,
            want: "",
            fwd: r##"{"SecurityOpt":["no-new-privileges:true"]}"##,
        },
        HostConfigRow {
            name: "caseVariantPrivilegedDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"privileged":true}}"##,
            want: "HostConfig.privileged is not allowed for service svc (the daemon reads it as HostConfig.Privileged)",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "caseVariantZeroSecurityOptDenied",
            policy: "secopt",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"securityopt":null}}"##,
            want: "HostConfig.securityopt is not allowed",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "caseVariantBindsDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"binds":["/:/host"]}}"##,
            want: "HostConfig.binds is not allowed",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "caseVariantLongSDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"\u017fecurityOpt":["seccomp=unconfined"]}}"##,
            want: "(the daemon reads it as HostConfig.SecurityOpt)",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "caseVariantKelvinDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Lin\u212as":["other:alias"]}}"##,
            want: "(the daemon reads it as HostConfig.Links)",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "topLevelHostConfigVariantDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","hostConfig":{"Privileged":true}}"##,
            want: "hostConfig is not allowed for service svc (the daemon reads it as HostConfig)",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "topLevelUserVariantDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","user":"root"}"##,
            want: "user is not allowed for service svc (the daemon reads it as User)",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "topLevelImageVariantDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","image":"alpine:3.20"}"##,
            want: "image is not allowed for service svc (the daemon reads it as Image)",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "networkingConfigVariantDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","NetworkingConfig":{"EndpointsConfig":{"default":{}},"endpointsconfig":{"evil-net":{}}}}"##,
            want: "NetworkingConfig.endpointsconfig is not allowed for service svc (the daemon reads it as NetworkingConfig.EndpointsConfig)",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "networkingConfigVariantBareDenied",
            policy: "bare",
            body: r##"{"Image":"chainsafe/lodestar:v1","NetworkingConfig":{"EndpointsConfig":{"default":{}},"endpointsconfig":{"evil-net":{}}}}"##,
            want: "NetworkingConfig.endpointsconfig is not allowed for service svc",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "networkingConfigVariantLongSDenied",
            policy: "bare",
            body: r##"{"Image":"chainsafe/lodestar:v1","NetworkingConfig":{"Endpoint\u017fConfig":{"evil-net":{}}}}"##,
            want: "(the daemon reads it as NetworkingConfig.EndpointsConfig)",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "networkingConfigUnforcedAllowed",
            policy: "bare",
            body: r##"{"Image":"chainsafe/lodestar:v1","NetworkingConfig":{"EndpointsConfig":{"default":{},"other":{}}}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "hostConfigNotObjectDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":"x"}"##,
            want: "HostConfig must be an object",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "capDropAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"CapDrop":["ALL"]}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "readonlyRootfsAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"ReadonlyRootfs":true}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "initAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Init":true}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "autoRemoveAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"AutoRemove":true}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "consoleSizeAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"ConsoleSize":[24,80]}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "shmSizeAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"ShmSize":67108864}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "portBindingsAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"PortBindings":{"8080/tcp":[{"HostIp":"127.0.0.1","HostPort":"8080"}]}}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "publishAllPortsAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"PublishAllPorts":true}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "dnsAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Dns":["1.1.1.1"]}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "dnsOptionsAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"DnsOptions":["ndots:1"]}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "dnsSearchAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"DnsSearch":["example.com"]}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "extraHostsAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"ExtraHosts":["host:10.0.0.1"]}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "tmpfsAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Tmpfs":{"/run":"rw,noexec"}}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "ulimitsAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Ulimits":[{"Name":"nofile","Soft":1024,"Hard":2048}]}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "memoryAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Memory":268435456}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "memoryReservationAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"MemoryReservation":134217728}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "memorySwapAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"MemorySwap":-1}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "memorySwappinessAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"MemorySwappiness":-1}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "nanoCpusAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"NanoCpus":500000000}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "cpuSharesAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"CpuShares":512}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "cpuPeriodAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"CpuPeriod":100000}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "cpuQuotaAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"CpuQuota":50000}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "cpusetCpusAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"CpusetCpus":"0-1"}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "cpusetMemsAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"CpusetMems":"0"}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "pidsLimitAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"PidsLimit":100}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "blkioWeightAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"BlkioWeight":10}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "containerIdFileAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"ContainerIDFile":"/tmp/cid"}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "networkModeAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"NetworkMode":"bridge"}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "restartPolicyAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"RestartPolicy":{"Name":"always","MaximumRetryCount":0}}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "logConfigAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"LogConfig":{"Type":"json-file","Config":{"max-size":"10m"}}}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "privilegedNeutralised",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Privileged":true}}"##,
            want: "",
            fwd: r##"{"Privileged":false}"##,
        },
        HostConfigRow {
            name: "privilegedNeutralisedEmptyContainerConfig",
            policy: "bare",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Privileged":true}}"##,
            want: "",
            fwd: r##"{"Privileged":false}"##,
        },
        HostConfigRow {
            name: "emptyContainerConfigForcesPrivilegedFalse",
            policy: "bare",
            body: r##"{"Image":"chainsafe/lodestar:v1"}"##,
            want: "",
            fwd: r##"{"Privileged":false}"##,
        },
        HostConfigRow {
            name: "mountBindRootDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"bind","Source":"/","Target":"/host"}]}}"##,
            want: "mount source \"/\" is not in the whitelist for service svc",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "mountBindAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"bind","Source":"/data","Target":"/data"}]}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "mountBindReadOnlyVolumeWritableDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"bind","Source":"/ro","Target":"/ro"}]}}"##,
            want: "mount of \"/ro\" must be read-only (ReadOnly: true) for service svc",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "mountBindReadOnlyVolumeReadOnlyFalseDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"bind","Source":"/ro","Target":"/ro","ReadOnly":false}]}}"##,
            want: "mount of \"/ro\" must be read-only",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "mountBindReadOnlyVolumeReadOnlyAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"bind","Source":"/ro","Target":"/ro","ReadOnly":true}]}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "mountVolumeTypeDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"volume","Source":"myvol","Target":"/v"}]}}"##,
            want: "mount type \"volume\" is not allowed for service svc",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "mountImageTypeDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"image","Source":"alpine:3.20","Target":"/i"}]}}"##,
            want: "mount type \"image\" is not allowed",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "mountNpipeTypeDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"npipe","Source":"//./pipe/docker_engine","Target":"/p"}]}}"##,
            want: "mount type \"npipe\" is not allowed",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "mountMissingTypeDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Source":"/data","Target":"/data"}]}}"##,
            want: "mount type \"\" is not allowed",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "mountTmpfsAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"tmpfs","Target":"/run","TmpfsOptions":{"SizeBytes":1048576}}]}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "mountTmpfsWithSourceDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"tmpfs","Source":"/","Target":"/run"}]}}"##,
            want: "tmpfs mount must not have a Source",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "mountPropagationRsharedDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"bind","Source":"/data","Target":"/data","BindOptions":{"Propagation":"rshared"}}]}}"##,
            want: "mount propagation \"rshared\" is not allowed",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "mountPropagationSlaveDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"bind","Source":"/data","Target":"/data","BindOptions":{"Propagation":"slave"}}]}}"##,
            want: "mount propagation \"slave\" is not allowed",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "mountPropagationRprivateAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"bind","Source":"/data","Target":"/data","BindOptions":{"Propagation":"rprivate"}}]}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "mountCreateMountpointAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"bind","Source":"/data","Target":"/data","BindOptions":{"CreateMountpoint":true}}]}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "mountReadOnlyNonRecursiveDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"bind","Source":"/ro","Target":"/ro","ReadOnly":true,"BindOptions":{"ReadOnlyNonRecursive":true}}]}}"##,
            want: "HostConfig.Mounts.BindOptions.ReadOnlyNonRecursive is not allowed",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "mountVolumeOptionsDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"bind","Source":"/data","Target":"/data","VolumeOptions":{"NoCopy":true}}]}}"##,
            want: "HostConfig.Mounts.VolumeOptions is not allowed",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "mountCaseVariantDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"tmpfs","Target":"/x","type":"bind","source":"/"}]}}"##,
            want: "HostConfig.Mounts.source is not allowed",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "mountNoVolumesDenied",
            policy: "bare",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":[{"Type":"bind","Source":"/data","Target":"/data"}]}}"##,
            want: "mount source \"/data\" is not in the whitelist",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "mountsNotListDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Mounts":{}}}"##,
            want: "HostConfig.Mounts must be a list",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "bindAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Binds":["/data:/data"]}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "bindReadOnlyVolumeRwDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Binds":["/ro:/ro:rw"]}}"##,
            want: "volume mount \"/ro\" must be read-only (:ro) for service svc",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "bindReadOnlyVolumeNoModeDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Binds":["/ro:/ro"]}}"##,
            want: "volume mount \"/ro\" must be read-only (:ro)",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "bindReadOnlyVolumeRoAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Binds":["/ro:/ro:ro"]}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "bindReadOnlyVolumeRoZAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Binds":["/ro:/ro:ro,Z"]}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "bindReadOnlyVolumeRoRwDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Binds":["/ro:/ro:ro,rw"]}}"##,
            want: "volume mount \"/ro\" must be read-only (:ro)",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "bindRsharedDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Binds":["/data:/data:rshared"]}}"##,
            want: "bind option \"rshared\" on volume mount \"/data\" is not allowed for service svc",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "bindRslaveDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Binds":["/data:/data:rw,rslave"]}}"##,
            want: "bind option \"rslave\" on volume mount \"/data\" is not allowed",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "bindConsistencyModeDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Binds":["/data:/data:cached"]}}"##,
            want: "bind option \"cached\" on volume mount \"/data\" is not allowed",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "bindRprivateAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Binds":["/data:/data:rw,rprivate"]}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "bindPrivateZAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Binds":["/data:/data:z,private"]}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "bindNocopyAllowed",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Binds":["/data:/data:nocopy"]}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "bindUnlistedDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Binds":["/etc:/etc:ro"]}}"##,
            want: "volume mount \"/etc\" is not in the whitelist for service svc",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "bindNoVolumesDenied",
            policy: "bare",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Binds":["/data:/data"]}}"##,
            want: "volume mount \"/data\" is not in the whitelist",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "bindNotStringDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Binds":[1]}}"##,
            want: "HostConfig.Binds must be a list of strings",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "bindTooManyPartsDenied",
            policy: "std",
            body: r##"{"Image":"chainsafe/lodestar:v1","HostConfig":{"Binds":["/data:/data:ro:x"]}}"##,
            want: "bind \"/data:/data:ro:x\" is not a valid bind",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "topLevelVolumesNoVolumesDenied",
            policy: "bare",
            body: r##"{"Image":"chainsafe/lodestar:v1","Volumes":{"/data":{}}}"##,
            want: "volume \"/data\" is not in the whitelist",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "topLevelVolumesEmptyAllowed",
            policy: "bare",
            body: r##"{"Image":"chainsafe/lodestar:v1","Volumes":{}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "dockerCliCreateBodyAllowed",
            policy: "std",
            body: r##"{"Hostname":"","Domainname":"","User":"","AttachStdin":false,"AttachStdout":true,"AttachStderr":true,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":null,"Cmd":["true"],"Image":"chainsafe/lodestar:v1","Volumes":{},"WorkingDir":"","Entrypoint":null,"Labels":{},"HostConfig":{"Binds":null,"ContainerIDFile":"","LogConfig":{"Type":"","Config":{}},"NetworkMode":"default","PortBindings":{},"RestartPolicy":{"Name":"no","MaximumRetryCount":0},"AutoRemove":false,"VolumeDriver":"","VolumesFrom":null,"ConsoleSize":[0,0],"CapAdd":null,"CapDrop":null,"CgroupnsMode":"","Dns":null,"DnsOptions":[],"DnsSearch":[],"ExtraHosts":null,"GroupAdd":null,"IpcMode":"","Cgroup":"","Links":null,"OomScoreAdj":0,"PidMode":"","Privileged":false,"PublishAllPorts":false,"ReadonlyRootfs":false,"SecurityOpt":null,"UTSMode":"","UsernsMode":"","ShmSize":0,"Isolation":"","CpuShares":0,"Memory":0,"NanoCpus":0,"CgroupParent":"","BlkioWeight":0,"BlkioWeightDevice":[],"BlkioDeviceReadBps":[],"BlkioDeviceWriteBps":[],"BlkioDeviceReadIOps":[],"BlkioDeviceWriteIOps":[],"CpuPeriod":0,"CpuQuota":0,"CpuRealtimePeriod":0,"CpuRealtimeRuntime":0,"CpusetCpus":"","CpusetMems":"","Devices":[],"DeviceCgroupRules":null,"DeviceRequests":null,"MemoryReservation":0,"MemorySwap":0,"MemorySwappiness":-1,"OomKillDisable":false,"PidsLimit":0,"Ulimits":null,"CpuCount":0,"CpuPercent":0,"IOMaximumIOps":0,"IOMaximumBandwidth":0,"MaskedPaths":null,"ReadonlyPaths":null},"NetworkingConfig":{"EndpointsConfig":{"default":{"IPAMConfig":null,"Links":null,"Aliases":null,"DriverOpts":null,"GwPriority":0,"NetworkID":"","EndpointID":"","Gateway":"","IPAddress":"","MacAddress":"","IPPrefixLen":0,"IPv6Gateway":"","GlobalIPv6Address":"","GlobalIPv6PrefixLen":0,"DNSNames":null}}}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "dockerCliCreateBodyBareAllowed",
            policy: "bare",
            body: r##"{"Hostname":"","Domainname":"","User":"","AttachStdin":false,"AttachStdout":true,"AttachStderr":true,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":null,"Cmd":["true"],"Image":"chainsafe/lodestar:v1","Volumes":{},"WorkingDir":"","Entrypoint":null,"Labels":{},"HostConfig":{"Binds":null,"ContainerIDFile":"","LogConfig":{"Type":"","Config":{}},"NetworkMode":"default","PortBindings":{},"RestartPolicy":{"Name":"no","MaximumRetryCount":0},"AutoRemove":false,"VolumeDriver":"","VolumesFrom":null,"ConsoleSize":[0,0],"CapAdd":null,"CapDrop":null,"CgroupnsMode":"","Dns":null,"DnsOptions":[],"DnsSearch":[],"ExtraHosts":null,"GroupAdd":null,"IpcMode":"","Cgroup":"","Links":null,"OomScoreAdj":0,"PidMode":"","Privileged":false,"PublishAllPorts":false,"ReadonlyRootfs":false,"SecurityOpt":null,"UTSMode":"","UsernsMode":"","ShmSize":0,"Isolation":"","CpuShares":0,"Memory":0,"NanoCpus":0,"CgroupParent":"","BlkioWeight":0,"BlkioWeightDevice":[],"BlkioDeviceReadBps":[],"BlkioDeviceWriteBps":[],"BlkioDeviceReadIOps":[],"BlkioDeviceWriteIOps":[],"CpuPeriod":0,"CpuQuota":0,"CpuRealtimePeriod":0,"CpuRealtimeRuntime":0,"CpusetCpus":"","CpusetMems":"","Devices":[],"DeviceCgroupRules":null,"DeviceRequests":null,"MemoryReservation":0,"MemorySwap":0,"MemorySwappiness":-1,"OomKillDisable":false,"PidsLimit":0,"Ulimits":null,"CpuCount":0,"CpuPercent":0,"IOMaximumIOps":0,"IOMaximumBandwidth":0,"MaskedPaths":null,"ReadonlyPaths":null},"NetworkingConfig":{"EndpointsConfig":{"default":{"IPAMConfig":null,"Links":null,"Aliases":null,"DriverOpts":null,"GwPriority":0,"NetworkID":"","EndpointID":"","Gateway":"","IPAddress":"","MacAddress":"","IPPrefixLen":0,"IPv6Gateway":"","GlobalIPv6Address":"","GlobalIPv6PrefixLen":0,"DNSNames":null}}}}"##,
            want: "",
            fwd: r##""##,
        },
        HostConfigRow {
            name: "ansibleCreateBodyAllowed",
            policy: "secopt",
            body: r##"{"Image":"chainsafe/lodestar:v1","Cmd":["beacon"],"Env":[],"Labels":{"app":"beacon"},"HostConfig":{"Binds":["/data:/data:rw","/ro:/ro:ro"],"NetworkMode":"host","RestartPolicy":{"Name":"unless-stopped","MaximumRetryCount":0},"LogConfig":{"Type":"json-file","Config":{"max-size":"100m"}},"SecurityOpt":["no-new-privileges:true"],"Init":false,"AutoRemove":false,"Privileged":false,"ReadonlyRootfs":false,"CapDrop":["ALL"],"Memory":0}}"##,
            want: "",
            fwd: r##""##,
        },
    ];
}
