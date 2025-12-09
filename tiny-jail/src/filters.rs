use libseccomp::{
    error::SeccompError, ScmpAction, ScmpArch, ScmpArgCompare, ScmpCompareOp, ScmpFilterContext,
    ScmpSyscall,
};
use log2::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::str::FromStr;
use std::sync::LazyLock;
use thiserror::Error;
use toml;

use crate::actions::{Action, ActionError};

// ============================================================================
// Error Types
// ============================================================================

#[derive(Error, Debug)]
pub enum ProfileError {
    #[error("Could not read profile file '{path}': {source}")]
    FileRead {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("Could not parse profile: {0}")]
    ProfileParse(#[from] toml::de::Error),
    #[error("Could not parse abstract rules: {0}")]
    AbstractParse(#[from] serde_json::Error),
    #[error("Unknown syscall name: {0}")]
    UnknownSyscall(String),
    #[error("Architecture conversion error: {0}")]
    ArchConversion(String),
    #[error("libseccomp error: {0}")]
    LibSeccomp(#[from] SeccompError),
    #[error("OCI profile has no syscalls")]
    NoSyscallsInProfile,
    #[error("Invalid action parameters: {0}")]
    Action(#[from] ActionError),
    #[error("Invalid OCI profile argument: {0}")]
    InvalidArgument(String),
    #[error("Circular group reference detected: {0}")]
    CircularReference(String),
    #[error("Unknown abstract group: {0}")]
    UnknownGroup(String),
    #[error("Abstract syscalls not expanded")]
    AbstractNotExpanded,
}

// ============================================================================
// Abstract rules data structure
// ============================================================================

#[derive(Deserialize, Debug, Clone)]
#[serde(untagged)]
enum GroupRule {
    Syscall(SyscallRule),
    GroupRef(GroupReference),
}

#[derive(Deserialize, Debug, Clone)]
struct SyscallRule {
    name: String,
    #[serde(default)]
    conditions: Vec<SyscallCondition>,
}

#[derive(Deserialize, Debug, Clone)]
struct GroupReference {
    group: String,
}

#[derive(Deserialize, Debug, Clone)]
struct SyscallCondition {
    #[serde(rename = "type")]
    type_: String,
    argument: String,
    value: Option<String>,
    flags: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
struct AbstractGroupDef {
    #[serde(default)]
    rules: Vec<GroupRule>,
}

#[derive(Deserialize, Debug)]
struct AbstractGroups {
    #[serde(flatten)]
    groups: HashMap<String, AbstractGroupDef>,
}

const ABSTRACT_RULES_DATA: &str = include_str!("../data/abstract_rules.min.json");

// ============================================================================
// Profile Structures
// ============================================================================

/// A single condition for a syscall rule. Fields are public for fuzzing purposes.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct OciSyscallCondition {
    pub index: u8,
    pub value: u64,
    pub value_two: Option<u64>,
    pub op: String,
}

/// A single syscall rule. Fields are public for fuzzing purposes.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct OciSyscall {
    pub names: Vec<String>,
    pub action: Action,
    pub errno_ret: Option<u32>,
    #[serde(default)]
    pub conditions: Vec<OciSyscallCondition>,
}

/// A single abstract syscall rule. Fields are public for fuzzing purposes.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct AbstractSyscall {
    names: Vec<String>,
    action: Action,
}

fn default_architectures() -> Vec<String> {
    vec!["SCMP_ARCH_X86_64".to_string()]
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct OciSeccomp {
    pub default_action: Action,
    pub default_errno_ret: Option<u32>,
    #[serde(default = "default_architectures")]
    pub architectures: Vec<String>,
    pub syscalls: Option<Vec<OciSyscall>>,
    pub abstract_syscalls: Option<Vec<AbstractSyscall>>,
}

// ============================================================================
// Public API
// ============================================================================

/// Load a seccomp profile from a file and expand abstract syscalls to concrete ones.
///
/// # Arguments
/// * `profile_path` - Path to the OCI seccomp profile TOML file
///
/// # Returns
/// A modified `OciSeccomp` struct where all abstract syscalls have been expanded
/// to their concrete syscall equivalents and merged with regular syscalls.
pub fn read_and_expand_profile(profile_path: &str) -> Result<OciSeccomp, ProfileError> {
    // Read and parse the profile file
    debug!("Loading profile from: {}", profile_path);
    let profile_content = fs::read_to_string(profile_path).map_err(|e| {
        error!("Failed to read profile: {}", e);
        ProfileError::FileRead {
            path: profile_path.to_string(),
            source: e,
        }
    })?;

    parse_and_expand_profile(&profile_content)
}

/// Parse a seccomp profile string and expand abstract syscalls to concrete ones.
pub fn parse_and_expand_profile(profile_content: &str) -> Result<OciSeccomp, ProfileError> {
    let mut oci_seccomp: OciSeccomp = toml::from_str(profile_content).map_err(|e| {
        error!("Failed to parse profile: {}", e);
        ProfileError::ProfileParse(e)
    })?;

    // Expand abstract syscalls if present
    if let Some(abstract_syscalls) = oci_seccomp.abstract_syscalls.take() {
        let abstract_groups =
            serde_json::from_str::<AbstractGroups>(ABSTRACT_RULES_DATA).map_err(|e| {
                error!("Failed to parse abstract rules: {}", e);
                ProfileError::AbstractParse(e)
            })?;

        let mut expanded_syscalls: Vec<OciSyscall> = Vec::new();

        for abstract_entry in abstract_syscalls {
            for group_name in &abstract_entry.names {
                debug!("Expanding abstract group: {}", group_name);
                let expanded_rules =
                    expand_group(group_name, &abstract_groups.groups, &mut HashSet::new())?;

                for syscall_rule in expanded_rules {
                    let oci_syscall =
                        convert_syscall_rule_to_oci(&syscall_rule, abstract_entry.action)?;
                    expanded_syscalls.push(oci_syscall);
                }
            }
        }

        // Merge expanded syscalls with existing ones
        match oci_seccomp.syscalls {
            Some(mut existing) => {
                existing.extend(expanded_syscalls);
                oci_seccomp.syscalls = Some(existing);
            }
            None => {
                oci_seccomp.syscalls = Some(expanded_syscalls);
            }
        }
    }

    debug!(
        "Profile loaded with {} syscall rules",
        oci_seccomp.syscalls.as_ref().map(|s| s.len()).unwrap_or(0)
    );
    Ok(oci_seccomp)
}

/// Load and configure a seccomp filter profile.
///
/// # Arguments
/// * `profile_path` - Optional path to an OCI seccomp profile JSON file
/// * `default_action_override` - Override the profile's default action
/// * `default_errno_ret_override` - Override the profile's default errno
/// * `kill_syscalls` - Syscalls to unconditionally kill (highest priority)
/// * `log_syscalls` - Syscalls to log when default action is Allow
/// * `log_allowed` - Convert Allow actions to Log actions
pub fn load_profile(
    profile_path: Option<String>,
    default_action_override: Option<Action>,
    default_errno_ret_override: Option<u32>,
    kill_syscalls: &[String],
    log_syscalls: &[String],
    log_allowed: bool,
) -> Result<ScmpFilterContext, ProfileError> {
    let mut ctx = if let Some(path) = profile_path {
        debug!("Parsing profile: {}", path);
        let profile = read_and_expand_profile(&path).map_err(|e| {
            error!("Failed to load profile from {}: {}", path, e);
            e
        })?;
        apply_profile(
            &profile,
            default_action_override,
            default_errno_ret_override,
            log_allowed,
        )?
    } else if log_allowed {
        info!("No profile provided, using default action: Log");
        ScmpFilterContext::new(Action::Log.to_scmp_action(None)?)?
    } else {
        info!("No profile provided, using default action: Allow");
        ScmpFilterContext::new(Action::Allow.to_scmp_action(None)?)?
    };

    if !kill_syscalls.is_empty() {
        apply_kill_overrides(&mut ctx, kill_syscalls)?;
    }
    if !log_syscalls.is_empty() {
        apply_log_overrides(&mut ctx, log_syscalls)?;
    }

    Ok(ctx)
}

// ============================================================================
// Profile Application
// ============================================================================

pub fn apply_profile(
    oci_seccomp: &OciSeccomp,
    default_action_override: Option<Action>,
    default_errno_ret_override: Option<u32>,
    log_allowed: bool,
) -> Result<ScmpFilterContext, ProfileError> {
    let default_errno_ret = default_errno_ret_override.or(oci_seccomp.default_errno_ret);
    let default_action = if log_allowed && oci_seccomp.default_action == Action::Allow {
        Action::Log.to_scmp_action(None)?
    } else {
        default_action_override
            .unwrap_or(oci_seccomp.default_action)
            .to_scmp_action(default_errno_ret)?
    };
    debug!("default_action={:?}", default_action);

    let mut ctx = ScmpFilterContext::new(default_action).map_err(|e| {
        error!(
            "Failed to create filter context with default_action={:?}: {}",
            default_action, e
        );
        ProfileError::LibSeccomp(e)
    })?;

    add_architectures(&mut ctx, &oci_seccomp.architectures)?;
    apply_syscall_rules(&mut ctx, oci_seccomp, log_allowed)?;

    Ok(ctx)
}

fn add_architectures(
    ctx: &mut ScmpFilterContext,
    architectures: &[String],
) -> Result<(), ProfileError> {
    for arch_str in architectures {
        let arch = ScmpArch::from_str(arch_str)
            .map_err(|e| ProfileError::ArchConversion(e.to_string()))?;

        if !ctx.is_arch_present(arch)? {
            ctx.add_arch(arch)?;
            debug!("Added architecture: {}", arch_str);
        }
    }

    Ok(())
}

pub fn apply_syscall_rules(
    ctx: &mut ScmpFilterContext,
    raw_profile: &OciSeccomp,
    log_allowed: bool,
) -> Result<(), ProfileError> {
    let syscalls = &raw_profile.syscalls;
    let abstract_syscalls = &raw_profile.abstract_syscalls;

    if syscalls.is_none() && abstract_syscalls.is_none() {
        let default_action = Action::from(ctx.get_act_default().unwrap_or(ScmpAction::Allow));
        warn_unconfigured_default_action(default_action);
        return Ok(());
    }

    if let Some(syscalls) = syscalls {
        for syscall_entry in syscalls {
            apply_syscall_rule(ctx, syscall_entry, log_allowed)?;
        }
    }

    if abstract_syscalls.is_some() {
        error!("Abstract syscalls should have been expanded by now");
        return Err(ProfileError::AbstractNotExpanded);
    }

    Ok(())
}

pub fn explode_syscalls(profile: &mut OciSeccomp) {
    let Some(syscalls) = profile.syscalls.take() else {
        return;
    };
    let mut exploded = Vec::with_capacity(syscalls.len());
    for sc in syscalls {
        if sc.names.len() <= 1 {
            exploded.push(sc);
            continue;
        }
        for name in sc.names {
            exploded.push(OciSyscall {
                names: vec![name],
                action: sc.action,
                errno_ret: sc.errno_ret,
                conditions: sc.conditions.clone(),
            });
        }
    }
    profile.syscalls = Some(exploded);
}

pub fn coalesce_rules_by_action(profile: &mut OciSeccomp) {
    let Some(syscalls) = profile.syscalls.take() else {
        return;
    };

    let mut groups: Vec<OciSyscall> = Vec::new();

    for sc in syscalls {
        // Find matching group
        if let Some(existing) = groups.iter_mut().find(|g| {
            g.action == sc.action
                && g.errno_ret == sc.errno_ret
                && conditions_equal(&g.conditions, &sc.conditions)
        }) {
            existing.names.extend(sc.names);
        } else {
            groups.push(sc);
        }
    }

    // Deduplicate and sort names
    for g in &mut groups {
        g.names.sort_unstable();
        g.names.dedup();
    }

    profile.syscalls = Some(groups);
}

fn conditions_equal(a: &[OciSyscallCondition], b: &[OciSyscallCondition]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for (x, y) in a.iter().zip(b.iter()) {
        if x.index != y.index || x.value != y.value || x.value_two != y.value_two || x.op != y.op {
            return false;
        }
    }
    true
}

fn expand_group<'a>(
    group_name: &'a str,
    groups: &'a HashMap<String, AbstractGroupDef>,
    visited: &mut HashSet<&'a str>,
) -> Result<Vec<SyscallRule>, ProfileError> {
    if !visited.insert(group_name) {
        return Err(ProfileError::CircularReference(group_name.to_string()));
    }

    let group_def = groups
        .get(group_name)
        .ok_or_else(|| ProfileError::UnknownGroup(group_name.to_string()))?;

    let mut result = Vec::new();
    for rule in &group_def.rules {
        match rule {
            GroupRule::Syscall(syscall_rule) => {
                result.push(syscall_rule.clone());
            }
            GroupRule::GroupRef(group_ref) => {
                let nested_rules = expand_group(&group_ref.group, groups, visited)?;
                result.extend(nested_rules);
            }
        }
    }

    visited.remove(group_name);
    Ok(result)
}

fn warn_unconfigured_default_action(action: Action) {
    match action {
        Action::Allow => info!("No syscalls specified: all syscalls will be allowed"),
        Action::Log => info!("No syscalls specified: all syscalls will be logged"),
        _ => warn!(
            "No syscalls specified with default action {:?}: this will {} on first syscall",
            action,
            match action {
                Action::KillThread => "kill the process",
                Action::Trap => "trap",
                Action::Errno => "return errno",
                _ => "take action",
            }
        ),
    }
}

fn apply_syscall_rule(
    ctx: &mut ScmpFilterContext,
    syscall_entry: &OciSyscall,
    log_allowed: bool,
) -> Result<(), ProfileError> {
    let action = resolve_action(syscall_entry.action, log_allowed);

    let scmp_action = action.to_scmp_action(syscall_entry.errno_ret)?;

    let default_action = ctx.get_act_default().unwrap_or(ScmpAction::Allow);

    if scmp_action == default_action {
        debug!(
            "Skipping syscall rule matching default action for: {:?}",
            syscall_entry.names
        );
        return Ok(());
    }

    let args_is_empty = syscall_entry.conditions.is_empty();

    let comparators: Vec<ScmpArgCompare> = if args_is_empty {
        vec![]
    } else {
        build_comparators(&syscall_entry.conditions)?
    };

    debug!(
        "Adding rule {:?} for syscalls: {:?}",
        scmp_action, syscall_entry.names
    );

    for syscall_name in &syscall_entry.names {
        if let Some(arity) = get_syscall_arity(syscall_name) {
            for cond in &syscall_entry.conditions {
                if cond.index >= arity {
                    warn!(
                        "Skipping invalid condition index {} for syscall {} (arity {})",
                        cond.index, syscall_name, arity
                    );
                    return Ok(());
                }
            }
        }

        let syscall = ScmpSyscall::from_name(syscall_name).map_err(|_| {
            error!("Unknown syscall: {}", syscall_name);
            ProfileError::UnknownSyscall(syscall_name.to_string())
        })?;

        if args_is_empty {
            ctx.add_rule(scmp_action, syscall)
        } else {
            debug!("With conditions: {:?}", comparators);
            ctx.add_rule_conditional(scmp_action, syscall, &comparators)
        }
        .map(|_| ())
        .map_err(|e| {
            error!("Failed to add rule for {}: {}", syscall_name, e);
            ProfileError::LibSeccomp(e)
        })?;
    }

    Ok(())
}

fn get_syscall_arity(name: &str) -> Option<u8> {
    match name {
        "read" | "write" | "socket" | "connect" | "bind" | "execve" | "mprotect" | "readlink"
        | "getdents" | "getdents64" | "fcntl" | "listxattr" | "llistxattr" | "flistxattr" => {
            Some(3)
        }
        "open" => Some(3),
        "openat" | "faccessat" | "readlinkat" | "getxattr" | "lgetxattr" | "fgetxattr" => Some(4),
        "close" | "fsync" | "fdatasync" | "syncfs" => Some(1),
        "clone" | "setxattr" | "lsetxattr" | "fsetxattr" => Some(5),
        "mmap" => Some(6),
        "munmap" | "fstat" | "stat" | "lstat" | "access" | "arch_prctl" | "flock"
        | "removexattr" | "lremovexattr" | "fremovexattr" | "getcwd" => Some(2),
        "sync" => Some(0),
        _ => None,
    }
}

// ============================================================================
// Override Application
// ============================================================================

fn apply_kill_overrides(
    ctx: &mut ScmpFilterContext,
    kill_syscalls: &[String],
) -> Result<(), ProfileError> {
    for syscall_name in kill_syscalls {
        debug!("Adding kill rule for syscall: {}", syscall_name);

        if let Ok(syscall) = ScmpSyscall::from_name(syscall_name) {
            ctx.add_rule(ScmpAction::KillThread, syscall)?;
        } else {
            warn!(
                "Could not add kill rule for unknown syscall: {}",
                syscall_name
            );
        }
    }
    Ok(())
}

fn apply_log_overrides(
    ctx: &mut ScmpFilterContext,
    log_syscalls: &[String],
) -> Result<(), ProfileError> {
    for syscall_name in log_syscalls {
        debug!("Adding log rule for syscall: {}", syscall_name);

        if let Ok(syscall) = ScmpSyscall::from_name(syscall_name) {
            ctx.add_rule(ScmpAction::Log, syscall)?;
        } else {
            warn!(
                "Could not add log rule for unknown syscall: {}",
                syscall_name
            );
        }
    }

    Ok(())
}

// ============================================================================
// Helper Functions
// ============================================================================

fn resolve_action(action: Action, log_allowed: bool) -> Action {
    if log_allowed && action == Action::Allow {
        Action::Log
    } else {
        action
    }
}

fn build_comparators(
    conditions: &[OciSyscallCondition],
) -> Result<Vec<ScmpArgCompare>, ProfileError> {
    conditions.iter().map(build_comparator).collect()
}

fn build_comparator(arg: &OciSyscallCondition) -> Result<ScmpArgCompare, ProfileError> {
    let (op, datum) = if arg.op == "SCMP_CMP_MASKED_EQ" {
        let datum = arg.value_two.ok_or_else(|| {
            ProfileError::InvalidArgument(
                "valueTwo must be present for SCMP_CMP_MASKED_EQ".to_string(),
            )
        })?;
        (ScmpCompareOp::MaskedEqual(arg.value), datum)
    } else {
        let op = parse_compare_op(&arg.op)?;
        (op, arg.value)
    };

    Ok(ScmpArgCompare::new(arg.index as u32, op, datum))
}

fn parse_compare_op(op: &str) -> Result<ScmpCompareOp, ProfileError> {
    match op {
        "SCMP_CMP_NE" => Ok(ScmpCompareOp::NotEqual),
        "SCMP_CMP_LT" => Ok(ScmpCompareOp::Less),
        "SCMP_CMP_LE" => Ok(ScmpCompareOp::LessOrEqual),
        "SCMP_CMP_EQ" => Ok(ScmpCompareOp::Equal),
        "SCMP_CMP_GE" => Ok(ScmpCompareOp::GreaterEqual),
        "SCMP_CMP_GT" => Ok(ScmpCompareOp::Greater),
        _ => Err(ProfileError::ArchConversion(format!(
            "Unknown comparison operator: {}",
            op
        ))),
    }
}

fn convert_syscall_rule_to_oci(
    syscall_rule: &SyscallRule,
    action: Action,
) -> Result<OciSyscall, ProfileError> {
    let mut all_conditions = Vec::new();

    for condition in &syscall_rule.conditions {
        let oci_conditions = convert_condition_to_oci(condition, syscall_rule.name.as_str())?;
        all_conditions.extend(oci_conditions);
    }

    Ok(OciSyscall {
        names: vec![syscall_rule.name.clone()],
        action,
        errno_ret: None,
        conditions: all_conditions,
    })
}

fn convert_condition_to_oci(
    condition: &SyscallCondition,
    syscall_name: &str,
) -> Result<Vec<OciSyscallCondition>, ProfileError> {
    let arg_index = get_argument_index(&condition.argument, syscall_name)?;

    match condition.type_.as_str() {
        "bitmask_all" => {
            let flags_str = condition.flags.as_ref().ok_or_else(|| {
                ProfileError::InvalidArgument("flags missing for bitmask_all".to_string())
            })?;
            let flag_value = parse_flags(flags_str)?;

            Ok(vec![OciSyscallCondition {
                index: arg_index,
                value: flag_value,           // mask
                value_two: Some(flag_value), // expected value after masking
                op: "SCMP_CMP_MASKED_EQ".to_string(),
            }])
        }
        "bitmask_any" => {
            let flags_str = condition.flags.as_ref().ok_or_else(|| {
                ProfileError::InvalidArgument("flags missing for bitmask_any".to_string())
            })?;
            let flag_value = parse_flags(flags_str)?;

            warn!("bitmask_any is limited in seccomp; using bitmask_all semantics");
            Ok(vec![OciSyscallCondition {
                index: arg_index,
                value: flag_value,
                value_two: Some(flag_value),
                op: "SCMP_CMP_MASKED_EQ".to_string(),
            }])
        }
        "bitmask_none" => {
            let flags_str = condition.flags.as_ref().ok_or_else(|| {
                ProfileError::InvalidArgument("flags missing for bitmask_none".to_string())
            })?;
            let flag_value = parse_flags(flags_str)?;

            Ok(vec![OciSyscallCondition {
                index: arg_index,
                value: flag_value,  // mask
                value_two: Some(0), // expected value after masking (0 means none set)
                op: "SCMP_CMP_MASKED_EQ".to_string(),
            }])
        }
        "equals" => {
            let value_str = condition.value.as_ref().ok_or_else(|| {
                ProfileError::InvalidArgument("value missing for equals".to_string())
            })?;
            let value = parse_value(value_str)?;

            Ok(vec![OciSyscallCondition {
                index: arg_index,
                value,
                value_two: None,
                op: "SCMP_CMP_EQ".to_string(),
            }])
        }
        "not_equals" => {
            let value_str = condition.value.as_ref().ok_or_else(|| {
                ProfileError::InvalidArgument("value missing for not_equals".to_string())
            })?;
            let value = parse_value(value_str)?;

            Ok(vec![OciSyscallCondition {
                index: arg_index,
                value,
                value_two: None,
                op: "SCMP_CMP_NE".to_string(),
            }])
        }
        "greater" => {
            let value_str = condition.value.as_ref().ok_or_else(|| {
                ProfileError::InvalidArgument("value missing for greater".to_string())
            })?;
            let value = parse_value(value_str)?;

            Ok(vec![OciSyscallCondition {
                index: arg_index,
                value,
                value_two: None,
                op: "SCMP_CMP_GT".to_string(),
            }])
        }
        "less" => {
            let value_str = condition.value.as_ref().ok_or_else(|| {
                ProfileError::InvalidArgument("value missing for less".to_string())
            })?;
            let value = parse_value(value_str)?;

            Ok(vec![OciSyscallCondition {
                index: arg_index,
                value,
                value_two: None,
                op: "SCMP_CMP_LT".to_string(),
            }])
        }
        _ => {
            warn!("Unknown condition type: {}", condition.type_);
            Ok(vec![])
        }
    }
}

static ARG_INDICES: LazyLock<HashMap<(&'static str, &'static str), u8>> = LazyLock::new(|| {
    HashMap::from([
        // File open arguments
        (("open", "flags"), 1),
        (("openat", "flags"), 2),
    ])
});

static DEFAULT_ARG_INDICES: LazyLock<HashMap<&'static str, u8>> = LazyLock::new(|| {
    HashMap::from([
        ("flags", 1),
        ("mode", 2),
        ("domain", 0),
        ("type", 1),
        ("protocol", 2),
        ("pid", 0),
        ("fd", 0),
        ("sockfd", 0),
        ("ruid", 0),
        ("euid", 1),
        ("suid", 2),
        ("rgid", 0),
        ("egid", 1),
        ("sgid", 2),
        ("name", 0),
        ("path", 0),
        ("address", 0),
    ])
});

fn get_argument_index(arg_name: &str, syscall_name: &str) -> Result<u8, ProfileError> {
    ARG_INDICES
        .get(&(syscall_name, arg_name))
        .or_else(|| DEFAULT_ARG_INDICES.get(arg_name))
        .copied()
        .ok_or_else(|| {
            ProfileError::InvalidArgument(format!(
                "Unknown argument name: {} for syscall: {}",
                arg_name, syscall_name
            ))
        })
}

static FLAG_MAP: LazyLock<HashMap<&'static str, u64>> = LazyLock::new(|| {
    HashMap::from([
        // File open flags
        ("O_RDONLY", 0o0),
        ("O_WRONLY", 0o1),
        ("O_RDWR", 0o2),
        ("O_CREAT", 0o100),
        ("O_EXCL", 0o200),
        ("O_NOCTTY", 0o400),
        ("O_TRUNC", 0o1000),
        ("O_APPEND", 0o2000),
        ("O_NONBLOCK", 0o4000),
        ("O_RONLY", 0o0),
        // Clone flags
        ("CLONE_THREAD", 0x00010000),
        ("CLONE_VM", 0x00000100),
        ("CLONE_FS", 0x00000200),
        ("CLONE_FILES", 0x00000400),
        ("CLONE_SIGHAND", 0x00000800),
        ("CLONE_PTRACE", 0x00002000),
        ("CLONE_VFORK", 0x00004000),
        ("CLONE_PARENT", 0x00008000),
        // Socket domains
        ("AF_UNIX", 1),
        ("AF_INET", 2),
        ("AF_INET6", 10),
        ("AF_NETLINK", 16),
    ])
});

fn parse_flags(flags_str: &str) -> Result<u64, ProfileError> {
    flags_str
        .split('|')
        .map(str::trim)
        .try_fold(0u64, |acc, flag| {
            FLAG_MAP
                .get(flag)
                .copied()
                .ok_or_else(|| ProfileError::InvalidArgument(format!("Unknown flag: {}", flag)))
                .map(|val| acc | val)
        })
}

fn parse_value(value_str: &str) -> Result<u64, ProfileError> {
    if let Ok(val) = value_str.parse::<u64>() {
        return Ok(val);
    }

    if let Some(hex_str) = value_str.strip_prefix("0x") {
        if let Ok(val) = u64::from_str_radix(hex_str, 16) {
            return Ok(val);
        }
    }

    // Handle named constants
    match value_str {
        "AF_UNIX" => Ok(1),
        "AF_INET" => Ok(2),
        "AF_INET6" => Ok(10),
        "AF_NETLINK" => Ok(16),
        _ => Err(ProfileError::InvalidArgument(format!(
            "Cannot parse value: {}",
            value_str
        ))),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Parse Value Tests
    // ========================================================================

    #[test]
    fn test_parse_value() {
        // Decimal
        assert_eq!(parse_value("42").unwrap(), 42);
        assert_eq!(parse_value("0").unwrap(), 0);
        assert_eq!(parse_value("65536").unwrap(), 65536);

        // Hex
        assert_eq!(parse_value("0x10").unwrap(), 16);
        assert_eq!(parse_value("0xFF").unwrap(), 255);
        assert_eq!(parse_value("0x0").unwrap(), 0);

        // Named constants
        assert_eq!(parse_value("AF_UNIX").unwrap(), 1);
        assert_eq!(parse_value("AF_INET").unwrap(), 2);
        assert_eq!(parse_value("AF_INET6").unwrap(), 10);
        assert_eq!(parse_value("AF_NETLINK").unwrap(), 16);

        // Invalid
        assert!(parse_value("invalid").is_err());
        assert!(parse_value("0xZZZ").is_err());
    }

    // ========================================================================
    // Parse Flags Tests
    // ========================================================================

    #[test]
    fn test_parse_flags() {
        // Single flags
        assert_eq!(parse_flags("O_WRONLY").unwrap(), 0o1);
        assert_eq!(parse_flags("O_RDWR").unwrap(), 0o2);
        assert_eq!(parse_flags("O_CREAT").unwrap(), 0o100);

        // Multiple flags
        assert_eq!(parse_flags("O_WRONLY|O_CREAT").unwrap(), 0o1 | 0o100);
        assert_eq!(
            parse_flags("O_RDWR|O_CREAT|O_TRUNC").unwrap(),
            0o2 | 0o100 | 0o1000
        );

        // With whitespace
        assert_eq!(
            parse_flags("O_WRONLY | O_CREAT | O_TRUNC").unwrap(),
            0o1 | 0o100 | 0o1000
        );

        // Clone flags
        assert_eq!(parse_flags("CLONE_THREAD").unwrap(), 0x00010000);
        assert_eq!(
            parse_flags("CLONE_THREAD|CLONE_VM").unwrap(),
            0x00010000 | 0x00000100
        );

        // Socket domains
        assert_eq!(parse_flags("AF_UNIX").unwrap(), 1);
        assert_eq!(parse_flags("AF_INET").unwrap(), 2);
    }

    #[test]
    fn test_parse_flags_unknown() {
        // If your implementation now errors on unknown flags (recommended):
        assert!(parse_flags("UNKNOWN_FLAG").is_err());
        assert!(parse_flags("O_WRONLY|UNKNOWN_FLAG|O_CREAT").is_err());
    }

    // ========================================================================
    // Get Argument Index Tests
    // ========================================================================

    #[test]
    fn test_get_argument_index() {
        // Syscall-specific indices for flags
        assert_eq!(get_argument_index("flags", "open").unwrap(), 1);
        assert_eq!(get_argument_index("flags", "openat").unwrap(), 2);
        assert_eq!(get_argument_index("flags", "socket").unwrap(), 1);

        // Standard arguments (use specific syscalls)
        assert_eq!(get_argument_index("mode", "open").unwrap(), 2);
        assert_eq!(get_argument_index("fd", "write").unwrap(), 0);
        assert_eq!(get_argument_index("sockfd", "bind").unwrap(), 0);
        assert_eq!(get_argument_index("domain", "socket").unwrap(), 0);
        assert_eq!(get_argument_index("type", "socket").unwrap(), 1);
        assert_eq!(get_argument_index("protocol", "socket").unwrap(), 2);

        // PID argument
        assert_eq!(get_argument_index("pid", "kill").unwrap(), 0);

        // UID/GID arguments
        assert_eq!(get_argument_index("ruid", "setresuid").unwrap(), 0);
        assert_eq!(get_argument_index("euid", "setresuid").unwrap(), 1);
        assert_eq!(get_argument_index("suid", "setresuid").unwrap(), 2);
        assert_eq!(get_argument_index("rgid", "setresgid").unwrap(), 0);
        assert_eq!(get_argument_index("egid", "setresgid").unwrap(), 1);
        assert_eq!(get_argument_index("sgid", "setresgid").unwrap(), 2);

        // Unknown argument
        assert!(matches!(
            get_argument_index("unknown_arg", "open"),
            Err(ProfileError::InvalidArgument(_))
        ));
    }

    // ========================================================================
    // Parse Compare Op Tests
    // ========================================================================

    #[test]
    fn test_parse_compare_op() {
        assert_eq!(
            parse_compare_op("SCMP_CMP_NE").unwrap(),
            ScmpCompareOp::NotEqual
        );
        assert_eq!(
            parse_compare_op("SCMP_CMP_LT").unwrap(),
            ScmpCompareOp::Less
        );
        assert_eq!(
            parse_compare_op("SCMP_CMP_LE").unwrap(),
            ScmpCompareOp::LessOrEqual
        );
        assert_eq!(
            parse_compare_op("SCMP_CMP_EQ").unwrap(),
            ScmpCompareOp::Equal
        );
        assert_eq!(
            parse_compare_op("SCMP_CMP_GE").unwrap(),
            ScmpCompareOp::GreaterEqual
        );
        assert_eq!(
            parse_compare_op("SCMP_CMP_GT").unwrap(),
            ScmpCompareOp::Greater
        );

        assert!(parse_compare_op("SCMP_CMP_INVALID").is_err());
    }

    // ========================================================================
    // Resolve Action Tests
    // ========================================================================

    #[test]
    fn test_resolve_action() {
        // Allow -> Log when log_allowed is true
        assert_eq!(resolve_action(Action::Allow, true), Action::Log);
        assert_eq!(resolve_action(Action::Allow, false), Action::Allow);

        // Other actions unchanged
        assert_eq!(resolve_action(Action::KillThread, true), Action::KillThread);
        assert_eq!(resolve_action(Action::Log, true), Action::Log);
        assert_eq!(resolve_action(Action::Trap, false), Action::Trap);
    }

    // ========================================================================
    // Convert Condition To OCI Tests
    // ========================================================================

    #[test]
    fn test_convert_condition_bitmask() {
        // bitmask_all
        let cond = SyscallCondition {
            type_: "bitmask_all".to_string(),
            argument: "flags".to_string(),
            value: None,
            flags: Some("O_WRONLY|O_CREAT".to_string()),
        };
        let result = convert_condition_to_oci(&cond, "open").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].op, "SCMP_CMP_MASKED_EQ");
        assert_eq!(result[0].value, 0o101);
        assert_eq!(result[0].value_two, Some(0o101));

        // bitmask_none
        let cond = SyscallCondition {
            type_: "bitmask_none".to_string(),
            argument: "flags".to_string(),
            value: None,
            flags: Some("O_CREAT|O_TRUNC".to_string()),
        };
        let result = convert_condition_to_oci(&cond, "open").unwrap();
        assert_eq!(result[0].value, 0o1100);
        assert_eq!(result[0].value_two, Some(0));
    }

    #[test]
    fn test_convert_condition_comparison() {
        let test_cases = vec![
            ("equals", "3", "SCMP_CMP_EQ", 3),
            ("not_equals", "0", "SCMP_CMP_NE", 0),
            ("greater", "2", "SCMP_CMP_GT", 2),
            ("less", "1024", "SCMP_CMP_LT", 1024),
        ];

        for (type_, value, expected_op, expected_val) in test_cases {
            let cond = SyscallCondition {
                type_: type_.to_string(),
                argument: "fd".to_string(),
                value: Some(value.to_string()),
                flags: None,
            };
            let result = convert_condition_to_oci(&cond, "read").unwrap();
            assert_eq!(result.len(), 1);
            assert_eq!(result[0].op, expected_op);
            assert_eq!(result[0].value, expected_val);
            assert_eq!(result[0].value_two, None);
        }
    }

    #[test]
    fn test_convert_condition_errors() {
        // Unknown type returns empty vec (or should error based on your review)
        let cond = SyscallCondition {
            type_: "unknown_type".to_string(),
            argument: "fd".to_string(),
            value: None,
            flags: None,
        };
        let result = convert_condition_to_oci(&cond, "read").unwrap();
        assert_eq!(result.len(), 0);

        // Missing flags
        let cond = SyscallCondition {
            type_: "bitmask_all".to_string(),
            argument: "flags".to_string(),
            value: None,
            flags: None,
        };
        assert!(convert_condition_to_oci(&cond, "open").is_err());

        // Missing value
        let cond = SyscallCondition {
            type_: "equals".to_string(),
            argument: "fd".to_string(),
            value: None,
            flags: None,
        };
        assert!(convert_condition_to_oci(&cond, "read").is_err());
    }

    // ========================================================================
    // Convert Syscall Rule To OCI Tests
    // ========================================================================

    #[test]
    fn test_convert_syscall_rule_to_oci() {
        // No conditions
        let rule = SyscallRule {
            name: "read".to_string(),
            conditions: vec![],
        };
        let result = convert_syscall_rule_to_oci(&rule, Action::Allow).unwrap();
        assert_eq!(result.names, vec!["read"]);
        assert_eq!(result.action, Action::Allow);
        assert_eq!(result.conditions.len(), 0);

        // With conditions
        let rule = SyscallRule {
            name: "open".to_string(),
            conditions: vec![SyscallCondition {
                type_: "bitmask_all".to_string(),
                argument: "flags".to_string(),
                value: None,
                flags: Some("O_WRONLY".to_string()),
            }],
        };
        let result = convert_syscall_rule_to_oci(&rule, Action::Log).unwrap();
        assert_eq!(result.names, vec!["open"]);
        assert_eq!(result.action, Action::Log);
        assert_eq!(result.conditions.len(), 1);
    }

    // ========================================================================
    // Group Expansion Tests
    // ========================================================================

    #[test]
    fn test_expand_group_simple() {
        let mut groups = HashMap::new();
        groups.insert(
            "test".to_string(),
            AbstractGroupDef {
                rules: vec![
                    GroupRule::Syscall(SyscallRule {
                        name: "read".to_string(),
                        conditions: vec![],
                    }),
                    GroupRule::Syscall(SyscallRule {
                        name: "write".to_string(),
                        conditions: vec![],
                    }),
                ],
            },
        );

        let mut visited = HashSet::new();
        let result = expand_group("test", &groups, &mut visited).unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].name, "read");
        assert_eq!(result[1].name, "write");
    }

    #[test]
    fn test_expand_group_nested() {
        let mut groups = HashMap::new();
        groups.insert(
            "inner".to_string(),
            AbstractGroupDef {
                rules: vec![GroupRule::Syscall(SyscallRule {
                    name: "read".to_string(),
                    conditions: vec![],
                })],
            },
        );
        groups.insert(
            "outer".to_string(),
            AbstractGroupDef {
                rules: vec![
                    GroupRule::Syscall(SyscallRule {
                        name: "write".to_string(),
                        conditions: vec![],
                    }),
                    GroupRule::GroupRef(GroupReference {
                        group: "inner".to_string(),
                    }),
                ],
            },
        );

        let mut visited = HashSet::new();
        let result = expand_group("outer", &groups, &mut visited).unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].name, "write");
        assert_eq!(result[1].name, "read");
    }

    #[test]
    fn test_expand_group_errors() {
        let mut groups = HashMap::new();

        // Unknown group
        let mut visited = HashSet::new();
        let result = expand_group("nonexistent", &groups, &mut visited);
        assert!(matches!(result, Err(ProfileError::UnknownGroup(_))));

        // Self-reference (circular)
        groups.insert(
            "self_ref".to_string(),
            AbstractGroupDef {
                rules: vec![GroupRule::GroupRef(GroupReference {
                    group: "self_ref".to_string(),
                })],
            },
        );
        let mut visited = HashSet::new();
        let result = expand_group("self_ref", &groups, &mut visited);
        assert!(matches!(result, Err(ProfileError::CircularReference(_))));

        // Circular reference A->B->A
        groups.clear();
        groups.insert(
            "a".to_string(),
            AbstractGroupDef {
                rules: vec![GroupRule::GroupRef(GroupReference {
                    group: "b".to_string(),
                })],
            },
        );
        groups.insert(
            "b".to_string(),
            AbstractGroupDef {
                rules: vec![GroupRule::GroupRef(GroupReference {
                    group: "a".to_string(),
                })],
            },
        );
        let mut visited = HashSet::new();
        let result = expand_group("a", &groups, &mut visited);
        assert!(matches!(result, Err(ProfileError::CircularReference(_))));
    }

    #[test]
    fn test_expand_group_complex_cycle() {
        // Test A->B->C->A cycle
        let mut groups = HashMap::new();
        groups.insert(
            "a".to_string(),
            AbstractGroupDef {
                rules: vec![GroupRule::GroupRef(GroupReference {
                    group: "b".to_string(),
                })],
            },
        );
        groups.insert(
            "b".to_string(),
            AbstractGroupDef {
                rules: vec![GroupRule::GroupRef(GroupReference {
                    group: "c".to_string(),
                })],
            },
        );
        groups.insert(
            "c".to_string(),
            AbstractGroupDef {
                rules: vec![GroupRule::GroupRef(GroupReference {
                    group: "a".to_string(),
                })],
            },
        );

        let mut visited = HashSet::new();
        let result = expand_group("a", &groups, &mut visited);
        assert!(matches!(result, Err(ProfileError::CircularReference(_))));
    }

    #[test]
    fn test_expand_group_no_false_positive() {
        // Test A->B, A->C (no cycle - shared dependency is OK)
        let mut groups = HashMap::new();
        groups.insert(
            "shared".to_string(),
            AbstractGroupDef {
                rules: vec![GroupRule::Syscall(SyscallRule {
                    name: "read".to_string(),
                    conditions: vec![],
                })],
            },
        );
        groups.insert(
            "a".to_string(),
            AbstractGroupDef {
                rules: vec![
                    GroupRule::GroupRef(GroupReference {
                        group: "shared".to_string(),
                    }),
                    GroupRule::Syscall(SyscallRule {
                        name: "write".to_string(),
                        conditions: vec![],
                    }),
                ],
            },
        );

        let mut visited = HashSet::new();
        let result = expand_group("a", &groups, &mut visited);
        assert!(result.is_ok());
        let rules = result.unwrap();
        assert_eq!(rules.len(), 2);
    }

    // ========================================================================
    // Profile Loading Tests
    // ========================================================================

    #[test]
    fn test_load_profile_with_file() {
        let profile_content = r#"
            default_action = "KillProcess"
            architectures = ["SCMP_ARCH_X86_64"]
        "#;

        let temp_dir = std::env::temp_dir();
        let profile_path = temp_dir.join("test_profile.toml");
        fs::write(&profile_path, profile_content).unwrap();

        let result = load_profile(
            Some(profile_path.to_str().unwrap().to_string()),
            None,
            None,
            &[],
            &[],
            false,
        );

        assert!(result.is_ok());
        let ctx = result.unwrap();
        assert_eq!(ctx.get_act_default().unwrap(), ScmpAction::KillProcess);
        assert!(ctx.is_arch_present(ScmpArch::X8664).unwrap());

        fs::remove_file(profile_path).unwrap();
    }

    #[test]
    fn test_load_profile_defaults() {
        // No profile, no log_allowed
        let ctx = load_profile(None, None, None, &[], &[], false).unwrap();
        assert_eq!(ctx.get_act_default().unwrap(), ScmpAction::Allow);

        // No profile, with log_allowed
        let ctx = load_profile(None, None, None, &[], &[], true).unwrap();
        assert_eq!(ctx.get_act_default().unwrap(), ScmpAction::Log);
    }

    // ========================================================================
    // Coalesce Rules Tests
    // ========================================================================

    #[test]
    fn test_coalesce_rules() {
        let mut profile = OciSeccomp {
            default_action: Action::Errno,
            default_errno_ret: None,
            architectures: vec!["SCMP_ARCH_X86_64".to_string()],
            syscalls: Some(vec![
                OciSyscall {
                    names: vec!["read".to_string()],
                    action: Action::Allow,
                    errno_ret: None,
                    conditions: vec![],
                },
                OciSyscall {
                    names: vec!["write".to_string()],
                    action: Action::Allow,
                    errno_ret: None,
                    conditions: vec![],
                },
                OciSyscall {
                    names: vec!["open".to_string()],
                    action: Action::Log,
                    errno_ret: None,
                    conditions: vec![],
                },
            ]),
            abstract_syscalls: None,
        };

        coalesce_rules_by_action(&mut profile);

        let syscalls = profile.syscalls.unwrap();
        assert_eq!(syscalls.len(), 2); // read+write merged, open separate

        // Find the Allow rule
        let allow_rule = syscalls.iter().find(|s| s.action == Action::Allow).unwrap();
        assert_eq!(allow_rule.names.len(), 2);
        assert!(allow_rule.names.contains(&"read".to_string()));
        assert!(allow_rule.names.contains(&"write".to_string()));
    }

    #[test]
    fn test_explode_syscalls() {
        let mut profile = OciSeccomp {
            default_action: Action::Errno,
            default_errno_ret: None,
            architectures: vec!["SCMP_ARCH_X86_64".to_string()],
            syscalls: Some(vec![OciSyscall {
                names: vec!["read".to_string(), "write".to_string(), "open".to_string()],
                action: Action::Allow,
                errno_ret: None,
                conditions: vec![],
            }]),
            abstract_syscalls: None,
        };

        explode_syscalls(&mut profile);

        let syscalls = profile.syscalls.unwrap();
        assert_eq!(syscalls.len(), 3);
        assert_eq!(syscalls[0].names, vec!["read"]);
        assert_eq!(syscalls[1].names, vec!["write"]);
        assert_eq!(syscalls[2].names, vec!["open"]);
    }
}
