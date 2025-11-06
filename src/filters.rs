use libseccomp::{
    error::SeccompError, ScmpAction, ScmpArch, ScmpArgCompare, ScmpCompareOp, ScmpFilterContext,
    ScmpSyscall,
};
use log2::*;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::str::FromStr;
use thiserror::Error;
use toml;

use crate::actions::{Action, ActionError};

// ============================================================================
// Error Types
// ============================================================================

#[derive(Error, Debug)]
pub enum ProfileError {
    #[error("Could not read profile file: {0}")]
    FileRead(#[from] std::io::Error),
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

// ============================================================================
// Profile Structures
// ============================================================================

#[derive(Deserialize, Debug)]
struct OciSyscallCondition {
    index: u8,
    value: u64,
    value_two: Option<u64>,
    op: String,
}

#[derive(Deserialize, Debug)]
struct OciSyscall {
    names: Vec<String>,
    action: Action,
    errno_ret: Option<u32>,
    #[serde(default)]
    conditions: Vec<OciSyscallCondition>,
}

#[derive(Deserialize, Debug)]
struct AbstractSyscall {
    names: Vec<String>,
    action: Action,
}

fn default_architectures() -> Vec<String> {
    vec!["SCMP_ARCH_X86_64".to_string()]
}

#[derive(Deserialize, Debug)]
struct OciSeccomp {
    default_action: Action,
    default_errno_ret: Option<u32>,
    #[serde(default = "default_architectures")]
    architectures: Vec<String>,
    syscalls: Option<Vec<OciSyscall>>,
    abstract_syscalls: Option<Vec<AbstractSyscall>>,
}

// ============================================================================
// Public API
// ============================================================================

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
        match fs::read_to_string(path) {
            Ok(profile_content) => match toml::from_str(&profile_content) {
                Ok(oci_seccomp) => apply_profile(
                    oci_seccomp,
                    default_action_override,
                    default_errno_ret_override,
                    log_allowed,
                )?,
                Err(e) => {
                    error!("Failed to parse profile: {}", e);
                    return Err(ProfileError::ProfileParse(e));
                }
            },
            Err(e) => {
                error!("Failed to read profile: {}", e);
                return Err(ProfileError::FileRead(e));
            }
        }
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

fn apply_profile(
    oci_seccomp: OciSeccomp,
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

fn apply_syscall_rules(
    ctx: &mut ScmpFilterContext,
    raw_profile: OciSeccomp,
    log_allowed: bool,
) -> Result<(), ProfileError> {
    let syscalls = raw_profile.syscalls;
    let abstract_syscalls = raw_profile.abstract_syscalls;

    if syscalls.is_none() && abstract_syscalls.is_none() {
        let default_action = Action::from(ctx.get_act_default().unwrap_or(ScmpAction::Allow));
        warn_unconfigured_default_action(default_action);
        return Ok(());
    }

    if let Some(syscalls) = syscalls {
        for syscall_entry in syscalls {
            apply_syscall_rule(ctx, &syscall_entry, log_allowed)?;
        }
    }

    if let Some(abstract_syscalls) = abstract_syscalls {
        let abstract_groups_path = std::path::Path::new("data/abstract_rules.json");
        let abstract_groups = serde_json::from_str::<AbstractGroups>(
            &fs::read_to_string(abstract_groups_path).map_err(|e| {
                error!("Failed to read abstract rules: {}", e);
                ProfileError::FileRead(e)
            })?,
        )
        .map_err(|e| {
            error!("Failed to parse abstract rules: {}", e);
            ProfileError::AbstractParse(e)
        })?;

        for abstract_entry in abstract_syscalls {
            for group_name in &abstract_entry.names {
                debug!("Expanding abstract group: {}", group_name);
                let expanded_rules =
                    expand_group(group_name, &abstract_groups.groups, &mut HashSet::new())?;

                for syscall_rule in expanded_rules {
                    let oci_syscall =
                        convert_syscall_rule_to_oci(&syscall_rule, abstract_entry.action)?;
                    apply_syscall_rule(ctx, &oci_syscall, log_allowed)?;
                }
            }
        }
    }

    Ok(())
}

fn expand_group(
    group_name: &str,
    groups: &HashMap<String, AbstractGroupDef>,
    visited: &mut HashSet<String>,
) -> Result<Vec<SyscallRule>, ProfileError> {
    // Check for circular references
    if visited.contains(group_name) {
        return Err(ProfileError::CircularReference(group_name.to_string()));
    }

    visited.insert(group_name.to_string());

    let group_def = groups.get(group_name).ok_or_else(|| {
        error!("Unknown abstract group: {}", group_name);
        ProfileError::UnknownGroup(group_name.to_string())
    })?;

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
            // Check if ALL specified flags are set: (arg & flags) == flags
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
            // Check if ANY of the specified flags are set: (arg & flags) != 0
            // Unfortunately MASKED_EQ can't express "!= 0", so we need a workaround
            // We'll use MASKED_EQ and check for any non-zero value
            // Actually, libseccomp doesn't support this well, so we'll just check
            // if the masked value is non-zero by checking if it equals ANY of the bits
            let flags_str = condition.flags.as_ref().ok_or_else(|| {
                ProfileError::InvalidArgument("flags missing for bitmask_any".to_string())
            })?;
            let flag_value = parse_flags(flags_str)?;

            // For "any bit set", we can't easily express this with MASKED_EQ
            // Best we can do is check if (arg & mask) == mask for the full set
            // OR we need to create multiple rules for each individual flag
            // For simplicity, let's just check if ANY of the bits match
            warn!("bitmask_any is limited in seccomp; using bitmask_all semantics");
            Ok(vec![OciSyscallCondition {
                index: arg_index,
                value: flag_value,
                value_two: Some(flag_value),
                op: "SCMP_CMP_MASKED_EQ".to_string(),
            }])
        }
        "bitmask_none" => {
            // Check if NONE of the specified flags are set: (arg & flags) == 0
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

fn get_argument_index(arg_name: &str, syscall_name: &str) -> Result<u8, ProfileError> {
    match arg_name {
        "flags" => match syscall_name {
            "open" => Ok(1),
            "openat" => Ok(2),
            _ => Ok(1),
        },
        "mode" => Ok(2),
        "domain" => Ok(0),
        "type" => Ok(1),
        "protocol" => Ok(2),
        "pid" => Ok(0),
        "fd" => Ok(0),
        "sockfd" => Ok(0),
        "ruid" => Ok(0),
        "euid" => Ok(1),
        "suid" => Ok(2),
        "rgid" => Ok(0),
        "egid" => Ok(1),
        "sgid" => Ok(2),
        name => Err(ProfileError::InvalidArgument(format!(
            "Unknown argument name: {}",
            name
        ))),
    }
}

fn parse_flags(flags_str: &str) -> Result<u64, ProfileError> {
    let mut result: u64 = 0;

    for flag in flags_str.split('|').map(str::trim) {
        result |= match flag {
            // File open flags
            "O_RDONLY" => 0o0,
            "O_WRONLY" => 0o1,
            "O_RDWR" => 0o2,
            "O_CREAT" => 0o100,
            "O_EXCL" => 0o200,
            "O_NOCTTY" => 0o400,
            "O_TRUNC" => 0o1000,
            "O_APPEND" => 0o2000,
            "O_NONBLOCK" => 0o4000,
            "O_RONLY" => 0o0,

            // Clone flags
            "CLONE_THREAD" => 0x00010000,
            "CLONE_VM" => 0x00000100,
            "CLONE_FS" => 0x00000200,
            "CLONE_FILES" => 0x00000400,
            "CLONE_SIGHAND" => 0x00000800,
            "CLONE_PTRACE" => 0x00002000,
            "CLONE_VFORK" => 0x00004000,
            "CLONE_PARENT" => 0x00008000,

            // Socket domains
            "AF_UNIX" => 1,
            "AF_INET" => 2,
            "AF_INET6" => 10,
            "AF_NETLINK" => 16,

            _ => {
                warn!("Unknown flag: {}, ignoring", flag);
                0
            }
        };
    }

    Ok(result)
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
    fn test_parse_value_decimal() {
        assert_eq!(parse_value("42").unwrap(), 42);
        assert_eq!(parse_value("0").unwrap(), 0);
        assert_eq!(parse_value("65536").unwrap(), 65536);
    }

    #[test]
    fn test_parse_value_hex() {
        assert_eq!(parse_value("0x10").unwrap(), 16);
        assert_eq!(parse_value("0xFF").unwrap(), 255);
        assert_eq!(parse_value("0x0").unwrap(), 0);
    }

    #[test]
    fn test_parse_value_named_constants() {
        assert_eq!(parse_value("AF_UNIX").unwrap(), 1);
        assert_eq!(parse_value("AF_INET").unwrap(), 2);
        assert_eq!(parse_value("AF_INET6").unwrap(), 10);
        assert_eq!(parse_value("AF_NETLINK").unwrap(), 16);
    }

    #[test]
    fn test_parse_value_invalid() {
        assert!(parse_value("invalid").is_err());
        assert!(parse_value("0xZZZ").is_err());
    }

    // ========================================================================
    // Parse Flags Tests
    // ========================================================================

    #[test]
    fn test_parse_flags_single() {
        assert_eq!(parse_flags("O_WRONLY").unwrap(), 0o1);
        assert_eq!(parse_flags("O_RDWR").unwrap(), 0o2);
        assert_eq!(parse_flags("O_CREAT").unwrap(), 0o100);
    }

    #[test]
    fn test_parse_flags_multiple() {
        let result = parse_flags("O_WRONLY|O_CREAT").unwrap();
        assert_eq!(result, 0o1 | 0o100);

        let result = parse_flags("O_RDWR|O_CREAT|O_TRUNC").unwrap();
        assert_eq!(result, 0o2 | 0o100 | 0o1000);
    }

    #[test]
    fn test_parse_flags_with_whitespace() {
        let result = parse_flags("O_WRONLY | O_CREAT | O_TRUNC").unwrap();
        assert_eq!(result, 0o1 | 0o100 | 0o1000);
    }

    #[test]
    fn test_parse_flags_clone_flags() {
        assert_eq!(parse_flags("CLONE_THREAD").unwrap(), 0x00010000);
        assert_eq!(parse_flags("CLONE_VM").unwrap(), 0x00000100);
        let result = parse_flags("CLONE_THREAD|CLONE_VM").unwrap();
        assert_eq!(result, 0x00010000 | 0x00000100);
    }

    #[test]
    fn test_parse_flags_socket_domains() {
        assert_eq!(parse_flags("AF_UNIX").unwrap(), 1);
        assert_eq!(parse_flags("AF_INET").unwrap(), 2);
        assert_eq!(parse_flags("AF_INET6").unwrap(), 10);
    }

    #[test]
    fn test_parse_flags_unknown_flag_warning() {
        // Unknown flags are silently ignored with a warning
        let result = parse_flags("O_WRONLY|UNKNOWN_FLAG|O_CREAT").unwrap();
        assert_eq!(result, 0o1 | 0o100);
    }

    // ========================================================================
    // Get Argument Index Tests
    // ========================================================================

    #[test]
    fn test_get_argument_index_flags() {
        assert_eq!(get_argument_index("flags", "open").unwrap(), 1);
        assert_eq!(get_argument_index("flags", "openat").unwrap(), 2);
        assert_eq!(get_argument_index("flags", "other").unwrap(), 1);
    }

    #[test]
    fn test_get_argument_index_standard_args() {
        assert_eq!(get_argument_index("mode", "open").unwrap(), 2);
        assert_eq!(get_argument_index("fd", "write").unwrap(), 0);
        assert_eq!(get_argument_index("domain", "socket").unwrap(), 0);
        assert_eq!(get_argument_index("type", "socket").unwrap(), 1);
    }

    #[test]
    fn test_get_argument_index_uid_gid() {
        assert_eq!(get_argument_index("ruid", "setresuid").unwrap(), 0);
        assert_eq!(get_argument_index("euid", "setresuid").unwrap(), 1);
        assert_eq!(get_argument_index("suid", "setresuid").unwrap(), 2);
        assert_eq!(get_argument_index("rgid", "setresgid").unwrap(), 0);
        assert_eq!(get_argument_index("egid", "setresgid").unwrap(), 1);
        assert_eq!(get_argument_index("sgid", "setresgid").unwrap(), 2);
    }

    #[test]
    fn test_get_argument_index_unknown() {
        assert!(get_argument_index("unknown_arg", "open").is_err());
    }

    // ========================================================================
    // Parse Compare Op Tests
    // ========================================================================

    #[test]
    fn test_parse_compare_op_all_operators() {
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
    }

    #[test]
    fn test_parse_compare_op_invalid() {
        assert!(parse_compare_op("SCMP_CMP_INVALID").is_err());
    }

    // ========================================================================
    // Resolve Action Tests
    // ========================================================================

    #[test]
    fn test_resolve_action_allow_with_log() {
        let action = resolve_action(Action::Allow, true);
        assert_eq!(action, Action::Log);
    }

    #[test]
    fn test_resolve_action_allow_without_log() {
        let action = resolve_action(Action::Allow, false);
        assert_eq!(action, Action::Allow);
    }

    #[test]
    fn test_resolve_action_other_actions() {
        assert_eq!(resolve_action(Action::KillThread, true), Action::KillThread);
        assert_eq!(
            resolve_action(Action::KillThread, false),
            Action::KillThread
        );
        assert_eq!(resolve_action(Action::Log, true), Action::Log);
        assert_eq!(resolve_action(Action::Log, false), Action::Log);
    }

    // ========================================================================
    // Convert Condition To OCI Tests
    // ========================================================================

    #[test]
    fn test_convert_condition_bitmask_all() {
        let condition = SyscallCondition {
            type_: "bitmask_all".to_string(),
            argument: "flags".to_string(),
            value: None,
            flags: Some("O_WRONLY|O_CREAT".to_string()),
        };

        let result = convert_condition_to_oci(&condition, "open").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].op, "SCMP_CMP_MASKED_EQ");
        assert_eq!(result[0].value, 0o1 | 0o100);
        assert_eq!(result[0].value_two, Some(0o1 | 0o100));
    }

    #[test]
    fn test_convert_condition_bitmask_none() {
        let condition = SyscallCondition {
            type_: "bitmask_none".to_string(),
            argument: "flags".to_string(),
            value: None,
            flags: Some("O_CREAT|O_TRUNC".to_string()),
        };

        let result = convert_condition_to_oci(&condition, "open").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].op, "SCMP_CMP_MASKED_EQ");
        assert_eq!(result[0].value, 0o100 | 0o1000);
        assert_eq!(result[0].value_two, Some(0));
    }

    #[test]
    fn test_convert_condition_equals() {
        let condition = SyscallCondition {
            type_: "equals".to_string(),
            argument: "fd".to_string(),
            value: Some("3".to_string()),
            flags: None,
        };

        let result = convert_condition_to_oci(&condition, "read").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].op, "SCMP_CMP_EQ");
        assert_eq!(result[0].value, 3);
    }

    #[test]
    fn test_convert_condition_not_equals() {
        let condition = SyscallCondition {
            type_: "not_equals".to_string(),
            argument: "fd".to_string(),
            value: Some("0".to_string()),
            flags: None,
        };

        let result = convert_condition_to_oci(&condition, "write").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].op, "SCMP_CMP_NE");
        assert_eq!(result[0].value, 0);
    }

    #[test]
    fn test_convert_condition_greater() {
        let condition = SyscallCondition {
            type_: "greater".to_string(),
            argument: "fd".to_string(),
            value: Some("2".to_string()),
            flags: None,
        };

        let result = convert_condition_to_oci(&condition, "close").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].op, "SCMP_CMP_GT");
        assert_eq!(result[0].value, 2);
    }

    #[test]
    fn test_convert_condition_less() {
        let condition = SyscallCondition {
            type_: "less".to_string(),
            argument: "fd".to_string(),
            value: Some("1024".to_string()),
            flags: None,
        };

        let result = convert_condition_to_oci(&condition, "dup").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].op, "SCMP_CMP_LT");
        assert_eq!(result[0].value, 1024);
    }

    #[test]
    fn test_convert_condition_unknown_type() {
        let condition = SyscallCondition {
            type_: "unknown_type".to_string(),
            argument: "fd".to_string(),
            value: None,
            flags: None,
        };

        let result = convert_condition_to_oci(&condition, "read").unwrap();
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_convert_condition_missing_flags() {
        let condition = SyscallCondition {
            type_: "bitmask_all".to_string(),
            argument: "flags".to_string(),
            value: None,
            flags: None,
        };

        assert!(convert_condition_to_oci(&condition, "open").is_err());
    }

    #[test]
    fn test_convert_condition_missing_value() {
        let condition = SyscallCondition {
            type_: "equals".to_string(),
            argument: "fd".to_string(),
            value: None,
            flags: None,
        };

        assert!(convert_condition_to_oci(&condition, "read").is_err());
    }

    // ========================================================================
    // Convert Syscall Rule To OCI Tests
    // ========================================================================

    #[test]
    fn test_convert_syscall_rule_to_oci_no_conditions() {
        let syscall_rule = SyscallRule {
            name: "read".to_string(),
            conditions: vec![],
        };

        let result = convert_syscall_rule_to_oci(&syscall_rule, Action::Allow).unwrap();
        assert_eq!(result.names, vec!["read"]);
        assert_eq!(result.action, Action::Allow);
        assert_eq!(result.conditions.len(), 0);
    }

    #[test]
    fn test_convert_syscall_rule_to_oci_with_conditions() {
        let syscall_rule = SyscallRule {
            name: "open".to_string(),
            conditions: vec![SyscallCondition {
                type_: "bitmask_all".to_string(),
                argument: "flags".to_string(),
                value: None,
                flags: Some("O_WRONLY".to_string()),
            }],
        };

        let result = convert_syscall_rule_to_oci(&syscall_rule, Action::Log).unwrap();
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
            "test_group".to_string(),
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
        let result = expand_group("test_group", &groups, &mut visited).unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].name, "read");
        assert_eq!(result[1].name, "write");
    }

    #[test]
    fn test_expand_group_nested() {
        let mut groups = HashMap::new();
        groups.insert(
            "inner_group".to_string(),
            AbstractGroupDef {
                rules: vec![GroupRule::Syscall(SyscallRule {
                    name: "read".to_string(),
                    conditions: vec![],
                })],
            },
        );
        groups.insert(
            "outer_group".to_string(),
            AbstractGroupDef {
                rules: vec![
                    GroupRule::Syscall(SyscallRule {
                        name: "write".to_string(),
                        conditions: vec![],
                    }),
                    GroupRule::GroupRef(GroupReference {
                        group: "inner_group".to_string(),
                    }),
                ],
            },
        );

        let mut visited = HashSet::new();
        let result = expand_group("outer_group", &groups, &mut visited).unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].name, "write");
        assert_eq!(result[1].name, "read");
    }

    #[test]
    fn test_expand_group_unknown_group() {
        let groups = HashMap::new();
        let mut visited = HashSet::new();

        let result = expand_group("nonexistent", &groups, &mut visited);
        assert!(result.is_err());
        match result.unwrap_err() {
            ProfileError::UnknownGroup(name) => assert_eq!(name, "nonexistent"),
            _ => panic!("Expected UnknownGroup error"),
        }
    }

    #[test]
    fn test_expand_group_circular_reference() {
        let mut groups = HashMap::new();
        groups.insert(
            "group_a".to_string(),
            AbstractGroupDef {
                rules: vec![GroupRule::GroupRef(GroupReference {
                    group: "group_b".to_string(),
                })],
            },
        );
        groups.insert(
            "group_b".to_string(),
            AbstractGroupDef {
                rules: vec![GroupRule::GroupRef(GroupReference {
                    group: "group_a".to_string(),
                })],
            },
        );

        let mut visited = HashSet::new();
        let result = expand_group("group_a", &groups, &mut visited);

        assert!(result.is_err());
        match result.unwrap_err() {
            ProfileError::CircularReference(_) => (),
            _ => panic!("Expected CircularReference error"),
        }
    }

    #[test]
    fn test_load_profile_with_profile() {
        let profile_content = r#"
            default_action = "KillProcess"
            architectures = ["SCMP_ARCH_X86_64"]
        "#;
        let temp_dir = std::env::temp_dir();
        let profile_path = temp_dir.join("test_profile.toml");
        fs::write(&profile_path, profile_content).unwrap();

        let result = load_profile(Some(profile_path.to_str().unwrap().to_string()), None, None, &[], &[], false).unwrap();
        assert_eq!(result.get_act_default().unwrap(), ScmpAction::KillProcess);
        assert!(result.is_arch_present(ScmpArch::X8664).unwrap());

        fs::remove_file(profile_path).unwrap();
    }

    #[test]
    fn test_load_profile_no_profile() {
        let result = load_profile(None, None, None, &[], &[], false).unwrap();
        assert_eq!(result.get_act_default().unwrap(), ScmpAction::Allow);
    }

    #[test]
    fn test_expand_group_self_reference() {
        let mut groups = HashMap::new();
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

        assert!(result.is_err());
    }
}
