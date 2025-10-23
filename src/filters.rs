use libseccomp::{
    error::SeccompError, ScmpAction, ScmpArch, ScmpArgCompare, ScmpCompareOp, ScmpFilterContext,
    ScmpSyscall,
};
use log2::*;
use serde::Deserialize;
use std::fs;
use std::str::FromStr;
use thiserror::Error;

use crate::actions::{Action, ActionError};

// ============================================================================
// Error Types
// ============================================================================

#[derive(Error, Debug)]
pub enum ProfileError {
    #[error("Could not read profile file: {0}")]
    FileRead(#[from] std::io::Error),
    #[error("Could not parse OCI profile: {0}")]
    OciParse(#[from] serde_json::Error),
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
}

// ============================================================================
// OCI Profile Structures
// ============================================================================

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct OciSyscallArg {
    index: u8,
    value: u64,
    value_two: Option<u64>,
    op: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct OciSyscall {
    names: Vec<String>,
    action: Action,
    errno_ret: Option<u32>,
    #[serde(default)]
    args: Vec<OciSyscallArg>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct AbstractSyscall {
    names: Vec<String>,
    action: Action,
}

fn default_architectures() -> Vec<String> {
    vec!["SCMP_ARCH_X86_64".to_string()]
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
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
        debug!("Parsing OCI profile: {}", path);
        match fs::read_to_string(path) {
            Ok(profile_content) => match serde_json::from_str(&profile_content) {
                Ok(oci_seccomp) => apply_oci_profile(
                    oci_seccomp,
                    default_action_override,
                    default_errno_ret_override,
                    log_allowed,
                )?,
                Err(e) => {
                    error!("Failed to parse OCI profile: {}", e);
                    return Err(ProfileError::FileRead(e.into()));
                }
            },
            Err(e) => {
                error!("Failed to read OCI profile: {}", e);
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

    debug!("kill_syscalls has {} entries", kill_syscalls.len());
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

fn apply_oci_profile(
    oci_seccomp: OciSeccomp,
    default_action_override: Option<Action>,
    default_errno_ret_override: Option<u32>,
    log_allowed: bool,
) -> Result<ScmpFilterContext, ProfileError> {
    let default_errno_ret = default_errno_ret_override.or(oci_seccomp.default_errno_ret);
    let default_action = if log_allowed {
        Action::Log.to_scmp_action(None)?
    } else {
        default_action_override
            .unwrap_or(oci_seccomp.default_action)
            .to_scmp_action(default_errno_ret)?
    };

    let mut ctx = ScmpFilterContext::new(default_action).map_err(|e| {
        error!(
            "Failed to create filter context with default_action={:?}: {}",
            default_action, e
        );
        ProfileError::LibSeccomp(e)
    })?;

    add_architectures(&mut ctx, &oci_seccomp.architectures)?;
    apply_syscall_rules(&mut ctx, oci_seccomp.syscalls, log_allowed)?;

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
    syscalls: Option<Vec<OciSyscall>>,
    log_allowed: bool,
) -> Result<(), ProfileError> {
    match syscalls {
        Some(syscalls) => {
            for syscall_entry in syscalls {
                debug!("Processing syscall: {}", syscall_entry.names.join(","));
                apply_syscall_rule(ctx, &syscall_entry, log_allowed)?;
            }
            Ok(())
        }
        None => {
            let default_action = Action::from(ctx.get_act_default().unwrap_or(ScmpAction::Allow));
            warn_unconfigured_default_action(default_action);
            Ok(())
        }
    }
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

    for syscall_name in &syscall_entry.names {
        add_rule_for_syscall(ctx, syscall_name, scmp_action, &syscall_entry.args)?;
    }

    Ok(())
}

fn add_rule_for_syscall(
    ctx: &mut ScmpFilterContext,
    syscall_name: &str,
    scmp_action: ScmpAction,
    args: &[OciSyscallArg],
) -> Result<(), ProfileError> {
    let syscall = ScmpSyscall::from_name(syscall_name).map_err(|_| {
        error!("Unknown syscall: {}", syscall_name);
        ProfileError::UnknownSyscall(syscall_name.to_string())
    })?;

    let default_action = ctx.get_act_default().unwrap_or(ScmpAction::Allow);

    if scmp_action == default_action {
        warn!("Ignoring syscall rule for default action: {}", syscall_name);
        return Ok(());
    }

    if args.is_empty() {
        debug!(
            "Adding unconditional rule: action={:?}, syscall={}",
            scmp_action, syscall_name
        );
        ctx.add_rule(scmp_action, syscall)
    } else {
        let comparators = build_comparators(args)?;
        debug!(
            "Adding conditional rule: action={:?}, syscall={}",
            scmp_action, syscall_name
        );
        ctx.add_rule_conditional(scmp_action, syscall, &comparators)
    }
    .map(|_| ())
    .map_err(|e| {
        error!("Failed to add rule for {}: {}", syscall_name, e);
        ProfileError::LibSeccomp(e)
    })
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

fn build_comparators(args: &[OciSyscallArg]) -> Result<Vec<ScmpArgCompare>, ProfileError> {
    args.iter().map(build_comparator).collect()
}

fn build_comparator(arg: &OciSyscallArg) -> Result<ScmpArgCompare, ProfileError> {
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

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(parse_compare_op("UNKNOWN_OP").is_err());
    }

    #[test]
    fn test_parse_syscall() {
        let profile = r#"
        {
            "defaultAction": "SCMP_ACT_ALLOW",
            "architectures": [
                "SCMP_ARCH_X86_64"
            ],
            "syscalls": [
                {
                    "names": [
                        "write",
                        "read"
                    ],
                    "action": "SCMP_ACT_LOG"
                }
            ]
        }
        "#;

        let profile: OciSeccomp = if let Ok(profile) = serde_json::from_str(profile) {
            profile
        } else {
            panic!("Failed to parse profile");
        };

        if let Some(syscalls) = profile.syscalls {
            for syscall in syscalls {
                assert_eq!(syscall.action, Action::Log);
                for name in syscall.names {
                    assert!(name.starts_with("write") || name.starts_with("read"));
                }
            }
        } else {
            println!("{:?}", profile);
            panic!("No syscalls found");
        }
    }

    #[test]
    fn test_parse_abstract_syscall() {
        let profile = r#"
        {
            "defaultAction": "SCMP_ACT_ALLOW",
            "architectures": [
                "SCMP_ARCH_X86_64"
            ],
            "syscalls": [
                {
                    "names": [
                        "stat",
                        "openat"
                    ],
                    "action": "SCMP_ACT_LOG"
                }
            ],
            "abstractSyscalls": [
                {
                    "names": [
                        "WriteOpen"
                    ],
                    "action": "SCMP_ACT_KILL"
                }
            ]
        }
        "#;

        let profile: OciSeccomp = if let Ok(profile) = serde_json::from_str(profile) {
            profile
        } else {
            panic!("Failed to parse profile");
        };

        if let Some(abstract_syscalls) = profile.abstract_syscalls {
            for abstract_syscall in abstract_syscalls {
                assert_eq!(
                    abstract_syscall.action,
                    Action::KillProcess,
                    "{}",
                    abstract_syscall.names.join(",")
                );
                for name in abstract_syscall.names {
                    assert!(name.starts_with("WriteOpen"));
                }
            }
        } else {
            println!("{:?}", profile);
            panic!("No abstract syscalls found");
        }
    }
}
