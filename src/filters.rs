use libseccomp::{
    error::SeccompError, ScmpAction, ScmpArch, ScmpArgCompare, ScmpCompareOp, ScmpFilterContext,
    ScmpSyscall,
};
use log2::*;
use serde::Deserialize;
use std::fs;
use std::str::FromStr;
use thiserror::Error;

use crate::actions::Action;

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
    #[error("Syscall number conversion error")]
    SyscallNumConversion,
    #[error("libseccomp error: {0}")]
    LibSeccomp(#[from] SeccompError),
    #[error("OCI profile has no syscalls")]
    NoSyscallsInProfile,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct OciSyscallArg {
    index: u8,
    value: u64,
    value_two: Option<u64>,
    op: String,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct OciSyscall {
    names: Vec<String>,
    action: Action,
    errno_ret: Option<u32>,
    #[serde(default)]
    args: Vec<OciSyscallArg>,
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
}

fn parse_scmp_compare_op(op: &str, value: u64) -> Result<ScmpCompareOp, ProfileError> {
    match op {
        "SCMP_CMP_NE" => Ok(ScmpCompareOp::NotEqual),
        "SCMP_CMP_LT" => Ok(ScmpCompareOp::Less),
        "SCMP_CMP_LE" => Ok(ScmpCompareOp::LessOrEqual),
        "SCMP_CMP_EQ" => Ok(ScmpCompareOp::Equal),
        "SCMP_CMP_GE" => Ok(ScmpCompareOp::GreaterEqual),
        "SCMP_CMP_GT" => Ok(ScmpCompareOp::Greater),
        "SCMP_CMP_MASKED_EQ" => Ok(ScmpCompareOp::MaskedEqual(value)),
        _ => Err(ProfileError::ArchConversion(format!(
            "Unknown comparison operator: {}",
            op
        ))),
    }
}

pub fn load_profile(
    profile_path: Option<String>,
    default_action_override: Option<Action>,
    default_errno_ret_override: Option<u32>,
    kill_syscalls: &[String],
    log_syscalls: &[String],
    log_allowed: bool,
) -> Result<ScmpFilterContext, ProfileError> {
    let mut ctx;

    if let Some(profile_path) = profile_path {
        debug!("Parsing OCI profile: {}", profile_path);
        let profile_content = fs::read_to_string(profile_path)?;
        let oci_seccomp: OciSeccomp = serde_json::from_str(&profile_content)?;

        let default_errno_ret = default_errno_ret_override.or(oci_seccomp.default_errno_ret);

        let default_action = default_action_override
            .unwrap_or(oci_seccomp.default_action)
            .to_scmp_action(default_errno_ret);

        ctx = ScmpFilterContext::new(default_action)?;

        // Add architectures from the profile
        if !oci_seccomp.architectures.is_empty() {
            for arch_str in &oci_seccomp.architectures {
                let arch = ScmpArch::from_str(arch_str)?;
                if !ctx.is_arch_present(arch)? {
                    ctx.add_arch(arch)?;
                }
                debug!("Adding architecture: {}", arch_str);
            }
        }

        // Process syscalls from the profile
        if let Some(syscalls) = oci_seccomp.syscalls {
            for syscall_entry in syscalls {
                let action = (if log_allowed && syscall_entry.action == Action::Allow {
                    Action::Log
                } else {
                    syscall_entry.action
                })
                .to_scmp_action(syscall_entry.errno_ret);

                for syscall_name in &syscall_entry.names {
                    let syscall = ScmpSyscall::from_name(syscall_name)
                        .map_err(|_| ProfileError::UnknownSyscall(syscall_name.clone()))?;

                    debug!("Adding rule for syscall: {}", syscall_name);

                    if syscall_entry.args.is_empty() {
                        // No conditions, add unconditional rule
                        ctx.add_rule(action, syscall)?;
                    } else {
                        // Build comparators from args
                        let comparators: Result<Vec<_>, ProfileError> = syscall_entry
                            .args
                            .iter()
                            .map(|arg| {
                                // For MASKED_EQ, value is the mask, value_two is the datum
                                // For others, value is the datum
                                let (op, datum) = if arg.op == "SCMP_CMP_MASKED_EQ" {
                                    let mask = arg.value;
                                    let datum = arg.value_two.unwrap_or(0);
                                    (ScmpCompareOp::MaskedEqual(mask), datum)
                                } else {
                                    (parse_scmp_compare_op(&arg.op, arg.value)?, arg.value)
                                };

                                Ok(ScmpArgCompare::new(arg.index as u32, op, datum))
                            })
                            .collect();

                        ctx.add_rule_conditional(action, syscall, &comparators?)?;
                    }
                }
            }
        } else {
            return Err(ProfileError::NoSyscallsInProfile);
        }
    } else {
        info!("No profile provided, using default action: Allow + parameter override");
        ctx = ScmpFilterContext::new(Action::Allow.to_scmp_action(None))?;
    }

    // Apply kill_syscalls overrides
    for syscall_name in kill_syscalls {
        debug!("Adding kill rule for syscall: {}", syscall_name);
        let syscall = ScmpSyscall::from_name(syscall_name);
        match syscall {
            Ok(syscall) => {
                ctx.add_rule(ScmpAction::KillThread, syscall)?;
            }
            Err(e) => warn!("Could not add kill rule for syscall: {}", e),
        };
    }

    // Apply log_syscalls overrides
    for syscall_name in log_syscalls {
        debug!("Adding log rule for syscall: {}", syscall_name);
        let syscall = ScmpSyscall::from_name(syscall_name);
        match syscall {
            Ok(syscall) => {
                ctx.add_rule(ScmpAction::Log, syscall)?;
            }
            Err(e) => warn!("Could not add log rule for syscall: {}", e),
        };
    }

    Ok(ctx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use libseccomp::ScmpCompareOp;

    #[test]
    fn test_parse_scmp_compare_op() {
        assert_eq!(
            parse_scmp_compare_op("SCMP_CMP_NE", 0).unwrap(),
            ScmpCompareOp::NotEqual
        );
        assert_eq!(
            parse_scmp_compare_op("SCMP_CMP_LT", 0).unwrap(),
            ScmpCompareOp::Less
        );
        assert_eq!(
            parse_scmp_compare_op("SCMP_CMP_LE", 0).unwrap(),
            ScmpCompareOp::LessOrEqual
        );
        assert_eq!(
            parse_scmp_compare_op("SCMP_CMP_EQ", 0).unwrap(),
            ScmpCompareOp::Equal
        );
        assert_eq!(
            parse_scmp_compare_op("SCMP_CMP_GE", 0).unwrap(),
            ScmpCompareOp::GreaterEqual
        );
        assert_eq!(
            parse_scmp_compare_op("SCMP_CMP_GT", 0).unwrap(),
            ScmpCompareOp::Greater
        );
        assert_eq!(
            parse_scmp_compare_op("SCMP_CMP_MASKED_EQ", 123).unwrap(),
            ScmpCompareOp::MaskedEqual(123)
        );

        assert!(parse_scmp_compare_op("UNKNOWN_OP", 0).is_err());
    }
}
