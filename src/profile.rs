use log2::*;
use seccompiler::{SeccompAction, SeccompFilter};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::convert::TryInto;
use std::fs;
use sysnames::Syscalls;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProfileError {
    #[error("Could not read profile file: {0}")]
    FileRead(#[from] std::io::Error),
    #[error("Could not parse OCI profile: {0}")]
    OciParse(#[from] serde_json::Error),
    #[error("Unknown syscall name: {0}")]
    UnknownSyscall(String),
    #[error("Unsupported seccomp action: {0}")]
    UnsupportedAction(String),
    #[error("Architecture conversion error: {0}")]
    ArchConversion(String),
    #[error("Syscall number conversion error")]
    SyscallNumConversion,
    #[error("Seccomp filter creation error: {0}")]
    FilterCreation(String),
    #[error("OCI profile has no syscalls")]
    NoSyscallsInProfile,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct OciSeccomp {
    default_action: String,
    architectures: Vec<String>,
    syscalls: Vec<OciSyscall>,
}

#[derive(Deserialize, Debug)]
struct OciSyscall {
    names: Vec<String>,
    action: String,
}

pub fn load_profile(profile_path: String, oci: bool) -> Result<SeccompFilter, ProfileError> {
    if oci {
        info!("Parsing OCI profile: {}", profile_path);
        let profile_content = fs::read_to_string(profile_path)?;
        let oci_seccomp: OciSeccomp = serde_json::from_str(&profile_content)?;

        info!("Architectures: {:?}", oci_seccomp.architectures);

        if oci_seccomp.syscalls.is_empty() {
            return Err(ProfileError::NoSyscallsInProfile);
        }

        let mismatch_action = action_from_string(&oci_seccomp.default_action)?;

        let match_action = action_from_string(&oci_seccomp.syscalls[0].action)?;

        let mut rules = BTreeMap::new();
        for syscall in oci_seccomp.syscalls {
            let action = action_from_string(&syscall.action)?;
            if action != match_action {
                warn!(
                    "Warning: OCI profile contains multiple actions. Only one is supported. Using {:?}.",
                    match_action
                );
            }

            for name in syscall.names {
                let sysno = Syscalls::number(&name)
                    .ok_or_else(|| ProfileError::UnknownSyscall(name.clone()))?;
                rules.insert(
                    sysno
                        .try_into()
                        .map_err(|_| ProfileError::SyscallNumConversion)?,
                    vec![],
                );
            }
        }

        let arch = std::env::consts::ARCH;
        let seccomp_arch = arch
            .try_into()
            .map_err(|_| ProfileError::ArchConversion(arch.to_string()))?;

        Ok(
            SeccompFilter::new(rules, mismatch_action, match_action, seccomp_arch)
                .map_err(|e| ProfileError::FilterCreation(e.to_string()))?,
        )
    } else {
        todo!()
    }
}

fn action_from_string(s: &str) -> Result<SeccompAction, ProfileError> {
    match s {
        "SCMP_ACT_KILL" => Ok(SeccompAction::KillProcess),
        "SCMP_ACT_KILL_PROCESS" => Ok(SeccompAction::KillProcess),
        "SCMP_ACT_KILL_THREAD" => Ok(SeccompAction::KillThread),
        "SCMP_ACT_TRAP" => Ok(SeccompAction::Trap),
        "SCMP_ACT_ERRNO" => Ok(SeccompAction::Errno(0)),
        "SCMP_ACT_TRACE" => Ok(SeccompAction::Trace(0)),
        "SCMP_ACT_ALLOW" => Ok(SeccompAction::Allow),
        "SCMP_ACT_LOG" => Ok(SeccompAction::Log),
        _ => Err(ProfileError::UnsupportedAction(s.to_string())),
    }
}
