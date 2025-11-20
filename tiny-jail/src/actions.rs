use clap::ValueEnum;
use libseccomp::ScmpAction;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt::Display;
use std::num::TryFromIntError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ActionError {
    #[error("errno value for SCMP_ACT_TRACE is out of u16 range")]
    TraceErrnoOutOfRange(#[from] TryFromIntError),
    #[error("Unknown action")]
    UnknownAction,
}

#[derive(ValueEnum, Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
pub enum Action {
    #[default]
    #[clap(name = "kill")]
    #[serde(
        rename = "SCMP_ACT_KILL_PROCESS",
        alias = "SCMP_ACT_KILL",
        alias = "KillProcess"
    )]
    KillProcess,
    #[clap(name = "kill-thread")]
    #[serde(rename = "SCMP_ACT_KILL_THREAD", alias = "KillThread")]
    KillThread,
    #[clap(name = "trap")]
    #[serde(rename = "SCMP_ACT_TRAP", alias = "Trap")]
    Trap,
    #[clap(name = "errno")]
    #[serde(rename = "SCMP_ACT_ERRNO", alias = "Errno")]
    Errno,
    #[clap(name = "trace")]
    #[serde(rename = "SCMP_ACT_TRACE", alias = "Trace")]
    Trace,
    #[clap(name = "allow")]
    #[serde(rename = "SCMP_ACT_ALLOW", alias = "Allow")]
    Allow,
    #[clap(name = "log")]
    #[serde(rename = "SCMP_ACT_LOG", alias = "Log")]
    Log,
    #[serde(other)]
    Unknown,
}

impl Action {
    fn restrictiveness_level(&self) -> u8 {
        match self {
            Action::KillProcess => 7,
            Action::KillThread => 6,
            Action::Trap => 5,
            Action::Errno => 4,
            Action::Trace => 3,
            Action::Log => 2,
            Action::Allow => 1,
            Action::Unknown => 0,
        }
    }

    pub fn to_scmp_action(&self, errno: Option<u32>) -> Result<ScmpAction, ActionError> {
        let eperm = nix::libc::EPERM as u32;
        match self {
            Action::KillProcess => Ok(ScmpAction::KillProcess),
            Action::KillThread => Ok(ScmpAction::KillThread),
            Action::Trap => Ok(ScmpAction::Trap),
            Action::Errno => Ok(ScmpAction::Errno(errno.unwrap_or(eperm).try_into()?)),
            Action::Trace => Ok(ScmpAction::Trace(errno.unwrap_or(0).try_into()?)),
            Action::Allow => Ok(ScmpAction::Allow),
            Action::Log => Ok(ScmpAction::Log),
            Action::Unknown => Err(ActionError::UnknownAction),
        }
    }
}

impl From<ScmpAction> for Action {
    fn from(action: ScmpAction) -> Self {
        match action {
            ScmpAction::KillProcess => Action::KillProcess,
            ScmpAction::KillThread => Action::KillThread,
            ScmpAction::Trap => Action::Trap,
            ScmpAction::Errno(_) => Action::Errno,
            ScmpAction::Trace(_) => Action::Trace,
            ScmpAction::Allow => Action::Allow,
            ScmpAction::Log => Action::Log,
            _ => Action::Unknown,
        }
    }
}

impl PartialOrd for Action {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Action {
    fn cmp(&self, other: &Self) -> Ordering {
        self.restrictiveness_level()
            .cmp(&other.restrictiveness_level())
    }
}

impl Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

const SECCOMP_RET_KILL_PROCESS: u32 = 0x80000000;
const SECCOMP_RET_KILL_THREAD: u32 = 0x00000000;
const SECCOMP_RET_TRAP: u32 = 0x00030000;
const SECCOMP_RET_ERRNO: u32 = 0x00050000;
const SECCOMP_RET_TRACE: u32 = 0x7ff00000;
const SECCOMP_RET_LOG: u32 = 0x7ffc0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;

/* Masks for the return value sections. */
const SECCOMP_RET_ACTION: u32 = 0x7fff0000;

impl Action {
    pub fn to_class(self) -> u32 {
        match self {
            Action::KillProcess => SECCOMP_RET_KILL_PROCESS,
            Action::KillThread => SECCOMP_RET_KILL_THREAD,
            Action::Trap => SECCOMP_RET_TRAP,
            Action::Errno => SECCOMP_RET_ERRNO,
            Action::Trace => SECCOMP_RET_TRACE,
            Action::Allow => SECCOMP_RET_ALLOW,
            Action::Log => SECCOMP_RET_LOG,
            Action::Unknown => SECCOMP_RET_KILL_THREAD,
        }
    }

    pub fn from_class(class: u32) -> Option<Self> {
        Some(match class & SECCOMP_RET_ACTION {
            SECCOMP_RET_KILL_PROCESS => Action::KillProcess,
            SECCOMP_RET_KILL_THREAD => Action::KillThread,
            SECCOMP_RET_TRAP => Action::Trap,
            SECCOMP_RET_ERRNO => Action::Errno,
            SECCOMP_RET_TRACE => Action::Trace,
            SECCOMP_RET_ALLOW => Action::Allow,
            SECCOMP_RET_LOG => Action::Log,
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libseccomp::ScmpAction;

    #[test]
    fn test_display_implementation() {
        assert_eq!(Action::KillProcess.to_string(), "KillProcess");
        assert_eq!(Action::KillThread.to_string(), "KillThread");
        assert_eq!(Action::Trap.to_string(), "Trap");
        assert_eq!(Action::Errno.to_string(), "Errno");
        assert_eq!(Action::Trace.to_string(), "Trace");
        assert_eq!(Action::Allow.to_string(), "Allow");
        assert_eq!(Action::Log.to_string(), "Log");
        assert_eq!(Action::Unknown.to_string(), "Unknown");
    }

    #[test]
    fn test_to_scmp_action_conversion() {
        assert_eq!(
            Action::KillProcess.to_scmp_action(None).unwrap(),
            ScmpAction::KillProcess
        );
        assert_eq!(
            Action::KillThread.to_scmp_action(None).unwrap(),
            ScmpAction::KillThread
        );
        assert_eq!(Action::Trap.to_scmp_action(None).unwrap(), ScmpAction::Trap);
        assert_eq!(
            Action::Allow.to_scmp_action(None).unwrap(),
            ScmpAction::Allow
        );
        assert_eq!(Action::Log.to_scmp_action(None).unwrap(), ScmpAction::Log);

        let eperm = nix::libc::EPERM as u32;
        assert_eq!(
            Action::Errno.to_scmp_action(None).unwrap(),
            ScmpAction::Errno(eperm as i32)
        );
        assert_eq!(
            Action::Errno.to_scmp_action(Some(123)).unwrap(),
            ScmpAction::Errno(123)
        );

        assert_eq!(
            Action::Trace.to_scmp_action(None).unwrap(),
            ScmpAction::Trace(0)
        );
        assert_eq!(
            Action::Trace.to_scmp_action(Some(456)).unwrap(),
            ScmpAction::Trace(456)
        );

        assert!(Action::Trace.to_scmp_action(Some(u32::MAX)).is_err());
        assert!(Action::Trace
            .to_scmp_action(Some(u16::MAX as u32 + 1))
            .is_err());
        assert!(Action::Trace.to_scmp_action(Some(u16::MAX as u32)).is_ok());
    }
}
