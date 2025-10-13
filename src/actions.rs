use clap::ValueEnum;
use libseccomp::ScmpAction;
use serde::Deserialize;

#[derive(ValueEnum, Clone, Copy, Debug, Deserialize, PartialEq, Eq, Hash)]
pub enum Action {
    #[clap(name = "kill")]
    #[serde(alias = "SCMP_ACT_KILL_PROCESS", alias = "SCMP_ACT_KILL")]
    KillProcess,
    #[clap(name = "kill-thread")]
    #[serde(alias = "SCMP_ACT_KILL_THREAD")]
    KillThread,
    #[clap(name = "trap")]
    #[serde(alias = "SCMP_ACT_TRAP")]
    Trap,
    #[clap(name = "errno")]
    #[serde(alias = "SCMP_ACT_ERRNO")]
    Errno,
    #[clap(name = "trace")]
    #[serde(alias = "SCMP_ACT_TRACE")]
    Trace,
    #[clap(name = "allow")]
    #[serde(alias = "SCMP_ACT_ALLOW")]
    Allow,
    #[clap(name = "log")]
    #[serde(alias = "SCMP_ACT_LOG")]
    Log,
}

impl Action {
    pub fn to_scmp_action(&self, errno: Option<u32>) -> ScmpAction {
        let eperm = nix::libc::EPERM as u32;
        match self {
            Action::KillProcess => ScmpAction::KillProcess,
            Action::KillThread => ScmpAction::KillThread,
            Action::Trap => ScmpAction::Trap,
            Action::Errno => ScmpAction::Errno(errno.unwrap_or(eperm).try_into().unwrap()),
            Action::Trace => ScmpAction::Trace(errno.unwrap_or(0).try_into().unwrap()),
            Action::Allow => ScmpAction::Allow,
            Action::Log => ScmpAction::Log,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libseccomp::ScmpAction;

    #[test]
    fn test_to_scmp_action_conversion() {
        assert_eq!(
            Action::KillProcess.to_scmp_action(None),
            ScmpAction::KillProcess
        );
        assert_eq!(
            Action::KillThread.to_scmp_action(None),
            ScmpAction::KillThread
        );
        assert_eq!(Action::Trap.to_scmp_action(None), ScmpAction::Trap);
        assert_eq!(Action::Allow.to_scmp_action(None), ScmpAction::Allow);
        assert_eq!(Action::Log.to_scmp_action(None), ScmpAction::Log);

        let eperm = nix::libc::EPERM;
        assert_eq!(Action::Errno.to_scmp_action(None), ScmpAction::Errno(eperm));
        assert_eq!(
            Action::Errno.to_scmp_action(Some(123)),
            ScmpAction::Errno(123)
        );

        assert_eq!(Action::Trace.to_scmp_action(None), ScmpAction::Trace(0));
        assert_eq!(
            Action::Trace.to_scmp_action(Some(456)),
            ScmpAction::Trace(456)
        );
    }
}
