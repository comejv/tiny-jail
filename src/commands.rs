use libseccomp::{error::SeccompError, ScmpFilterContext};
use log2::*;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{execve, fork, ForkResult};
use std::ffi::CString;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CommandError {
    #[error("Filter conversion error: {0}")]
    FilterConversion(String),
    #[error("Fork failed")]
    Fork,
    #[error("Waitpid failed: {0}")]
    Waitpid(String),
    #[error("Child was terminated by unexpected signal")]
    UnexpectedSignal,
    #[error("Child exited unexpectedly")]
    UnexpectedExit,
    #[error("libseccomp error: {0}")]
    LibSeccomp(#[from] SeccompError),
    #[error("CString conversion failed: {0}")]
    CStringConversion(#[from] std::ffi::NulError),
    #[error("Execve failed: {0}")]
    Execve(String),
    #[error("Fuzzing not implemented")]
    FuzzingNotImplemented,
}

pub fn filtered_exec(ctx: ScmpFilterContext, path: Vec<String>) -> Result<(), CommandError> {
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child, .. }) => {
            let status = waitpid(child, None).map_err(|e| CommandError::Waitpid(e.to_string()))?;
            info!("Child process exited with status: {:?}", status);
            match status {
                WaitStatus::Exited(pid, code) => {
                    if code == 0 {
                        info!("Child {} exited normally.", pid);
                        Ok(())
                    } else {
                        warn!("Child {} exited with non-zero exit code: {}", pid, code);
                        Err(CommandError::UnexpectedExit)
                    }
                }
                WaitStatus::Signaled(_, signal, _) => {
                    if signal == nix::sys::signal::Signal::SIGSYS {
                        info!("Child was terminated by seccomp filter.");
                        Ok(())
                    } else {
                        warn!("Child was terminated by unexpected signal: {:?}", signal);
                        Err(CommandError::UnexpectedSignal)
                    }
                }
                _ => {
                    // Handle other statuses like Stopped, Continued, etc. if necessary
                    warn!("Child exited with unhandled status: {:?}", status);
                    Err(CommandError::UnexpectedExit)
                }
            }
        }
        Ok(ForkResult::Child) => {
            // In the child process, we must not return. We either exec or exit.
            // Returning would cause the child to continue execution as a copy of the parent.
            if let Err(e) = ctx.load() {
                eprintln!("Error loading seccomp filter in child process: {}", e);
                std::process::exit(126);
            }

            let exec_res = CString::new(path[0].as_str());
            let args_res: Result<Vec<CString>, _> =
                path.iter().map(|s| CString::new(s.as_str())).collect();
            let env_res: Result<Vec<CString>, _> = std::env::vars()
                .map(|(key, value)| CString::new(format!("{}={}", key, value)))
                .collect();

            match (exec_res, args_res, env_res) {
                (Ok(exec), Ok(args), Ok(env)) => {
                    let args_as_cstrs: Vec<&std::ffi::CStr> =
                        args.iter().map(|c| c.as_c_str()).collect();
                    let env_as_cstrs: Vec<&std::ffi::CStr> =
                        env.iter().map(|c| c.as_c_str()).collect();

                    let _ = execve(&exec, &args_as_cstrs, &env_as_cstrs);

                    // execve only returns on error.
                    eprintln!("execve failed: {}", nix::errno::Errno::last());
                    std::process::exit(127);
                }
                (Err(e), _, _) => {
                    eprintln!("Invalid executable path: {}", e);
                    std::process::exit(127);
                }
                (_, Err(e), _) => {
                    eprintln!("Invalid arguments: {}", e);
                    std::process::exit(127);
                }
                (_, _, Err(e)) => {
                    eprintln!("Invalid environment: {}", e);
                    std::process::exit(127);
                }
            }
        }
        Err(_) => Err(CommandError::Fork),
    }
}

pub fn fuzz_exec(path: Vec<String>) -> Result<(), CommandError> {
    let _ = path; // remove unused variable warning
    Err(CommandError::FuzzingNotImplemented)
}
