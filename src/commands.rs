use log2::*;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{execve, fork, ForkResult};
use seccompiler::{apply_filter, BpfProgram, SeccompFilter};
use std::convert::TryInto;
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
    #[error("Apply filter failed: {0}")]
    ApplyFilter(String),
    #[error("CString conversion failed: {0}")]
    CStringConversion(#[from] std::ffi::NulError),
    #[error("Execve failed: {0}")]
    Execve(String),
    #[error("Fuzzing not implemented")]
    FuzzingNotImplemented,
}

pub fn filtered_exec(filter: SeccompFilter, path: Vec<String>) -> Result<(), CommandError> {
    let filter: BpfProgram = TryInto::<BpfProgram>::try_into(filter)
        .map_err(|e| CommandError::FilterConversion(e.to_string()))?;

    match unsafe { fork() } {
        Ok(ForkResult::Parent { child, .. }) => {
            let status = waitpid(child, None).map_err(|e| CommandError::Waitpid(e.to_string()))?;
            info!("Child process exited with status: {:?}", status);
            if let WaitStatus::Signaled(_, signal, _) = status {
                if signal == nix::sys::signal::Signal::SIGSYS {
                    info!("\nSuccess: Child was terminated by SIGSYS, as expected.");
                    Ok(())
                } else {
                    Err(CommandError::UnexpectedSignal)
                }
            } else {
                Err(CommandError::UnexpectedExit)
            }
        }
        Ok(ForkResult::Child) => {
            apply_filter(&filter).map_err(|e| CommandError::ApplyFilter(e.to_string()))?;

            let exec = CString::new(path[0].as_str())?;

            let args: Vec<CString> = path
                .iter()
                .map(|s| CString::new(s.as_str()))
                .collect::<Result<Vec<_>, _>>()?;
            let args_as_cstrs: Vec<&std::ffi::CStr> = args.iter().map(|c| c.as_c_str()).collect();

            let environment: Vec<CString> = std::env::vars()
                .map(|(key, value)| {
                    let env_pair = format!("{}={}", key, value);
                    CString::new(env_pair)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let env_as_cstrs: Vec<&std::ffi::CStr> =
                environment.iter().map(|c| c.as_c_str()).collect();
            if let Some(path_var) = std::env::var_os("PATH") {
                if let Some(path_str) = path_var.to_str() {
                    println!("PATH environment variable: {}", path_str);
                }
            } else {
                println!("PATH environment variable not found.");
            }

            execve(&exec, &args_as_cstrs, &env_as_cstrs)
                .map_err(|e| CommandError::Execve(e.to_string()))?;
            Ok(())
        }
        Err(_) => Err(CommandError::Fork),
    }
}

/*
 *     match unsafe { fork() } {
        Ok(ForkResult::Parent { child, .. }) => {
            let status = waitpid(child, None).unwrap();
            println!("Child process exited with status: {:?}", status);
            if let WaitStatus::Signaled(_, signal, _) = status {
                if signal == nix::sys::signal::Signal::SIGSYS {
                    println!("\nSuccess: Child was terminated by SIGSYS, as expected.");
                }
            }
        }
        Ok(ForkResult::Child) => {
            apply_filter(&bpf_program).unwrap();

            let path = CString::new(cli.exec[0].as_str()).unwrap();
            let args: Vec<CString> = cli
                .exec
                .iter()
                .map(|s| CString::new(s.as_str()).unwrap())
                .collect();
            let args_as_cstrs: Vec<&std::ffi::CStr> = args.iter().map(|c| c.as_c_str()).collect();

            execv(&path, &args_as_cstrs).expect("execv failed");
        }
        Err(_) => {
            eprintln!("Fork failed");
        }
    }
*/

pub fn fuzz_exec(path: Vec<String>) -> Result<(), CommandError> {
    let _ = path; // remove unused variable warning
    Err(CommandError::FuzzingNotImplemented)
}
