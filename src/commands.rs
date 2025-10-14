use libseccomp::{error::SeccompError, ScmpFilterContext};
use log2::*;
use std::io;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::Command;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::time::Duration;
use thiserror::Error;

use crate::monitor_log::{monitor_seccomp_logs, SeccompEvent, SeccompStats};

#[derive(Error, Debug)]
pub enum CommandError {
    #[error("Child process exited unexpectedly")]
    UnexpectedExit,
    #[error("Child process terminated by unexpected signal")]
    UnexpectedSignal,
    #[error("libseccomp error: {0}")]
    LibSeccomp(#[from] SeccompError),
    #[error("Command execution failed: {0}")]
    Exec(String),
    #[error("Monitor failed: {0}")]
    Monitor(String),
    #[error("Fuzzing not implemented")]
    FuzzingNotImplemented,
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

fn handle_exit_status(status: std::process::ExitStatus) -> Result<(), CommandError> {
    if status.success() {
        info!("Child exited normally.");
        Ok(())
    } else if let Some(code) = status.code() {
        warn!("Child exited with code: {}", code);
        Err(CommandError::UnexpectedExit)
    } else if let Some(signal) = status.signal() {
        if signal == nix::libc::SIGSYS {
            info!("Child terminated by seccomp (SIGSYS).");
            Ok(())
        } else {
            warn!("Child terminated by signal: {}", signal);
            Err(CommandError::UnexpectedSignal)
        }
    } else {
        warn!("Child exited with unknown status: {:?}", status);
        Err(CommandError::UnexpectedExit)
    }
}

pub fn filtered_exec(
    ctx: ScmpFilterContext,
    path: Vec<String>,
    pass_env: bool,
    show_log: bool,
) -> Result<(), CommandError> {
    // Export the filter to BPF bytecode (Send + Sync)
    let bpf_bytes = ctx.export_bpf_mem()?;

    let mut command = Command::new(&path[0]);
    command.args(&path[1..]);
    if !pass_env {
        command.env_clear();
    }

    // Load seccomp from BPF bytes in pre_exec
    unsafe {
        command.pre_exec(move || {
            #[repr(C)]
            struct SockFilter {
                code: u16,
                jt: u8,
                jf: u8,
                k: u32,
            }

            #[repr(C)]
            struct SockFprog {
                len: u16,
                filter: *const SockFilter,
            }

            // Each BPF instruction is 8 bytes
            let filter_ptr = bpf_bytes.as_ptr() as *const SockFilter;
            let filter_len = bpf_bytes.len() / 8;

            let prog = SockFprog {
                len: filter_len as u16,
                filter: filter_ptr,
            };

            let ret = nix::libc::prctl(nix::libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            if ret != 0 {
                return Err(io::Error::last_os_error());
            }

            let ret = nix::libc::prctl(
                nix::libc::PR_SET_SECCOMP,
                nix::libc::SECCOMP_MODE_FILTER,
                &prog as *const _ as *const nix::libc::c_void,
                0,
                0,
            );
            if ret != 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(())
        });
    }

    if !show_log {
        let status = command.status()?;
        debug!("Child process exited with status: {:?}", status);
        return handle_exit_status(status);
    }

    // Monitoring logic
    let (tx, rx): (Sender<SeccompEvent>, Receiver<SeccompEvent>) = mpsc::channel();
    let mut stats = SeccompStats::default();
    let (tx_ready, rx_ready) = mpsc::channel::<()>();

    warn!("Starting seccomp monitor (requires sudo)...\n");

    let monitor_handle = monitor_seccomp_logs(tx, tx_ready)
        .map_err(|e| CommandError::Monitor(format!("{:?}", e)))?;

    match rx_ready.recv_timeout(Duration::from_secs(30)) {
        Ok(()) => debug!("Monitor reported ready; releasing child."),
        Err(e) => {
            monitor_handle.stop();
            return Err(CommandError::Monitor(format!(
                "Timeout waiting for monitor readiness: {}",
                e
            )));
        }
    }

    let mut child = command.spawn()?;

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                debug!("Child process exited with status: {:?}", status);
                while let Ok(event) = rx.try_recv() {
                    event.print_event();
                    stats.add_event(&event);
                }
                monitor_handle.stop();
                stats.print_summary();
                return handle_exit_status(status);
            }
            Ok(None) => match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(event) => {
                    event.print_event();
                    stats.add_event(&event);
                }
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => {
                    error!("Monitor died unexpectedly");
                    break;
                }
            },
            Err(e) => {
                monitor_handle.stop();
                stats.print_summary();
                return Err(CommandError::Io(e));
            }
        }
    }

    monitor_handle.stop();
    stats.print_summary();
    let status = child.wait()?;
    handle_exit_status(status)
}

pub fn fuzz_exec(_path: Vec<String>, _pass_env: bool) -> Result<(), CommandError> {
    Err(CommandError::FuzzingNotImplemented)
}

