use libseccomp::{error::SeccompError, ScmpFilterContext};
use log2::*;
use nix::libc;
use std::io;
#[cfg(not(feature = "libseccomp-2-6"))]
use std::io::Read;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::Command;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::time::Duration;
use thiserror::Error;

use crate::monitor::{monitor_seccomp_logs, SeccompEvent, SeccompStats};

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
        if signal == libc::SIGSYS {
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
    let bpf_bytes;

    #[cfg(feature = "libseccomp-2-6")]
    {
        bpf_bytes = ctx.export_bpf_mem()?;
    }
    #[cfg(not(feature = "libseccomp-2-6"))]
    {
        warn!("libseccomp version is < 2.6.0, falling back to BPF export to file");
        // Export the filter to file then load in memory
        let (mut reader, writer) = io::pipe().map_err(CommandError::Io)?;
        ctx.export_bpf(&writer).map_err(CommandError::LibSeccomp)?;
        drop(writer);
        bpf_bytes = Vec::new();
        reader
            .read_to_end(&mut bpf_bytes)
            .map_err(CommandError::Io)?;
    }

    let mut command = Command::new(&path[0]);
    command.args(&path[1..]);
    if !pass_env {
        command.env_clear();
    }

    unsafe {
        command.pre_exec(move || {
            // Each BPF instruction is 8 bytes
            let filter_ptr = bpf_bytes.as_ptr() as *const libc::sock_filter;
            let filter_len = bpf_bytes.len() / std::mem::size_of::<libc::sock_filter>();

            let prog = libc::sock_fprog {
                len: filter_len as u16,
                filter: filter_ptr as *mut _,
            };

            nix::sys::prctl::set_no_new_privs().map_err(io::Error::other)?;

            let ret = libc::syscall(
                libc::SYS_seccomp as libc::c_long,
                libc::SECCOMP_SET_MODE_FILTER as libc::c_long,
                0 as libc::c_long,
                &prog as *const _ as *const libc::c_void,
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
