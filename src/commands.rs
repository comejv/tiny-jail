use libseccomp::{error::SeccompError, ScmpFilterContext};
use log2::*;
use nix::libc;
use std::io;
#[cfg(not(libseccomp_2_6))]
use std::io::Read;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::Command;
use std::sync::{
    mpsc::{self, Receiver, Sender},
    Arc, Mutex,
};
use std::thread;
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

fn execute_and_monitor(
    mut command: Command,
) -> Result<(), CommandError> {
    // Monitoring logic
    let (tx, rx): (Sender<SeccompEvent>, Receiver<SeccompEvent>) = mpsc::channel();
    let stats = Arc::new(Mutex::new(SeccompStats::default()));
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

    thread::sleep(Duration::from_millis(500));
    // Spawn a thread to handle events as they come in.
    let stats_clone = Arc::clone(&stats);
    let event_handle = thread::spawn(move || {
        for event in rx {
            event.print_event();
            if let Ok(mut guard) = stats_clone.lock() {
                guard.add_event(&event);
            }
        }
    });

    let mut child = command.spawn()?;
    let status_res = child.wait();

    // Give a moment for any final events to come through from the kernel logs.
    thread::sleep(Duration::from_millis(500));

    // Stop the monitor, which will close the channel and cause the event thread to exit.
    monitor_handle.stop();

    // Wait for the event processing thread to finish.
    // We don't care if it panicked, we'll just not get a full summary.
    let _ = event_handle.join();

    // Print the final summary.
    if let Ok(guard) = stats.lock() {
        guard.print_summary();
    }

    // Now handle the child's exit status.
    let status = status_res?;
    handle_exit_status(status)
}

pub fn filtered_exec(
    ctx: ScmpFilterContext,
    path: Vec<String>,
    pass_env: bool,
    show_log: bool,
) -> Result<(), CommandError> {
    let bpf_bytes: Vec<u8> = {
        #[cfg(libseccomp_2_6)]
        {
            ctx.export_bpf_mem()?
        }
        #[cfg(not(libseccomp_2_6))]
        {
            warn!("compiled with libseccomp version < 2.6.0, intermediate BPF exports to file");
            let (mut reader, writer) = io::pipe().map_err(CommandError::Io)?;
            ctx.export_bpf(&writer).map_err(CommandError::LibSeccomp)?;
            drop(writer);

            let mut buf = Vec::new();
            reader.read_to_end(&mut buf).map_err(CommandError::Io)?;
            buf
        }
    };

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

            match nix::sys::prctl::set_no_new_privs() {
                Ok(_) => {}
                Err(e) => {
                    error!("Failed to set no_new_privs: {}", e);
                    warn!("Continuing anyway...");
                }
            }

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

    if show_log {
        execute_and_monitor(command)
    } else {
        let status = command.status()?;
        debug!("Child process exited with status: {:?}", status);
        handle_exit_status(status)
    }
}

pub fn fuzz_exec(_path: Vec<String>, _pass_env: bool) -> Result<(), CommandError> {
    Err(CommandError::FuzzingNotImplemented)
}
