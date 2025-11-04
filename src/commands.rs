use libseccomp::{error::SeccompError, ScmpFilterContext};
use log2::*;
use nix::libc;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;
use std::io;
#[cfg(not(libseccomp_2_6))]
use std::io::Read;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::Command;
use std::thread;
use std::time::Duration;
use thiserror::Error;

use crate::monitor::SeccompMonitor;

// ============================================================================
// Error Types
// ============================================================================

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

// ============================================================================
// Public API
// ============================================================================

/// Execute a command with a seccomp filter applied.
///
/// # Arguments
/// * `ctx` - The seccomp filter context to apply
/// * `path` - Command and arguments to execute
/// * `pass_env` - Whether to pass environment variables to the child
/// * `show_log` - Whether to show seccomp event logs
/// * `show_all` - Whether to show all events (implies show_log)
pub fn filtered_exec(
    ctx: ScmpFilterContext,
    path: Vec<String>,
    pass_env: bool,
    show_log: bool,
    show_all: bool,
) -> Result<(), CommandError> {
    let bpf_bytes = export_bpf_filter(&ctx)?;
    let mut command = build_command(&path, pass_env);
    apply_seccomp_filter(&mut command, bpf_bytes);

    if show_log || show_all {
        execute_with_monitoring(command, show_all)
    } else {
        execute_without_monitoring(command)
    }
}

/// Execute a command in fuzzing mode (not yet implemented).
pub fn fuzz_exec(_path: Vec<String>, _pass_env: bool) -> Result<(), CommandError> {
    Err(CommandError::FuzzingNotImplemented)
}

// ============================================================================
// BPF Filter Export
// ============================================================================

fn export_bpf_filter(ctx: &ScmpFilterContext) -> Result<Vec<u8>, CommandError> {
    #[cfg(libseccomp_2_6)]
    {
        ctx.export_bpf_mem().map_err(CommandError::LibSeccomp)
    }

    #[cfg(not(libseccomp_2_6))]
    {
        warn!("Compiled with libseccomp < 2.6.0, using pipe for BPF export");
        export_bpf_via_pipe(ctx)
    }
}

#[cfg(not(libseccomp_2_6))]
fn export_bpf_via_pipe(ctx: &ScmpFilterContext) -> Result<Vec<u8>, CommandError> {
    let (mut reader, writer) = io::pipe().map_err(CommandError::Io)?;
    ctx.export_bpf(&writer).map_err(CommandError::LibSeccomp)?;
    drop(writer);

    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).map_err(CommandError::Io)?;
    Ok(buf)
}

// ============================================================================
// Command Building
// ============================================================================

fn build_command(path: &[String], pass_env: bool) -> Command {
    let mut command = Command::new(&path[0]);
    command.args(&path[1..]);

    if !pass_env {
        debug!("Clearing environment for child process");
        command.env_clear();
    }

    command
}

fn apply_seccomp_filter(command: &mut Command, bpf_bytes: Vec<u8>) {
    unsafe {
        command.pre_exec(move || {
            set_no_new_privs()?;
            install_seccomp_filter(&bpf_bytes)?;
            Ok(())
        });
    }
}

// ============================================================================
// Seccomp Filter Installation (runs in child process)
// ============================================================================

fn set_no_new_privs() -> io::Result<()> {
    debug!("Setting no_new_privs in child process");
    nix::sys::prctl::set_no_new_privs().map_err(|e| {
        error!("Failed to set no_new_privs: {}", e);
        io::Error::other(e)
    })
}

fn install_seccomp_filter(bpf_bytes: &[u8]) -> io::Result<()> {
    debug!(
        "Installing seccomp filter with {} instructions",
        bpf_bytes.len() / std::mem::size_of::<libc::sock_filter>()
    );

    // SAFETY: We construct a valid sock_fprog pointing to our BPF bytes.
    // This is safe because:
    // - bpf_bytes is guaranteed to be valid for the syscall
    // - We only call this in pre_exec (after fork, before exec)
    // - The syscall doesn't persist or escape the child process
    let ret = unsafe {
        let filter_ptr = bpf_bytes.as_ptr() as *const libc::sock_filter;
        let filter_len = bpf_bytes.len() / std::mem::size_of::<libc::sock_filter>();

        let prog = libc::sock_fprog {
            len: filter_len as u16,
            filter: filter_ptr as *mut _,
        };

        libc::syscall(
            libc::SYS_seccomp as libc::c_long,
            libc::SECCOMP_SET_MODE_FILTER as libc::c_long,
            0 as libc::c_long,
            &prog as *const _ as *const libc::c_void,
        )
    };

    if ret != 0 {
        let err = io::Error::last_os_error();
        error!("Failed to install seccomp filter: {}", err);
        Err(err)
    } else {
        debug!("Seccomp filter installed successfully");
        Ok(())
    }
}

// ============================================================================
// Execution Without Monitoring
// ============================================================================

fn execute_without_monitoring(mut command: Command) -> Result<(), CommandError> {
    debug!("Executing command without monitoring");
    let status = command.status()?;
    debug!("Child process exited with status: {:?}", status);
    handle_exit_status(status)
}

// ============================================================================
// Execution With Monitoring
// ============================================================================

fn execute_with_monitoring(mut command: Command, show_all: bool) -> Result<(), CommandError> {
    // Start the monitor
    let mut monitor = SeccompMonitor::new();
    warn!("Starting seccomp monitor (requires sudo)...\n");

    monitor
        .start()
        .map_err(|e| CommandError::Monitor(format!("{:?}", e)))?;

    // Small delay to ensure monitor is fully initialized
    thread::sleep(Duration::from_millis(500));

    // Spawn the child process
    let child_pid = spawn_child(&mut command)?;
    debug!("Child process spawned with PID: {}", child_pid);

    // Wait for child and collect events concurrently
    let status = wait_and_collect_events(child_pid, &mut monitor, show_all)?;

    // Allow final events to arrive
    thread::sleep(Duration::from_millis(500));

    // Collect any remaining events
    let remaining_events = monitor.collect_events();
    for event in remaining_events {
        event.print_event();
    }

    // Stop monitoring and print summary
    monitor.stop();
    monitor.stats().print_summary();

    handle_exit_status(status)
}

fn spawn_child(command: &mut Command) -> Result<u32, CommandError> {
    let child = command.spawn()?;
    let pid = child.id();

    // Store child in a way we can wait on it later
    // We need to leak it here because we want to return the PID
    // The actual waiting happens in wait_and_collect_events
    std::mem::forget(child);

    Ok(pid)
}

fn wait_and_collect_events(
    child_pid: u32,
    monitor: &mut SeccompMonitor,
    show_all: bool,
) -> Result<std::process::ExitStatus, CommandError> {
    // Spawn wait thread
    let (tx_status, rx_status) = std::sync::mpsc::channel();
    let wait_handle = thread::spawn(move || {
        let status = wait_for_child(child_pid);
        let _ = tx_status.send(status);
    });

    // Main loop: collect and print events until child exits
    loop {
        // Check if child has exited (non-blocking)
        match rx_status.try_recv() {
            Ok(status_result) => {
                let _ = wait_handle.join();
                return status_result;
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {
                // Child still running
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                return Err(CommandError::Monitor(
                    "Wait thread disconnected".to_string(),
                ));
            }
        }

        // Collect and print events
        if let Some(event) = monitor.next_event(Duration::from_millis(100)) {
            if show_all || event.is_fatal() {
                event.print_event();
            }
        }
    }
}

fn wait_for_child(pid: u32) -> Result<std::process::ExitStatus, CommandError> {
    loop {
        match waitpid(Pid::from_raw(pid as i32), None) {
            Ok(WaitStatus::Exited(_, code)) => {
                let raw_status = code << 8;
                return Ok(std::process::ExitStatus::from_raw(raw_status));
            }
            Ok(WaitStatus::Signaled(_, signal, _)) => {
                let raw_status = signal as i32;
                return Ok(std::process::ExitStatus::from_raw(raw_status));
            }
            Ok(other) => {
                debug!("Unexpected wait status: {:?}, continuing", other);
                continue;
            }
            Err(nix::errno::Errno::EINTR) => {
                debug!("waitpid interrupted, retrying");
                continue;
            }
            Err(e) => {
                error!("waitpid failed: {}", e);
                return Err(CommandError::Io(io::Error::from_raw_os_error(e as i32)));
            }
        }
    }
}

fn handle_exit_status(status: std::process::ExitStatus) -> Result<(), CommandError> {
    if status.success() {
        info!("Child exited normally");
        Ok(())
    } else if let Some(code) = status.code() {
        warn!("Child exited with code: {}", code);
        Err(CommandError::UnexpectedExit)
    } else if let Some(signal) = status.signal() {
        warn!(
            "Child terminated by signal: {} ({})",
            signal,
            get_signal_name(signal)
        );
        if signal == libc::SIGSYS {
            info!("Seccomp violation detected");
            Ok(())
        } else if signal == libc::SIGSEGV {
            warn!("SIGSEGV - likely caused by blocked syscall");
            Err(CommandError::UnexpectedSignal)
        } else {
            Err(CommandError::UnexpectedSignal)
        }
    } else {
        warn!("Child exited with unknown status: {:?}", status);
        Err(CommandError::UnexpectedExit)
    }
}

fn get_signal_name(signal: i32) -> String {
    match Signal::try_from(signal) {
        Ok(sig) => format!("{:?}", sig),
        Err(_) => format!("UNKNOWN({})", signal),
    }
}
