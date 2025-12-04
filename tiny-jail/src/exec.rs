use libseccomp::ScmpFilterContext;
use log2::*;
use nix::libc;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::File;
#[cfg(not(libseccomp_2_6))]
use std::io::Read;
use std::io::{self, BufReader};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::error::JailError;
use crate::io::{capture_and_display_stream, CapturedOutput};
use crate::monitor::SeccompMonitor;
use crate::options::FilteredExecOptions;

// ============================================================================
// FILTERED EXECUTION
// ============================================================================

/// Execute a command with a seccomp filter applied.
///
/// # Arguments
/// * `ctx` - The seccomp filter context to apply
/// * `options` - Options for the execution
pub fn filtered_exec(
    ctx: ScmpFilterContext,
    options: &FilteredExecOptions,
) -> Result<Option<CapturedOutput>, JailError> {
    let bpf_bytes = export_bpf_filter(&ctx)?;
    let mut command = build_command(options.path, options.pass_env, options.capture_output);
    apply_seccomp_filter(&mut command, bpf_bytes);

    if options.show_log || options.show_all {
        execute_with_monitoring(command, options.stats_output, options.batch_mode)?;
        Ok(None)
    } else if options.capture_output {
        execute_with_capture(command).map(Some)
    } else {
        execute_without_monitoring(command)?;
        Ok(None)
    }
}

// ============================================================================
// BPF Filter Export
// ============================================================================

fn export_bpf_filter(ctx: &ScmpFilterContext) -> Result<Vec<u8>, JailError> {
    #[cfg(libseccomp_2_6)]
    {
        ctx.export_bpf_mem().map_err(JailError::LibSeccomp)
    }

    #[cfg(not(libseccomp_2_6))]
    {
        warn!("Compiled with libseccomp < 2.6.0, using pipe for BPF export");
        export_bpf_via_pipe(ctx)
    }
}

#[cfg(not(libseccomp_2_6))]
fn export_bpf_via_pipe(ctx: &ScmpFilterContext) -> Result<Vec<u8>, JailError> {
    let (mut reader, writer) = io::pipe().map_err(JailError::Io)?;
    ctx.export_bpf(&writer).map_err(JailError::LibSeccomp)?;
    drop(writer);

    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).map_err(JailError::Io)?;
    Ok(buf)
}

// ============================================================================
// Command Building
// ============================================================================

fn build_command(path: &[String], pass_env: bool, capture_output: bool) -> Command {
    let mut command = Command::new(&path[0]);
    command.args(&path[1..]);

    if capture_output {
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
    }

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

fn execute_without_monitoring(mut command: Command) -> Result<(), JailError> {
    debug!("Executing command without monitoring");
    match command.status() {
        Ok(status) => {
            debug!("Child process exited with status: {:?}", status);
            handle_exit_status(status)
        }
        Err(e) => {
            error!("Failed to execute command: {}", e);
            Err(JailError::Exec(e.to_string()))
        }
    }
}

fn execute_with_capture(mut command: Command) -> Result<CapturedOutput, JailError> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut child = command
        .spawn()
        .map_err(|e| JailError::Exec(e.to_string()))?;

    // Shared buffers for captured output
    let captured_stdout = Arc::new(Mutex::new(Vec::new()));
    let captured_stderr = Arc::new(Mutex::new(Vec::new()));

    let stdout_handle = {
        let stdout = child.stdout.take().unwrap();
        let reader = BufReader::new(stdout);
        let output = Arc::clone(&captured_stdout);
        capture_and_display_stream(reader, output, "stdout")
    };

    let stderr_handle = {
        let stderr = child.stderr.take().unwrap();
        let reader = BufReader::new(stderr);
        let output = Arc::clone(&captured_stderr);
        capture_and_display_stream(reader, output, "stderr")
    };

    // Wait for child to complete
    let status = child.wait()?;

    // Wait for capture threads to finish
    stdout_handle.join().ok();
    stderr_handle.join().ok();

    let stdout = match Arc::try_unwrap(captured_stdout) {
        Ok(mutex) => mutex.into_inner().unwrap(),
        Err(arc) => arc.lock().unwrap().clone(),
    };

    let stderr = match Arc::try_unwrap(captured_stderr) {
        Ok(mutex) => mutex.into_inner().unwrap(),
        Err(arc) => arc.lock().unwrap().clone(),
    };
    let output = CapturedOutput {
        stdout,
        stderr,
        exit_code: status.code(),
    };

    debug!(
        "Captured: exit_code={:?}, stdout={} bytes, stderr={} bytes",
        output.exit_code,
        output.stdout.len(),
        output.stderr.len()
    );

    handle_exit_status(status)?;

    Ok(output)
}

// ============================================================================
// Execution With Monitoring
// ============================================================================

fn execute_with_monitoring(
    mut command: Command,
    stats_output: &Option<PathBuf>,
    batch_mode: bool,
) -> Result<(), JailError> {
    // Start the monitor
    let mut monitor = SeccompMonitor::new();
    info!("Starting seccomp monitor...\n");

    monitor
        .start()
        .map_err(|e| JailError::Monitor(format!("{:?}", e)))?;

    // Small delay to ensure monitor is fully initialized
    thread::sleep(Duration::from_millis(500));

    // Spawn the child process
    let child_pid = spawn_child(&mut command)?;
    debug!("Child process spawned with PID: {}", child_pid);

    // Wait for child and collect events concurrently
    let status = wait_and_collect_events(child_pid, &mut monitor, batch_mode)?;

    // Allow final events to arrive
    thread::sleep(Duration::from_millis(500));

    // Collect any remaining events
    let remaining_events = monitor.collect_events();
    if !batch_mode {
        for event in remaining_events {
            event.print_event();
        }
    }

    if let Some(stats_output) = stats_output {
        write_detailed_stats(&monitor, stats_output)?;
    }

    // Stop monitoring and print summary
    monitor.stop();
    if !batch_mode {
        monitor.stats().print_summary();
    }

    handle_exit_status(status)
}

#[derive(Serialize, Deserialize)]
struct DetailedStats {
    by_syscall: HashMap<String, i64>,
    total_runs: i64,
    tested_binaries: HashSet<String>,
}

fn write_detailed_stats(monitor: &SeccompMonitor, stats_output: &PathBuf) -> Result<(), JailError> {
    let mut stats: DetailedStats = if stats_output.exists() {
        let file = File::open(stats_output)?;
        serde_json::from_reader(file).unwrap_or_else(|_| DetailedStats {
            by_syscall: HashMap::new(),
            total_runs: 0,
            tested_binaries: HashSet::new(),
        })
    } else {
        DetailedStats {
            by_syscall: HashMap::new(),
            total_runs: 0,
            tested_binaries: HashSet::new(),
        }
    };

    let new_stats = monitor.stats();
    stats.total_runs += 1;

    for syscall_num in new_stats.by_syscall.keys() {
        let syscall_name =
            libseccomp::ScmpSyscall::from_raw_syscall(*syscall_num as i32).get_name();
        let name = syscall_name.unwrap_or_else(|_| "UNKNOWN".to_string());
        *stats.by_syscall.entry(name).or_insert(0) += 1;
    }

    stats
        .tested_binaries
        .extend(new_stats.by_exe.keys().cloned());

    let file = File::create(stats_output)?;
    serde_json::to_writer_pretty(file, &stats)?;

    info!("Detailed stats written to {}", stats_output.display());

    Ok(())
}

fn spawn_child(command: &mut Command) -> Result<u32, JailError> {
    command.stdout(Stdio::inherit()).stderr(Stdio::inherit());
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
    batch_mode: bool,
) -> Result<std::process::ExitStatus, JailError> {
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
                return Err(JailError::Monitor("Wait thread disconnected".to_string()));
            }
        }

        // Collect and print events
        if !batch_mode {
            if let Some(event) = monitor.next_event(Duration::from_millis(100)) {
                event.print_event();
            }
        }
    }
}

fn wait_for_child(pid: u32) -> Result<std::process::ExitStatus, JailError> {
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
                return Err(JailError::Io(io::Error::from_raw_os_error(e as i32)));
            }
        }
    }
}

fn handle_exit_status(status: std::process::ExitStatus) -> Result<(), JailError> {
    if status.success() {
        Ok(())
    } else if let Some(code) = status.code() {
        warn!("Child exited with code: {}", code);
        Err(JailError::UnexpectedExit)
    } else if let Some(signal) = status.signal() {
        warn!(
            "Child terminated by signal: {} ({})",
            signal,
            get_signal_name(signal)
        );
        if signal == libc::SIGSYS {
            warn!("Seccomp violation detected");
            Err(JailError::UnexpectedSignal)
        } else if signal == libc::SIGSEGV {
            warn!("SIGSEGV - likely caused by blocked syscall");
            Err(JailError::UnexpectedSignal)
        } else {
            Err(JailError::UnexpectedSignal)
        }
    } else {
        warn!("Child exited with unknown status: {:?}", status);
        Err(JailError::UnexpectedExit)
    }
}

fn get_signal_name(signal: i32) -> String {
    match Signal::try_from(signal) {
        Ok(sig) => format!("{:?}", sig),
        Err(_) => format!("UNKNOWN({})", signal),
    }
}
