use libseccomp::{error::SeccompError, ScmpFilterContext};
use log2::*;
use nix::libc;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::fs::File;
#[cfg(not(libseccomp_2_6))]
use std::io::Read;
use std::io::{self, BufReader, Write};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use thiserror::Error;

use crate::filters::{
    apply_profile, coalesce_rules_by_action, explode_syscalls, read_and_expand_profile, OciSeccomp,
    ProfileError,
};
use crate::io::{capture_and_display_stream, CapturedOutput};
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
    #[error("JSON serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Profile operation failed: {0}")]
    Profile(#[from] ProfileError),
    #[error("TOML serialization failed: {0}")]
    Toml(#[from] toml::ser::Error),
}

// ============================================================================
// FILTERED EXECUTION
// ============================================================================

/// Execute a command with a seccomp filter applied.
///
/// # Arguments
/// * `ctx` - The seccomp filter context to apply
/// * `path` - Command and arguments to execute
/// * `pass_env` - Whether to pass environment variables to the child
/// * `show_log` - Whether to show seccomp event logs
/// * `show_all` - Whether to show all events (implies show_log)
/// * `stats_output` - Path to write detailed stats to
pub fn filtered_exec(
    ctx: ScmpFilterContext,
    path: &[String],
    pass_env: bool,
    show_log: bool,
    show_all: bool,
    stats_output: &Option<PathBuf>,
    batch_mode: bool,
    capture_output: bool,
) -> Result<Option<CapturedOutput>, CommandError> {
    let bpf_bytes = export_bpf_filter(&ctx)?;
    let mut command = build_command(path, pass_env, capture_output);
    apply_seccomp_filter(&mut command, bpf_bytes);

    if show_log || show_all {
        execute_with_monitoring(command, stats_output, batch_mode)?;
        Ok(None)
    } else if capture_output {
        execute_with_capture(command).map(Some)
    } else {
        execute_without_monitoring(command)?;
        Ok(None)
    }
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

fn execute_without_monitoring(mut command: Command) -> Result<(), CommandError> {
    debug!("Executing command without monitoring");
    match command.status() {
        Ok(status) => {
            debug!("Child process exited with status: {:?}", status);
            handle_exit_status(status)
        }
        Err(e) => {
            error!("Failed to execute command: {}", e);
            Err(CommandError::Exec(e.to_string()))
        }
    }
}

fn execute_with_capture(mut command: Command) -> Result<CapturedOutput, CommandError> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut child = command
        .spawn()
        .map_err(|e| CommandError::Exec(e.to_string()))?;

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
) -> Result<(), CommandError> {
    // Start the monitor
    let mut monitor = SeccompMonitor::new();
    info!("Starting seccomp monitor...\n");

    monitor
        .start()
        .map_err(|e| CommandError::Monitor(format!("{:?}", e)))?;

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

fn write_detailed_stats(
    monitor: &SeccompMonitor,
    stats_output: &PathBuf,
) -> Result<(), CommandError> {
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

fn spawn_child(command: &mut Command) -> Result<u32, CommandError> {
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
        if !batch_mode {
            if let Some(event) = monitor.next_event(Duration::from_millis(100)) {
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
            warn!("Seccomp violation detected");
            Err(CommandError::UnexpectedSignal)
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

// ============================================================================
// REDUCE PROFILE
// ============================================================================

pub fn reduce_profile(
    input_profile: String,
    output_file: String,
    exec_cmd: Vec<String>,
    env: bool,
    batch: bool,
    initial_chunks: usize,
    with_err: bool,
) -> Result<(), CommandError> {
    info!("Loading profile: {}", input_profile);
    let mut profile: OciSeccomp =
        read_and_expand_profile(&input_profile).map_err(CommandError::Profile)?;

    if profile.syscalls.is_none() {
        return Err(CommandError::Profile(ProfileError::NoSyscallsInProfile));
    }

    explode_syscalls(&mut profile);
    let initial_count = profile.syscalls.as_ref().map_or(0, |v| v.len());
    info!("Initial profile has {} syscall rules", initial_count);

    // Capture golden output with full profile
    info!("\n=== Capturing Golden Output ===");
    info!("Running command with full profile...\n");

    let golden_output = capture_golden_output(&profile, &exec_cmd, env)?;

    if !batch {
        print!("\nDoes this output look correct? Continue reduction? [Y/n]: ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        if input.trim().eq_ignore_ascii_case("n") {
            return Err(CommandError::Exec(
                "Golden output rejected by user".to_string(),
            ));
        }
    }

    info!("\n=== Starting Reduction (exact match mode) ===");

    let mut total_tests = 0;

    partition_reduce(
        &mut profile,
        &exec_cmd,
        env,
        batch,
        initial_chunks,
        &mut total_tests,
        Some(&golden_output),
        with_err,
    )?;

    let final_count = profile.syscalls.as_ref().map_or(0, |v| v.len());
    let reduction = initial_count - final_count;
    let reduction_pct = (reduction as f64 / initial_count as f64) * 100.0;

    info!("\n=== Reduction Complete ===");
    info!("Initial syscalls: {}", initial_count);
    info!("Final syscalls:   {}", final_count);
    info!("Removed:          {} ({:.1}%)", reduction, reduction_pct);
    info!("Total tests:      {}", total_tests);

    coalesce_rules_by_action(&mut profile);
    let output_json = toml::to_string_pretty(&profile)?;
    fs::write(&output_file, output_json)?;

    info!("Minimized profile saved to: {}", output_file);

    Ok(())
}

fn capture_golden_output(
    profile: &OciSeccomp,
    exec_cmd: &[String],
    env: bool,
) -> Result<CapturedOutput, CommandError> {
    let ctx = apply_profile(profile, None, None, false)?;

    let output = filtered_exec(
        ctx, exec_cmd, env, false, // show_log
        false, // show_all
        &None, // stats_output
        true,  // batch_mode
        true,  // capture_output
    )?
    .ok_or_else(|| CommandError::Exec("Failed to capture golden output".to_string()))?;

    Ok(output)
}

fn partition_reduce(
    profile: &mut OciSeccomp,
    exec_cmd: &[String],
    env: bool,
    batch: bool,
    initial_chunks: usize,
    total_tests: &mut usize,
    golden_output: Option<&CapturedOutput>,
    with_err: bool,
) -> Result<Vec<String>, CommandError> {
    let original = match profile.syscalls.as_ref() {
        Some(v) if !v.is_empty() => v.clone(),
        _ => return Ok(Vec::new()),
    };

    let mut working = original;
    let mut n = initial_chunks.max(2).min(working.len());
    let auto_mode = golden_output.is_some();

    if auto_mode {
        info!("Auto-comparison enabled (exact match)");
    }

    let original_count = working.len();

    loop {
        if n > working.len() {
            break;
        }

        let chunk_size = working.len().div_ceil(n);
        let mut made_progress = false;

        let progress = 100.0 * (1.0 - (working.len() as f64 / original_count as f64));
        info!(
            "\n--- Progress: {:.1}% ({} → {} rules, n={}) ---",
            progress,
            original_count,
            working.len(),
            n
        );

        let mut i = 0;
        while i < n {
            let start = i * chunk_size;
            let end = ((i + 1) * chunk_size).min(working.len());

            if start >= working.len() {
                break;
            }

            let mut candidate = Vec::with_capacity(working.len());
            candidate.extend_from_slice(&working[..start]);
            if end < working.len() {
                candidate.extend_from_slice(&working[end..]);
            }

            if candidate.is_empty() {
                i += 1;
                continue;
            }

            let removed_names: Vec<&str> = working[start..end]
                .iter()
                .flat_map(|r| r.names.iter().map(|s| s.as_str()))
                .collect();

            info!(
                "\n  Test {}: Removing chunk {}/{} [{}-{}] ({} rules)\n  Syscalls: {:?}",
                *total_tests + 1,
                i + 1,
                n,
                start,
                end,
                end - start,
                removed_names
            );

            let mut tmp_profile = profile.clone();
            tmp_profile.syscalls = Some(candidate.clone());

            *total_tests += 1;
            let passed = match test_profile_with_golden(
                &tmp_profile,
                exec_cmd,
                env,
                batch,
                golden_output,
                with_err,
            ) {
                Ok(passed) => passed,
                Err(CommandError::Exec(e)) => {
                    warn!("Error during test: {}", e);
                    info!("Assuming test failure, continuing");
                    false
                }
                Err(e) => {
                    warn!("Error during test: {}", e);
                    return Err(e);
                }
            };

            if passed {
                info!("✓ PASS - removed {} rules", end - start);
                working = candidate;
                made_progress = true;
                n = 2;
                break;
            } else {
                info!("✗ FAIL - keeping rules");
                i += 1;
            }
        }

        if !made_progress {
            if n >= working.len() {
                break;
            }
            n = (n * 2).min(working.len());
            info!("  No progress, increasing granularity to n={}", n);
        }
    }

    profile.syscalls = Some(working.clone());

    let kept_names: Vec<String> = working
        .iter()
        .flat_map(|r| r.names.iter().cloned())
        .collect();

    info!(
        "\n✓ Partitioning complete: {} rules remaining",
        working.len()
    );

    Ok(kept_names)
}

fn test_profile_with_golden(
    profile: &OciSeccomp,
    exec_cmd: &[String],
    env: bool,
    batch: bool,
    golden_output: Option<&CapturedOutput>,
    with_err: bool,
) -> Result<bool, CommandError> {
    let ctx = apply_profile(profile, None, None, false)?;

    // Run with capture
    let result = filtered_exec(
        ctx, exec_cmd, env, false, // show_log
        false, // show_all
        &None, // stats_output
        true,  // batch_mode
        true,  // capture_output
    );

    let test_output = match result {
        Ok(Some(output)) => output,
        Ok(None) => {
            warn!("Failed to capture test output");
            return Ok(false);
        }
        Err(CommandError::UnexpectedSignal) | Err(CommandError::UnexpectedExit) => {
            // Expected failure for seccomp violations
            debug!("Test failed (seccomp violation)");
            return Ok(false);
        }
        Err(e) => {
            warn!("Unexpected error during test: {}", e);
            return Err(e);
        }
    };

    if let Some(golden) = golden_output {
        let sim_score = test_output.sim_score(golden, with_err);

        if sim_score == 1.0 {
            info!("      ✓ Output matches exactly!");
            return Ok(true);
        } else {
            if !batch {
                test_output.print_diff(golden, sim_score);

                print!("\nManual override? Accept anyway? [y/N]: ");
                io::stdout().flush().unwrap();

                let mut input = String::new();
                io::stdin().read_line(&mut input)?;

                return Ok(input.trim().eq_ignore_ascii_case("y"));
            }

            return Ok(false);
        }
    }

    // If no golden output
    if batch {
        Ok(true)
    } else {
        print!("\nDoes the behavior look correct? [y/N]: ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        Ok(input.trim().eq_ignore_ascii_case("y"))
    }
}

// ============================================================================
// FUZZ PROFILE
// ============================================================================

/// Execute a command in fuzzing mode (not yet implemented).
pub fn fuzz_exec(_path: Vec<String>, _pass_env: bool) -> Result<(), CommandError> {
    Err(CommandError::FuzzingNotImplemented)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fuzz_exec() {
        let result = fuzz_exec(vec!["true".to_string()], false);
        assert!(matches!(result, Err(CommandError::FuzzingNotImplemented)));
    }
}
