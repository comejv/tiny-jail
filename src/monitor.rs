use log2::*;
use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::process::Child;
use std::process::{Command, Stdio};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Debug, Clone, Default)]
pub struct SeccompEvent {
    pub timestamp: String,
    pub auid: u32,
    pub uid: u32,
    pub gid: u32,
    pub ses: u32,
    pub pid: u32,
    pub comm: String,
    pub exe: String,
    pub sig: u32,
    pub arch: String,
    pub syscall: u32,
    pub compat: u32,
    pub ip: String,
    pub code: String,
}

#[derive(Debug)]
pub enum MonitorError {
    CommandFailed(String),
    ParseError(String),
}

impl SeccompEvent {
    /// Parse a seccomp audit log line
    fn parse(line: &str) -> Result<Self, MonitorError> {
        // Check if it's a seccomp audit entry (type=1326)
        if !line.contains("type=1326") {
            return Err(MonitorError::ParseError(
                "Not a seccomp audit entry".to_string(),
            ));
        }

        let mut event = SeccompEvent::default();
        // Parse audit timestamp
        // Timestamp is in the format "[mar. 14 oct. 11:11:44 2025]"
        let ts_start = line
            .find('[')
            .ok_or_else(|| MonitorError::ParseError("Timestamp start not found".to_string()))?
            + 1;
        let ts_end = line
            .find(']')
            .ok_or_else(|| MonitorError::ParseError("Timestamp end not found".to_string()))?;
        if ts_start > ts_end {
            return Err(MonitorError::ParseError(
                "Invalid timestamp format".to_string(),
            ));
        }
        event.timestamp = line[ts_start..ts_end].to_string();

        let details = &line[ts_end..];

        // Helper function to extract field values
        let extract_field = |field: &str| -> Option<String> {
            details.find(field).map(|start| {
                let after = &details[start + field.len()..];
                let end = after.find(' ').unwrap_or(after.len());
                after[..end].to_string()
            })
        };

        // Helper for quoted fields
        let extract_quoted = |field: &str| -> Option<String> {
            details.find(field).and_then(|start| {
                let after = &details[start + field.len()..];
                if let Some(s) = after.strip_prefix('"') {
                    s.find('"').map(|end| s[..end].to_string())
                } else {
                    let end = after.find(' ').unwrap_or(after.len());
                    Some(after[..end].to_string())
                }
            })
        };

        // Helper to convert Option to Result and parse
        let parse_field = |field: &str| -> Result<u32, MonitorError> {
            extract_field(field)
                .ok_or_else(|| MonitorError::ParseError(format!("Missing {}", field)))?
                .parse()
                .map_err(|_| MonitorError::ParseError(format!("Invalid {}", field)))
        };

        // Extract all fields
        event.auid = parse_field("auid=")?;
        event.uid = parse_field("uid=")?;
        event.gid = parse_field("gid=")?;
        event.ses = parse_field("ses=")?;
        event.pid = parse_field("pid=")?;
        event.comm = extract_quoted("comm=")
            .ok_or_else(|| MonitorError::ParseError("Missing comm".to_string()))?;
        event.exe = extract_quoted("exe=")
            .ok_or_else(|| MonitorError::ParseError("Missing exe".to_string()))?;
        event.sig = parse_field("sig=")?;
        event.arch = extract_field("arch=")
            .ok_or_else(|| MonitorError::ParseError("Missing arch".to_string()))?;
        event.syscall = parse_field("syscall=")?;
        event.compat = parse_field("compat=")?;
        event.ip = extract_field("ip=")
            .ok_or_else(|| MonitorError::ParseError("Missing ip".to_string()))?;
        event.code = extract_field("code=")
            .ok_or_else(|| MonitorError::ParseError("Missing code".to_string()))?;
        Ok(event)
    }

    pub fn print_event(&self) {
        println!("┌─ Seccomp Event ─────────────────────────────────────┐");
        println!("│ Process: {} (PID: {})", self.comm, self.pid);
        println!("│ Executable: {}", self.exe);
        println!("│ Syscall: {} (arch: {})", self.syscall, self.arch);
        println!("│ User: uid={}, gid={}", self.uid, self.gid);
        println!("│ Code: {}", self.code);
        println!("│ Timestamp: {}", self.timestamp);
        println!("└─────────────────────────────────────────────────────┘\n");
    }
}

pub struct MonitorHandle {
    pub thread: thread::JoinHandle<()>,
    pub child_process: std::sync::Arc<std::sync::Mutex<Option<Child>>>,
}

impl MonitorHandle {
    pub fn stop(self) {
        debug!("Stopping monitor thread...");
        // Kill the journalctl process
        if let Ok(mut guard) = self.child_process.lock() {
            if let Some(mut child) = guard.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
        // Thread will exit when journalctl dies
        let _ = self.thread.join();
    }
}

pub fn monitor_seccomp_logs(
    tx_events: Sender<SeccompEvent>,
    tx_ready: Sender<()>,
) -> Result<MonitorHandle, MonitorError> {
    let child_process = Arc::new(Mutex::new(None));
    let child_process_clone = child_process.clone();

    let handle = thread::spawn(move || {
        // 1) Refresh sudo credentials; this will prompt the user if needed.
        match Command::new("sudo")
            .arg("-v")
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
        {
            Ok(status) if status.success() => {
                // credentials are now cached
            }
            Ok(status) => {
                error!("sudo –v failed, exit code {:?}", status.code());
                let _ = tx_ready.send(()); // unblock parent so it can error out
                return;
            }
            Err(e) => {
                error!("failed to exec sudo –v: {}", e);
                let _ = tx_ready.send(());
                return;
            }
        }

        // 2) Now spawn the actual dmesg monitor under sudo
        let mut child = match Command::new("sudo")
            .args(["dmesg", "-w", "-T"])
            .stdin(Stdio::inherit()) // dmesg won't read stdin, but we inherit so no surprise
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit()) // if it somehow needs a prompt again, user will see it
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                error!("failed to start `sudo dmesg`: {}", e);
                let _ = tx_ready.send(());
                return;
            }
        };

        // pull off the pipe and store the child handle
        let stdout = match child.stdout.take() {
            Some(s) => s,
            None => {
                error!("could not capture dmesg stdout");
                let _ = tx_ready.send(());
                let _ = child.kill();
                let _ = child.wait();
                return;
            }
        };
        *child_process_clone.lock().unwrap() = Some(child);

        // 3) Only now do we signal the parent that the monitor is truly
        //    up (and credentials are in place), so it can release the exec.
        let _ = tx_ready.send(());

        // 4) Stream lines from dmesg → parse → tx_events
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            match line {
                Ok(l) => {
                    if let Ok(ev) = SeccompEvent::parse(&l) {
                        if tx_events.send(ev).is_err() {
                            break;
                        }
                    }
                }
                Err(err) => {
                    warn!("error reading from dmesg: {}", err);
                    break;
                }
            }
        }

        // 5) Cleanup: kill dmesg if it's still running
        if let Ok(mut guard) = child_process_clone.lock() {
            if let Some(mut child) = guard.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    });

    Ok(MonitorHandle {
        thread: handle,
        child_process,
    })
}

#[derive(Default)]
pub struct SeccompStats {
    pub total_events: usize,
    pub by_process: HashMap<String, usize>,
    pub by_syscall: HashMap<u32, usize>,
    pub by_exe: HashMap<String, usize>,
}

impl SeccompStats {
    pub fn add_event(&mut self, event: &SeccompEvent) {
        self.total_events += 1;
        *self.by_process.entry(event.comm.clone()).or_insert(0) += 1;
        *self.by_syscall.entry(event.syscall).or_insert(0) += 1;
        *self.by_exe.entry(event.exe.clone()).or_insert(0) += 1;
    }

    pub fn print_summary(&self) {
        println!("\n═══════════════════════════════════════════════");
        println!("          SECCOMP STATISTICS");
        println!("═══════════════════════════════════════════════");
        println!("Total Events: {}\n", self.total_events);

        println!("Top Processes:");
        let mut sorted_procs: Vec<_> = self.by_process.iter().collect();
        sorted_procs.sort_by(|a, b| b.1.cmp(a.1));
        for (proc, count) in sorted_procs.iter().take(5) {
            println!("  {} - {} events", proc, count);
        }

        println!("\nTop Syscalls:");
        let mut sorted_syscalls: Vec<_> = self.by_syscall.iter().collect();
        sorted_syscalls.sort_by(|a, b| b.1.cmp(a.1));
        for (syscall, count) in sorted_syscalls.iter().take(5) {
            println!("  syscall {} - {} events", syscall, count);
        }

        println!("\nTop Executables:");
        let mut sorted_exes: Vec<_> = self.by_exe.iter().collect();
        sorted_exes.sort_by(|a, b| b.1.cmp(a.1));
        for (exe, count) in sorted_exes.iter().take(5) {
            println!("  {} - {} events", exe, count);
        }
    }
}
