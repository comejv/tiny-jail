use log2::*;
use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::process::Child;
use std::process::{Command, Stdio};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;

use crate::actions::Action;

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
    pub code: u32,
    pub decoded: DecodedCode,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DecodedCode {
    pub raw: u32,
    pub class: u32,
    pub data: u16,
    pub action: Action,
}

#[derive(Debug)]
pub enum MonitorError {
    CommandFailed(String),
    ParseError(String),
    CallbackSuppressed,
}

const SECCOMP_RET_ACTION_FULL: u32 = 0xffff0000;
const SECCOMP_RET_DATA: u32 = 0x0000ffff;
pub fn decode_code(raw: u32) -> DecodedCode {
    let class = raw & SECCOMP_RET_ACTION_FULL;
    let data = (raw & SECCOMP_RET_DATA) as u16;
    let action = Action::from_class(class).unwrap_or(Action::Unknown);
    DecodedCode {
        raw,
        class,
        data,
        action,
    }
}

impl SeccompEvent {
    fn parse(line: &str) -> Result<Self, MonitorError> {
        // Check if it's a seccomp audit entry (type=1326) or suppressed callbacks
        if !line.contains("type=1326") {
            if line.contains("callbacks suppressede") {
                return Err(MonitorError::CallbackSuppressed);
            }
            return Err(MonitorError::ParseError(
                "Not a seccomp audit entry".to_string(),
            ));
        }

        // Parse audit timestamp from audit(timestamp:id) format
        let timestamp = line
            .find("audit(")
            .and_then(|start| {
                let after = &line[start + 6..];
                after.find(')').map(|end| &after[..end])
            })
            .ok_or_else(|| MonitorError::ParseError("Timestamp not found".to_string()))?
            .to_string();

        // Helper to extract field values (single pass per field)
        let extract_field = |field: &str| -> Option<&str> {
            line.find(field).map(|start| {
                let after = &line[start + field.len()..];
                let end = after.find(' ').unwrap_or(after.len());
                &after[..end]
            })
        };

        // Helper for quoted fields
        let extract_quoted = |field: &str| -> Option<String> {
            line.find(field).and_then(|start| {
                let after = &line[start + field.len()..];
                after
                    .strip_prefix('"')
                    .and_then(|s| s.find('"').map(|end| s[..end].to_string()))
            })
        };

        // Parse numeric field (handles both hex and decimal)
        let parse_u32 = |field: &str| -> Result<u32, MonitorError> {
            let value = extract_field(field)
                .ok_or_else(|| MonitorError::ParseError(format!("Missing {}", field)))?;

            if let Some(hex) = value.strip_prefix("0x") {
                u32::from_str_radix(hex, 16)
            } else {
                value.parse()
            }
            .map_err(|_| MonitorError::ParseError(format!("Invalid {}: {}", field, value)))
        };

        // Extract string field
        let get_string = |field: &str| -> Result<String, MonitorError> {
            extract_field(field)
                .map(|s| s.to_string())
                .ok_or_else(|| MonitorError::ParseError(format!("Missing {}", field)))
        };

        Ok(SeccompEvent {
            timestamp,
            auid: parse_u32("auid=")?,
            uid: parse_u32("uid=")?,
            gid: parse_u32("gid=")?,
            ses: parse_u32("ses=")?,
            pid: parse_u32("pid=")?,
            comm: extract_quoted("comm=")
                .ok_or_else(|| MonitorError::ParseError("Missing comm".to_string()))?,
            exe: extract_quoted("exe=")
                .ok_or_else(|| MonitorError::ParseError("Missing exe".to_string()))?,
            sig: parse_u32("sig=")?,
            arch: get_string("arch=")?,
            syscall: parse_u32("syscall=")?,
            compat: parse_u32("compat=")?,
            ip: get_string("ip=")?,
            code: parse_u32("code=")?,
            decoded: DecodedCode::default(),
        }
        .with_decoded())
    }

    fn with_decoded(mut self) -> Self {
        self.decoded = decode_code(self.code);
        self
    }

    fn is_fatal(&self) -> bool {
        matches!(
            self.decoded.action,
            Action::KillProcess | Action::KillThread
        ) || (matches!(self.decoded.action, Action::Trap) && self.sig == 31)
    }

    fn decoded_summary(&self) -> String {
        let d = &self.decoded;
        match d.action {
            Action::Allow => "ALLOW".to_string(),
            Action::Log => "LOG".to_string(),
            Action::Errno => format!("ERRNO={}", d.data),
            Action::Trap => {
                if self.sig == 31 {
                    "TRAP(SIGSYS)".to_string()
                } else {
                    "TRAP".to_string()
                }
            }
            Action::Trace => format!("TRACE(cookie=0x{:04x})", d.data),
            Action::KillThread => "KILL_THREAD".to_string(),
            Action::KillProcess => "KILL_PROCESS".to_string(),
            Action::Unknown => format!("UNKNOWN(0x{:08x})", d.raw),
        }
    }

    pub fn print_event(&self) {
        let fatal = self.is_fatal();
        let head = if fatal {
            "┌─ Seccomp Event [FATAL] ──────────────────────────────┐"
        } else {
            "┌─ Seccomp Event ──────────────────────────────────────┐"
        };

        let syscall_name = libseccomp::ScmpSyscall::from_raw_syscall(self.syscall as i32)
            .get_name()
            .unwrap_or("UNKNOWN".to_string());

        println!("{}", head);

        println!("│ Process: {} (PID: {})", self.comm, self.pid);
        println!("│ Executable: {}", self.exe);
        println!("│ Syscall: {}({})", syscall_name, self.syscall);
        println!(
            "│ User: uid={}, gid={}, auid={}, ses={}",
            self.uid, self.gid, self.auid, self.ses
        );

        println!("│ Action: {}", self.decoded_summary());

        if self.sig != 0 {
            let sig = if self.sig == 31 {
                "SIGSYS(31)"
            } else {
                "other"
            };
            println!("│ Signal: {}", sig);
        } else {
            println!("│ Signal: none");
        }

        println!("│ IP: {}", self.ip);
        println!(
            "│ Code: raw=0x{:08x} class=0x{:08x} data=0x{:04x}",
            self.decoded.raw, self.decoded.class, self.decoded.data
        );
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
            .args(["dmesg", "-W", "-T"])
            .stdin(Stdio::inherit())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
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

        // 3) Signal the parent that we are ready
        let _ = tx_ready.send(());

        // 4) Stream lines from dmesg → parse → tx_events
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            match line {
                Ok(l) => match SeccompEvent::parse(&l) {
                    Ok(ev) => {
                        if tx_events.send(ev).is_err() {
                            error!("Could not send the event");
                            continue;
                        }
                    }
                    Err(MonitorError::ParseError(e)) if e.contains("Not a seccomp audit entry") => {
                        debug!("Skipping line: {}", l);
                        continue;
                    }
                    Err(MonitorError::CallbackSuppressed) => {
                        warn!("audit is being throttled, not all events will be shown");
                        continue;
                    }
                    Err(e) => {
                        error!("Could not parse the event: {:?}", e);
                        continue;
                    }
                },
                Err(err) => {
                    error!("error reading from dmesg: {}", err);
                    continue;
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
        let syscall_names = sorted_syscalls
            .iter()
            .map(|(syscall, count)| {
                (
                    libseccomp::ScmpSyscall::from_raw_syscall(**syscall as i32)
                        .get_name()
                        .unwrap_or("UNKNOWN".to_string()),
                    count,
                )
            })
            .collect::<Vec<_>>();

        for (syscall, count) in syscall_names.iter().take(5) {
            println!("  * {} - {} events", syscall, count);
        }

        println!("\nTop Executables:");
        let mut sorted_exes: Vec<_> = self.by_exe.iter().collect();
        sorted_exes.sort_by(|a, b| b.1.cmp(a.1));
        for (exe, count) in sorted_exes.iter().take(5) {
            println!("  {} - {} events", exe, count);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_seccomp_event() {
        let line = r#"[mer. 22 oct. 16:59:18 2025] audit: type=1326 audit(1761049793.948:471): auid=1000 uid=1000 gid=1000 ses=2 pid=38620 comm="ls" exe="/usr/bin/ls" sig=31 arch=c000003e syscall=1 compat=0 ip=0x7ffff7ca6527 code=0x0"#
            .to_string();

        let event = SeccompEvent::parse(&line).unwrap();
        assert_eq!(event.auid, 1000);
        assert_eq!(event.uid, 1000);
        assert_eq!(event.gid, 1000);
        assert_eq!(event.ses, 2);
        assert_eq!(event.pid, 38620);
        assert_eq!(event.comm, "ls");
        assert_eq!(event.exe, "/usr/bin/ls");
        assert_eq!(event.sig, 31);
        assert_eq!(event.syscall, 1);
        assert_eq!(event.compat, 0);
        assert_eq!(event.ip, "0x7ffff7ca6527");
        assert_eq!(event.code, 0);
        assert_eq!(event.decoded.raw, 0);
        assert_eq!(event.decoded.class, 0);
        assert_eq!(event.decoded.data, 0);
        assert_eq!(event.decoded.action, Action::KillThread);
    }

    #[test]
    fn test_decode_code() {
        let code = decode_code(0x7fff0000);
        assert_eq!(code.raw, 0x7fff0000);
        assert_eq!(code.class, 0x7fff0000);
        assert_eq!(code.data, 0x0000);
        assert_eq!(code.action, Action::Allow);

        let code = decode_code(0x7fff0000 | 0x0000abcd);
        assert_eq!(code.raw, 0x7fffabcd);
        assert_eq!(code.class, 0x7fff0000);
        assert_eq!(code.data, 0xabcd);
        assert_eq!(code.action, Action::Allow);

        let code = decode_code(0x7ff00000 | 0x0000ffff);
        assert_eq!(code.raw, 0x7ff0ffff);
        assert_eq!(code.class, 0x7ff00000);
        assert_eq!(code.data, 0xffff);
        assert_eq!(code.action, Action::Trace);

        let code = decode_code(0x7ffc0000 | 0x0000ffff | 0x00000001);
        assert_eq!(code.raw, 0x7ffcffff);
        assert_eq!(code.class, 0x7ffc0000);
        assert_eq!(code.data, 0xffff);
        assert_eq!(code.action, Action::Log);
    }
}
