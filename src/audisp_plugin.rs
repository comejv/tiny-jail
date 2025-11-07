use std::fs::OpenOptions;
use std::io::{self, BufRead, Write};

fn main() -> io::Result<()> {
    let log_path = "/tmp/audit.log";

    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(log_path)
        .map_err(|e| {
            eprintln!("audisp-plugin: Failed to open log file {}: {}", log_path, e);
            e
        })?;

    let stdin = io::stdin();
    for line_result in stdin.lock().lines() {
        match line_result {
            Ok(line) => {
                if line.contains("type=SECCOMP") {
                    if let Err(e) = writeln!(file, "{}", line) {
                        eprintln!("audisp-plugin: Failed to write to log file: {}", e);
                    }
                }
            }
            Err(e) => {
                eprintln!("audisp-plugin: Failed to read line from stdin: {}", e);
                // Continue processing other lines, don't crash the plugin
            }
        }
    }

    Ok(())
}
