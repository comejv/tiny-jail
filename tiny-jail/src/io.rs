use std::io::{self, BufRead, Write};
use std::sync::{Arc, Mutex};
use std::thread;

pub struct CapturedOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: Option<i32>,
}

impl Default for CapturedOutput {
    fn default() -> Self {
        Self::new()
    }
}

impl CapturedOutput {
    pub fn new() -> Self {
        Self {
            stdout: Vec::new(),
            stderr: Vec::new(),
            exit_code: None,
        }
    }

    fn calculate_stream_score(stream_a: &[u8], stream_b: &[u8]) -> f32 {
        let lines_a: Vec<_> = stream_a.lines().map(|l| l.unwrap_or_default()).collect();
        let lines_b: Vec<_> = stream_b.lines().map(|l| l.unwrap_or_default()).collect();

        if lines_a.len() != lines_b.len() {
            return 0.0;
        }

        if lines_a.is_empty() {
            return 1.0;
        }

        let matches = lines_a
            .iter()
            .zip(lines_b.iter())
            .filter(|&(a, b)| a == b)
            .count();
        matches as f32 / lines_a.len() as f32
    }

    pub fn sim_score(&self, other: &Self, with_err: bool) -> f32 {
        if self.exit_code != other.exit_code {
            return 0.0;
        }

        let score_out = Self::calculate_stream_score(&self.stdout, &other.stdout);

        if !with_err {
            return score_out;
        }

        let score_err = Self::calculate_stream_score(&self.stderr, &other.stderr);

        // Average scores only if both streams have content in at least one of the outputs
        let out_present = !self.stdout.is_empty() || !other.stdout.is_empty();
        let err_present = !self.stderr.is_empty() || !other.stderr.is_empty();

        match (out_present, err_present) {
            (true, true) => (score_out + score_err) / 2.0,
            (true, false) => score_out,
            (false, true) => score_err,
            (false, false) => 1.0, // Both empty
        }
    }

    pub fn print_diff(&self, other: &Self, score: f32) {
        let mut stdout = io::stdout();

        stdout.write_all(b"\x1b[31mOutput differs, score: ").ok();
        stdout.write_all(format!("{:.2}", score).as_bytes()).ok();
        stdout.write_all(b" (expected 1.0, actual ").ok();
        stdout
            .write_all(format!("{:.2}", 1.0 - score).as_bytes())
            .ok();
        stdout.write_all(b")\x1b[0m\n").ok();
        stdout
            .write_all(b"\t(- is expected, + is actual):\x1b[0m\n")
            .ok();

        print_stream_diff(&mut stdout, "Stdout", &self.stdout, &other.stdout);
        print_stream_diff(&mut stdout, "Stderr", &self.stderr, &other.stderr);
    }
}

fn print_stream_diff(writer: &mut dyn Write, name: &str, stream_a: &[u8], stream_b: &[u8]) {
    let lines_a: Vec<String> = stream_a.lines().map(|l| l.unwrap_or_default()).collect();
    let lines_b: Vec<String> = stream_b.lines().map(|l| l.unwrap_or_default()).collect();

    if lines_a.is_empty() && lines_b.is_empty() {
        return;
    }

    if lines_a == lines_b {
        return;
    }

    writer
        .write_all(format!("\x1b[1m{}:\x1b[0m\n", name).as_bytes())
        .ok();

    let max_lines = lines_a.len().max(lines_b.len());

    for i in 0..max_lines {
        let line_a = lines_a.get(i);
        let line_b = lines_b.get(i);

        match (line_a, line_b) {
            (Some(a), Some(b)) => {
                if a == b {
                    writer.write_all(b"  ").ok();
                    writer.write_all(a.as_bytes()).ok();
                } else {
                    writer.write_all(b"\x1b[31m- ").ok();
                    writer.write_all(b.as_bytes()).ok();
                    writer.write_all(b"\x1b[0m\n").ok();
                    writer.write_all(b"\x1b[32m+ ").ok();
                    writer.write_all(a.as_bytes()).ok();
                    writer.write_all(b"\x1b[0m").ok();
                }
            }
            (Some(a), None) => {
                writer.write_all(b"\x1b[32m+ ").ok();
                writer.write_all(a.as_bytes()).ok();
                writer.write_all(b"\x1b[0m").ok();
            }
            (None, Some(b)) => {
                writer.write_all(b"\x1b[31m- ").ok();
                writer.write_all(b.as_bytes()).ok();
                writer.write_all(b"\x1b[0m").ok();
            }
            (None, None) => unreachable!(),
        }
        writer.write_all(b"\n").ok();
    }
}

pub fn capture_and_display_stream(
    reader: impl BufRead + Send + 'static,
    output: Arc<Mutex<Vec<u8>>>,
    stream_name: &str,
) -> thread::JoinHandle<()> {
    let name = stream_name.to_string();
    thread::spawn(move || {
        let mut writer = io::stdout(); // Always write to stdout
        for line_result in reader.split(b'\n') {
            match line_result {
                Ok(mut line) => {
                    // Display in real-time
                    writer.write_all(&line).ok();
                    writer.write_all(b"\n").ok();
                    writer.flush().ok();

                    // Capture for later
                    line.push(b'\n');
                    output.lock().unwrap().extend_from_slice(&line);
                }
                Err(e) => {
                    eprintln!("[{}] Error reading: {}", name, e);
                    break;
                }
            }
        }
    })
}
