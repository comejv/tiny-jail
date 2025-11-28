use std::collections::HashSet;
use std::io::{self, BufRead, Write};
use std::sync::{Arc, Mutex};
use std::thread;

pub struct CapturedOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: Option<i32>,
}

#[derive(Debug, Clone, Copy)]
pub struct SimilarityConfig {
    /// Allow some tolerance in line count differences (0.0 = strict, 1.0 = very lenient)
    pub line_count_tolerance: f32,
    /// Normalize whitespace before comparison
    pub normalize_whitespace: bool,
    /// Immediate discard threshold (0.0-1.0, higher = stricter)
    pub discard_threshold: f32,
    /// Use fuzzy matching for individual lines (slower but more tolerant)
    pub fuzzy_lines: bool,
    /// Threshold for fuzzy line matching (0.0-1.0, higher = stricter)
    pub fuzzy_threshold: f32,
    /// Allow lines to be in different order (use set-based comparison)
    pub order_insensitive: bool,
    /// Weight for exit code match (0.0-1.0)
    pub exit_code_weight: f32,
}

impl Default for SimilarityConfig {
    fn default() -> Self {
        Self {
            line_count_tolerance: 0.1, // Allow 10% difference
            normalize_whitespace: true,
            discard_threshold: 0.5,
            fuzzy_lines: false, // Exact matching by default
            fuzzy_threshold: 0.85,
            order_insensitive: false,
            exit_code_weight: 0.3, // 30% weight to exit code
        }
    }
}

impl SimilarityConfig {
    /// Strict mode: exact matching
    pub fn strict() -> Self {
        Self {
            line_count_tolerance: 0.0,
            normalize_whitespace: false,
            discard_threshold: 0.7,
            fuzzy_lines: false,
            fuzzy_threshold: 1.0,
            order_insensitive: false,
            exit_code_weight: 0.5,
        }
    }

    /// Lenient mode: tolerant of minor differences
    pub fn lenient() -> Self {
        Self {
            line_count_tolerance: 0.2,
            normalize_whitespace: true,
            discard_threshold: 0.4,
            fuzzy_lines: true,
            fuzzy_threshold: 0.8,
            order_insensitive: false,
            exit_code_weight: 0.2,
        }
    }

    /// Very lenient: for non-deterministic outputs
    pub fn very_lenient() -> Self {
        Self {
            line_count_tolerance: 0.5,
            normalize_whitespace: true,
            discard_threshold: 0.3,
            fuzzy_lines: true,
            fuzzy_threshold: 0.7,
            order_insensitive: true,
            exit_code_weight: 0.1,
        }
    }
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

    /// Calculate similarity with default config (backward compatible)
    pub fn sim_score(&self, other: &Self, with_err: bool) -> f32 {
        self.sim_score_with_config(other, with_err, &SimilarityConfig::default())
    }

    /// Calculate similarity with custom configuration
    pub fn sim_score_with_config(
        &self,
        other: &Self,
        with_err: bool,
        config: &SimilarityConfig,
    ) -> f32 {
        // Exit code comparison
        let exit_code_match = if self.exit_code == other.exit_code {
            1.0
        } else {
            0.0
        };

        // Stream comparisons
        let score_out = Self::calculate_stream_score(&self.stdout, &other.stdout, config);

        let score_err = if with_err {
            Self::calculate_stream_score(&self.stderr, &other.stderr, config)
        } else {
            1.0 // Don't penalize if we're not comparing stderr
        };

        // Determine weights based on what's present
        let out_present = !self.stdout.is_empty() || !other.stdout.is_empty();
        let err_present = with_err && (!self.stderr.is_empty() || !other.stderr.is_empty());

        let stream_score = match (out_present, err_present) {
            (true, true) => (score_out + score_err) / 2.0,
            (true, false) => score_out,
            (false, true) => score_err,
            (false, false) => 1.0,
        };

        // Weighted combination
        let exit_weight = config.exit_code_weight;
        let stream_weight = 1.0 - exit_weight;

        exit_code_match * exit_weight + stream_score * stream_weight
    }

    fn calculate_stream_score(stream_a: &[u8], stream_b: &[u8], config: &SimilarityConfig) -> f32 {
        let lines_a: Vec<_> = stream_a.lines().map(|l| l.unwrap_or_default()).collect();
        let lines_b: Vec<_> = stream_b.lines().map(|l| l.unwrap_or_default()).collect();

        // Both empty is perfect match
        if lines_a.is_empty() && lines_b.is_empty() {
            return 1.0;
        }

        // One empty, one not
        if lines_a.is_empty() || lines_b.is_empty() {
            return 0.0;
        }

        // Check line count tolerance
        let max_len = lines_a.len().max(lines_b.len()) as f32;
        let min_len = lines_a.len().min(lines_b.len()) as f32;
        let len_ratio = min_len / max_len;

        if len_ratio < (1.0 - config.line_count_tolerance) {
            // Too much difference in line count
            return len_ratio * 0.5; // Partial credit based on length ratio
        }

        if config.order_insensitive {
            Self::calculate_set_based_score(&lines_a, &lines_b, config)
        } else {
            Self::calculate_line_by_line_score(&lines_a, &lines_b, config)
        }
    }

    fn calculate_line_by_line_score(
        lines_a: &[String],
        lines_b: &[String],
        config: &SimilarityConfig,
    ) -> f32 {
        let max_len = lines_a.len().max(lines_b.len());
        let mut total_score = 0.0;

        for i in 0..max_len {
            let score = match (lines_a.get(i), lines_b.get(i)) {
                (Some(a), Some(b)) => Self::compare_lines(a, b, config),
                (None, Some(_)) | (Some(_), None) => {
                    // Missing line penalty
                    0.0
                }
                (None, None) => unreachable!(),
            };
            total_score += score;
        }

        total_score / max_len as f32
    }

    fn calculate_set_based_score(
        lines_a: &[String],
        lines_b: &[String],
        config: &SimilarityConfig,
    ) -> f32 {
        let normalized_a: Vec<_> = lines_a
            .iter()
            .map(|l| Self::normalize_line(l, config))
            .collect();
        let normalized_b: Vec<_> = lines_b
            .iter()
            .map(|l| Self::normalize_line(l, config))
            .collect();

        if config.fuzzy_lines {
            // Fuzzy set-based comparison
            Self::fuzzy_set_comparison(&normalized_a, &normalized_b, config)
        } else {
            // Exact set-based comparison (Jaccard similarity)
            let set_a: HashSet<_> = normalized_a.iter().collect();
            let set_b: HashSet<_> = normalized_b.iter().collect();

            let intersection = set_a.intersection(&set_b).count();
            let union = set_a.union(&set_b).count();

            if union == 0 {
                1.0
            } else {
                intersection as f32 / union as f32
            }
        }
    }

    fn fuzzy_set_comparison(
        lines_a: &[String],
        lines_b: &[String],
        config: &SimilarityConfig,
    ) -> f32 {
        let mut matched_b = vec![false; lines_b.len()];
        let mut total_score = 0.0;

        // For each line in A, find best match in B
        for line_a in lines_a {
            let mut best_match = 0.0;
            let mut best_idx = None;

            for (idx, line_b) in lines_b.iter().enumerate() {
                if matched_b[idx] {
                    continue;
                }

                let similarity = Self::line_similarity(line_a, line_b);
                if similarity > best_match && similarity >= config.fuzzy_threshold {
                    best_match = similarity;
                    best_idx = Some(idx);
                }
            }

            if let Some(idx) = best_idx {
                matched_b[idx] = true;
                total_score += best_match;
            }
        }

        let max_matches = lines_a.len().max(lines_b.len());
        if max_matches == 0 {
            1.0
        } else {
            total_score / max_matches as f32
        }
    }

    fn compare_lines(line_a: &str, line_b: &str, config: &SimilarityConfig) -> f32 {
        let norm_a = Self::normalize_line(line_a, config);
        let norm_b = Self::normalize_line(line_b, config);

        if norm_a == norm_b {
            return 1.0;
        }

        if config.fuzzy_lines {
            Self::line_similarity(&norm_a, &norm_b)
        } else {
            0.0
        }
    }

    fn normalize_line(line: &str, config: &SimilarityConfig) -> String {
        if config.normalize_whitespace {
            line.split_whitespace().collect::<Vec<_>>().join(" ")
        } else {
            line.to_string()
        }
    }

    /// Calculate line similarity using Levenshtein distance
    fn line_similarity(a: &str, b: &str) -> f32 {
        if a == b {
            return 1.0;
        }

        let distance = levenshtein_distance(a, b);
        let max_len = a.len().max(b.len());

        if max_len == 0 {
            return 1.0;
        }

        1.0 - (distance as f32 / max_len as f32)
    }

    pub fn print_diff(&self, other: &Self, score: f32) {
        let mut stdout = io::stdout();

        stdout.write_all(b"\x1b[31mOutput differs, score: ").ok();
        stdout.write_all(format!("{:.2}", score).as_bytes()).ok();

        // Exit code comparison
        if self.exit_code != other.exit_code {
            stdout
                .write_all(
                    format!(
                        "\x1b[31mExit code mismatch: expected {:?}, got {:?}\x1b[0m\n",
                        other.exit_code, self.exit_code
                    )
                    .as_bytes(),
                )
                .ok();
        }

        stdout
            .write_all(b"\t(- is expected, + is actual):\x1b[0m\n")
            .ok();

        print_stream_diff(&mut stdout, "Stdout", &self.stdout, &other.stdout);
        print_stream_diff(&mut stdout, "Stderr", &self.stderr, &other.stderr);
    }
}

/// Calculate Levenshtein distance between two strings
fn levenshtein_distance(a: &str, b: &str) -> usize {
    let a_len = a.chars().count();
    let b_len = b.chars().count();

    if a_len == 0 {
        return b_len;
    }
    if b_len == 0 {
        return a_len;
    }

    let mut prev_row: Vec<usize> = (0..=b_len).collect();
    let mut curr_row = vec![0; b_len + 1];

    for (i, ca) in a.chars().enumerate() {
        curr_row[0] = i + 1;

        for (j, cb) in b.chars().enumerate() {
            let cost = if ca == cb { 0 } else { 1 };
            curr_row[j + 1] = (curr_row[j] + 1)
                .min(prev_row[j + 1] + 1)
                .min(prev_row[j] + cost);
        }

        std::mem::swap(&mut prev_row, &mut curr_row);
    }

    prev_row[b_len]
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
        let mut writer = io::stdout();
        for line_result in reader.split(b'\n') {
            match line_result {
                Ok(mut line) => {
                    writer.write_all(&line).ok();
                    writer.write_all(b"\n").ok();
                    writer.flush().ok();

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
