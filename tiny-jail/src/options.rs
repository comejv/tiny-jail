
use std::path::PathBuf;

/// Options for filtered command execution.
#[derive(Debug)]
pub struct FilteredExecOptions<'a> {
    pub path: &'a [String],
    pub pass_env: bool,
    pub show_log: bool,
    pub show_all: bool,
    pub stats_output: &'a Option<PathBuf>,
    pub batch_mode: bool,
    pub capture_output: bool,
}

/// Options for profile reduction.
#[derive(Debug)]
pub struct ReduceProfileOptions {
    pub input_profile: String,
    pub output_file: String,
    pub exec_cmd: Vec<String>,
    pub env: bool,
    pub batch: bool,
    pub initial_chunks: usize,
    pub with_err: bool,
}

/// Options for fuzzing.
#[derive(Debug)]
pub struct FuzzOptions {
    pub exec: Vec<String>,
    pub env: bool,
    pub output: Option<String>,
    pub iterations: u32,
    pub threads: u32,
    pub batch: bool,
}
