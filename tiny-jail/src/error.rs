use std::io;
use thiserror::Error;
use libseccomp::error::SeccompError;
use crate::filters::ProfileError;

#[derive(Error, Debug)]
pub enum JailError {
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
    #[error("Golden output rejected by user")]
    GoldenOutputRejected,
}
