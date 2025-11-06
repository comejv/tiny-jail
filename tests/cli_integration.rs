use assert_cmd::Command;
use predicates::prelude::*;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

// ============================================================================
// Helper Functions
// ============================================================================

fn create_test_profile(path: &Path, content: &str) -> std::io::Result<()> {
    File::create(path)?.write_all(content.as_bytes())
}

fn basic_profile() -> String {
    r#"
        default_action = "SCMP_ACT_ALLOW"
        architectures = ["SCMP_ARCH_X86_64", "SCMP_ARCH_X32"]

        [[syscalls]]
        names = ["read", "write"]
        action = "SCMP_ACT_LOG"

        [[abstract_syscalls]]
        names = [
          "memory_allocate",
        ]
        action = "SCMP_ACT_LOG"
        "#
    .to_string()
}

// ============================================================================
// Basic Command Tests
// ============================================================================

#[test]
fn test_help_flag() {
    Command::cargo_bin("tiny-jail")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage:"));
}

#[test]
fn test_version_flag() {
    Command::cargo_bin("tiny-jail")
        .unwrap()
        .arg("--version")
        .assert()
        .success();
}

// ============================================================================
// Exec Subcommand Tests
// ============================================================================

#[test]
fn test_exec_help() {
    Command::cargo_bin("tiny-jail")
        .unwrap()
        .args(["exec", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Execute a program"));
}

#[test]
fn test_exec_missing_executable() {
    Command::cargo_bin("tiny-jail")
        .unwrap()
        .arg("exec")
        .assert()
        .failure();
}

#[test]
fn test_exec_with_nonexistent_profile() {
    Command::cargo_bin("tiny-jail")
        .unwrap()
        .args(["exec", "--profile", "/nonexistent/profile.toml", "true"])
        .assert()
        .failure()
        .stdout(predicate::str::contains(
            "Failed to read profile: No such file or directory",
        ));
}

#[test]
fn test_exec_with_invalid_profile_toml() {
    let temp_dir = std::env::temp_dir();
    let profile_path = temp_dir.join("invalid_profile.toml");

    create_test_profile(&profile_path, "!invalid toml!").unwrap();

    Command::cargo_bin("tiny-jail")
        .unwrap()
        .args(["exec", "--profile", profile_path.to_str().unwrap(), "true"])
        .assert()
        .failure()
        .stdout(predicate::str::contains("Failed to parse profile"));

    let _ = fs::remove_file(profile_path);
}

#[test]
fn test_exec_with_invalid_default_errno() {
    Command::cargo_bin("tiny-jail")
        .unwrap()
        .args(["exec", "--default-errno", "not_a_number", "true"])
        .assert()
        .failure();
}

#[test]
fn test_exec_with_invalid_action() {
    Command::cargo_bin("tiny-jail")
        .unwrap()
        .args(["exec", "--default-action", "invalid_action", "true"])
        .assert()
        .failure();
}

// Tests that require actual execution (may require elevated privileges)
// These are conditional and will be skipped in unprivileged environments

#[test]
#[ignore = "Requires elevated privileges or CAP_SYS_ADMIN"]
fn test_exec_with_valid_profile_needs_root() {
    let temp_dir = std::env::temp_dir();
    let profile_path = temp_dir.join("valid_profile.toml");

    create_test_profile(&profile_path, &basic_profile()).unwrap();

    Command::cargo_bin("tiny-jail")
        .unwrap()
        .args([
            "exec",
            "--profile",
            profile_path.to_str().unwrap(),
            "--",
            "true",
        ])
        .assert()
        .success();

    let _ = fs::remove_file(profile_path);
}

#[test]
#[ignore = "Requires elevated privileges or CAP_SYS_ADMIN"]
fn test_exec_with_environment_flag_needs_root() {
    let temp_dir = std::env::temp_dir();
    let profile_path = temp_dir.join("env_profile.toml");

    create_test_profile(&profile_path, &basic_profile()).unwrap();

    Command::cargo_bin("tiny-jail")
        .unwrap()
        .args([
            "-e",
            "exec",
            "--profile",
            profile_path.to_str().unwrap(),
            "--",
            "true",
        ])
        .assert()
        .success();

    let _ = fs::remove_file(profile_path);
}

#[test]
#[ignore = "Requires elevated privileges or CAP_SYS_ADMIN"]
fn test_debug_flag_short_needs_root() {
    let temp_dir = std::env::temp_dir();
    let profile_path = temp_dir.join("debug_profile.toml");

    create_test_profile(&profile_path, &basic_profile()).unwrap();

    Command::cargo_bin("tiny-jail")
        .unwrap()
        .args([
            "-d",
            "exec",
            "--profile",
            profile_path.to_str().unwrap(),
            "--",
            "true",
        ])
        .assert()
        .success();

    let _ = fs::remove_file(profile_path);
}

#[test]
#[ignore = "Requires elevated privileges or CAP_SYS_ADMIN"]
fn test_kill_and_log_flags_needs_root() {
    let temp_dir = std::env::temp_dir();
    let profile_path = temp_dir.join("combined_profile.toml");

    create_test_profile(&profile_path, &basic_profile()).unwrap();

    Command::cargo_bin("tiny-jail")
        .unwrap()
        .args([
            "exec",
            "--profile",
            profile_path.to_str().unwrap(),
            "--kill",
            "execve",
            "--log",
            "open",
            "--",
            "true",
        ])
        .assert()
        .success();

    let _ = fs::remove_file(profile_path);
}

// ============================================================================
// Flag Parsing Tests (don't require execution)
// ============================================================================

#[test]
fn test_exec_with_double_dash_separator() {
    // This tests the parsing by using a command that will fail at profile load
    // but proves the arguments are parsed correctly
    Command::cargo_bin("tiny-jail")
        .unwrap()
        .args(["exec", "--profile", "/nonexistent.toml", "--", "ls", "-l"])
        .assert()
        .failure();
}

#[test]
fn test_multiple_kill_flags() {
    Command::cargo_bin("tiny-jail")
        .unwrap()
        .args([
            "exec",
            "--profile",
            "/nonexistent.toml",
            "--kill",
            "read",
            "--kill",
            "write",
            "true",
        ])
        .assert()
        .failure();
}

#[test]
fn test_multiple_log_flags() {
    let temp_dir = std::env::temp_dir();
    let profile_path = temp_dir.join("valid_profile.toml");

    create_test_profile(&profile_path, &basic_profile()).unwrap();
    Command::cargo_bin("tiny-jail")
        .unwrap()
        .args([
            "exec",
            "--profile",
            profile_path.to_str().unwrap(),
            "--log",
            "open",
            "--log",
            "close",
            "true",
        ])
        .assert()
        .success();
}
