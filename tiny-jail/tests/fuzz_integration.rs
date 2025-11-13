use assert_cmd::{cargo_bin, Command};
use predicates::prelude::*;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

// ===========================================================================
// Helper Functions
// ===========================================================================

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

// ===========================================================================
// Fuzz Subcommand Tests
// ===========================================================================

#[test]
fn test_fuzz_help() {
    Command::new(cargo_bin!())
        .args(["fuzz", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Fuzz the given executable to generate a new profile.",
        ));
}

#[test]
fn test_fuzz_missing_executable() {
    Command::new(cargo_bin!()).arg("fuzz").assert().failure();
}

#[test]
fn test_fuzz_with_output_file() {
    let temp_dir = std::env::temp_dir();
    let profile_path = temp_dir.join("fuzz_profile.toml");

    Command::new(cargo_bin!())
        .args([
            "fuzz",
            "--output",
            profile_path.to_str().unwrap(),
            "--",
            "true",
        ])
        .assert()
        .failure();

    let _ = fs::remove_file(profile_path);
}
