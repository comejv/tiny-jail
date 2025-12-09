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
