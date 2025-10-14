use std::fs::{self, File};
use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn test_regression_architecture_handling() {
    // 1. Create a temporary profile file that caused the original issue.
    let profile = r#"
    {
        "defaultAction": "SCMP_ACT_ALLOW",
        "architectures": [
            "SCMP_ARCH_X86_64"
        ],
        "syscalls": [
            {
                "names": [
                    "write"
                ],
                "action": "SCMP_ACT_KILL"
            }
        ]
    }
    "#;

    let profile_path = "./regression_test_profile.json";
    let mut file = File::create(profile_path).expect("Failed to create test profile");
    file.write_all(profile.as_bytes())
        .expect("Failed to write test profile");

    // 2. Run the tiny-jail binary with this profile.
    // We expect the `ls -l` command to be killed by SIGSYS when it tries to write.
    let output = Command::new("./target/debug/tiny-jail")
        .arg("exec")
        .arg("--profile")
        .arg(profile_path)
        .arg("--")
        .arg("/bin/ls")
        .arg("-l")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to execute tiny-jail");

    // 3. Assert that tiny-jail exits successfully and reports that the child was terminated.
    let status = output.status;
    assert!(
        status.success(),
        "tiny-jail process should exit successfully"
    );

    // Clean up the temporary profile file.
    fs::remove_file(profile_path).expect("Failed to remove test profile");
}
