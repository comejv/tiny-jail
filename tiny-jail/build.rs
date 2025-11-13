use std::fs;
use std::process::Command;

fn main() {
    // Minify abstract rules json with jq
    let output = Command::new("jq")
        .args(["-r", "tostring", "data/abstract_rules.json"])
        .output()
        .expect("Failed to run jq");

    if !output.status.success() {
        panic!(
            "jq command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fs::write("data/abstract_rules.min.json", output.stdout)
        .expect("Failed to write minified json");

    // Try to detect libseccomp version from pkg-config
    if let Ok(output) = Command::new("pkg-config")
        .args(["--modversion", "libseccomp"])
        .output()
    {
        if let Ok(version) = String::from_utf8(output.stdout) {
            let version = version.trim();
            if let Some((major, rest)) = version.split_once('.') {
                if let Some((minor, _)) = rest.split_once('.') {
                    if let (Ok(maj), Ok(min)) = (major.parse::<u32>(), minor.parse::<u32>()) {
                        if maj > 2 || (maj == 2 && min >= 6) {
                            println!("cargo:rustc-cfg=libseccomp_2_6");
                        }
                    }
                }
            }
        }
    }
}
