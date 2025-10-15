use std::process::Command;

fn main() {
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
