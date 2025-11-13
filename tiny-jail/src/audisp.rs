use log2::*;
use macros::include_bytes_or;
use std::fs::File;
use std::io::Write;
use std::process::Command;

pub struct AudispGuard;

impl AudispGuard {
    /// Install the audisp plugin and return a guard that uninstalls on drop
    pub fn install() -> Result<Self, String> {
        install_plugin()?;
        Ok(AudispGuard)
    }
}

impl Drop for AudispGuard {
    fn drop(&mut self) {
        if let Err(e) = uninstall_plugin() {
            error!("Failed to uninstall audisp plugin: {}", e);
        }
    }
}

const PLUGIN_NAME: &str = "audisp-plugin";
const PLUGIN_PATH: &str = "/usr/local/sbin/";
const PLUGIN_CONF_PATH: &str = "/etc/audit/plugins.d/";

// Select the prebuilt blob for the current target.
const PLUGIN_BYTES: &[u8] =
    include_bytes_or!("target/release/audisp-plugin", "target/debug/audisp-plugin");

fn install_plugin() -> Result<(), String> {
    let output = Command::new("systemctl")
        .args(["is-active", "auditd"])
        .output()
        .map_err(|e| format!("Failed to check auditd status: {}", e))?;

    if !output.status.success() {
        return Err(
            "auditd service is not running. Start it with: sudo systemctl start auditd".to_string(),
        );
    }

    info!("Creating audit log file...");
    sudo_command(&["touch", "/tmp/audit.log"])?;
    sudo_command(&["chmod", "666", "/tmp/audit.log"])?;

    info!("Installing audisp plugin...");

    // Refresh sudo credentials
    if !refresh_sudo() {
        return Err("Failed to refresh sudo credentials".to_string());
    }

    // Write embedded plugin to a temp file
    let tmp_dir = std::env::temp_dir();
    let tmp_bin = tmp_dir.join(format!("{}.tmp", PLUGIN_NAME));
    {
        let mut f = File::create(&tmp_bin)
            .map_err(|e| format!("Failed to create temp file for plugin: {}", e))?;
        f.write_all(PLUGIN_BYTES)
            .map_err(|e| format!("Failed to write embedded plugin: {}", e))?;
        let _ = f.sync_all();
    }

    // Install plugin binary with correct permissions atomically
    info!("Installing audisp plugin binary...");
    let dest_path = format!("{}{}", PLUGIN_PATH, PLUGIN_NAME);
    sudo_command(&[
        "install",
        "-m",
        "0755",
        tmp_bin.to_str().unwrap(),
        &dest_path,
    ])?;
    let _ = std::fs::remove_file(&tmp_bin);

    // Write the config file atomically with perms
    info!("Writing audisp plugin config...");
    let conf_content = format!(
        "active = yes\ndirection = out\npath = {}{}\ntype = always\nformat = string\n",
        PLUGIN_PATH, PLUGIN_NAME
    );
    let tmp_conf = tmp_dir.join(format!("{}.conf.tmp", PLUGIN_NAME));
    std::fs::write(&tmp_conf, conf_content.as_bytes())
        .map_err(|e| format!("Failed to write temp config: {}", e))?;

    let conf_file_path = format!("{}{}.conf", PLUGIN_CONF_PATH, PLUGIN_NAME);
    sudo_command(&[
        "install",
        "-m",
        "0644",
        tmp_conf.to_str().unwrap(),
        &conf_file_path,
    ])?;
    let _ = std::fs::remove_file(&tmp_conf);

    // Reload auditd configuration
    info!("Reloading auditd configuration...");
    let output = Command::new("sudo")
        .args(["systemctl", "reload", "auditd.service"])
        .output()
        .map_err(|e| format!("Failed to execute systemctl reload: {}", e))?;

    let reloaded = output.status.success();

    if !reloaded {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("systemctl reload auditd.service failed: {}", stderr.trim());
        sudo_command(&["pkill", "-HUP", "auditd"])?;
    }

    info!("Audisp plugin installed successfully.");
    Ok(())
}

fn uninstall_plugin() -> Result<(), String> {
    info!("Uninstalling audisp plugin...");

    if !refresh_sudo() {
        return Err("Failed to refresh sudo credentials".to_string());
    }

    info!("Removing audisp plugin config and binary...");
    let conf_file_path = format!("{}{}.conf", PLUGIN_CONF_PATH, PLUGIN_NAME);
    sudo_command(&["rm", "-f", &conf_file_path])?;
    let plugin_path = format!("{}{}", PLUGIN_PATH, PLUGIN_NAME);
    sudo_command(&["rm", "-f", &plugin_path])?;

    info!("Reloading auditd configuration...");
    let output = Command::new("sudo")
        .args(["systemctl", "reload", "auditd.service"])
        .output()
        .map_err(|e| format!("Failed to execute systemctl reload: {}", e))?;

    let reloaded = output.status.success();

    if !reloaded {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("systemctl reload auditd.service failed: {}", stderr.trim());
        sudo_command(&["pkill", "-HUP", "auditd"])?;
    }

    info!("Audisp plugin uninstalled successfully.");
    Ok(())
}

fn refresh_sudo() -> bool {
    Command::new("sudo")
        .arg("-v")
        .status()
        .is_ok_and(|s| s.success())
}

fn sudo_command(args: &[&str]) -> Result<(), String> {
    let status = Command::new("sudo")
        .args(args)
        .status()
        .map_err(|e| format!("Failed to execute sudo command: {}", e))?;

    if !status.success() {
        Err(format!("Sudo command failed: {:?}", args))
    } else {
        Ok(())
    }
}
