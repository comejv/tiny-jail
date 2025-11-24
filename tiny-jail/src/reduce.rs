use std::fs;
use std::io::{self, Write};

use log2::*;

use crate::commands::filtered_exec;
use crate::error::JailError;
use crate::filters::{
    apply_profile, coalesce_rules_by_action, explode_syscalls, read_and_expand_profile, OciSeccomp,
    ProfileError,
};
use crate::io::CapturedOutput;
use crate::options::{FilteredExecOptions, ReduceProfileOptions};

// ============================================================================
// REDUCE PROFILE
// ============================================================================

pub fn reduce_profile(options: ReduceProfileOptions) -> Result<(), JailError> {
    info!("Loading profile: {}", options.input_profile);
    let mut profile: OciSeccomp =
        read_and_expand_profile(&options.input_profile).map_err(JailError::Profile)?;

    if profile.syscalls.is_none() {
        return Err(JailError::Profile(ProfileError::NoSyscallsInProfile));
    }

    explode_syscalls(&mut profile);
    let initial_count = profile.syscalls.as_ref().map_or(0, |v| v.len());
    info!("Initial profile has {} syscall rules", initial_count);

    // Capture golden output with full profile
    info!("\n=== Capturing Golden Output ===");
    info!("Running command with full profile...\n");

    let golden_output = capture_golden_output(&profile, &options.exec_cmd, options.env)?;

    if !options.batch {
        print!("\nDoes this output look correct? Continue reduction? [Y/n]: ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        if input.trim().eq_ignore_ascii_case("n") {
            return Err(JailError::GoldenOutputRejected);
        }
    }

    info!("\n=== Starting Reduction (exact match mode) ===");

    let mut total_tests = 0;

    partition_reduce(&mut profile, &options, &mut total_tests, Some(&golden_output))?;

    let final_count = profile.syscalls.as_ref().map_or(0, |v| v.len());
    let reduction = initial_count - final_count;
    let reduction_pct = (reduction as f64 / initial_count as f64) * 100.0;

    info!("\n=== Reduction Complete ===");
    info!("Initial syscalls: {}", initial_count);
    info!("Final syscalls:   {}", final_count);
    info!("Removed:          {} ({:.1}%)", reduction, reduction_pct);
    info!("Total tests:      {}", total_tests);

    coalesce_rules_by_action(&mut profile);
    let output_json = toml::to_string_pretty(&profile)?;
    fs::write(&options.output_file, output_json)?;

    info!("Minimized profile saved to: {}", options.output_file);

    Ok(())
}

fn capture_golden_output(
    profile: &OciSeccomp,
    exec_cmd: &[String],
    env: bool,
) -> Result<CapturedOutput, JailError> {
    let ctx = apply_profile(profile, None, None, false)?;
    let options = FilteredExecOptions {
        path: exec_cmd,
        pass_env: env,
        show_log: false,
        show_all: false,
        stats_output: &None,
        batch_mode: true,
        capture_output: true,
    };

    let output = filtered_exec(ctx, &options)?
        .ok_or_else(|| JailError::Exec("Failed to capture golden output".to_string()))?;

    Ok(output)
}

fn partition_reduce(
    profile: &mut OciSeccomp,
    options: &ReduceProfileOptions,
    total_tests: &mut usize,
    golden_output: Option<&CapturedOutput>,
) -> Result<Vec<String>, JailError> {
    let original = match profile.syscalls.as_ref() {
        Some(v) if !v.is_empty() => v.clone(),
        _ => return Ok(Vec::new()),
    };

    let mut working = original;
    let mut n = options.initial_chunks.max(2).min(working.len());
    let auto_mode = golden_output.is_some();

    if auto_mode {
        info!("Auto-comparison enabled (exact match)");
    }

    let original_count = working.len();

    loop {
        if n > working.len() {
            break;
        }

        let chunk_size = working.len().div_ceil(n);
        let mut made_progress = false;

        let progress = 100.0 * (1.0 - (working.len() as f64 / original_count as f64));
        info!(
            "\n--- Progress: {:.1}% ({} → {} rules, n={}) ---",
            progress,
            original_count,
            working.len(),
            n
        );

        let mut i = 0;
        while i < n {
            let start = i * chunk_size;
            let end = ((i + 1) * chunk_size).min(working.len());

            if start >= working.len() {
                break;
            }

            let mut candidate = Vec::with_capacity(working.len());
            candidate.extend_from_slice(&working[..start]);
            if end < working.len() {
                candidate.extend_from_slice(&working[end..]);
            }

            if candidate.is_empty() {
                i += 1;
                continue;
            }

            let removed_names: Vec<&str> = working[start..end]
                .iter()
                .flat_map(|r| r.names.iter().map(|s| s.as_str()))
                .collect();

            info!(
                "\n  Test {}: Removing chunk {}/{} [{}-{}] ({} rules)\n  Syscalls: {:?}",
                *total_tests + 1,
                i + 1,
                n,
                start,
                end,
                end - start,
                removed_names
            );

            let mut tmp_profile = profile.clone();
            tmp_profile.syscalls = Some(candidate.clone());

            *total_tests += 1;
            let passed = match test_profile_with_golden(&tmp_profile, options, golden_output) {
                Ok(passed) => passed,
                Err(JailError::Exec(e)) => {
                    warn!("Error during test: {}", e);
                    info!("Assuming test failure, continuing");
                    false
                }
                Err(e) => {
                    warn!("Error during test: {}", e);
                    return Err(e);
                }
            };

            if passed {
                info!("✓ PASS - removed {} rules", end - start);
                working = candidate;
                made_progress = true;
                n = 2;
                break;
            } else {
                info!("✗ FAIL - keeping rules");
                i += 1;
            }
        }

        if !made_progress {
            if n >= working.len() {
                break;
            }
            n = (n * 2).min(working.len());
            info!("  No progress, increasing granularity to n={}", n);
        }
    }

    profile.syscalls = Some(working.clone());

    let kept_names: Vec<String> = working
        .iter()
        .flat_map(|r| r.names.iter().cloned())
        .collect();

    info!(
        "\n✓ Partitioning complete: {} rules remaining",
        working.len()
    );

    Ok(kept_names)
}

fn test_profile_with_golden(
    profile: &OciSeccomp,
    options: &ReduceProfileOptions,
    golden_output: Option<&CapturedOutput>,
) -> Result<bool, JailError> {
    let ctx = apply_profile(profile, None, None, false)?;

    // Run with capture
    let exec_options = FilteredExecOptions {
        path: &options.exec_cmd,
        pass_env: options.env,
        show_log: false,
        show_all: false,
        stats_output: &None,
        batch_mode: true,
        capture_output: true,
    };
    let result = filtered_exec(ctx, &exec_options);

    let test_output = match result {
        Ok(Some(output)) => output,
        Ok(None) => {
            warn!("Failed to capture test output");
            return Ok(false);
        }
        Err(JailError::UnexpectedSignal) | Err(JailError::UnexpectedExit) => {
            // Expected failure for seccomp violations
            debug!("Test failed (seccomp violation)");
            return Ok(false);
        }
        Err(e) => {
            warn!("Unexpected error during test: {}", e);
            return Err(e);
        }
    };

    if let Some(golden) = golden_output {
        let sim_score = test_output.sim_score(golden, options.with_err);

        if sim_score == 1.0 {
            info!("      ✓ Output matches exactly!");
            return Ok(true);
        } else {
            if !options.batch {
                test_output.print_diff(golden, sim_score);

                print!("\nManual override? Accept anyway? [y/N]: ");
                io::stdout().flush().unwrap();

                let mut input = String::new();
                io::stdin().read_line(&mut input)?;

                return Ok(input.trim().eq_ignore_ascii_case("y"));
            }

            return Ok(false);
        }
    }

    // If no golden output
    if options.batch {
        Ok(true)
    } else {
        print!("\nDoes the behavior look correct? [y/N]: ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        Ok(input.trim().eq_ignore_ascii_case("y"))
    }
}
