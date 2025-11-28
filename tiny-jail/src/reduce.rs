use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Write};

use log2::*;

use crate::error::JailError;
use crate::exec::filtered_exec;
use crate::filters::{
    apply_profile, coalesce_rules_by_action, explode_syscalls, read_and_expand_profile, OciSeccomp,
    ProfileError,
};
use crate::io::CapturedOutput;
use crate::options::{FilteredExecOptions, ReduceProfileOptions};

#[allow(dead_code)]
#[derive(Deserialize)]
struct DetailedStats {
    by_syscall: HashMap<String, u64>,
    total_runs: u64,
    tested_binaries: HashSet<String>,
}

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

    // Load stats if available
    let stats = options
        .stats_file
        .as_ref()
        .and_then(|path| match fs::read_to_string(path) {
            Ok(content) => match serde_json::from_str::<DetailedStats>(&content) {
                Ok(s) => {
                    info!("Loaded syscall usage statistics from {}", path);
                    Some(s)
                }
                Err(e) => {
                    warn!("Failed to parse stats file: {}", e);
                    None
                }
            },
            Err(e) => {
                warn!("Failed to read stats file: {}", e);
                None
            }
        });

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

    info!("\n=== Starting Reduction ===");
    let mut total_tests = 0;

    // Phase 1: Partition-based reduction (delta debugging)
    info!("\n--- Phase 1: Partition Reduction ---");
    partition_reduce(
        &mut profile,
        &options,
        &mut total_tests,
        Some(&golden_output),
        stats.as_ref(),
    )?;

    let after_partition = profile.syscalls.as_ref().map_or(0, |v| v.len());

    // Phase 2: Greedy one-by-one reduction
    if options.greedy_pass {
        info!("\n--- Phase 2: Greedy One-by-One Reduction ---");
        greedy_reduce(
            &mut profile,
            &options,
            &mut total_tests,
            &golden_output,
            stats.as_ref(),
        )?;
    }

    let final_count = profile.syscalls.as_ref().map_or(0, |v| v.len());
    let reduction = initial_count - final_count;
    let reduction_pct = (reduction as f64 / initial_count as f64) * 100.0;

    info!("\n=== Reduction Complete ===");
    info!("Initial syscalls:       {}", initial_count);
    if options.greedy_pass {
        info!("After partition phase:  {}", after_partition);
    }
    info!("Final syscalls:         {}", final_count);
    info!(
        "Removed:                {} ({:.1}%)",
        reduction, reduction_pct
    );
    info!("Total tests:            {}", total_tests);

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
    stats: Option<&DetailedStats>,
) -> Result<Vec<String>, JailError> {
    let original = match profile.syscalls.as_ref() {
        Some(v) if !v.is_empty() => v.clone(),
        _ => return Ok(Vec::new()),
    };

    let mut working = original;

    // Sort by usage frequency if stats available (WDD)
    if let Some(stats) = stats {
        info!("Applying Weighted Delta Debugging - sorting by usage frequency");
        working.sort_by_cached_key(|rule| {
            let total_calls: u64 = rule
                .names
                .iter()
                .filter_map(|name| stats.by_syscall.get(name.as_str()))
                .sum();
            // Sort ascending: least-used syscalls first
            total_calls
        });

        // Log top candidates for removal
        let candidates: Vec<_> = working
            .iter()
            .take(5)
            .map(|r| {
                let total: u64 = r
                    .names
                    .iter()
                    .filter_map(|n| stats.by_syscall.get(n.as_str()))
                    .sum();
                (r.names.join(","), total)
            })
            .collect();
        info!("Top removal candidates: {:?}", candidates);
    }

    let mut n = options.initial_chunks.max(2).min(working.len());
    let original_count = working.len();
    let mut iteration = 0;

    loop {
        iteration += 1;
        if n > working.len() {
            break;
        }

        let chunk_size = working.len().div_ceil(n);
        let mut made_progress = false;

        let progress = 100.0 * (1.0 - (working.len() as f64 / original_count as f64));
        info!(
            "\nIteration {}: {:.1}% complete ({}/{} rules, splitting into {} chunks)",
            iteration,
            progress,
            working.len(),
            original_count,
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

            // Show usage stats for removed chunk if available
            let usage_info = if let Some(stats) = stats {
                let total: u64 = removed_names
                    .iter()
                    .filter_map(|name| stats.by_syscall.get(*name))
                    .sum();
                format!(" (usage: {})", total)
            } else {
                String::new()
            };

            info!(
                "  Test {}: Chunk {}/{} - removing {} rules{}\n  Syscalls: {:?}",
                *total_tests + 1,
                i + 1,
                n,
                end - start,
                usage_info,
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
                info!("  ✓ PASS - removed {} rules", end - start);
                working = candidate;
                made_progress = true;
                // Reset to aggressive splitting after success
                n = options.initial_chunks.max(2).min(working.len());
                break;
            } else {
                info!("  ✗ FAIL - keeping rules");
                i += 1;
            }
        }

        if !made_progress {
            if n >= working.len() {
                break;
            }
            let old_n = n;
            n = (n * 2).min(working.len());
            info!(
                "  No progress at granularity {}, increasing to {}",
                old_n, n
            );
        }
    }

    profile.syscalls = Some(working.clone());

    let kept_names: Vec<String> = working
        .iter()
        .flat_map(|r| r.names.iter().cloned())
        .collect();

    info!(
        "\n✓ Partition phase complete: {} rules remaining",
        working.len()
    );

    Ok(kept_names)
}

fn greedy_reduce(
    profile: &mut OciSeccomp,
    options: &ReduceProfileOptions,
    total_tests: &mut usize,
    golden_output: &CapturedOutput,
    stats: Option<&DetailedStats>,
) -> Result<(), JailError> {
    let mut working = match profile.syscalls.as_ref() {
        Some(v) if !v.is_empty() => v.clone(),
        _ => return Ok(()),
    };

    // Sort by usage if stats available
    if let Some(stats) = stats {
        working.sort_by_cached_key(|rule| {
            let total_calls: u64 = rule
                .names
                .iter()
                .filter_map(|name| stats.by_syscall.get(name.as_str()))
                .sum();
            total_calls
        });
    }

    let original_count = working.len();
    let mut removed_count = 0;
    let mut i = 0;

    info!("Testing removal of individual rules (least-used first)...");

    while i < working.len() {
        let rule = &working[i];
        let rule_names: Vec<&str> = rule.names.iter().map(|s| s.as_str()).collect();

        let usage_info = if let Some(stats) = stats {
            let total: u64 = rule
                .names
                .iter()
                .filter_map(|name| stats.by_syscall.get(name.as_str()))
                .sum();
            format!(" [usage: {}]", total)
        } else {
            String::new()
        };

        info!(
            "  Test {}: Trying to remove rule {}/{}: {:?}{}",
            *total_tests + 1,
            i + 1,
            working.len(),
            rule_names,
            usage_info
        );

        let mut candidate = working.clone();
        candidate.remove(i);

        let mut tmp_profile = profile.clone();
        tmp_profile.syscalls = Some(candidate.clone());

        *total_tests += 1;
        let passed = match test_profile_with_golden(&tmp_profile, options, Some(golden_output)) {
            Ok(passed) => passed,
            Err(JailError::Exec(e)) => {
                warn!("Error during test: {}", e);
                false
            }
            Err(e) => {
                warn!("Error during test: {}", e);
                return Err(e);
            }
        };

        if passed {
            info!("    ✓ PASS - removed");
            working = candidate;
            removed_count += 1;
            // Don't increment i, check the next rule at this position
        } else {
            info!("    ✗ FAIL - keeping");
            i += 1;
        }

        if (i + removed_count) % 10 == 0 {
            let progress = 100.0 * ((i + removed_count) as f64 / original_count as f64);
            info!(
                "  Progress: {:.1}% ({}/{} rules checked, {} removed so far)",
                progress,
                i + removed_count,
                original_count,
                removed_count
            );
        }
    }

    profile.syscalls = Some(working);

    info!(
        "\n✓ Greedy phase complete: removed {} additional rules",
        removed_count
    );

    Ok(())
}

fn test_profile_with_golden(
    profile: &OciSeccomp,
    options: &ReduceProfileOptions,
    golden_output: Option<&CapturedOutput>,
) -> Result<bool, JailError> {
    let ctx = apply_profile(profile, None, None, false)?;

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
            debug!("Test failed (seccomp violation)");
            return Ok(false);
        }
        Err(e) => {
            warn!("Unexpected error during test: {}", e);
            return Err(e);
        }
    };

    if let Some(golden) = golden_output {
        let sim_score =
            test_output.sim_score_with_config(golden, options.with_err, &options.similarity_config);

        if sim_score >= 0.95 {
            // Allow some tolerance
            debug!("Output matches (score: {:.3})", sim_score);
            return Ok(true);
        } else if sim_score <= 0.5 {
            // Too much difference
            debug!("Output differs (score: {:.3})", sim_score);
            return Ok(false);
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
