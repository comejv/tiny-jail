use std::path::PathBuf;

use clap::{ArgAction, Args, Parser, Subcommand};
use log2::*;
use thiserror::Error;

use tiny_jail::actions::Action;
use tiny_jail::audisp::AudispGuard;
use tiny_jail::commands;
use tiny_jail::error::JailError;
use tiny_jail::filters::{self, ProfileError};

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Profile loading failed: {0}")]
    Profile(#[from] ProfileError),
    #[error("Command execution failed: {0}")]
    Command(#[from] JailError),
    #[error("{0}")]
    Message(String),
    #[error("Audisp control failed: {0}")]
    Audisp(String),
}

#[derive(Parser, Debug)]
#[command(author, version)]
#[command(propagate_version = true)]
struct Cli {
    /// Set log level to debug (default: info).
    #[arg(short = 'd', long)]
    debug: bool,

    /// Allow executable to see the environment variables.
    #[arg(short = 'e', long)]
    env: bool,

    /// Batch mode
    #[arg(short = 'b', long)]
    batch: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Fuzz the given executable to generate a new profile.
    ///
    /// This command will run the executable with various inputs to
    /// create a comprehensive profile of its behavior.
    Fuzz(FuzzArgs),

    /// Execute a program with optional profiling/monitoring.
    ///
    /// This is the default mode if no other subcommand is specified.
    Exec(ExecArgs),

    /// Reduce a profile to its minimum set of required syscalls.
    ///
    /// Uses delta debugging and greedy deletion strategies to efficiently
    /// minimize the profile while maintaining correct behavior.
    Reduce(ReduceArgs),
}

#[derive(Args, Debug)]
struct FuzzArgs {
    /// Output file for the generated profile.
    ///
    /// If not specified, a default filename will be used (e.g., 'fuzz_profile.json').
    #[arg(short = 'o', long, value_name = "OUTPUT_FILE")]
    output: Option<String>,

    /// Number of fuzzing iterations.
    ///
    /// Specifies how many times the executable should be fuzzed.
    #[arg(short = 'i', long, default_value_t = 100, value_name = "COUNT")]
    iterations: u32,

    /// Number of fuzzing threads.
    ///
    /// Controls how many parallel threads will be used for fuzzing.
    #[arg(short = 't', long, default_value_t = 1, value_name = "COUNT")]
    threads: u32,

    /// The executable command to run and its arguments.
    ///
    /// To pass arguments to the executable that start with a hyphen, you must use `--`
    /// to separate the arguments for tiny-jail from the arguments for the executable.
    ///
    /// For example: `tiny-jail fuzz -i 10 -- my-program --with-arg`
    #[arg(required = true, name = "EXECUTABLE_AND_ARGS", trailing_var_arg = true)]
    exec: Vec<String>,
}

#[derive(Args, Debug)]
struct ExecArgs {
    /// Path to the profile file.
    ///
    /// This file is used for loading existing profiles or for generating new ones.
    #[arg(short = 'p', long, value_name = "FILE")]
    profile: Option<String>,

    /// Default action for syscalls not specified in the profile.
    ///
    /// This will override the default action in the profile.
    #[arg(short = 'd', long, value_enum)]
    default_action: Option<Action>,

    /// Default errno return value for SCMP_ACT_ERRNO actions.
    ///
    /// This will override the errno_ret in the profile.
    #[arg(short = 'e', long, value_name = "ERRNO_VALUE")]
    default_errno: Option<u32>,

    /// Kill processes that call the specified syscall name.
    ///
    /// Will be enforced in addition to the specified profile.
    /// Can be specified multiple times.
    ///
    /// For example: --kill write --kill read
    #[arg(long, value_name = "SYSCALL_NAME", action = ArgAction::Append)]
    kill: Vec<String>,

    /// Log processes that call the specified syscall name.
    ///
    /// Will be enforced in addition to the specified profile.
    /// Can be specified multiple times.
    ///
    /// For example: --log write --log read
    #[arg(long, value_name = "SYSCALL_NAME", action = ArgAction::Append)]
    log: Vec<String>,

    /// Prints the logged syscalls to the console.
    ///
    /// Requires admin privileges.
    #[arg(short = 'w', long = "watch-logs")]
    show_log: bool,

    /// Change all SCMP_ACT_ALLOW rules to SCMP_ACT_LOG and show the logs in the output.
    ///
    /// Requires admin privileges.
    #[arg(short = 'W', long = "watch-all-logs")]
    show_all: bool,

    /// Output file for detailed statistics.
    #[arg(long = "stats-output", value_name = "FILE")]
    stats_output: Option<PathBuf>,

    /// The executable command to run and its arguments.
    ///
    /// To pass arguments to the executable that start with a hyphen, you must use `--`
    /// to separate the arguments for tiny-jail from the arguments for the executable.
    ///
    /// For example: `tiny-jail exec --profile p.json -- ls -l`
    #[arg(required = true, name = "EXECUTABLE_AND_ARGS", trailing_var_arg = true)]
    exec: Vec<String>,
}

#[derive(Args, Debug)]
struct ReduceArgs {
    /// Input profile file to minimize.
    #[arg(short = 'p', long, value_name = "PROFILE_FILE", required = true)]
    profile: String,

    /// Output file for the minimized profile.
    ///
    /// If not specified, will use '<input>_minimized.toml'.
    #[arg(short = 'o', long, value_name = "OUTPUT_FILE")]
    output: Option<String>,

    /// Initial chunk size for partitioning (default: 2, meaning split in half).
    ///
    /// Smaller values = more aggressive initial reduction but more iterations.
    #[arg(short = 'c', long, default_value_t = 2, value_name = "SIZE")]
    initial_chunks: usize,

    /// Include stderr in the comparison.
    ///
    /// This will increase the number of tests performed.
    #[arg(short = 'e', long = "with-err")]
    with_err: bool,

    /// The executable command to run and its arguments.
    ///
    /// This command will be tested after each reduction to verify behavior.
    ///
    /// To pass arguments to the executable that start with a hyphen, you must use `--`
    /// to separate the arguments for tiny-jail from the arguments for the executable.
    ///
    /// For example: `tiny-jail reduce -p profile.toml -- my-program --with-arg`
    #[arg(required = true, name = "EXECUTABLE_AND_ARGS", trailing_var_arg = true)]
    exec: Vec<String>,
}

fn main() {
    if let Err(e) = run() {
        error!("Error: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<(), AppError> {
    let cli = Cli::parse();

    let _log2 = log2::stdout()
        .module(cli.debug)
        .level(if cli.debug {
            "debug"
        } else if cli.batch {
            "error"
        } else {
            "info"
        })
        .start();

    match cli.command {
        Commands::Exec(exec_args) => {
            let _guard = if exec_args.show_log || exec_args.show_all {
                if !cli.batch {
                    warn!("Getting log from auditd requires sudo, do you want to continue? [y/N]");
                    let mut input = String::new();
                    std::io::stdin()
                        .read_line(&mut input)
                        .map_err(|e| AppError::Audisp(format!("Failed to read input: {}", e)))?;
                    if !input.trim().eq_ignore_ascii_case("y") {
                        return Ok(());
                    }
                }
                Some(AudispGuard::install().map_err(AppError::Audisp)?)
            } else {
                None
            };

            let filter = filters::load_profile(
                exec_args.profile,
                exec_args.default_action,
                exec_args.default_errno,
                &exec_args.kill,
                &exec_args.log,
                exec_args.show_all,
            )?;

            info!("Running the given command...");
            debug!("Command: {:?}", exec_args.exec);
            let options = tiny_jail::options::FilteredExecOptions {
                path: exec_args.exec.as_ref(),
                pass_env: cli.env,
                show_log: exec_args.show_log,
                show_all: exec_args.show_all,
                stats_output: &exec_args.stats_output,
                batch_mode: cli.batch,
                capture_output: false,
            };
            commands::filtered_exec(filter, &options)?;
            info!("Execution finished.");
        }
        Commands::Fuzz(fuzz_args) => {
            info!("Fuzzing the given command...");
            debug!("Command: {:?}", fuzz_args.exec);
            commands::fuzz_exec(fuzz_args.exec, cli.env)?;
            info!("Fuzzing finished.");
        }
        Commands::Reduce(reduce_args) => {
            info!("Reducing profile to minimum...");
            debug!("Input profile: {}", reduce_args.profile);
            debug!("Command: {:?}", reduce_args.exec);

            let output_file = reduce_args.output.clone().unwrap_or_else(|| {
                let input = &reduce_args.profile;
                if let Some(stem) = input.strip_suffix(".toml") {
                    format!("{}_minimized.toml", stem)
                } else {
                    format!("{}_minimized.toml", input)
                }
            });

            let options = tiny_jail::options::ReduceProfileOptions {
                input_profile: reduce_args.profile,
                output_file,
                exec_cmd: reduce_args.exec,
                env: cli.env,
                batch: cli.batch,
                initial_chunks: reduce_args.initial_chunks,
                with_err: reduce_args.with_err,
            };
            commands::reduce_profile(options)?;
            info!("Profile reduction finished.");
        }
    }

    Ok(())
}
