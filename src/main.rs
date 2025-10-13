use clap::{ArgAction, Args, Parser, Subcommand};
use log2::*;
use thiserror::Error;

use tiny_jail::actions::Action;
use tiny_jail::commands::{filtered_exec, fuzz_exec, CommandError};
use tiny_jail::filters::{load_profile, ProfileError};

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Profile loading failed: {0}")]
    Profile(#[from] ProfileError),
    #[error("Command execution failed: {0}")]
    Command(#[from] CommandError),
    #[error("{0}")]
    Message(String),
}

#[derive(Parser, Debug)]
#[command(author, version)]
#[command(propagate_version = true)]
struct Cli {
    /// Path to the profile file.
    ///
    /// This file is used for loading existing profiles or for generating new ones.
    #[arg(long, value_name = "FILE")]
    profile: Option<String>,

    /// Default action for syscalls not specified in the profile.
    /// This will override the default action in the profile.
    #[arg(short = 'd', long, value_enum)]
    default_action: Option<Action>,

    /// Default errno return value for SCMP_ACT_ERRNO actions.
    /// This will override the errno_ret in the profile.
    #[arg(long, value_name = "ERRNO_VALUE")]
    default_errno: Option<u32>,

    /// Kill processes that call the specified syscall name.
    ///
    /// Will be enforced in addition to the specified profile.
    /// Can be specified multiple times.
    /// For example: -k write -k read
    #[arg(short = 'k', long, value_name = "SYSCALL_NAME", action = ArgAction::Append)]
    kill: Vec<String>,

    /// Log processes that call the specified syscall name.
    ///
    /// Will be enforced in addition to the specified profile.
    /// Can be specified multiple times.
    /// For example: -l write -l read
    #[arg(short = 'l', long, value_name = "SYSCALL_NAME", action = ArgAction::Append)]
    log: Vec<String>,

    /// Set log level to debug (default: info).
    #[arg(short = 'D', long)]
    debug: bool,

    /// Allow executable to see the environment variables.
    #[arg(short = 'e', long)]
    env: bool,

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
    /// All arguments after this are treated as arguments for the executable.
    #[arg(
        required = true,
        name = "EXECUTABLE_AND_ARGS",
        trailing_var_arg = true,
        allow_hyphen_values = true
    )]
    exec: Vec<String>,
}

#[derive(Args, Debug)]
struct ExecArgs {
    /// The executable command to run and its arguments.
    ///
    /// All arguments after this are treated as arguments for the executable.
    #[arg(
        required = true,
        name = "EXECUTABLE_AND_ARGS",
        trailing_var_arg = true,
        allow_hyphen_values = true
    )]
    exec: Vec<String>,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<(), AppError> {
    let cli = Cli::parse();

    let _log2 = log2::stdout()
        .module(cli.debug)
        .level(if cli.debug { "debug" } else { "info" })
        .start();

    let filter = if let Some(profile_path) = cli.profile {
        load_profile(
            profile_path,
            cli.default_action,
            cli.default_errno,
            &cli.kill,
            &cli.log,
        )?
    } else {
        return Err(AppError::Message("No profile provided".to_string()));
    };

    match cli.command {
        Commands::Exec(exec_args) => {
            info!("Executing command: {:?}", exec_args.exec);
            filtered_exec(filter, exec_args.exec)?;
            info!("Execution finished.");
        }
        Commands::Fuzz(fuzz_args) => {
            info!("Fuzzing command: {:?}", fuzz_args.exec);
            fuzz_exec(fuzz_args.exec)?;
            info!("Fuzzing finished.");
        }
    }

    Ok(())
}
