use clap::{ArgAction, Args, Parser, Subcommand};
use log2::{debug, error, info};
use thiserror::Error;

use tiny_jail::actions::Action;
use tiny_jail::commands::{filtered_exec, fuzz_exec, CommandError};
use tiny_jail::filters::{load_profile, ProfileError};
use tiny_jail::tui::TuiError;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Profile loading failed: {0}")]
    Profile(#[from] ProfileError),
    #[error("Command execution failed: {0}")]
    Command(#[from] CommandError),
    #[error("TUI error: {0}")]
    Tui(#[from] TuiError),
    #[error("{0}")]
    Message(String),
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

    /// Enable TUI mode (interactive terminal interface).
    #[arg(long)]
    tui: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Fuzz the given executable to generate a new profile.
    Fuzz(FuzzArgs),

    /// Execute a program with optional profiling/monitoring.
    Exec(ExecArgs),

    /// Explore abstract syscalls in a TUI.
    Explore(ExploreArgs),
}

#[derive(Args, Debug)]
struct ExploreArgs {}

#[derive(Args, Debug)]
struct FuzzArgs {
    /// Output file for the generated profile.
    #[arg(short = 'o', long, value_name = "OUTPUT_FILE")]
    output: Option<String>,

    /// Number of fuzzing iterations.
    #[arg(short = 'i', long, default_value_t = 100, value_name = "COUNT")]
    iterations: u32,

    /// Number of fuzzing threads.
    #[arg(short = 't', long, default_value_t = 1, value_name = "COUNT")]
    threads: u32,

    /// The executable command to run and its arguments.
    #[arg(required = true, name = "EXECUTABLE_AND_ARGS", trailing_var_arg = true)]
    exec: Vec<String>,
}

#[derive(Args, Debug)]
struct ExecArgs {
    /// Path to the profile file.
    #[arg(long, value_name = "FILE")]
    profile: Option<String>,

    /// Default action for syscalls not specified in the profile.
    #[arg(short = 'd', long, value_enum)]
    default_action: Option<Action>,

    /// Default errno return value for SCMP_ACT_ERRNO actions.
    #[arg(short = 'e', long, value_name = "ERRNO_VALUE")]
    default_errno: Option<u32>,

    /// Kill processes that call the specified syscall name.
    #[arg(long, value_name = "SYSCALL_NAME", action = ArgAction::Append)]
    kill: Vec<String>,

    /// Log processes that call the specified syscall name.
    #[arg(long, value_name = "SYSCALL_NAME", action = ArgAction::Append)]
    log: Vec<String>,

    /// Prints the logged syscalls to the console.
    #[arg(short = 'w', long = "watch-logs")]
    show_log: bool,

    /// Change all SCMP_ACT_ALLOW rules to SCMP_ACT_LOG and show the logs.
    #[arg(short = 'W', long = "watch-all-logs")]
    show_all: bool,

    /// The executable command to run and its arguments.
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

    // Don't initialize logger if TUI mode is enabled
    let _log2 = if !cli.tui {
        Some(
            log2::stdout()
                .module(cli.debug)
                .level(if cli.debug { "debug" } else { "info" })
                .start(),
        )
    } else {
        None
    };

    match cli.command {
        Commands::Exec(exec_args) => {
            let filter = load_profile(
                exec_args.profile,
                exec_args.default_action,
                exec_args.default_errno,
                &exec_args.kill,
                &exec_args.log,
                exec_args.show_all,
            )?;

            // Determine if we should use TUI mode
            let use_tui = cli.tui || exec_args.show_log || exec_args.show_all;

            if use_tui {
                // Run with TUI monitoring
                tiny_jail::tui::run_exec_with_tui(
                    filter,
                    exec_args.exec,
                    cli.env,
                    exec_args.show_all,
                )?;
            } else {
                info!("Running the given command...");
                debug!("Command: {:?}", exec_args.exec);
                filtered_exec(filter, exec_args.exec, cli.env, false, false)?;
                info!("Execution finished.");
            }
        }
        Commands::Fuzz(fuzz_args) => {
            if cli.tui {
                return Err(AppError::Message(
                    "TUI mode not yet implemented for fuzz command".to_string(),
                ));
            }
            info!("Fuzzing the given command...");
            debug!("Command: {:?}", fuzz_args.exec);
            fuzz_exec(fuzz_args.exec, cli.env)?;
            info!("Fuzzing finished.");
        }
        Commands::Explore(_explore_args) => {
            tiny_jail::tui::run_explore_tui()?;
        }
    }

    Ok(())
}
