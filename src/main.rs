use clap::{ArgAction, Args, Parser, Subcommand};
use log2::*;
use std::error::Error;

mod commands;
mod profile;

use crate::commands::{filtered_exec, fuzz_exec};
use crate::profile::load_profile;

#[derive(Parser, Debug)]
#[command(author, version)]
#[command(propagate_version = true)]
struct Cli {
    /// Path to the profile file.
    ///
    /// This file is used for loading existing profiles or for generating new ones.
    #[arg(long, value_name = "FILE")]
    profile: Option<String>,

    /// Use OCI profile format.
    ///
    /// When this flag is set, the tool will interpret and generate profiles
    /// using the OCI (Open Container Initiative) format.
    #[arg(long)]
    oci: bool,

    /// Kill processes with the specified signal.
    ///
    /// Will be enforced in addition to the specified profile.
    /// Can be specified multiple times to send different signals.
    /// For example: `-k 9 -k 15`
    #[arg(short = 'k', long, value_name = "SIGNAL", action = ArgAction::Append)]
    kill: Vec<i32>,

    /// Log processes with the specified signal.
    ///
    /// Will be enforced in addition to the specified profile.
    /// Similar to --kill, this can be specified multiple times.
    #[arg(short = 'l', long, value_name = "SIGNAL", action = ArgAction::Append)]
    log: Vec<i32>,

    /// Set log level to debug (default: info).
    #[arg(short = 'd', long)]
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

fn run() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    let _log2 = log2::stdout()
        .module(cli.debug)
        .level(if cli.debug { "debug" } else { "info" })
        .start();

    let filter = if let Some(profile_path) = cli.profile {
        load_profile(profile_path, cli.oci)?
    } else {
        return Err("No profile provided".into());
    };

    match cli.command {
        Commands::Exec(exec_args) => {
            debug!("exec args: {:?}", exec_args.exec);
            filtered_exec(filter, exec_args.exec)?;
            println!("Exec success");
        }
        Commands::Fuzz(fuzz_args) => {
            debug!("fuzz args: {:?}", fuzz_args.exec);
            fuzz_exec(fuzz_args.exec)?;
            println!("fuzzing success");
        }
    }

    Ok(())
}
