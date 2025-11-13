## High-Level Architecture

```rust
// Core components I'd need

pub struct FuzzingConfig {
    pub timeout_secs: u64,
    pub max_iterations: usize,
    pub no_new_syscall_timeout_secs: u64,
    pub cli_flags: Vec<String>,  // From static analysis
    pub stdin_corpus: Vec<Vec<u8>>,  // Initial inputs
}

pub struct FuzzingState {
    pub discovered_syscalls: HashSet<String>,
    pub test_cases: Vec<Vec<u8>>,
    pub last_new_syscall_time: Instant,
}

pub async fn fuzzing_mode(
    command: &str,
    config: FuzzingConfig,
    profile: SeccompProfile,
) -> Result<SeccompProfile> {
    let mut state = FuzzingState::default();
    let mut current_filter = profile.clone();

    loop {
        // Generate new test input
        let input = generate_test_input(&state, &config);

        // Run with logging seccomp filter
        let new_syscalls = run_with_monitoring(
            command,
            &input,
            &current_filter,
        ).await?;

        // Update discovered syscalls
        if !new_syscalls.is_empty() {
            state.discovered_syscalls.extend(new_syscalls.iter().cloned());
            state.last_new_syscall_time = Instant::now();
            current_filter.add_syscalls(&new_syscalls);
        }

        // Check stopping conditions
        if should_stop_fuzzing(&state, &config) {
            break;
        }
    }

    Ok(current_filter)
}
```

## 1. Input Generation Strategy

```rust
pub struct InputMutator {
    cli_flags: Vec<String>,
    rng: ThreadRng,
}

impl InputMutator {
    pub fn generate_next(&mut self, corpus: &[Vec<u8>]) -> (Vec<String>, Vec<u8>) {
        let cli_args = self.generate_cli_args();
        let stdin = self.mutate_stdin(corpus);
        (cli_args, stdin)
    }

    fn generate_cli_args(&mut self) -> Vec<String> {
        match self.rng.gen_range(0..3) {
            // Pick random valid flags
            0 => self.random_flags(),
            // Combine flags that might trigger different paths
            1 => self.flag_combinations(),
            // Single flags that depend on other inputs
            _ => vec![self.rng.choose(&self.cli_flags).unwrap().clone()],
        }
    }

    fn mutate_stdin(&mut self, corpus: &[Vec<u8>]) -> Vec<u8> {
        if corpus.is_empty() {
            return vec![0u8; self.rng.gen_range(0..4096)];
        }

        let mut input = self.rng.choose(corpus).unwrap().clone();

        match self.rng.gen_range(0..4) {
            // Bitflip
            0 => {
                let idx = self.rng.gen_range(0..input.len());
                input[idx] ^= 1 << self.rng.gen_range(0..8);
            }
            // Insert bytes
            1 => {
                let idx = self.rng.gen_range(0..=input.len());
                input.insert(idx, self.rng.gen());
            }
            // Delete bytes
            2 => {
                if !input.is_empty() {
                    let idx = self.rng.gen_range(0..input.len());
                    input.remove(idx);
                }
            }
            // Random overwrite
            _ => {
                let idx = self.rng.gen_range(0..input.len());
                let len = self.rng.gen_range(1..=input.len() - idx);
                for i in 0..len {
                    input[idx + i] = self.rng.gen();
                }
            }
        }

        input
    }
}
```

## 2. Monitoring Integration

Since I already have dmesg monitoring, wrap it in a fuzzing context:

```rust
pub async fn run_with_monitoring(
    command: &str,
    args: &[String],
    stdin_data: &[u8],
    profile: &SeccompProfile,
) -> Result<Vec<String>> {
    let mut dmesg_reader = DmesgMonitor::new();
    let baseline_syscalls = dmesg_reader.current_syscalls().await;

    // Spawn child process
    let mut child = Command::new(command)
        .args(args)
        .stdin(Stdio::piped())
        .spawn()?;

    // Write stdin
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(stdin_data)?;
    }

    // Wait with timeout
    let timeout = Duration::from_secs(5);
    let start = Instant::now();

    loop {
        match child.try_wait() {
            Ok(Some(_status)) => break,
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(e) => return Err(e.into()),
        }
    }

    // Get new syscalls detected
    let new_syscalls = dmesg_reader
        .current_syscalls()
        .await
        .difference(&baseline_syscalls)
        .cloned()
        .collect();

    Ok(new_syscalls)
}
```

## 3. Fuzzing Loop with Feedback

```rust
pub struct Fuzzer {
    mutator: InputMutator,
    state: FuzzingState,
    config: FuzzingConfig,
}

impl Fuzzer {
    pub async fn run(&mut self, command: &str, profile: &SeccompProfile) -> Result<()> {
        let start = Instant::now();
        let mut iteration = 0;

        loop {
            // Check stopping conditions
            if iteration >= self.config.max_iterations {
                println!("Reached max iterations");
                break;
            }

            if start.elapsed() > Duration::from_secs(self.config.timeout_secs) {
                println!("Reached overall timeout");
                break;
            }

            if self.state.last_new_syscall_time.elapsed() 
                > Duration::from_secs(self.config.no_new_syscall_timeout_secs) {
                println!("No new syscalls for {}s", self.config.no_new_syscall_timeout_secs);
                break;
            }

            // Generate input
            let (args, stdin) = self.mutator.generate_next(&self.state.test_cases);

            // Run with monitoring
            let new_syscalls = run_with_monitoring(
                command,
                &args,
                &stdin,
                profile,
            ).await?;

            // Update state
            if !new_syscalls.is_empty() {
                println!("Found {} new syscalls", new_syscalls.len());
                self.state.discovered_syscalls.extend(new_syscalls);
                self.state.test_cases.push(stdin.clone());
                self.state.last_new_syscall_time = Instant::now();
            }

            if iteration % 100 == 0 {
                println!(
                    "[{}] Iteration: {}, Discovered: {}, Args: {:?}",
                    start.elapsed().as_secs(),
                    iteration,
                    self.state.discovered_syscalls.len(),
                    args
                );
            }

            iteration += 1;
        }

        println!("Fuzzing complete. Found {} syscalls", 
                 self.state.discovered_syscalls.len());

        Ok(())
    }
}
```

## 4. CLI Integration

```rust
#[derive(Parser)]
#[command(name = "seccomp-fuzzer")]
enum Command {
    Fuzz {
        #[arg(short)]
        command: String,

        #[arg(short)]
        profile: PathBuf,

        #[arg(long, default_value = "300")]
        timeout: u64,

        #[arg(long, default_value = "10")]
        no_new_syscall_timeout: u64,

        #[arg(short)]
        output: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    match Command::parse() {
        Command::Fuzz {
            command,
            profile,
            timeout,
            no_new_syscall_timeout,
            output,
        } => {
            let profile = SeccompProfile::load(&profile)?;
            let config = FuzzingConfig {
                timeout_secs: timeout,
                max_iterations: usize::MAX,
                no_new_syscall_timeout_secs: no_new_syscall_timeout,
                cli_flags: vec![],  // Populate from static analysis
                stdin_corpus: vec![b"".to_vec()],
            };

            let mut fuzzer = Fuzzer::new(config);
            fuzzer.run(&command, &profile).await?;

            if let Some(output_path) = output {
                fuzzer.generate_profile()?.save(&output_path)?;
            }
        }
    }
    Ok(())
}
```

## Key Differences from AFL++ Approach

- ✅ Already monitoring dmesg (no audit framework overhead)
- ✅ Already have seccomp action handling
- ⚠️ Missing: Static analysis for CLI flags (use KLEE or just parse --help output)
- ⚠️ Missing: Binary instrumentation for coverage feedback

## Recommendations

1. **For CLI flags**: Parse `command --help` output instead of full static analysis
2. **For coverage**: Consider using `strace` coverage or just rely on syscall discovery
3. **For efficiency**: Start with simple random mutations, add AFL-style tweaks if needed
4. **For quality**: Add corpus minimization when new syscalls are found
