# Goals

## Project Scope

This project aims to provide a wrapper around the seccomp-bpf library that allows for the creation of a sandboxed environment for a process.
The core mechanism used will be **SECCOMP_MODE_FILTER**, which leverages the Berkeley Packet Filter (BPF) technology.
The sandboxing rules are to be easily configurable for the user, without the need to know details about system calls.

The project will be structured as follows:

- The `src` directory will contain the source code for the project.
- The `notes` directory will contain notes and documentation for the project.
- The `tools` directory will contain tools and utilities for the project.

The project will be developed using the **Rust programming language**, leveraging production-ready tools such as the `seccompiler` crate.

The project will be aimed at **X86_64 Linux systems** and tested on CachyOS.

### Minimum Viable Product

- [x] calling the seccomp-bpf library (or a high-level wrapper like `libseccomp` or `seccompiler`) to create a sandboxed environment
- [x] handling of the command line arguments
    - [x] setting the sandboxing rules (e.g., specifying architecture as `SCMP_ARCH_X86_64`)
- [x] parsing sandboxing rules from a file
    - [x] defining the format of the file, preferably as an **OCI-compliant JSON structure**
    - [x] parsing the file to define the required list of system calls (`syscalls`) and a mandatory `defaultAction`
- [x] "complain mode" to log violations of the sandboxing rules
- [x] "enforce mode" to kill the process if a violation is detected

### Additional Features

- [ ] Handling of **abstract syscall groups** in the policy.
- [ ] Implementing a **Hybrid Coverage-Guided Policy Generation** system which includes:
    - [ ] **Static Pre-Analysis** to establish a secure, restrictive baseline (Deny-by-Default posture).
    - [ ] **Coverage-Guided Fuzzing Refinement** to maximize execution path coverage and iteratively update the policy -> libAfl.
    - [ ] **Fuzzing Refinement Loop** using the loaded BPF filter to detect crashes/trace events (SECCOMP_RET_KILL) caused by undiscovered syscalls.
- [ ] Providing a TUI to configure the sandboxing rules and generating the configuration file (outputting OCI-compliant JSON).
- [x] Logging of the system calls, possibly by using the `SCMP_ACT_LOG` action.
- [ ] Implementing **Syscall Argument Filtering** to achieve true Least Privilege compliance by generating complex BPF rules that check register values (arguments).
- [ ] Exposing an API to allow for another instance of tiny-jail to monitor the first instance and dynamically update the BPF filter (through `SCMP_ACT_NOTIFY`, asking notify daemon what should be done about a new syscall).
- [ ] Show “which syscalls seen / which missed”, timeline view, --explain SYS_open to show call sites if available.

## Personal goals

My personal goals for this project are:

1. To learn Rust and leverage the secure and high-performance foundation it provides.
2. To get better at writing safe, performant, and readable code
    - memory safety (leveraging Rust's features)
    - concurrency (handling simultaneous demands of syscall tracing via PTRACE and fuzzer management)
    - testing (using test suites and coverage metrics to confirm functional correctness)
3. To understand and apply the Principle of Least Privilege (PoLP) in the context of syscall restriction.
