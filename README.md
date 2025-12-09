# Rust-Based Seccomp Sandbox: A Hybrid Policy Generator (RustSecCompGen)

This project focuses on developing a command-line utility in Rust designed to enhance system security by sandboxing applications using Linux's `seccomp-bpf` mechanism. The core filtering mechanism relies on **SECCOMP_MODE_FILTER**, which utilizes the Berkeley Packet Filter (BPF) technology. The core idea is to provide a tool that allows specifying precise system call policies, thereby reducing the massive kernel attack surface available to a target program.

The tool is conceptually inspired by the `seccomp` capabilities of projects like `Firejail` and `Bubblewrap`.

## Progress Tracking

* [x] Implement a basic policy parser and generator.
* [x] Give means to apply the policy to a target program.
* [x] Let user specify additional actions on command-line.
* [x] Handle log action and show logs in the output.
* [x] Handle abstract syscall groups in the policy.
* [x] Minimizing an existing policy.
* [ ] Fuzzer-Based Dynamic Generation.

## Implementation and Policy Structure

The implementation will leverage Rust's memory safety and concurrency features to safely and efficiently interact with the operating system. Key components include:

*   The **`nix` Rust crate** for essential Unix system calls, primarily for process management via `fork` and `execve`.
*   The **`libseccomp` Rust crate** to build and load filters in the kernel. This library provides a high-level, safe API, abstracting away the complex BPF-based filter language.

Policies will be defined and output in the **OCI Runtime Specification JSON format**. This standardized format ensures compatibility with modern container runtimes and orchestrators like Kubernetes.

Policies will allow users to specify a required `defaultAction` and specific actions for individual system calls, which can include:

*   **`SCMP_ACT_ALLOW`** (permit the call).
*   **`SCMP_ACT_KILL_THREAD`** (terminate the thread).
*   **`SCMP_ACT_ERRNO`** (return a specific error code, e.g., `EPERM`).
*   **`SCMP_ACT_NOTIFY`** (send the process state to a userspace agent for dynamic handling).

## Building

This project is structured as a Cargo workspace. To compile all packages, including `tiny-jail`, `audisp-plugin` and `macros`, simply run:

```bash
cargo build
```

For a release build, use:
```bash
cargo build --release
```

## Running

To run the main application, you must specify the binary name:
```bash
cargo run --bin tiny-jail
```
You can then append any command-line arguments you need, for example:
```bash
cargo run --bin tiny-jail -- -p /path/to/your/profile.json /bin/ls -la
```

---
**External References:**

*   **`syscalls classification` article:** <https://www.seclab.cs.sunysb.edu/sekar/papers/syscallclassif.htm>
*   **`seccomp` man page:** `man 2 seccomp` (or online: <https://man7.org/linux/man-pages/man2/seccomp.2.html>)
*   **`libseccomp` rust crate:** <https://docs.rs/libseccomp/latest/libseccomp/>
*   **`SeccompFuzzer` paper and gitlab repo:** <https://gitlab.com/iot-aalen/fuzz-seccomp-filter>
*   **`nix` Rust crate:** <https://docs.rs/nix/latest/nix/>
*   **OCI Runtime Specification Seccomp Schema:** Policies will conform to OCI standards.
*   **`Firejail` project:** <https://firejail.wordpress.com/> (for conceptual inspiration)
*   **`Bubblewrap` project:** <https://github.com/containers/bubblewrap> (for conceptual inspiration)
