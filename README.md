# Rust-Based Seccomp Sandbox: A Hybrid Policy Generator (RustSecCompGen)

This project focuses on developing a command-line utility in Rust designed to enhance system security by sandboxing applications using Linux's `seccomp-bpf` mechanism. The core filtering mechanism relies on **SECCOMP_MODE_FILTER**, which utilizes the Berkeley Packet Filter (BPF) technology. The core idea is to provide a tool that allows specifying precise system call policies, thereby reducing the massive kernel attack surface available to a target program.

The tool is conceptually inspired by the `seccomp` capabilities of projects like `Firejail` and `Bubblewrap`.

## Progress Tracking

* [x] Implement a basic policy parser and generator.
* [x] Give means to apply the policy to a target program.
* [x] Let user specify additional actions on command-line.
* [x] Handle log action and show logs in the output.
* [-] Handle abstract syscall groups in the policy.
* [ ] Fuzzer-Based Dynamic Generation.

See [notes/goals.md](notes/goals.md) for more details.

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

## Advanced Security Features

### 1. Syscall Argument Filtering

The project targets true Least Privilege compliance by moving beyond simple syscall ID filtering. The dynamic analysis will capture and analyze the concrete argument values passed in CPU registers for critical syscalls (e.g., `openat`, `mmap`). This data is used to generate **highly granular BPF rules** that check register contents using comparison operators (`SCMP_CMP_EQ`, `SCMP_CMP_MASKED_EQ`, etc.), ensuring, for example, that a file operation is only permitted with specific flags or on designated paths.

---
**External References:**

*   **`seccomp` man page:** `man 2 seccomp` (or online: <https://man7.org/linux/man-pages/man2/seccomp.2.html>)
*   **`libseccomp` rust crate:** <https://docs.rs/libseccomp/latest/libseccomp/>
*   **`SeccompFuzzer` paper and gitlab repo:** <https://gitlab.com/iot-aalen/fuzz-seccomp-filter>
*   **`nix` Rust crate:** <https://docs.rs/nix/latest/nix/>
*   **`Firejail` project:** <https://firejail.wordpress.com/> (for conceptual inspiration)
*   **`Bubblewrap` project:** <https://github.com/containers/bubblewrap> (for conceptual inspiration)
*   **OCI Runtime Specification Seccomp Schema:** Policies will conform to OCI standards.
*   **Syscall Policy Generation Research:** Inspired by Chestnuts (Static Analysis) and Fuzzer-Based Dynamic Generation methods.
