# Rust-Based Seccomp Sandbox: A Hybrid Policy Generator (RustSecCompGen)

This project focuses on developing a command-line utility in Rust designed to enhance system security by sandboxing applications using Linux's `seccomp-bpf` mechanism. The core filtering mechanism relies on **SECCOMP_MODE_FILTER**, which utilizes the Berkeley Packet Filter (BPF) technology. The core idea is to provide a tool that allows specifying precise system call policies, thereby reducing the massive kernel attack surface available to a target program.

The tool is conceptually inspired by the `seccomp` capabilities of projects like `Firejail` and `Bubblewrap`.

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

## Core Innovation: Hybrid Policy Generation

To overcome the inherent security limitations of simple dynamic "learning modes" (which are prone to missing rare syscall paths, known as the false negative trap), this project implements a **Hybrid Coverage-Guided Policy Generation Architecture**.

This multi-phase approach ensures adherence to the **Principle of Least Privilege (PoLP)**:

1.  **Phase 1: Static Pre-Analysis and Baseline (Deny-by-Default)**: Static analysis techniques (similar to the Chestnut framework) are used to quickly establish a restrictive baseline, identifying an initial set of necessary syscalls based on code structure (e.g., blocking 86.5% of the syscall attack surface quickly). The initial BPF filter is loaded to enforce a **Deny-by-Default** posture (`SECCOMP_RET_KILL` for all unlisted calls).
2.  **Phase 2 & 3: Coverage-Guided Refinement**: The application is executed under dynamic tracing and **structure-aware fuzzing** (via tools like AFL++). The loaded BPF filter acts as a detector: when the fuzzer discovers a new execution path that requires an unlisted syscall, the filter triggers a detectable crash or trace event (`SECCOMP_RET_KILL` or `SECCOMP_RET_TRACE`), signaling the need for policy update. This continuous feedback loop iteratively refines the policy, maximizing coverage and fidelity.

## Advanced Security Features

### 1. Syscall Argument Filtering

The project targets true Least Privilege compliance by moving beyond simple syscall ID filtering. The dynamic analysis will capture and analyze the concrete argument values passed in CPU registers for critical syscalls (e.g., `openat`, `mmap`). This data is used to generate **highly granular BPF rules** that check register contents using comparison operators (`SCMP_CMP_EQ`, `SCMP_CMP_MASKED_EQ`, etc.), ensuring, for example, that a file operation is only permitted with specific flags or on designated paths.

---
**External References:**

*   **`seccomp` man page:** `man 2 seccomp` (or online: <https://man7.org/linux/man-pages/man2/seccomp.2.html>)
*   **`libseccomp` rust crate:** <https://docs.rs/libseccomp/latest/libseccomp/>
*   **`nix` Rust crate:** <https://docs.rs/nix/latest/nix/>
*   **`Firejail` project:** <https://firejail.wordpress.com/> (for conceptual inspiration)
*   **`Bubblewrap` project:** <https://github.com/containers/bubblewrap> (for conceptual inspiration)
*   **OCI Runtime Specification Seccomp Schema:** Policies will conform to OCI standards.
*   **Syscall Policy Generation Research:** Inspired by Chestnuts (Static Analysis) and Fuzzer-Based Dynamic Generation methods.
