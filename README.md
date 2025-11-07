# Rust-Based Seccomp Sandbox: A Hybrid Policy Generator (RustSecCompGen)

This project focuses on developing a command-line utility in Rust designed to enhance system security by sandboxing applications using Linux's `seccomp-bpf` mechanism. The core filtering mechanism relies on **SECCOMP_MODE_FILTER**, which utilizes the Berkeley Packet Filter (BPF) technology. The core idea is to provide a tool that allows specifying precise system call policies, thereby reducing the massive kernel attack surface available to a target program.

The tool is conceptually inspired by the `seccomp` capabilities of projects like `Firejail` and `Bubblewrap`.

## Progress Tracking

* [x] Implement a basic policy parser and generator.
* [x] Give means to apply the policy to a target program.
* [x] Let user specify additional actions on command-line.
* [x] Handle log action and show logs in the output.
* [x] Handle abstract syscall groups in the policy.
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

## Building

To compile `tiny-jail`, the `audisp-plugin` must be built first. This is because `tiny-jail` includes the `audisp-plugin` as a byte array, and the build process expects the plugin to be pre-compiled.

If you encounter an error like:
```
error: couldn't read `src/../target/release/audisp-plugin`: No such file or directory (os error 2)
  --> src/audisp.rs:29:29
   |
29 | const PLUGIN_BYTES: &[u8] = include_bytes!("../target/release/audisp-plugin");
   |                             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

error: could not compile `tiny-jail` (bin "tiny-jail") due to 1 previous error
```
You need to manually build the `audisp-plugin` first. Navigate to the `audisp_plugin` directory and run `cargo build --release`. After the plugin is built, you can then build the main `tiny-jail` project.

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
