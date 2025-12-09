# Tiy-Jail Project

## Overview
`tiny-jail` is a tool for generating and applying seccomp profiles for Linux binaries. It was written for the Telecom Paris 2025 Safe System Programming course by Côme VINCENT.

## Features

With this project, you can:

*   Apply existing seccomp OCI compliant profiles to a target program:
    `tiny-jail exec --profile /path/to/profile.json -- /path/to/executable --with-arg`
*   Use hybrid profiles with abstract syscall groups.
*   Minimize an existing seccomp profile:
    `tiny-jail reduce -p /path/to/profile.toml -- /path/to/executable --with-arg`
*   Log system calls made by a target program:

To learn more about what's possible run `tiny-jail --help` or `tiny-jail <command> --help`.

## Compiling

This project is written in Rust and uses Cargo as the build system.

To compile the project, run:

```bash
cargo build
```

To compile the project with debug symbols, run:

```bash
cargo build --release
```
