# Seccomp Syscall Data Files

This document describes the three JSON files used for creating seccomp rules based on syscall functionality.

## Overview

The three files serve different purposes:

1. **`syscalls.json`** - Raw syscall definitions from the kernel
2. **`abstract_syscalls.json`** - Functional groupings of related syscalls
3. **`oci_1-1.md`** - OCI Linux Container Configuration (seccomp rules)

---

## 1. `syscalls.json` - Kernel Syscall Definitions

**Purpose:** Complete list of system calls with their numbers and metadata from the Linux kernel.

**Source:** Extracted from the kernel's syscall table (`arch/x86/entry/syscalls/syscall_64.tbl`)

**Structure:**
```json
[
  {
    "number": 0,
    "abi": "common",
    "name": "read",
    "entry_point": "sys_read"
  },
  {
    "number": 2,
    "abi": "common",
    "name": "open",
    "entry_point": "sys_open"
  }
]
```

**Fields:**
* `number` - Syscall number used by seccomp filters
* `abi` - Application Binary Interface: `common`, `64`, or `x32`
* `name` - Syscall name as called from userspace
* `entry_point` - Kernel function name (with `sys_` prefix)

**Use Case:**
* Reference for all available syscalls
* Looking up syscall numbers for direct filtering
* Understanding which syscalls exist on the system

---

## 2. `abstract_syscalls.json` - Functional Groups

> [!NOTE]
> These groups are inspired by the work of [R. Sekar](https://www.seclab.cs.sunysb.edu/sekar/) available at <https://www.seclab.cs.sunysb.edu/sekar/papers/syscallclassif.htm>

**Purpose:** Groups related syscalls by functionality to simplify policy creation.

**Rationale:** Many syscalls have overlapping functionality. For example, both `open()` and `creat()` can create files. Grouping them allows writing policies based on *what* a program does, not *how* it does it.

**Structure:**
```json
{
  "stdio_app": {
    "description": "Application with stdin/stdout/stderr",
    "rules": [
      {
        "name": "read",
        "conditions": [
          {
            "type": "equals",
            "argument": "fd",
            "value": "0"
          }
        ]
      },
      {
        "name": "write",
        "conditions": [
          {
            "type": "equals",
            "argument": "fd",
            "value": "1"
          }
        ]
      },
      {
        "name": "write",
        "conditions": [
          {
            "type": "equals",
            "argument": "fd",
            "value": "2"
          }
        ]
      },
      { "group": "close_ops" },
      { "group": "memory_allocate" },
      { "group": "exit_ops" }
    ]
  },
}
```

**Fields:**
* `description` - What this group of syscalls does
* `rules` - List of rules that can be either:
  * a syscall name and its conditions: `{ "name": "open", "conditions": [] }`
  * a group reference: `{ "group": "WriteOpen" }`

**Example Groups:**
* `open_read` - Opening files for reading only
* `close_ops` - Opening files for writing (includes O_WRONLY and O_RDWR)
* `chmod_ops` - Changing file permissions (via `chmod` or `fchmod` or `fchmodat`)
* `socket_inet` - Creating Internet sockets (AF_INET, AF_INET6)

**Use Case:**
* Understanding syscall relationships
* Writing high-level security policies
* Documentation of syscall semantics

---

## 3. Extended OCI Linux Container Configuration for Seccomp

**Purpose:** OCI Linux Container Configuration (OCI 1.1) for seccomp rules with support for abstract syscalls, using TOML format.

**Structure:**
```toml
default_action = "Errno"
default_errno_ret = 1  # EPERM
architectures = ["SCMP_ARCH_X86_64"]

[[syscalls]]
names = ["read", "write"]
action = "Allow"

[[syscalls]]
names = ["openat"]
action = "Allow"
# Optional: errno return value for this specific rule (if action is Errno)
# errno_ret = 13 # EACCES

[[abstract_syscalls]]
names = ["WriteOpen"]
action = "KillThread"
```

**Fields:**
* `default_action` - Default action for syscalls not specified in the profile (e.g., `Allow`, `Log`, `KillThread`, `Errno`, `Trap`)
* `default_errno_ret` - Default errno return value for `Errno` actions (optional)
* `architectures` - List of architectures supported by the profile (default: `["SCMP_ARCH_X86_64"]`)
* `syscalls` - List of concrete syscall rules. Each rule contains:
    * `names`: List of syscall names
    * `action`: The action to take
    * `errno_ret`: Optional errno override
    * `conditions`: Optional list of argument inspection conditions
* `abstract_syscalls` - List of abstract syscall group rules (our extension to the OCI spec). Each rule contains:
    * `names`: List of abstract group names (defined in `abstract_rules.json`)
    * `action`: The action to take

**Use Case:**
* Applying a security policy to a container
* Applying a security policy to a process

