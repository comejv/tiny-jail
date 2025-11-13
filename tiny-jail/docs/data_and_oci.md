# Seccomp Syscall Data Files

This document describes the three JSON files used for creating seccomp rules based on syscall functionality.

## Overview

The three files serve different purposes:

1. **`syscalls.json`** - Raw syscall definitions from the kernel
2. **`abstract_syscalls.json`** - Functional groupings of related syscalls
3. **`seccomp_rules.json`** - Merged data ready for seccomp rule generation
4. **`oci_1-1.md`** - OCI Linux Container Configuration (seccomp rules)

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

## 4. Extended OCI Linux Container Configuration for Seccomp

**Purpose:** OCI Linux Container Configuration (OCI 1.1) for seccomp rules with support for abstract syscalls.

**Structure:**
```json
{
  "defaultAction": "SCMP_ACT_***",
  "defaultErrnoRet": ***,
  "architectures": [
    "SCMP_ARCH_X86_64"
  ],
  "syscalls": [
    {
      "names": [
        "***",
        "***"
      ],
      "action": "SCMP_ACT_***"
    },
    {
      "names": [
        "***",
        "***"
      ],
      "action": "SCMP_ACT_***"
    }
  ],
  "abstractSyscalls": [
    {
      "names": [
        "WriteOpen"
      ],
      "action": "SCMP_ACT_KILL"
    }
  ]
}
```

**Fields:**
* `defaultAction` - Default action for syscalls not specified in the profile
* `defaultErrnoRet` - Default errno return value for SCMP_ACT_ERRNO actions
* `architectures` - List of architectures supported by the profile
* `syscalls` - List of syscalls to apply the profile to
* `abstractSyscalls` - List of abstract syscalls to apply the profile to (our addition to the OCI spec)

**Use Case:**
* Applying a security policy to a container
* Applying a security policy to a process

