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
- `number` - Syscall number used by seccomp filters
- `abi` - Application Binary Interface: `common`, `64`, or `x32`
- `name` - Syscall name as called from userspace
- `entry_point` - Kernel function name (with `sys_` prefix)

**Use Case:**
- Reference for all available syscalls
- Looking up syscall numbers for direct filtering
- Understanding which syscalls exist on the system

---

## 2. `abstract_syscalls.json` - Functional Groups

> [!NOTE]
> These groups are the work of [R. Sekar](https://www.seclab.cs.sunysb.edu/sekar/) available at <https://www.seclab.cs.sunysb.edu/sekar/papers/syscallclassif.htm>

**Purpose:** Groups related syscalls by functionality to simplify policy creation.

**Rationale:** Many syscalls have overlapping functionality. For example, both `open()` and `creat()` can create files. Grouping them allows writing policies based on *what* a program does, not *how* it does it.

**Structure:**
```json
{
  "WriteOpen": {
    "parameters": "path",
    "description": "open and possibly create a file for write",
    "implementations": [
      {
        "call": "open(path, flags)",
        "base_name": "open",
        "condition": "(flags & (O_WRONLY | O_APPEND | O_TRUNC))"
      },
      {
        "call": "creat(path, mode)",
        "base_name": "creat"
      }
    ]
  }
}
```

**Fields:**
- `parameters` - Abstract parameters for the functional group
- `description` - What this group of syscalls does
- `implementations` - List of syscalls that implement this functionality
  - `call` - Full syscall signature
  - `base_name` - Syscall name
  - `condition` - Optional filtering condition (e.g., flag requirements)

**Example Groups:**
- `WriteOpen` - Opening files for writing
- `ReadOpen` - Opening files for reading
- `chmod_2` - Changing file permissions (via `chmod` or `fchmod`)
- `recv_2` - Receiving data (via `recv`, `recvfrom`, or `recvmsg`)

**Use Case:**
- Understanding syscall relationships
- Writing high-level security policies
- Documentation of syscall semantics

---

## 3. `seccomp_data.json` - Merged Seccomp Rules

**Purpose:** Combined data optimized for seccomp rule generation in Rust/C programs.

**Source:** Automatically merged from `syscalls.json` and `abstract_syscalls.json`

**Structure:**
```json
{
  "abstract_groups": {
    "WriteOpen": {
      "description": "open and possibly create a file for write",
      "parameters": "path",
      "rules": [
        {
          "name": "open",
          "number": 2,
          "call": "open(path, flags)",
          "condition": {
            "type": "bitwise_and",
            "argument": "flags",
            "flags": "O_WRONLY | O_APPEND | O_TRUNC",
            "raw": "(flags & (O_WRONLY | O_APPEND | O_TRUNC))"
          }
        },
        {
          "name": "creat",
          "number": 85,
          "call": "creat(path, mode)"
        }
      ]
    }
  },
  "syscalls": {
    "read": {
      "number": 0,
      "abi": "common"
    },
    "open": {
      "number": 2,
      "abi": "common"
    }
  }
}
```

**Fields:**

### `abstract_groups`
Functional groups with resolved syscall numbers and parsed conditions.

Each group contains:
- `description` - What the group does
- `parameters` - Abstract parameters
- `rules` - List of concrete syscall rules
  - `name` - Syscall name
  - `number` - Syscall number for seccomp filtering
  - `call` - Full function signature
  - `condition` - Structured condition for argument filtering
    - `type` - Condition type: `bitwise_and`, `equality`, or `raw`
    - `argument` - Which argument to check
    - `flags` - Flag values to check (for bitwise_and)
    - `raw` - Original condition string

### `syscalls`
Simple mapping of all syscall names to their numbers and ABI.

**Use Case:**
- **Primary file for implementing seccomp rules**
- Direct mapping from abstract groups to syscall numbers
- Structured conditions ready for seccomp argument filtering
- Quick lookup for individual syscalls

---

## 4. OCI Linux Container Configuration for Seccomp

**Purpose:** OCI Linux Container Configuration (OCI 1.1) for seccomp rules.

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
  ]
}
```
