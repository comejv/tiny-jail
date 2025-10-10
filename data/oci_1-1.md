# Linux Container Configuration

This document describes the schema for the [Linux-specific section](config.md#platform-specific-configuration) of the [container configuration](config.md).
The Linux container specification uses various kernel features like namespaces, cgroups, capabilities, LSM, and filesystem jails to fulfill the spec.

## Seccomp

Seccomp provides application sandboxing mechanism in the Linux kernel.
Seccomp configuration allows one to configure actions to take for matched syscalls and furthermore also allows matching on values passed as arguments to syscalls.
For more information about Seccomp, see [Seccomp][seccomp] kernel documentation.
The actions, architectures, and operators are strings that match the definitions in seccomp.h from [libseccomp][] and are translated to corresponding values.

**`seccomp`** (object, OPTIONAL)

The following parameters can be specified to set up seccomp:

* **`defaultAction`** *(string, REQUIRED)* - the default action for seccomp. Allowed values are the same as `syscalls[].action`.
* **`defaultErrnoRet`** *(uint, OPTIONAL)* - the errno return code to use.
    Some actions like `SCMP_ACT_ERRNO` and `SCMP_ACT_TRACE` allow to specify the errno code to return.
    When the action doesn't support an errno, the runtime MUST print and error and fail.
    The default is `EPERM`.
* **`architectures`** *(array of strings, OPTIONAL)* - the architecture used for system calls.
    A valid list of constants as of libseccomp v2.6.0 is shown below.

    * `SCMP_ARCH_X86`
    * `SCMP_ARCH_X86_64`
    * `SCMP_ARCH_X32`
    * `SCMP_ARCH_ARM`
    * `SCMP_ARCH_AARCH64`
    * `SCMP_ARCH_MIPS`
    * `SCMP_ARCH_MIPS64`
    * `SCMP_ARCH_MIPS64N32`
    * `SCMP_ARCH_MIPSEL`
    * `SCMP_ARCH_MIPSEL64`
    * `SCMP_ARCH_MIPSEL64N32`
    * `SCMP_ARCH_PPC`
    * `SCMP_ARCH_PPC64`
    * `SCMP_ARCH_PPC64LE`
    * `SCMP_ARCH_S390`
    * `SCMP_ARCH_S390X`
    * `SCMP_ARCH_PARISC`
    * `SCMP_ARCH_PARISC64`
    * `SCMP_ARCH_RISCV64`
    * `SCMP_ARCH_LOONGARCH64`
    * `SCMP_ARCH_M68K`
    * `SCMP_ARCH_SH`
    * `SCMP_ARCH_SHEB`

* **`flags`** *(array of strings, OPTIONAL)* - list of flags to use with seccomp(2).

    A valid list of constants is shown below.

    * `SECCOMP_FILTER_FLAG_TSYNC`
    * `SECCOMP_FILTER_FLAG_LOG`
    * `SECCOMP_FILTER_FLAG_SPEC_ALLOW`
    * `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV`

* **`listenerPath`** *(string, OPTIONAL)* - specifies the path of UNIX domain socket over which the runtime will send the [container process state](#containerprocessstate) data structure when the `SCMP_ACT_NOTIFY` action is used.
    This socket MUST use `AF_UNIX` domain and `SOCK_STREAM` type.
    The runtime MUST send exactly one [container process state](#containerprocessstate) per connection.
    The connection MUST NOT be reused and it MUST be closed after sending a seccomp state.
    If sending to this socket fails, the runtime MUST [generate an error](runtime.md#errors).
    If the `SCMP_ACT_NOTIFY` action is not used this value is ignored.

    The runtime sends the following file descriptors using `SCM_RIGHTS` and set their names in the `fds` array of the [container process state](#containerprocessstate):

    * **`seccompFd`** (string, REQUIRED) is the seccomp file descriptor returned by the seccomp syscall.

* **`listenerMetadata`** *(string, OPTIONAL)* - specifies an opaque data to pass to the seccomp agent.
    This string will be sent as the `metadata` field in the [container process state](#containerprocessstate).
    This field MUST NOT be set if `listenerPath` is not set.

* **`syscalls`** *(array of objects, OPTIONAL)* - match a syscall in seccomp.
    While this property is OPTIONAL, some values of `defaultAction` are not useful without `syscalls` entries.
    For example, if `defaultAction` is `SCMP_ACT_KILL` and `syscalls` is empty or unset, the kernel will kill the container process on its first syscall.
    Each entry has the following structure:

    * **`names`** *(array of strings, REQUIRED)* - the names of the syscalls.
        `names` MUST contain at least one entry.
    * **`action`** *(string, REQUIRED)* - the action for seccomp rules.
        A valid list of constants as of libseccomp v2.6.0 is shown below.

        * `SCMP_ACT_KILL`
        * `SCMP_ACT_KILL_PROCESS`
        * `SCMP_ACT_KILL_THREAD`
        * `SCMP_ACT_TRAP`
        * `SCMP_ACT_ERRNO`
        * `SCMP_ACT_TRACE`
        * `SCMP_ACT_ALLOW`
        * `SCMP_ACT_LOG`
        * `SCMP_ACT_NOTIFY`

    * **`errnoRet`** *(uint, OPTIONAL)* - the errno return code to use.
        Some actions like `SCMP_ACT_ERRNO` and `SCMP_ACT_TRACE` allow to specify the errno code to return.
        When the action doesn't support an errno, the runtime MUST print and error and fail.
        The default is `EPERM`.

    * **`args`** *(array of objects, OPTIONAL)* - the specific syscall in seccomp.
        Each entry has the following structure:

        * **`index`** *(uint, REQUIRED)* - the index for syscall arguments in seccomp.
        * **`value`** *(uint64, REQUIRED)* - the value for syscall arguments in seccomp.
        * **`valueTwo`** *(uint64, OPTIONAL)* - the value for syscall arguments in seccomp.
        * **`op`** *(string, REQUIRED)* - the operator for syscall arguments in seccomp.
            A valid list of constants as of libseccomp v2.6.0 is shown below.

            * `SCMP_CMP_NE`
            * `SCMP_CMP_LT`
            * `SCMP_CMP_LE`
            * `SCMP_CMP_EQ`
            * `SCMP_CMP_GE`
            * `SCMP_CMP_GT`
            * `SCMP_CMP_MASKED_EQ`

### Example

```json
"seccomp": {
    "defaultAction": "SCMP_ACT_ALLOW",
    "architectures": [
        "SCMP_ARCH_X86",
        "SCMP_ARCH_X32"
    ],
    "syscalls": [
        {
            "names": [
                "getcwd",
                "chmod"
            ],
            "action": "SCMP_ACT_ERRNO"
        }
    ]
}
```

### The Container Process State

The container process state is a data structure passed via a UNIX socket.
The container runtime MUST send the container process state over the UNIX socket as regular payload serialized in JSON and file descriptors MUST be sent using `SCM_RIGHTS`.
The container runtime MAY use several `sendmsg(2)` calls to send the aforementioned data.
If more than one `sendmsg(2)` is used, the file descriptors MUST be sent only in the first call.

The container process state includes the following properties:

* **`ociVersion`** (string, REQUIRED) is version of the Open Container Initiative Runtime Specification with which the container process state complies.
* **`fds`** (array, OPTIONAL) is a string array containing the names of the file descriptors passed.
    The index of the name in this array corresponds to index of the file descriptors in the `SCM_RIGHTS` array.
* **`pid`** (int, REQUIRED) is the container process ID, as seen by the runtime.
* **`metadata`** (string, OPTIONAL) opaque metadata.
* **`state`** ([state](runtime.md#state), REQUIRED) is the state of the container.

Example sending a single `seccompFd` file descriptor in the `SCM_RIGHTS` array:

```json
{
    "ociVersion": "1.0.2",
    "fds": [
        "seccompFd"
    ],
    "pid": 4422,
    "metadata": "MKNOD=/dev/null,/dev/net/tun;BPF_MAP_TYPES=hash,array",
    "state": {
        "ociVersion": "1.0.2",
        "id": "oci-container1",
        "status": "creating",
        "pid": 4422,
        "bundle": "/containers/redis",
        "annotations": {
            "myKey": "myValue"
        }
    }
}
```

