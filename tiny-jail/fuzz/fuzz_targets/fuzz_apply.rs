#![no_main]
use crate::arbitrary::Arbitrary;
use crate::arbitrary::Unstructured;
use libfuzzer_sys::{arbitrary, fuzz_target};
use tiny_jail::actions::Action;
use tiny_jail::filters::*;

// Valid syscall pool
const SYSCALLS: &[&str] = &[
    "read",
    "write",
    "open",
    "openat",
    "close",
    "socket",
    "connect",
    "bind",
    "clone",
    "execve",
    "mmap",
    "mprotect",
    "munmap",
    "fstat",
    "stat",
    "lstat",
    "access",
    "faccessat",
    "readlink",
    "readlinkat",
    "getdents",
    "getdents64",
    "arch_prctl",
    "fcntl",
    "flock",
    "fsync",
    "fdatasync",
    "sync",
    "syncfs",
    "getxattr",
    "lgetxattr",
    "fgetxattr",
    "listxattr",
    "llistxattr",
    "flistxattr",
    "setxattr",
    "lsetxattr",
    "fsetxattr",
    "removexattr",
    "lremovexattr",
    "fremovexattr",
    "getcwd",
];

const OPS: &[&str] = &[
    "SCMP_CMP_EQ",
    "SCMP_CMP_NE",
    "SCMP_CMP_LT",
    "SCMP_CMP_LE",
    "SCMP_CMP_GT",
    "SCMP_CMP_GE",
    "SCMP_CMP_MASKED_EQ",
];

const ARCHS: &[&str] = &[
    "SCMP_ARCH_X86_64",
    "SCMP_ARCH_X86",
    "SCMP_ARCH_AARCH64",
    "SCMP_ARCH_ARM",
];

#[derive(Debug)]
struct ValidProfile {
    profile: OciSeccomp,
}

impl<'a> Arbitrary<'a> for ValidProfile {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let syscall_count = u.int_in_range(0..=20)?;
        let mut syscalls = Vec::new();

        for _ in 0..syscall_count {
            let name_count = u.int_in_range(1..=3)?;
            let names: Vec<String> = (0..name_count)
                .map(|_| Ok(u.choose(SYSCALLS)?.to_string()))
                .collect::<arbitrary::Result<_>>()?;

            let action = u.choose(&[
                Action::Allow,
                Action::Log,
                Action::Errno,
                Action::KillThread,
                Action::Trap,
            ])?;

            let cond_count = u.int_in_range(0..=2)?;
            let mut conditions = Vec::new();

            for _ in 0..cond_count {
                let op = u.choose(OPS)?.to_string();
                let value_two = if op == "SCMP_CMP_MASKED_EQ" {
                    Some(u64::arbitrary(u)?)
                } else {
                    None
                };

                conditions.push(OciSyscallCondition {
                    index: u.int_in_range(0..=5)?,
                    value: u64::arbitrary(u)?,
                    value_two,
                    op,
                });
            }

            syscalls.push(OciSyscall {
                names,
                action: *action,
                errno_ret: u.arbitrary()?,
                conditions,
            });
        }

        let arch_count = u.int_in_range(1..=3)?;
        let architectures: Vec<String> = (0..arch_count)
            .map(|_| Ok(u.choose(ARCHS)?.to_string()))
            .collect::<arbitrary::Result<_>>()?;

        Ok(ValidProfile {
            profile: OciSeccomp {
                default_action: *u.choose(&[Action::Allow, Action::KillThread, Action::Errno])?,
                default_errno_ret: u.arbitrary()?,
                architectures,
                syscalls: Some(syscalls),
                abstract_syscalls: None,
            },
        })
    }
}

fuzz_target!(|valid: ValidProfile| {
    // Now this will actually reach deep logic
    let _ = apply_profile(&valid.profile, None, None, false);

    let mut profile = valid.profile.clone();
    explode_syscalls(&mut profile);
    coalesce_rules_by_action(&mut profile);
});
