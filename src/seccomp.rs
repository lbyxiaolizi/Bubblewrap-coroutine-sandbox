//! Classic-BPF (`sock_filter`) seccomp filter for `bwrap --seccomp`.
//!
//! Denies a targeted denylist of kernel-surface syscalls frequently abused in
//! unprivileged user-namespace exploits (`io_uring_*`, `bpf`, `userfaultfd`,
//! `perf_event_open`, `keyctl`, `add_key`, `request_key`, `kexec_load`,
//! `kexec_file_load`, `open_by_handle_at`, `acct`, `swapon`, `swapoff`) with
//! `EPERM`, while killing foreign-ABI (`ia32` on x86_64) or x32-ABI
//! (`nr >= __X32_SYSCALL_BIT`, `0x4000_0000`) invocations.

use std::io::{self, Seek, SeekFrom, Write};
use std::os::fd::OwnedFd;

use rustix::fs::{fcntl_add_seals, memfd_create, MemfdFlags, SealFlags};

const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
#[cfg(any(target_arch = "x86_64", test))]
const BPF_JGE: u16 = 0x30;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;

/// Offsets inside `struct seccomp_data` (`nr: i32` at 0, `arch: u32` at 4).
const OFFSET_NR: u32 = 0;
const OFFSET_ARCH: u32 = 4;

/// On x86_64, x32-ABI syscalls share `AUDIT_ARCH_X86_64` with `nr | 0x4000_0000`.
#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

#[cfg(target_arch = "x86_64")]
const EXPECTED_AUDIT_ARCH: u32 = 0xc000_003e; // AUDIT_ARCH_X86_64
#[cfg(target_arch = "aarch64")]
const EXPECTED_AUDIT_ARCH: u32 = 0xc000_00b7; // AUDIT_ARCH_AARCH64
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const EXPECTED_AUDIT_ARCH: u32 = 0;

#[derive(Clone, Copy, Debug)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

impl SockFilter {
    const fn stmt(code: u16, k: u32) -> Self {
        Self {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }

    const fn jump_eq(k: u32, jt: u8, jf: u8) -> Self {
        Self {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt,
            jf,
            k,
        }
    }

    #[cfg(target_arch = "x86_64")]
    const fn jump_ge(k: u32, jt: u8, jf: u8) -> Self {
        Self {
            code: BPF_JMP | BPF_JGE | BPF_K,
            jt,
            jf,
            k,
        }
    }

    fn to_ne_bytes(self) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[0..2].copy_from_slice(&self.code.to_ne_bytes());
        out[2] = self.jt;
        out[3] = self.jf;
        out[4..8].copy_from_slice(&self.k.to_ne_bytes());
        out
    }
}

fn blocked_syscalls() -> &'static [i64] {
    &[
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_userfaultfd,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_kexec_load,
        libc::SYS_kexec_file_load,
        libc::SYS_open_by_handle_at,
        libc::SYS_acct,
        libc::SYS_swapon,
        libc::SYS_swapoff,
    ]
}

fn build_filter_program() -> Vec<SockFilter> {
    if EXPECTED_AUDIT_ARCH == 0 {
        return Vec::new();
    }

    let syscalls = blocked_syscalls();
    let n = syscalls.len();
    let mut prog = Vec::with_capacity(n + 7);

    // 0: A = seccomp_data.arch
    prog.push(SockFilter::stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARCH));
    // 1: if A == EXPECTED_AUDIT_ARCH jump +1 (to load nr), else fall through to KILL
    prog.push(SockFilter::jump_eq(EXPECTED_AUDIT_ARCH, 1, 0));
    // 2: foreign ABI (e.g. IA32 `int 0x80` on x86_64) -> KILL_PROCESS
    prog.push(SockFilter::stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
    // 3: A = seccomp_data.nr
    prog.push(SockFilter::stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR));

    #[cfg(target_arch = "x86_64")]
    {
        // Reject x32 ABI (`nr >= 0x4000_0000`) which shares `AUDIT_ARCH_X86_64`!
        // On match (jt=0), fall through to KILL_PROCESS; otherwise (jf=1) skip KILL_PROCESS.
        prog.push(SockFilter::jump_ge(X32_SYSCALL_BIT, 0, 1));
        prog.push(SockFilter::stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
    }

    // Compare each blocked syscall; on match jump over remaining comparisons + ALLOW to DENY.
    for (i, &nr) in syscalls.iter().enumerate() {
        let jt_to_deny = (n - i) as u8;
        prog.push(SockFilter::jump_eq(nr as u32, jt_to_deny, 0));
    }

    // Default ALLOW
    prog.push(SockFilter::stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    // DENY with EPERM
    prog.push(SockFilter::stmt(
        BPF_RET | BPF_K,
        SECCOMP_RET_ERRNO | (libc::EPERM as u32),
    ));

    prog
}

/// Builds the raw native-endian `struct sock_filter[]` bytes expected by
/// `bwrap --seccomp`.
pub(crate) fn default_exec_bpf_bytes() -> Vec<u8> {
    let prog = build_filter_program();
    let mut bytes = Vec::with_capacity(prog.len() * 8);
    for insn in prog {
        bytes.extend_from_slice(&insn.to_ne_bytes());
    }
    bytes
}

/// Creates a sealed, read-only `memfd` positioned at offset 0 containing `bpf_bytes`.
pub(crate) fn create_seccomp_memfd(bpf_bytes: &[u8]) -> io::Result<OwnedFd> {
    let fd = memfd_create(
        c"cs-seccomp-bpf",
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
    )
    .map_err(io::Error::from)?;
    let mut file = std::fs::File::from(fd);
    file.write_all(bpf_bytes)?;
    file.seek(SeekFrom::Start(0))?;
    let fd = OwnedFd::from(file);
    let _ = fcntl_add_seals(
        &fd,
        SealFlags::SEAL | SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE,
    );
    Ok(fd)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pure classic-BPF interpreter over `(arch, nr)` to verify jump offsets,
    /// foreign-arch kills, x32 bit kills, and denylist EPERM actions.
    fn eval_bpf(prog: &[SockFilter], nr: u32, arch: u32) -> u32 {
        let mut pc = 0usize;
        let mut acc = 0u32;
        loop {
            let insn = prog[pc];
            match insn.code {
                c if c == (BPF_LD | BPF_W | BPF_ABS) => {
                    acc = match insn.k {
                        OFFSET_NR => nr,
                        OFFSET_ARCH => arch,
                        other => panic!("unexpected load offset {other}"),
                    };
                    pc += 1;
                }
                c if c == (BPF_JMP | BPF_JEQ | BPF_K) => {
                    pc += 1 + if acc == insn.k {
                        insn.jt as usize
                    } else {
                        insn.jf as usize
                    };
                }
                c if c == (BPF_JMP | BPF_JGE | BPF_K) => {
                    pc += 1 + if acc >= insn.k {
                        insn.jt as usize
                    } else {
                        insn.jf as usize
                    };
                }
                c if c == (BPF_RET | BPF_K) => return insn.k,
                other => panic!("unexpected opcode {other:#x}"),
            }
        }
    }

    #[test]
    fn bpf_simulator_verifies_normal_allow_denylist_eperm_foreign_arch_and_x32_kill() {
        let prog = build_filter_program();
        if EXPECTED_AUDIT_ARCH == 0 {
            return;
        }
        // Allowed normal syscalls
        assert_eq!(
            eval_bpf(&prog, libc::SYS_read as u32, EXPECTED_AUDIT_ARCH),
            SECCOMP_RET_ALLOW
        );
        assert_eq!(
            eval_bpf(&prog, libc::SYS_execve as u32, EXPECTED_AUDIT_ARCH),
            SECCOMP_RET_ALLOW
        );

        // Every blocked syscall returns EPERM
        for &nr in blocked_syscalls() {
            assert_eq!(
                eval_bpf(&prog, nr as u32, EXPECTED_AUDIT_ARCH),
                SECCOMP_RET_ERRNO | (libc::EPERM as u32),
                "syscall {nr} was not blocked with EPERM"
            );
        }

        // Foreign AUDIT_ARCH (e.g. IA32 0x4000_0003) -> KILL_PROCESS
        assert_eq!(
            eval_bpf(&prog, libc::SYS_read as u32, 0x4000_0003),
            SECCOMP_RET_KILL_PROCESS
        );

        // x32 syscall bit (`0x4000_0000 | nr`) with `AUDIT_ARCH_X86_64` -> KILL_PROCESS!
        #[cfg(target_arch = "x86_64")]
        {
            assert_eq!(
                eval_bpf(
                    &prog,
                    X32_SYSCALL_BIT | (libc::SYS_keyctl as u32),
                    EXPECTED_AUDIT_ARCH
                ),
                SECCOMP_RET_KILL_PROCESS
            );
            assert_eq!(
                eval_bpf(
                    &prog,
                    X32_SYSCALL_BIT | (libc::SYS_read as u32),
                    EXPECTED_AUDIT_ARCH
                ),
                SECCOMP_RET_KILL_PROCESS
            );
            // Negative syscall numbers (`u32::MAX`) also satisfy `>= 0x4000_0000` -> KILL_PROCESS
            assert_eq!(
                eval_bpf(&prog, u32::MAX, EXPECTED_AUDIT_ARCH),
                SECCOMP_RET_KILL_PROCESS
            );
        }
    }
}
