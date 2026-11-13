//! Directory-scoped file operations and `bubblewrap` subprocess execution for
//! Tokio tasks.
//!
//! Tokio tasks run inside the same OS process and share one address space and
//! file descriptor table. This crate targets workloads where the host Rust task
//! is trusted orchestration code, while path inputs and external programs are
//! untrusted:
//! - Path operations on [`Workspace`] resolve relative to a pinned directory
//!   descriptor via `openat2(RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS)`.
//! - External commands launched via [`Workspace::exec`] run in a fresh
//!   `bubblewrap` container with unshared namespaces, dropped capabilities, and
//!   a `seccomp` filter.

#![allow(clippy::disallowed_types, clippy::disallowed_methods)]

#[cfg(not(target_os = "linux"))]
compile_error!("coroutine-sandbox requires Linux (namespaces, openat2, and seccomp)");

mod bwrap;
mod exec;
mod fs_ops;
mod sandbox;
mod seccomp;

pub use bwrap::Access;
pub use exec::ExecOutput;
pub use fs_ops::{SandboxReader, SandboxWriter};
pub use sandbox::{Limits, Sandbox, Stats, Workspace};

fn lock<T>(mutex: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
