//! Public coordinator ([`Sandbox`]) and directory capability ([`Workspace`]).

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::io;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use tokio::sync::Semaphore;

use crate::bwrap::{Access, BwrapLayout};
use crate::exec::{self, ExecOutput, ExecSpec};
use crate::fs_ops::{self, Bulkhead, Counters, SandboxReader, SandboxWriter};
use crate::lock;

#[derive(Clone, Debug)]
pub struct Limits {
    /// Maximum byte size of a buffered `read`/`write`, `list`, or combined
    /// `stdout + stderr` of an `exec` command.
    pub max_payload: usize,
    /// Maximum concurrent operations per `(inode, access)` domain.
    pub max_in_flight: usize,
    /// Global cap on concurrent blocking filesystem tasks across all domains.
    pub max_global_fs_in_flight: usize,
    /// Wall-clock timeout for one `exec` invocation.
    pub exec_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_payload: 16 << 20,
            max_in_flight: 32,
            max_global_fs_in_flight: 64,
            exec_timeout: Duration::from_secs(60),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub active_domains: usize,
    pub running_fs_tasks: usize,
    pub peak_running_fs_tasks: usize,
    pub file_ops: u64,
    pub stream_opens: u64,
    pub exec_invocations: u64,
}

type DomainKey = (u64, u64, Access);

pub struct Sandbox {
    layout: Arc<BwrapLayout>,
    limits: Limits,
    fs_slots: Arc<Semaphore>,
    counters: Arc<Counters>,
    domains: Mutex<HashMap<DomainKey, Weak<Domain>>>,
}

impl Sandbox {
    pub fn new(bwrap: impl Into<PathBuf>, limits: Limits) -> io::Result<Self> {
        if limits.max_in_flight == 0 || limits.max_global_fs_in_flight == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "max_in_flight and max_global_fs_in_flight must be >= 1",
            ));
        }
        let layout = BwrapLayout::probe(bwrap.into())?;
        let fs_slots = Arc::new(Semaphore::new(limits.max_global_fs_in_flight));
        Ok(Self {
            layout: Arc::new(layout),
            limits,
            fs_slots,
            counters: Arc::new(Counters::default()),
            domains: Mutex::new(HashMap::new()),
        })
    }

    /// Opens `dir` (`O_RDONLY | O_DIRECTORY | O_CLOEXEC`) and returns a
    /// [`Workspace`] scoped to its inode. Live handles for the same
    /// `(st_dev, st_ino, access)` share one underlying descriptor.
    pub fn workspace(&self, dir: impl AsRef<Path>, access: Access) -> io::Result<Workspace> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY)
            .open(dir)?;
        let meta = file.metadata()?;
        let key = (meta.dev(), meta.ino(), access);

        let mut domains = lock(&self.domains);
        if let Some(existing) = domains.get(&key).and_then(Weak::upgrade) {
            return Ok(Workspace { domain: existing });
        }
        domains.retain(|_, w| w.strong_count() > 0);

        let path = std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))?;
        let bulkhead = Bulkhead {
            domain: Arc::new(Semaphore::new(self.limits.max_in_flight)),
            global: Arc::clone(&self.fs_slots),
            counters: Arc::clone(&self.counters),
        };
        let domain = Arc::new(Domain {
            path,
            dir: OwnedFd::from(file),
            access,
            layout: Arc::clone(&self.layout),
            limits: self.limits.clone(),
            counters: Arc::clone(&self.counters),
            bulkhead,
        });
        domains.insert(key, Arc::downgrade(&domain));
        Ok(Workspace { domain })
    }

    pub fn stats(&self) -> Stats {
        let active_domains = lock(&self.domains)
            .values()
            .filter(|w| w.strong_count() > 0)
            .count();
        Stats {
            active_domains,
            running_fs_tasks: self.counters.running_fs_tasks.load(Ordering::SeqCst),
            peak_running_fs_tasks: self.counters.peak_running_fs_tasks.load(Ordering::SeqCst),
            file_ops: self.counters.file_ops.load(Ordering::Relaxed),
            stream_opens: self.counters.stream_opens.load(Ordering::Relaxed),
            exec_invocations: self.counters.exec_invocations.load(Ordering::Relaxed),
        }
    }
}

struct Domain {
    path: PathBuf,
    dir: OwnedFd,
    access: Access,
    layout: Arc<BwrapLayout>,
    limits: Limits,
    counters: Arc<Counters>,
    bulkhead: Bulkhead,
}

impl Domain {
    fn ensure_writable(&self) -> io::Result<()> {
        match self.access {
            Access::ReadWrite => Ok(()),
            Access::ReadOnly => Err(io::Error::from_raw_os_error(libc::EROFS)),
        }
    }

    async fn run_fs_blocking<T, F>(
        self: &Arc<Self>,
        counter: &std::sync::atomic::AtomicU64,
        op: F,
    ) -> io::Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&Domain) -> io::Result<T> + Send + 'static,
    {
        counter.fetch_add(1, Ordering::Relaxed);
        let domain = Arc::clone(self);
        self.bulkhead.run_blocking(move || op(&domain)).await
    }
}

#[derive(Clone)]
pub struct Workspace {
    domain: Arc<Domain>,
}

impl Workspace {
    pub fn dir(&self) -> &Path {
        &self.domain.path
    }

    pub fn access(&self) -> Access {
        self.domain.access
    }

    pub async fn read(&self, path: impl AsRef<Path>) -> io::Result<Vec<u8>> {
        let path_bytes = path.as_ref().as_os_str().as_bytes().to_vec();
        fs_ops::validate_path(&path_bytes)?;
        self.domain
            .run_fs_blocking(&self.domain.counters.file_ops, move |d| {
                fs_ops::read_bounded(d.dir.as_fd(), &path_bytes, d.limits.max_payload)
            })
            .await
    }

    pub async fn write(&self, path: impl AsRef<Path>, data: impl AsRef<[u8]>) -> io::Result<()> {
        let path_bytes = path.as_ref().as_os_str().as_bytes().to_vec();
        let data_bytes = data.as_ref().to_vec();
        fs_ops::validate_path(&path_bytes)?;
        if data_bytes.len() > self.domain.limits.max_payload {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "payload of {} bytes exceeds {}-byte limit",
                    data_bytes.len(),
                    self.domain.limits.max_payload
                ),
            ));
        }
        self.domain
            .run_fs_blocking(&self.domain.counters.file_ops, move |d| {
                if d.access == Access::ReadOnly {
                    let _ = fs_ops::list_bounded(
                        d.dir.as_fd(),
                        parent_or_dot(&path_bytes),
                        d.limits.max_payload,
                    )?;
                    return Err(io::Error::from_raw_os_error(libc::EROFS));
                }
                fs_ops::write_atomic(
                    d.dir.as_fd(),
                    &path_bytes,
                    &data_bytes,
                    d.limits.max_payload,
                )
            })
            .await
    }

    pub async fn list(&self, path: impl AsRef<Path>) -> io::Result<Vec<OsString>> {
        let path_bytes = path.as_ref().as_os_str().as_bytes().to_vec();
        fs_ops::validate_path(&path_bytes)?;
        self.domain
            .run_fs_blocking(&self.domain.counters.file_ops, move |d| {
                fs_ops::list_bounded(d.dir.as_fd(), &path_bytes, d.limits.max_payload)
            })
            .await
    }

    pub async fn open_read(&self, path: impl AsRef<Path>) -> io::Result<SandboxReader> {
        let path_bytes = path.as_ref().as_os_str().as_bytes().to_vec();
        fs_ops::validate_path(&path_bytes)?;
        let bulkhead = self.domain.bulkhead.clone();
        self.domain
            .run_fs_blocking(&self.domain.counters.stream_opens, move |d| {
                fs_ops::open_reader(d.dir.as_fd(), &path_bytes, bulkhead)
            })
            .await
    }

    pub async fn open_write(&self, path: impl AsRef<Path>) -> io::Result<SandboxWriter> {
        self.domain.ensure_writable()?;
        let path_bytes = path.as_ref().as_os_str().as_bytes().to_vec();
        fs_ops::validate_path(&path_bytes)?;
        let bulkhead = self.domain.bulkhead.clone();
        self.domain
            .run_fs_blocking(&self.domain.counters.stream_opens, move |d| {
                fs_ops::open_writer(d.dir.as_fd(), &path_bytes, bulkhead)
            })
            .await
    }

    pub async fn exec<P, I, S>(&self, program: P, args: I) -> io::Result<ExecOutput>
    where
        P: AsRef<OsStr>,
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let domain_permit = Arc::clone(&self.domain.bulkhead.domain)
            .acquire_owned()
            .await
            .expect("domain semaphore closed");
        let dir_fd = self.domain.dir.try_clone()?;
        self.domain
            .counters
            .exec_invocations
            .fetch_add(1, Ordering::Relaxed);
        exec::run_oneshot(
            ExecSpec {
                layout: Arc::clone(&self.domain.layout),
                dir_fd,
                domain_permit,
                access: self.domain.access,
                timeout: self.domain.limits.exec_timeout,
                max_payload: self.domain.limits.max_payload,
            },
            program.as_ref(),
            args,
        )
        .await
    }
}

fn parent_or_dot(path: &[u8]) -> &[u8] {
    let mut trimmed = path;
    while trimmed.len() > 1 && trimmed.last() == Some(&b'/') {
        trimmed = &trimmed[..trimmed.len() - 1];
    }
    match trimmed.iter().rposition(|&b| b == b'/') {
        Some(0) | None => b".",
        Some(idx) => &trimmed[..idx],
    }
}
