//! Directory-scoped file operations built on `openat2(RESOLVE_IN_ROOT |
//! RESOLVE_NO_MAGICLINKS)`.

use std::ffi::{CString, OsStr, OsString};
use std::future::Future;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use rustix::fs::{
    fstat, openat, openat2, renameat, statat, unlinkat, AtFlags, Dir, FileType, Mode, OFlags,
    ResolveFlags,
};
use rustix::io::Errno;
use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const TEMP_PREFIX: &[u8] = b".cs-tmp-";
const STREAM_BUF_CAP: usize = 64 << 10;

#[derive(Default, Debug)]
pub(crate) struct Counters {
    pub(crate) running_fs_tasks: AtomicUsize,
    pub(crate) peak_running_fs_tasks: AtomicUsize,
    pub(crate) file_ops: AtomicU64,
    pub(crate) stream_opens: AtomicU64,
    pub(crate) exec_invocations: AtomicU64,
}

impl Counters {
    fn enter_blocking(&self) -> RunningGuard<'_> {
        let cur = self.running_fs_tasks.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak_running_fs_tasks.fetch_max(cur, Ordering::SeqCst);
        RunningGuard(self)
    }
}

struct RunningGuard<'a>(&'a Counters);

impl Drop for RunningGuard<'_> {
    fn drop(&mut self) {
        self.0.running_fs_tasks.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Per-domain and global semaphores shared across buffered and streaming I/O.
#[derive(Clone, Debug)]
pub(crate) struct Bulkhead {
    pub(crate) domain: Arc<Semaphore>,
    pub(crate) global: Arc<Semaphore>,
    pub(crate) counters: Arc<Counters>,
}

impl Bulkhead {
    pub(crate) async fn acquire_owned(&self) -> (OwnedSemaphorePermit, OwnedSemaphorePermit) {
        let domain_permit = Arc::clone(&self.domain)
            .acquire_owned()
            .await
            .expect("domain semaphore closed");
        let global_permit = Arc::clone(&self.global)
            .acquire_owned()
            .await
            .expect("global semaphore closed");
        (domain_permit, global_permit)
    }

    /// Runs `op` on Tokio's blocking pool while holding both permits inside the
    /// blocking closure, so cancelling the outer future does not release slots
    /// before the syscall finishes.
    pub(crate) async fn run_blocking<T, F>(&self, op: F) -> io::Result<T>
    where
        T: Send + 'static,
        F: FnOnce() -> io::Result<T> + Send + 'static,
    {
        let permits = self.acquire_owned().await;
        let counters = Arc::clone(&self.counters);
        tokio::task::spawn_blocking(move || {
            let _held = permits;
            let _running = counters.enter_blocking();
            op()
        })
        .await
        .map_err(|e| io::Error::other(format!("fs blocking task panicked: {e}")))?
    }
}

type ReadStep = io::Result<(std::fs::File, Vec<u8>)>;
type SeekStep = io::Result<(std::fs::File, u64)>;
type WriteStep = io::Result<std::fs::File>;
type FlushStep = io::Result<std::fs::File>;

enum ReaderState {
    Idle(std::fs::File),
    Reading(Pin<Box<dyn Future<Output = ReadStep> + Send>>),
    Seeking(Pin<Box<dyn Future<Output = SeekStep> + Send>>),
    Poisoned,
}

/// Streaming read handle to a regular file inside a [`crate::Workspace`].
pub struct SandboxReader {
    state: ReaderState,
    meta_fd: OwnedFd,
    bulkhead: Bulkhead,
    buffered: Vec<u8>,
    consumed: usize,
    position: u64,
}

impl std::fmt::Debug for SandboxReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SandboxReader").finish_non_exhaustive()
    }
}

impl SandboxReader {
    fn new(file: std::fs::File, meta_fd: OwnedFd, bulkhead: Bulkhead) -> Self {
        Self {
            state: ReaderState::Idle(file),
            meta_fd,
            bulkhead,
            buffered: Vec::new(),
            consumed: 0,
            position: 0,
        }
    }

    pub async fn len(&self) -> io::Result<u64> {
        let fd = self.meta_fd.try_clone()?;
        // Bypass the bulkhead here: `fstat` reads already-opened inode metadata,
        // and taking a semaphore permit on `&self` could deadlock with a dormant
        // `Reading`/`Seeking` future stored inside `self.state`.
        tokio::task::spawn_blocking(move || Ok(fstat(&fd).map_err(errno_to_io)?.st_size as u64))
            .await
            .map_err(|e| io::Error::other(format!("stat task panicked: {e}")))?
    }

    pub async fn is_empty(&self) -> io::Result<bool> {
        Ok(self.len().await? == 0)
    }
}

impl AsyncRead for SandboxReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if self.consumed < self.buffered.len() {
                let n = buf.remaining().min(self.buffered.len() - self.consumed);
                buf.put_slice(&self.buffered[self.consumed..self.consumed + n]);
                self.consumed += n;
                self.position += n as u64;
                return Poll::Ready(Ok(()));
            }
            match std::mem::replace(&mut self.state, ReaderState::Poisoned) {
                ReaderState::Idle(mut file) => {
                    let want = buf.remaining().min(STREAM_BUF_CAP);
                    let bulkhead = self.bulkhead.clone();
                    let fut = Box::pin(async move {
                        bulkhead
                            .run_blocking(move || {
                                let mut chunk = vec![0u8; want];
                                let n = file.read(&mut chunk)?;
                                chunk.truncate(n);
                                Ok((file, chunk))
                            })
                            .await
                    });
                    self.state = ReaderState::Reading(fut);
                }
                ReaderState::Reading(mut fut) => match fut.as_mut().poll(cx) {
                    Poll::Pending => {
                        self.state = ReaderState::Reading(fut);
                        return Poll::Pending;
                    }
                    Poll::Ready(Ok((file, chunk))) => {
                        self.state = ReaderState::Idle(file);
                        self.buffered = chunk;
                        self.consumed = 0;
                        if self.buffered.is_empty() {
                            return Poll::Ready(Ok(()));
                        }
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                },
                ReaderState::Seeking(mut fut) => match fut.as_mut().poll(cx) {
                    Poll::Pending => {
                        self.state = ReaderState::Seeking(fut);
                        return Poll::Pending;
                    }
                    Poll::Ready(Ok((file, pos))) => {
                        self.position = pos;
                        self.state = ReaderState::Idle(file);
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                },
                ReaderState::Poisoned => {
                    return Poll::Ready(Err(io::Error::other("reader failed previously")));
                }
            }
        }
    }
}

impl AsyncSeek for SandboxReader {
    fn start_seek(mut self: Pin<&mut Self>, position: SeekFrom) -> io::Result<()> {
        match std::mem::replace(&mut self.state, ReaderState::Poisoned) {
            ReaderState::Idle(mut file) => {
                // Adjust relative seeks for unread bytes buffered from a cancelled read.
                let position = match position {
                    SeekFrom::Current(offset) => {
                        let unread = (self.buffered.len() - self.consumed) as i64;
                        let Some(adjusted) = offset.checked_sub(unread) else {
                            self.state = ReaderState::Idle(file);
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "relative seek offset overflow",
                            ));
                        };
                        SeekFrom::Current(adjusted)
                    }
                    other => other,
                };
                self.buffered.clear();
                self.consumed = 0;
                let bulkhead = self.bulkhead.clone();
                let fut = Box::pin(async move {
                    bulkhead
                        .run_blocking(move || {
                            let pos = file.seek(position)?;
                            Ok((file, pos))
                        })
                        .await
                });
                self.state = ReaderState::Seeking(fut);
                Ok(())
            }
            other => {
                self.state = other;
                Err(io::Error::other("reader busy or poisoned"))
            }
        }
    }

    fn poll_complete(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        match std::mem::replace(&mut self.state, ReaderState::Poisoned) {
            ReaderState::Idle(file) => {
                self.state = ReaderState::Idle(file);
                Poll::Ready(Ok(self.position))
            }
            ReaderState::Reading(mut fut) => match fut.as_mut().poll(cx) {
                Poll::Pending => {
                    self.state = ReaderState::Reading(fut);
                    Poll::Pending
                }
                Poll::Ready(Ok((file, chunk))) => {
                    self.state = ReaderState::Idle(file);
                    self.buffered = chunk;
                    self.consumed = 0;
                    Poll::Ready(Ok(self.position))
                }
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            },
            ReaderState::Seeking(mut fut) => match fut.as_mut().poll(cx) {
                Poll::Pending => {
                    self.state = ReaderState::Seeking(fut);
                    Poll::Pending
                }
                Poll::Ready(Ok((file, pos))) => {
                    self.state = ReaderState::Idle(file);
                    self.position = pos;
                    Poll::Ready(Ok(pos))
                }
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            },
            other => {
                self.state = other;
                Poll::Ready(Err(io::Error::other("reader busy or poisoned")))
            }
        }
    }
}

enum WriterState {
    Idle(std::fs::File),
    Writing(Pin<Box<dyn Future<Output = WriteStep> + Send>>),
    Flushing(Pin<Box<dyn Future<Output = FlushStep> + Send>>),
    Shutdown(std::fs::File),
    Poisoned,
}

struct StagedFile {
    parent_fd: OwnedFd,
    temp_name: CString,
    leaf_name: CString,
    published: bool,
}

impl StagedFile {
    fn publish(mut self) -> io::Result<()> {
        renameat(
            &self.parent_fd,
            self.temp_name.as_c_str(),
            &self.parent_fd,
            self.leaf_name.as_c_str(),
        )
        .map_err(errno_to_io)?;
        self.published = true;
        Ok(())
    }
}

impl Drop for StagedFile {
    fn drop(&mut self) {
        if !self.published {
            let _ = unlinkat(&self.parent_fd, self.temp_name.as_c_str(), AtFlags::empty());
        }
    }
}

/// Staged streaming writer inside a [`crate::Workspace`].
///
/// Writes go to a temporary file in the target directory and only become
/// visible at the target path when [`SandboxWriter::commit`] succeeds.
pub struct SandboxWriter {
    state: WriterState,
    bulkhead: Bulkhead,
    staged: Option<StagedFile>,
}

impl std::fmt::Debug for SandboxWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SandboxWriter")
            .field("submitted", &self.staged.is_none())
            .finish_non_exhaustive()
    }
}

impl SandboxWriter {
    /// Flushes buffered data and renames the temporary file onto the target path.
    pub async fn commit(mut self) -> io::Result<()> {
        if !matches!(self.state, WriterState::Shutdown(_)) {
            self.flush().await?;
        }
        let file = match std::mem::replace(&mut self.state, WriterState::Poisoned) {
            WriterState::Idle(f) | WriterState::Shutdown(f) => f,
            _ => return Err(io::Error::other("writer had incomplete in-flight state")),
        };
        drop(file);

        let staged = self.staged.take().expect("writer owns staged file");
        self.bulkhead.run_blocking(move || staged.publish()).await
    }

    fn poll_drain(&mut self, cx: &mut Context<'_>, seal_after_flush: bool) -> Poll<io::Result<()>> {
        loop {
            match std::mem::replace(&mut self.state, WriterState::Poisoned) {
                WriterState::Idle(mut file) => {
                    let bulkhead = self.bulkhead.clone();
                    let fut = Box::pin(async move {
                        bulkhead
                            .run_blocking(move || {
                                file.flush()?;
                                Ok(file)
                            })
                            .await
                    });
                    self.state = WriterState::Flushing(fut);
                }
                WriterState::Flushing(mut fut) => match fut.as_mut().poll(cx) {
                    Poll::Pending => {
                        self.state = WriterState::Flushing(fut);
                        return Poll::Pending;
                    }
                    Poll::Ready(Ok(file)) => {
                        self.state = if seal_after_flush {
                            WriterState::Shutdown(file)
                        } else {
                            WriterState::Idle(file)
                        };
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                },
                WriterState::Writing(mut fut) => match fut.as_mut().poll(cx) {
                    Poll::Pending => {
                        self.state = WriterState::Writing(fut);
                        return Poll::Pending;
                    }
                    Poll::Ready(Ok(file)) => {
                        self.state = WriterState::Idle(file);
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                },
                WriterState::Shutdown(file) => {
                    self.state = WriterState::Shutdown(file);
                    return Poll::Ready(Ok(()));
                }
                WriterState::Poisoned => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "writer failed previously",
                    )));
                }
            }
        }
    }
}

impl AsyncWrite for SandboxWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if matches!(self.state, WriterState::Shutdown(_)) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "writer has been shut down",
            )));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        loop {
            match std::mem::replace(&mut self.state, WriterState::Poisoned) {
                WriterState::Idle(mut file) => {
                    let chunk = buf[..buf.len().min(STREAM_BUF_CAP)].to_vec();
                    let accepted = chunk.len();
                    let bulkhead = self.bulkhead.clone();
                    let fut = Box::pin(async move {
                        bulkhead
                            .run_blocking(move || {
                                file.write_all(&chunk)?;
                                Ok(file)
                            })
                            .await
                    });
                    self.state = WriterState::Writing(fut);
                    return Poll::Ready(Ok(accepted));
                }
                WriterState::Writing(mut fut) => match fut.as_mut().poll(cx) {
                    Poll::Pending => {
                        self.state = WriterState::Writing(fut);
                        return Poll::Pending;
                    }
                    Poll::Ready(Ok(file)) => {
                        self.state = WriterState::Idle(file);
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                },
                WriterState::Flushing(mut fut) => match fut.as_mut().poll(cx) {
                    Poll::Pending => {
                        self.state = WriterState::Flushing(fut);
                        return Poll::Pending;
                    }
                    Poll::Ready(Ok(file)) => self.state = WriterState::Idle(file),
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                },
                WriterState::Shutdown(file) => {
                    self.state = WriterState::Shutdown(file);
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "writer has been shut down",
                    )));
                }
                WriterState::Poisoned => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "writer failed previously",
                    )));
                }
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_drain(cx, false)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_drain(cx, true)
    }
}

pub(crate) fn validate_path(path: &[u8]) -> io::Result<()> {
    if path.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path must not be empty",
        ));
    }
    if path.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path must not contain NUL bytes",
        ));
    }
    Ok(())
}

fn open_in_root(
    root_fd: BorrowedFd<'_>,
    path: &[u8],
    oflags: OFlags,
    mode: Mode,
) -> Result<OwnedFd, Errno> {
    // `openat2(RESOLVE_IN_ROOT)` can return EAGAIN if a concurrent rename bumps
    // the kernel's `rename_lock` sequence counter mid-lookup; retry per openat2(2).
    loop {
        match openat2(
            root_fd,
            OsStr::from_bytes(path),
            oflags | OFlags::CLOEXEC,
            mode,
            ResolveFlags::IN_ROOT | ResolveFlags::NO_MAGICLINKS,
        ) {
            Err(Errno::AGAIN | Errno::INTR) => std::thread::yield_now(),
            other => return other,
        }
    }
}

pub(crate) fn open_regular_readonly(root_fd: BorrowedFd<'_>, path: &[u8]) -> io::Result<OwnedFd> {
    validate_path(path)?;
    let fd = open_in_root(
        root_fd,
        path,
        OFlags::RDONLY | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(errno_to_io)?;
    let st = fstat(&fd).map_err(errno_to_io)?;
    match FileType::from_raw_mode(st.st_mode) {
        FileType::Directory => return Err(errno_to_io(Errno::ISDIR)),
        FileType::RegularFile => {}
        _ => return Err(errno_to_io(Errno::INVAL)),
    }
    rustix::fs::fcntl_setfl(&fd, OFlags::RDONLY).map_err(errno_to_io)?;
    Ok(fd)
}

pub(crate) fn read_bounded(
    root_fd: BorrowedFd<'_>,
    path: &[u8],
    max_payload: usize,
) -> io::Result<Vec<u8>> {
    let fd = open_regular_readonly(root_fd, path)?;
    let st = fstat(&fd).map_err(errno_to_io)?;
    if st.st_size > 0 && (st.st_size as u64) > max_payload as u64 {
        return Err(errno_to_io(Errno::FBIG));
    }
    let mut file = std::fs::File::from(fd);
    let mut buf = Vec::new();
    (&mut file)
        .take(max_payload as u64 + 1)
        .read_to_end(&mut buf)?;
    if buf.len() > max_payload {
        return Err(errno_to_io(Errno::FBIG));
    }
    Ok(buf)
}

pub(crate) fn open_reader(
    root_fd: BorrowedFd<'_>,
    path: &[u8],
    bulkhead: Bulkhead,
) -> io::Result<SandboxReader> {
    let fd = open_regular_readonly(root_fd, path)?;
    let meta_fd = fd.try_clone()?;
    Ok(SandboxReader::new(
        std::fs::File::from(fd),
        meta_fd,
        bulkhead,
    ))
}

pub(crate) fn open_writer(
    root_fd: BorrowedFd<'_>,
    path: &[u8],
    bulkhead: Bulkhead,
) -> io::Result<SandboxWriter> {
    validate_path(path)?;
    let (parent_fd, leaf_name, mode) =
        resolve_target_parent_and_mode(root_fd, path).map_err(errno_to_io)?;
    let (temp_name, tmp_fd) = create_temp_sibling(parent_fd.as_fd(), mode).map_err(errno_to_io)?;
    Ok(SandboxWriter {
        state: WriterState::Idle(std::fs::File::from(tmp_fd)),
        bulkhead,
        staged: Some(StagedFile {
            parent_fd,
            temp_name,
            leaf_name,
            published: false,
        }),
    })
}

pub(crate) fn write_atomic(
    root_fd: BorrowedFd<'_>,
    path: &[u8],
    data: &[u8],
    max_payload: usize,
) -> io::Result<()> {
    validate_path(path)?;
    if data.len() > max_payload {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "payload of {} bytes exceeds {max_payload}-byte limit",
                data.len()
            ),
        ));
    }
    let (parent_fd, leaf, mode) =
        resolve_target_parent_and_mode(root_fd, path).map_err(errno_to_io)?;
    let (tmp_name, tmp_fd) = create_temp_sibling(parent_fd.as_fd(), mode).map_err(errno_to_io)?;
    let mut tmp_file = std::fs::File::from(tmp_fd);
    let write_res = tmp_file.write_all(data);
    drop(tmp_file);

    if let Err(err) = write_res {
        let _ = unlinkat(&parent_fd, tmp_name.as_c_str(), AtFlags::empty());
        return Err(err);
    }
    if let Err(err) = renameat(&parent_fd, tmp_name.as_c_str(), &parent_fd, leaf.as_c_str()) {
        let _ = unlinkat(&parent_fd, tmp_name.as_c_str(), AtFlags::empty());
        return Err(errno_to_io(err));
    }
    Ok(())
}

pub(crate) fn list_bounded(
    root_fd: BorrowedFd<'_>,
    path: &[u8],
    max_payload: usize,
) -> io::Result<Vec<OsString>> {
    validate_path(path)?;
    let dir_fd = open_in_root(
        root_fd,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .map_err(errno_to_io)?;
    let dir = Dir::read_from(dir_fd).map_err(errno_to_io)?;

    let mut names: Vec<OsString> = Vec::new();
    let mut total_bytes = 0usize;

    for entry in dir {
        let entry = entry.map_err(errno_to_io)?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." || name.starts_with(TEMP_PREFIX) {
            continue;
        }
        total_bytes = total_bytes.saturating_add(name.len() + 1);
        if total_bytes > max_payload {
            return Err(errno_to_io(Errno::FBIG));
        }
        names.push(OsString::from_vec(name.to_vec()));
    }

    names.sort();
    Ok(names)
}

fn split_parent_and_leaf(path: &[u8]) -> Result<(&[u8], CString), Errno> {
    let mut trimmed = path;
    while trimmed.len() > 1 && trimmed.last() == Some(&b'/') {
        trimmed = &trimmed[..trimmed.len() - 1];
    }
    let (parent, leaf) = match trimmed.iter().rposition(|&b| b == b'/') {
        Some(idx) => {
            let p = if idx == 0 { &b"."[..] } else { &trimmed[..idx] };
            (p, &trimmed[idx + 1..])
        }
        None => (&b"."[..], trimmed),
    };
    if leaf.is_empty() || leaf == b"." {
        return Err(Errno::ISDIR);
    }
    if leaf == b".." {
        return Err(Errno::INVAL);
    }
    let c_leaf = CString::new(leaf).map_err(|_| Errno::INVAL)?;
    Ok((parent, c_leaf))
}

fn resolve_target_parent_and_mode(
    root_fd: BorrowedFd<'_>,
    path: &[u8],
) -> Result<(OwnedFd, CString, Mode), Errno> {
    let (parent_path, leaf) = split_parent_and_leaf(path)?;
    let parent_fd = open_in_root(
        root_fd,
        parent_path,
        OFlags::RDONLY | OFlags::DIRECTORY,
        Mode::empty(),
    )?;

    let mut mode = Mode::from_raw_mode(0o666);
    if let Ok(st) = statat(&parent_fd, leaf.as_c_str(), AtFlags::SYMLINK_NOFOLLOW) {
        let kind = FileType::from_raw_mode(st.st_mode);
        if kind == FileType::Directory {
            return Err(Errno::ISDIR);
        }
        if kind == FileType::RegularFile {
            mode = Mode::from_raw_mode(st.st_mode & 0o7777);
        }
    }
    Ok((parent_fd, leaf, mode))
}

fn create_temp_sibling(parent_fd: BorrowedFd<'_>, mode: Mode) -> Result<(CString, OwnedFd), Errno> {
    static NEXT_TMP: AtomicU64 = AtomicU64::new(0);
    let pid = std::process::id();
    for _ in 0..64 {
        let seq = NEXT_TMP.fetch_add(1, Ordering::Relaxed);
        let name = CString::new(format!(".cs-tmp-{pid}-{seq}")).unwrap();
        match openat(
            parent_fd,
            name.as_c_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            mode,
        ) {
            Ok(fd) => return Ok((name, fd)),
            Err(Errno::EXIST) => continue,
            Err(err) => return Err(err),
        }
    }
    Err(Errno::EXIST)
}

fn errno_to_io(err: Errno) -> io::Error {
    io::Error::from_raw_os_error(err.raw_os_error())
}

#[cfg(test)]
mod tests;
