//! `bubblewrap` command builder and host layout detection.

use std::ffi::{OsStr, OsString};
use std::io;
use std::os::fd::{OwnedFd, RawFd};
use std::path::PathBuf;
use std::sync::{mpsc, LazyLock};

use tokio::process::Command;
use tokio::sync::oneshot;

use crate::seccomp;

pub(crate) const WORK_DIR: &str = "/work";
type SpawnJob = Box<dyn FnOnce() + Send>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Access {
    ReadOnly,
    ReadWrite,
}

impl Access {
    pub(crate) fn bind_fd_flag(self) -> &'static str {
        match self {
            Self::ReadOnly => "--ro-bind-fd",
            Self::ReadWrite => "--bind-fd",
        }
    }
}

pub(crate) struct BwrapLayout {
    bwrap: PathBuf,
    sys_args: Vec<OsString>,
    exec_seccomp_bpf: Vec<u8>,
    spawner: LazyLock<io::Result<mpsc::Sender<SpawnJob>>>,
}

impl BwrapLayout {
    pub(crate) fn probe(bwrap: PathBuf) -> io::Result<Self> {
        let mut sys_args = Vec::new();
        sys_args.extend(["--ro-bind".into(), "/usr".into(), "/usr".into()]);
        for top in ["/bin", "/sbin", "/lib", "/lib32", "/lib64"] {
            match std::fs::symlink_metadata(top) {
                Ok(meta) if meta.file_type().is_symlink() => {
                    let target = std::fs::read_link(top)?;
                    sys_args.push("--symlink".into());
                    sys_args.push(target.into_os_string());
                    sys_args.push(top.into());
                }
                Ok(meta) if meta.is_dir() => {
                    sys_args.push("--ro-bind".into());
                    sys_args.push(top.into());
                    sys_args.push(top.into());
                }
                _ => {}
            }
        }

        Ok(Self {
            bwrap,
            sys_args,
            exec_seccomp_bpf: seccomp::default_exec_bpf_bytes(),
            spawner: LazyLock::new(start_spawner_thread),
        })
    }

    /// Runs `op` on a dedicated spawner thread whose lifetime matches this
    /// `BwrapLayout` (unlike `tokio::task::spawn_blocking`, whose threads exit
    /// after 10s idle and would trigger `bwrap --die-with-parent`'s `PDEATHSIG`
    /// mid-execution on commands running longer than 10s).
    pub(crate) async fn run_spawn<T, F>(&self, op: F) -> io::Result<T>
    where
        T: Send + 'static,
        F: FnOnce() -> io::Result<T> + Send + 'static,
    {
        let tx = self
            .spawner
            .as_ref()
            .map_err(|e| io::Error::new(e.kind(), e.to_string()))?;

        let rt = tokio::runtime::Handle::current();
        let (done_tx, done_rx) = oneshot::channel();
        let job: SpawnJob = Box::new(move || {
            let _guard = rt.enter();
            let _ = done_tx.send(op());
        });
        tx.send(job)
            .map_err(|_| io::Error::other("bwrap spawner thread exited"))?;
        done_rx
            .await
            .map_err(|_| io::Error::other("bwrap spawner dropped job"))?
    }

    pub(crate) fn make_exec_seccomp_fd(&self) -> io::Result<Option<OwnedFd>> {
        if self.exec_seccomp_bpf.is_empty() {
            return Ok(None);
        }
        seccomp::create_seccomp_memfd(&self.exec_seccomp_bpf).map(Some)
    }

    pub(crate) fn oneshot_exec_command<I, S>(
        &self,
        dir_fd: RawFd,
        access: Access,
        status_fd: RawFd,
        seccomp_fd: Option<RawFd>,
        program: &OsStr,
        args: I,
    ) -> Command
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut inherited = vec![dir_fd, status_fd];
        let mut cmd = Command::new(&self.bwrap);
        cmd.args(&self.sys_args)
            .args(["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"])
            .arg(access.bind_fd_flag())
            .arg(dir_fd.to_string())
            .arg(WORK_DIR)
            .args(["--chdir", WORK_DIR])
            .args(["--unshare-all", "--unshare-user", "--disable-userns"])
            .args(["--cap-drop", "ALL"])
            .args(["--new-session", "--die-with-parent"])
            .args([
                "--clearenv",
                "--setenv",
                "PATH",
                "/usr/bin:/bin:/usr/sbin:/sbin",
            ])
            .arg("--json-status-fd")
            .arg(status_fd.to_string());

        if let Some(sfd) = seccomp_fd {
            cmd.arg("--seccomp").arg(sfd.to_string());
            inherited.push(sfd);
        }

        cmd.arg("--").arg(program).args(args);
        inherit_fds(&mut cmd, &inherited);
        cmd
    }
}

fn start_spawner_thread() -> io::Result<mpsc::Sender<SpawnJob>> {
    let (tx, rx) = mpsc::channel::<SpawnJob>();
    std::thread::Builder::new()
        .name("cs-bwrap-spawner".into())
        .spawn(move || {
            while let Ok(job) = rx.recv() {
                job();
            }
        })
        .map(|_| tx)
}

pub(crate) fn inherit_fds(cmd: &mut Command, fds: &[RawFd]) {
    let fds: Vec<RawFd> = fds.to_vec();
    // SAFETY: runs between fork and exec; `fcntl` is async-signal-safe.
    unsafe {
        cmd.pre_exec(move || {
            for &fd in &fds {
                if libc::fcntl(fd, libc::F_SETFD, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
}
