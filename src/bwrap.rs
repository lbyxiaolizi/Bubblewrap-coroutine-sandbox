//! `bubblewrap` command builder and host layout detection.

use std::ffi::{OsStr, OsString};
use std::io;
use std::os::fd::{OwnedFd, RawFd};
use std::path::PathBuf;

use tokio::process::Command;

use crate::seccomp;

pub(crate) const WORK_DIR: &str = "/work";

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
        })
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
