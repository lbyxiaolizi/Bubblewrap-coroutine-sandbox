//! Per-call `bwrap` subprocess execution for [`crate::Workspace::exec`].

use std::ffi::OsStr;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::unix::pipe;
use tokio::sync::OwnedSemaphorePermit;

use crate::bwrap::{Access, BwrapLayout};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecOutput {
    /// Exit code reported by `bwrap` (`0..=255`; `128 + sig` if killed by signal).
    pub code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl ExecOutput {
    pub fn success(&self) -> bool {
        self.code == 0
    }
}

pub(crate) struct ExecSpec {
    pub(crate) layout: Arc<BwrapLayout>,
    pub(crate) dir_fd: OwnedFd,
    pub(crate) domain_permit: OwnedSemaphorePermit,
    pub(crate) access: Access,
    pub(crate) timeout: Duration,
    pub(crate) max_payload: usize,
}

pub(crate) async fn run_oneshot<I, S>(
    spec: ExecSpec,
    program: &OsStr,
    args: I,
) -> io::Result<ExecOutput>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let ExecSpec {
        layout,
        dir_fd,
        domain_permit,
        access,
        timeout,
        max_payload,
    } = spec;
    let prog = program.to_os_string();
    let arg_list: Vec<_> = args
        .into_iter()
        .map(|a| a.as_ref().to_os_string())
        .collect();

    // Spawn on `layout`'s dedicated persistent thread (not `spawn_blocking`,
    // whose 10s idle thread exit would fire `bwrap --die-with-parent`), while
    // keeping `layout` alive for the full duration of `run_oneshot`.
    let layout_for_spawn = Arc::clone(&layout);
    let (mut child, status_rx, _held_permit) = layout
        .run_spawn(move || -> io::Result<_> {
            let (status_tx, status_rx) = pipe::pipe()?;
            let status_fd = status_tx.into_blocking_fd()?;
            let seccomp_fd = layout_for_spawn.make_exec_seccomp_fd()?;
            let mut cmd = layout_for_spawn.oneshot_exec_command(
                dir_fd.as_raw_fd(),
                access,
                status_fd.as_raw_fd(),
                seccomp_fd.as_ref().map(AsRawFd::as_raw_fd),
                &prog,
                &arg_list,
            );
            let child = cmd
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .spawn()?;
            drop(status_fd);
            drop(seccomp_fd);
            drop(dir_fd);
            Ok((child, status_rx, domain_permit))
        })
        .await?;
    let _keep_spawner_alive = layout;

    let stdout = child.stdout.take().expect("stdout piped");
    let stderr = child.stderr.take().expect("stderr piped");
    let remaining = AtomicUsize::new(max_payload);

    let io_and_wait = async {
        let (bwrap_status, out, err, status_text) = tokio::try_join!(
            child.wait(),
            read_capped(stdout, &remaining),
            read_capped(stderr, &remaining),
            read_status_pipe(status_rx),
        )?;

        if let Some(code) = parse_exit_code(&status_text) {
            return Ok(ExecOutput {
                code,
                stdout: out,
                stderr: err,
            });
        }

        Err(classify_bwrap_failure(bwrap_status, &status_text, &err))
    };

    match tokio::time::timeout(timeout, io_and_wait).await {
        Ok(Ok(output)) => Ok(output),
        Ok(Err(err)) => {
            let _ = child.kill().await;
            Err(err)
        }
        Err(_) => {
            let _ = child.kill().await;
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("command exceeded {timeout:?} exec timeout"),
            ))
        }
    }
}

async fn read_capped(
    mut reader: impl AsyncRead + Unpin,
    remaining: &AtomicUsize,
) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let want = remaining
            .load(Ordering::Relaxed)
            .saturating_add(1)
            .min(chunk.len());
        let n = reader.read(&mut chunk[..want]).await?;
        if n == 0 {
            return Ok(buf);
        }
        reserve_budget(remaining, n)?;
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn reserve_budget(remaining: &AtomicUsize, n: usize) -> io::Result<()> {
    let mut left = remaining.load(Ordering::Relaxed);
    loop {
        let next = left
            .checked_sub(n)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EFBIG))?;
        match remaining.compare_exchange_weak(left, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return Ok(()),
            Err(observed) => left = observed,
        }
    }
}

async fn read_status_pipe(mut rx: pipe::Receiver) -> io::Result<String> {
    let mut buf = Vec::new();
    (&mut rx).take(16 << 10).read_to_end(&mut buf).await?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn parse_exit_code(status_json: &str) -> Option<i32> {
    for line in status_json.lines() {
        if let Some(pos) = line.find("\"exit-code\":") {
            let tail = line[pos + "\"exit-code\":".len()..].trim_start();
            let digits_len = tail
                .bytes()
                .take_while(|b| b.is_ascii_digit() || *b == b'-')
                .count();
            if digits_len > 0 {
                if let Ok(code) = tail[..digits_len].parse::<i32>() {
                    return Some(code);
                }
            }
        }
    }
    None
}

fn classify_bwrap_failure(
    bwrap_status: std::process::ExitStatus,
    status_text: &str,
    stderr: &[u8],
) -> io::Error {
    let msg = String::from_utf8_lossy(stderr).trim().to_string();
    let kind = if msg.contains("No such file or directory") {
        io::ErrorKind::NotFound
    } else if msg.contains("Permission denied") {
        io::ErrorKind::PermissionDenied
    } else {
        io::ErrorKind::Other
    };
    io::Error::new(
        kind,
        if msg.is_empty() {
            format!(
                "bwrap failed before starting command ({bwrap_status}, status={:?})",
                status_text.trim()
            )
        } else {
            msg
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bwrap_json_status_lines() {
        let sample = "{ \"child-pid\": 123, \"mnt-namespace\": 4026532 }\n{ \"exit-code\": 42 }\n";
        assert_eq!(parse_exit_code(sample), Some(42));
        assert_eq!(parse_exit_code("{ \"child-pid\": 123 }\n"), None);
    }
}
