//! Integration tests for `coroutine-sandbox`.

#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use std::ffi::OsString;
use std::io::{ErrorKind, SeekFrom};
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use coroutine_sandbox::{Access, ExecOutput, Limits, Sandbox, Workspace};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

fn sandbox(limits: Limits) -> Sandbox {
    let bwrap = std::env::var_os("BWRAP").unwrap_or_else(|| "bwrap".into());
    Sandbox::new(bwrap, limits).expect("Sandbox::new")
}

struct Scratch(PathBuf);

impl Scratch {
    fn new(names: &[&str]) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "coroutine-sandbox-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        for name in names {
            std::fs::create_dir_all(root.join(name)).unwrap();
            std::fs::write(
                root.join(name).join("secret.txt"),
                format!("secret of {name}\n"),
            )
            .unwrap();
        }
        Self(root.canonicalize().unwrap())
    }

    fn dir(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim().to_string()
}

async fn sh(ws: &Workspace, script: &str) -> ExecOutput {
    ws.exec("sh", ["-c", script]).await.unwrap()
}

fn host_entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// Scans **host** `/proc` to count live processes whose cmdline contains `needle`.
fn count_host_processes_with_arg(needle: &str) -> usize {
    let Ok(proc_dir) = std::fs::read_dir("/proc") else {
        return 0;
    };
    let mut count = 0;
    for entry in proc_dir.flatten() {
        if entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<i32>().ok())
            .is_none()
        {
            continue;
        }
        let Ok(cmdline) = std::fs::read(entry.path().join("cmdline")) else {
            continue;
        };
        let Ok(status) = std::fs::read_to_string(entry.path().join("status")) else {
            continue;
        };
        if status.lines().any(|l| l.starts_with("State:\tZ")) {
            continue;
        }
        if String::from_utf8_lossy(&cmdline).contains(needle) {
            count += 1;
        }
    }
    count
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn each_task_reaches_only_its_own_directory() {
    let scratch = Scratch::new(&["A", "B", "C"]);
    std::os::unix::fs::symlink(
        scratch.dir("B").join("secret.txt"),
        scratch.dir("A").join("link-to-B"),
    )
    .unwrap();
    let sb = sandbox(Limits::default());

    let mut tasks = Vec::new();
    for name in ["A", "B", "C"] {
        let ws = sb.workspace(scratch.dir(name), Access::ReadWrite).unwrap();
        let others: Vec<PathBuf> = ["A", "B", "C"]
            .iter()
            .filter(|&&o| o != name)
            .map(|o| scratch.dir(o))
            .collect();

        tasks.push(tokio::spawn(async move {
            assert_eq!(
                ws.read(Path::new("secret.txt")).await.unwrap(),
                format!("secret of {name}\n").as_bytes()
            );
            let own_file = PathBuf::from(format!("own-{name}.txt"));
            ws.write(&own_file, name.as_bytes()).await.unwrap();
            assert!(ws
                .list(".")
                .await
                .unwrap()
                .contains(&own_file.into_os_string()));

            let found = sh(
                &ws,
                "find / -name secret.txt -not -path '/proc/*' 2>/dev/null",
            )
            .await;
            assert_eq!(text(&found.stdout), "/work/secret.txt");

            for other in &others {
                let other_name = other.file_name().unwrap().to_str().unwrap();
                let host_secret = other.join("secret.txt");

                let rel_err = ws
                    .read(format!("../{other_name}/secret.txt"))
                    .await
                    .unwrap_err();
                assert_eq!(rel_err.kind(), ErrorKind::NotFound);
                assert_eq!(rel_err.raw_os_error(), Some(libc::ENOENT));

                let abs_err = ws.read(&host_secret).await.unwrap_err();
                assert_eq!(abs_err.raw_os_error(), Some(libc::ENOENT));

                let cat = ws.exec("cat", [&host_secret]).await.unwrap();
                assert!(!cat.success() && cat.stdout.is_empty());
            }

            if name == "A" {
                let err = ws.read("link-to-B").await.unwrap_err();
                assert_eq!(err.raw_os_error(), Some(libc::ENOENT));
            }
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }

    for name in ["A", "B", "C"] {
        let mut expected = vec![format!("own-{name}.txt"), "secret.txt".to_string()];
        if name == "A" {
            expected.insert(0, "link-to-B".to_string());
        }
        assert_eq!(host_entries(&scratch.dir(name)), expected);
    }
}

#[tokio::test]
async fn openat2_confines_absolute_paths_magic_links_and_readonly_invariants() {
    let scratch = Scratch::new(&["A"]);
    let sb = sandbox(Limits::default());
    let rw = sb.workspace(scratch.dir("A"), Access::ReadWrite).unwrap();
    let ro = sb.workspace(scratch.dir("A"), Access::ReadOnly).unwrap();

    assert_eq!(rw.read("/secret.txt").await.unwrap(), b"secret of A\n");

    for escaped in ["/etc/passwd", "/proc/self/maps", "/usr/bin/sh", "/dev/zero"] {
        let err = rw.read(escaped).await.unwrap_err();
        assert_eq!(
            err.raw_os_error(),
            Some(libc::ENOENT),
            "escaped via {escaped}"
        );
    }
    assert_eq!(
        ro.write("/tmp/evil", b"x")
            .await
            .unwrap_err()
            .raw_os_error(),
        Some(libc::ENOENT)
    );
    assert_eq!(
        ro.write("/evil", b"x").await.unwrap_err().raw_os_error(),
        Some(libc::EROFS)
    );
    assert_eq!(
        ro.open_write("evil.bin").await.unwrap_err().raw_os_error(),
        Some(libc::EROFS)
    );
    assert!(!sh(&ro, "rm secret.txt").await.success());
    assert_eq!(host_entries(&scratch.dir("A")), ["secret.txt"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exec_seccomp_blocks_denylist_and_x32_and_cleans_daemons_on_host() {
    let scratch = Scratch::new(&["A"]);
    let ws = sandbox(Limits::default())
        .workspace(scratch.dir("A"), Access::ReadWrite)
        .unwrap();

    let seccomp_status = sh(&ws, "grep '^Seccomp:' /proc/self/status").await;
    assert_eq!(text(&seccomp_status.stdout), "Seccomp:\t2");

    let probe_py = r#"
import ctypes
libc = ctypes.CDLL(None, use_errno=True)
for name, nr in [("bpf", 321), ("keyctl", 250), ("io_uring_setup", 425), ("userfaultfd", 323)]:
    rc = libc.syscall(nr, 0, 0, 0, 0, 0)
    err = ctypes.get_errno()
    print(f"{name}:{rc}:{err}")
"#;
    if Path::new("/usr/bin/python3").exists() && cfg!(target_arch = "x86_64") {
        let py = ws.exec("python3", ["-c", probe_py]).await.unwrap();
        assert!(py.success(), "{:?}", text(&py.stderr));
        for line in text(&py.stdout).lines() {
            assert!(
                line.ends_with(":-1:1"),
                "expected EPERM (errno=1) from seccomp filter, got {line}"
            );
        }

        // Verify `__X32_SYSCALL_BIT` (`0x4000_0000 | SYS_getpid`) triggers immediate
        // `SECCOMP_RET_KILL_PROCESS` (`SIGSYS` = signal 31 -> bwrap exit code `128 + 31 = 159`)!
        let x32_probe = ws
            .exec(
                "python3",
                ["-c", "import ctypes; ctypes.CDLL(None).syscall(0x40000027)"],
            )
            .await
            .unwrap();
        assert_eq!(
            x32_probe.code, 159,
            "x32 syscall bit must kill process with SIGSYS (159), got {x32_probe:?}"
        );
    }

    // Verify FROM THE HOST'S `/proc` that a `setsid` background daemon spawned inside
    // `exec` (after timeout) is completely gone on the host once `exec` returns!
    let ws_short = sandbox(Limits {
        exec_timeout: Duration::from_millis(500),
        ..Limits::default()
    })
    .workspace(scratch.dir("A"), Access::ReadWrite)
    .unwrap();

    let unique_sleep = "31.415926";
    let _ = ws_short
        .exec(
            "sh",
            [
                "-c",
                &format!("setsid sleep {unique_sleep} </dev/null >/dev/null 2>&1 & sleep 10"),
            ],
        )
        .await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        count_host_processes_with_arg(unique_sleep),
        0,
        "setsid daemon leaked on host after exec sandbox teardown"
    );
}

#[tokio::test]
async fn output_overflow_kills_sigpipe_ignoring_child_immediately_not_waiting_for_timeout() {
    let scratch = Scratch::new(&["A"]);
    // Set a huge `exec_timeout` (30s) and tiny `max_payload` (64 KiB).
    let ws = sandbox(Limits {
        max_payload: 64 << 10,
        exec_timeout: Duration::from_secs(30),
        ..Limits::default()
    })
    .workspace(scratch.dir("A"), Access::ReadWrite)
    .unwrap();

    // Child ignores SIGPIPE, writes 256 KiB (> 64 KiB cap), then sleeps 25.12345s!
    // Previously `tokio::join!` waited 30s and returned `TimedOut`; now `try_join!` +
    // `child.kill().await` must return `FileTooLarge` (`EFBIG`) in well under 3s and
    // leave zero sleeping processes on the host!
    let unique_sleep = "25.12345";
    let script = format!("trap '' PIPE; head -c 262144 /dev/zero; exec sleep {unique_sleep}");
    let t0 = Instant::now();
    let err = ws.exec("sh", ["-c", &script]).await.unwrap_err();
    let elapsed = t0.elapsed();

    assert_eq!(
        err.kind(),
        ErrorKind::FileTooLarge,
        "expected FileTooLarge, got {err:?}"
    );
    assert_eq!(err.raw_os_error(), Some(libc::EFBIG));
    assert!(
        elapsed < Duration::from_secs(3),
        "overflow waited {elapsed:?} instead of killing child immediately"
    );

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        count_host_processes_with_arg(unique_sleep),
        0,
        "overflowing child survived on host"
    );
}

#[tokio::test]
async fn combined_output_overflow_terminates_before_timeout() {
    let scratch = Scratch::new(&["A"]);
    let ws = sandbox(Limits {
        max_payload: 8,
        exec_timeout: Duration::from_secs(5),
        ..Limits::default()
    })
    .workspace(scratch.dir("A"), Access::ReadWrite)
    .unwrap();
    let started = Instant::now();
    let err = ws
        .exec(
            "sh",
            ["-c", "printf 123456; printf 123456 >&2; exec sleep 20"],
        )
        .await
        .unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::EFBIG));
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[tokio::test]
async fn combined_output_accepts_exact_budget_and_handles_zero_budget() {
    let scratch = Scratch::new(&["A"]);
    for (max_payload, script, stdout, stderr) in [
        (
            8,
            "printf 1234; printf 5678 >&2",
            &b"1234"[..],
            &b"5678"[..],
        ),
        (0, "true", &b""[..], &b""[..]),
    ] {
        let ws = sandbox(Limits {
            max_payload,
            ..Limits::default()
        })
        .workspace(scratch.dir("A"), Access::ReadWrite)
        .unwrap();
        let out = ws.exec("sh", ["-c", script]).await.unwrap();
        assert!(out.success());
        assert_eq!(out.stdout, stdout);
        assert_eq!(out.stderr, stderr);
        if max_payload == 0 {
            let err = ws.exec("sh", ["-c", "printf x >&2"]).await.unwrap_err();
            assert_eq!(err.raw_os_error(), Some(libc::EFBIG));
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancellation_storms_respect_bulkhead_cap_and_exec_fd_ownership() {
    let scratch = Scratch::new(&["A", "B"]);
    let max_global = 4usize;
    let sb = std::sync::Arc::new(sandbox(Limits {
        max_in_flight: 8,
        max_global_fs_in_flight: max_global,
        ..Limits::default()
    }));
    let ws = sb.workspace(scratch.dir("A"), Access::ReadWrite).unwrap();
    ws.write("blob.bin", vec![0x42u8; 256 << 10]).await.unwrap();

    // 1. Fire 300 tasks cancelling `read`, `write`, and streaming `open_read` mid-flight.
    //    Because `OwnedSemaphorePermit` lives inside `spawn_blocking`, `peak_running_fs_tasks`
    //    must NEVER exceed `max_global_fs_in_flight` (4)!
    let mut tasks = Vec::new();
    for i in 0..300 {
        let ws = ws.clone();
        tasks.push(tokio::spawn(async move {
            let _ = tokio::time::timeout(Duration::from_micros(5), ws.read("blob.bin")).await;
            if i % 3 == 0 {
                if let Ok(mut r) = ws.open_read("blob.bin").await {
                    let mut buf = vec![0u8; 128 << 10];
                    let _ = tokio::time::timeout(Duration::from_micros(5), r.read(&mut buf)).await;
                }
            }
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    // Wait briefly for any in-flight blocking closures from cancelled futures to finish.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let stats = sb.stats();
    assert_eq!(stats.running_fs_tasks, 0);
    assert!(
        stats.peak_running_fs_tasks <= max_global,
        "cancellation storm breached global fs bulkhead: peak={} > cap={max_global}",
        stats.peak_running_fs_tasks
    );

    // 2. Rapidly create ephemeral `Workspace` for A, start `exec`, cancel immediately,
    //    drop `Workspace`, while concurrently opening descriptors to B—verifying no
    //    `RawFd` use-after-close / cross-mount occurs.
    let mut churn = Vec::new();
    for _ in 0..40 {
        let sb_clone = std::sync::Arc::clone(&sb);
        let dir_a = scratch.dir("A");
        let dir_b = scratch.dir("B");
        churn.push(tokio::spawn(async move {
            let ephemeral = sb_clone.workspace(&dir_a, Access::ReadOnly).unwrap();
            let _ = tokio::time::timeout(
                Duration::from_micros(10),
                ephemeral.exec("cat", ["secret.txt"]),
            )
            .await;
            drop(ephemeral);
            // Immediately open unrelated descriptors on the host to encourage fd number reuse.
            let _f = std::fs::File::open(dir_b.join("secret.txt")).unwrap();
        }));
    }
    for c in churn {
        c.await.unwrap();
    }
    // Confirm a clean subsequent exec on A still reads A's secret, never B's.
    let clean_ws = sb.workspace(scratch.dir("A"), Access::ReadOnly).unwrap();
    let out = clean_ws.exec("cat", ["secret.txt"]).await.unwrap();
    assert_eq!(out.stdout, b"secret of A\n");
}

#[tokio::test]
async fn streaming_handles_large_files_and_synchronously_cleans_aborted_writes() {
    let scratch = Scratch::new(&["A", "B"]);
    std::os::unix::fs::symlink(
        scratch.dir("B").join("secret.txt"),
        scratch.dir("A").join("escape-sym"),
    )
    .unwrap();

    let sb = sandbox(Limits {
        max_payload: 64 << 10,
        ..Limits::default()
    });
    let ws = sb.workspace(scratch.dir("A"), Access::ReadWrite).unwrap();

    assert_eq!(
        ws.open_read(".").await.unwrap_err().raw_os_error(),
        Some(libc::EISDIR)
    );
    assert_eq!(
        ws.open_read("../B/secret.txt")
            .await
            .unwrap_err()
            .raw_os_error(),
        Some(libc::ENOENT)
    );
    assert_eq!(
        ws.open_read("escape-sym").await.unwrap_err().raw_os_error(),
        Some(libc::ENOENT)
    );

    {
        let mut aborted = ws.open_write("secret.txt").await.unwrap();
        aborted.write_all(b"CORRUPTED").await.unwrap();
        let during = ws.list(".").await.unwrap();
        assert!(!during
            .iter()
            .any(|n| n.to_string_lossy().starts_with(".cs-tmp-")));
    }
    assert_eq!(ws.read("secret.txt").await.unwrap(), b"secret of A\n");
    assert_eq!(
        host_entries(&scratch.dir("A")),
        ["escape-sym", "secret.txt"]
    );

    let mut writer = ws.open_write("huge.bin").await.unwrap();
    let block: Vec<u8> = (0..65_536usize).map(|i| (i % 251) as u8).collect();
    for _ in 0..64 {
        writer.write_all(&block).await.unwrap();
    }
    writer.commit().await.unwrap();

    assert_eq!(
        ws.read("huge.bin").await.unwrap_err().raw_os_error(),
        Some(libc::EFBIG)
    );

    let mut reader = ws.open_read("huge.bin").await.unwrap();
    assert_eq!(reader.len().await.unwrap(), 4 << 20);
    reader
        .seek(SeekFrom::Start((4 << 20) - 65_536))
        .await
        .unwrap();
    let mut tail = Vec::new();
    reader.read_to_end(&mut tail).await.unwrap();
    assert_eq!(tail, block);
}

#[tokio::test]
async fn path_swap_cannot_redirect_pinned_domain_or_exec_sandbox() {
    let scratch = Scratch::new(&["data/A", "outside"]);
    let sb = sandbox(Limits::default());
    let parent = sb
        .workspace(scratch.dir("data"), Access::ReadWrite)
        .unwrap();
    let a = sb
        .workspace(scratch.dir("data/A"), Access::ReadWrite)
        .unwrap();

    let outside = scratch.dir("outside");
    assert!(sh(
        &parent,
        &format!("mv A A.orig && ln -s {} A", outside.display())
    )
    .await
    .success());

    assert_eq!(a.read("secret.txt").await.unwrap(), b"secret of data/A\n");
    assert_eq!(
        text(&sh(&a, "cat secret.txt").await.stdout),
        "secret of data/A"
    );
    a.write("after-swap", b"ok").await.unwrap();
    assert!(scratch.dir("data/A.orig/after-swap").exists());
    assert_eq!(host_entries(&outside), ["secret.txt"]);
}

#[tokio::test]
async fn thousand_handles_deduplicate_to_single_fd_and_support_non_utf8_paths() {
    let scratch = Scratch::new(&["A"]);
    let dir_a = scratch.dir("A");
    let sb = sandbox(Limits::default());

    let handles: Vec<Workspace> = (0..1000)
        .map(|_| sb.workspace(&dir_a, Access::ReadWrite).unwrap())
        .collect();
    let open_fds_to_a = std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .flatten()
        .filter(|e| std::fs::read_link(e.path()).ok().as_deref() == Some(dir_a.as_path()))
        .count();
    assert_eq!(
        open_fds_to_a, 1,
        "1000 handles must share exactly 1 open fd to A"
    );
    assert_eq!(sb.stats().active_domains, 1);

    let ws = &handles[0];
    let odd_name = OsString::from_vec(vec![b'f', b'-', 0xff, 0xfe, b'.', b'b', b'i', b'n']);
    let payload: Vec<u8> = (0..=255u8).cycle().take(50_000).collect();
    ws.write(&odd_name, &payload).await.unwrap();
    assert!(ws.list(".").await.unwrap().contains(&odd_name));
    assert_eq!(ws.read(&odd_name).await.unwrap(), payload);
}

#[tokio::test]
async fn exec_timeout_and_fifo_protection() {
    let bad = Sandbox::new(
        "bwrap",
        Limits {
            max_global_fs_in_flight: 0,
            ..Limits::default()
        },
    );
    assert_eq!(bad.err().map(|e| e.kind()), Some(ErrorKind::InvalidInput));

    let scratch = Scratch::new(&["A"]);
    let ws = sandbox(Limits {
        exec_timeout: Duration::from_millis(600),
        max_payload: 1 << 20,
        ..Limits::default()
    })
    .workspace(scratch.dir("A"), Access::ReadWrite)
    .unwrap();

    let t0 = Instant::now();
    assert_eq!(
        ws.exec("sleep", ["30"]).await.unwrap_err().kind(),
        ErrorKind::TimedOut
    );
    assert!(t0.elapsed() < Duration::from_secs(4));

    assert!(sh(&ws, "mkfifo pipe0").await.success());
    assert_eq!(
        ws.read("pipe0").await.unwrap_err().raw_os_error(),
        Some(libc::EINVAL)
    );
    assert_eq!(
        ws.open_read("pipe0").await.unwrap_err().raw_os_error(),
        Some(libc::EINVAL)
    );
}
