use super::*;
use std::sync::atomic::AtomicUsize;
use std::task::Waker;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

struct Fixture {
    root: std::path::PathBuf,
    dir: std::fs::File,
    bulkhead: Bulkhead,
}

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "cs-stream-regression-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        let dir = std::fs::File::open(&root).unwrap();
        Self {
            root,
            dir,
            bulkhead: Bulkhead {
                domain: Arc::new(Semaphore::new(8)),
                global: Arc::new(Semaphore::new(1)),
                counters: Arc::new(Counters::default()),
            },
        }
    }

    fn writer(&self) -> SandboxWriter {
        open_writer(self.dir.as_fd(), b"result", self.bulkhead.clone()).unwrap()
    }

    fn reader(&self) -> SandboxReader {
        std::fs::write(self.root.join("data"), b"ABCDEFGH").unwrap();
        open_reader(self.dir.as_fd(), b"data", self.bulkhead.clone()).unwrap()
    }

    fn entries(&self) -> Vec<OsString> {
        std::fs::read_dir(&self.root)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.root).unwrap();
    }
}

#[tokio::test]
async fn cancelled_read_resumes_with_smaller_buffer_without_losing_bytes() {
    let fixture = Fixture::new();
    let mut reader = fixture.reader();
    let held = fixture
        .bulkhead
        .global
        .clone()
        .acquire_owned()
        .await
        .unwrap();
    let mut first = [0; 4];
    let mut cx = Context::from_waker(Waker::noop());
    assert!(Pin::new(&mut reader)
        .poll_read(&mut cx, &mut ReadBuf::new(&mut first))
        .is_pending());
    drop(held);

    let mut small = [0; 1];
    assert_eq!(reader.read(&mut small).await.unwrap(), 1);
    assert_eq!(&small, b"A");
    let mut rest = Vec::new();
    reader.read_to_end(&mut rest).await.unwrap();
    assert_eq!(rest, b"BCDEFGH");
    assert!(
        fixture
            .bulkhead
            .counters
            .peak_running_fs_tasks
            .load(Ordering::SeqCst)
            >= 1
    );
}

#[tokio::test]
async fn reader_len_works_while_read_is_pending_and_shutdown_seals_writer() {
    let fixture = Fixture::new();
    let mut reader = fixture.reader();
    let held = fixture
        .bulkhead
        .global
        .clone()
        .acquire_owned()
        .await
        .unwrap();
    let mut buf = [0u8; 4];
    let mut cx = Context::from_waker(Waker::noop());
    assert!(Pin::new(&mut reader)
        .poll_read(&mut cx, &mut ReadBuf::new(&mut buf))
        .is_pending());
    drop(held);
    // `len()` uses `meta_fd` and does not fail with `WouldBlock` when `state` is `Reading`.
    assert_eq!(reader.len().await.unwrap(), 8);
    drop(reader);

    let mut writer = fixture.writer();
    writer.write_all(b"sealed").await.unwrap();
    writer.shutdown().await.unwrap();
    assert_eq!(
        writer.write(b"more").await.unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
    writer.commit().await.unwrap();
    assert_eq!(
        std::fs::read(fixture.root.join("result")).unwrap(),
        b"sealed"
    );
}

#[tokio::test]
async fn seek_uses_delivered_position_after_cancelled_read_and_read_ahead() {
    let fixture = Fixture::new();
    let mut reader = fixture.reader();
    let held = fixture
        .bulkhead
        .global
        .clone()
        .acquire_owned()
        .await
        .unwrap();
    let mut first = [0; 4];
    let mut cx = Context::from_waker(Waker::noop());
    assert!(Pin::new(&mut reader)
        .poll_read(&mut cx, &mut ReadBuf::new(&mut first))
        .is_pending());
    drop(held);

    // No bytes were delivered by the cancelled read, even if its kernel read
    // completed. SeekExt must settle that read and seek from logical offset 0.
    assert_eq!(reader.seek(SeekFrom::Current(1)).await.unwrap(), 1);
    let held = fixture
        .bulkhead
        .global
        .clone()
        .acquire_owned()
        .await
        .unwrap();
    assert!(Pin::new(&mut reader)
        .poll_read(&mut cx, &mut ReadBuf::new(&mut first))
        .is_pending());
    drop(held);
    let mut small = [0; 1];
    reader.read_exact(&mut small).await.unwrap();
    assert_eq!(&small, b"B");
    assert_eq!(reader.stream_position().await.unwrap(), 2);
    assert_eq!(reader.seek(SeekFrom::Current(1)).await.unwrap(), 3);
    let mut rest = Vec::new();
    reader.read_to_end(&mut rest).await.unwrap();
    assert_eq!(rest, b"DEFGH");
}

#[tokio::test]
async fn cancelled_write_never_acknowledges_old_bytes_for_a_new_buffer() {
    let fixture = Fixture::new();
    let mut writer = fixture.writer();
    let held = fixture
        .bulkhead
        .global
        .clone()
        .acquire_owned()
        .await
        .unwrap();
    let mut cx = Context::from_waker(Waker::noop());
    // Both buffering (Ready) and backpressure (Pending) are valid, but Pending
    // must not accept bytes, and a later call must account for its own buffer.
    let mut expected = Vec::new();
    match Pin::new(&mut writer).poll_write(&mut cx, b"AAAA") {
        Poll::Ready(Ok(n)) => expected.extend_from_slice(&b"AAAA"[..n]),
        Poll::Pending => {}
        other => panic!("unexpected write result: {other:?}"),
    }
    drop(held);
    assert_eq!(writer.write(b"B").await.unwrap(), 1);
    expected.push(b'B');
    writer.commit().await.unwrap();
    assert_eq!(
        std::fs::read(fixture.root.join("result")).unwrap(),
        expected
    );
}

#[tokio::test]
async fn pending_write_is_not_accepted_and_cancelled_flush_can_resume() {
    let fixture = Fixture::new();
    let mut writer = fixture.writer();
    // First call is accepted into the bounded buffer, before acquiring permits.
    assert_eq!(writer.write(b"A").await.unwrap(), 1);
    let held = fixture
        .bulkhead
        .global
        .clone()
        .acquire_owned()
        .await
        .unwrap();
    let mut cx = Context::from_waker(Waker::noop());
    assert!(Pin::new(&mut writer)
        .poll_write(&mut cx, b"discard")
        .is_pending());
    assert!(Pin::new(&mut writer).poll_flush(&mut cx).is_pending());
    drop(held);
    assert_eq!(writer.write(b"B").await.unwrap(), 1);
    writer.commit().await.unwrap();
    assert_eq!(std::fs::read(fixture.root.join("result")).unwrap(), b"AB");
}

#[tokio::test]
async fn deferred_write_failure_prevents_commit_and_cleans_temp() {
    let fixture = Fixture::new();
    let mut writer = fixture.writer();
    // Inject a deterministic disk-write failure without exhausting the host disk.
    writer.state = WriterState::Idle(
        std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .unwrap(),
    );
    writer.write_all(b"data").await.unwrap();
    assert_eq!(
        writer.flush().await.unwrap_err().raw_os_error(),
        Some(libc::ENOSPC)
    );
    assert!(writer.commit().await.is_err());
    assert!(fixture.entries().is_empty());
}

#[tokio::test]
async fn failed_rename_cleans_temp_and_preserves_destination() {
    let fixture = Fixture::new();
    let mut writer = fixture.writer();
    writer.write_all(b"data").await.unwrap();
    std::fs::create_dir(fixture.root.join("result")).unwrap();
    assert!(writer.commit().await.is_err());
    assert_eq!(fixture.entries(), [OsString::from("result")]);
    assert!(fixture.root.join("result").is_dir());
}

#[test]
fn cancelling_commit_while_waiting_for_permit_cleans_staged_file() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    rt.block_on(async {
        let fixture = Fixture::new();
        let writer = fixture.writer();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            started_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
        started_rx.recv().unwrap();
        let mut commit = Box::pin(writer.commit());
        let mut cx = Context::from_waker(Waker::noop());
        // Flush acquires the permit, then queues behind the blocking task.
        let first_poll = commit.as_mut().poll(&mut cx);
        let mut acquire = Box::pin(fixture.bulkhead.global.clone().acquire_owned());
        let waiter_poll = acquire.as_mut().poll(&mut cx);
        release_tx.send(()).unwrap();
        assert!(first_poll.is_pending());
        assert!(waiter_poll.is_pending());
        // Semaphore fairness gives this waiter the permit released by flush.
        let held = acquire.await.unwrap();
        blocker.await.unwrap();
        assert!(commit.as_mut().poll(&mut cx).is_pending());
        drop(commit);
        drop(held);
        assert!(
            fixture.entries().is_empty(),
            "cancelled commit leaked a file"
        );
    });
}
