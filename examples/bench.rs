//! Latency and throughput benchmark for `coroutine-sandbox`.
//!
//! Run:
//! ```sh
//! BWRAP=bwrap cargo run --release --example bench -- /tmp/bench-scratch
//! ```

#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use coroutine_sandbox::{Access, Limits, Sandbox};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn pct(mut samples: Vec<Duration>, p: f64) -> Duration {
    samples.sort();
    samples[((samples.len() as f64 - 1.0) * p) as usize]
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let root = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .expect("usage: bench <scratch-dir>");
    let bwrap = std::env::var_os("BWRAP").unwrap_or_else(|| "bwrap".into());

    let sb = Arc::new(Sandbox::new(bwrap, Limits::default())?);

    let domains = 100;
    for i in 0..domains {
        let d = root.join(format!("d{i}"));
        std::fs::create_dir_all(&d)?;
        std::fs::write(d.join("f"), "hello")?;
    }

    // 1. Granting 100 fresh domain capabilities + first read (zero subprocesses spawned!).
    let mut first_op = Vec::with_capacity(domains);
    let mut handles = Vec::with_capacity(domains);
    for i in 0..domains {
        let t = Instant::now();
        let ws = sb.workspace(root.join(format!("d{i}")), Access::ReadWrite)?;
        ws.read("f").await?;
        first_op.push(t.elapsed());
        handles.push(ws);
    }
    println!(
        "1. grant + 1st read (n={domains} domains): p50={:?}  p99={:?}  (0 worker procs)",
        pct(first_op.clone(), 0.5),
        pct(first_op, 0.99)
    );

    // 2. Sequential `ws.read` latency (`spawn_blocking` + `openat2`).
    let ws0 = handles[0].clone();
    let mut warm = Vec::with_capacity(5000);
    for _ in 0..5000 {
        let t = Instant::now();
        ws0.read("f").await?;
        warm.push(t.elapsed());
    }
    println!(
        "2. sequential `ws.read` (n=5000):    p50={:?}  p99={:?}",
        pct(warm.clone(), 0.5),
        pct(warm, 0.99)
    );

    // 3. High-concurrency buffered reads: 1 domain vs 100 domains.
    for (label, spread) in [("1 domain", false), ("100 domains", true)] {
        let t = Instant::now();
        let mut tasks = Vec::with_capacity(1000);
        for i in 0..1000 {
            let idx = if spread { i % domains } else { 0 };
            let ws = sb.workspace(root.join(format!("d{idx}")), Access::ReadWrite)?;
            tasks.push(tokio::spawn(async move {
                for _ in 0..20 {
                    ws.read("f").await.unwrap();
                }
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        let ops_sec = 20_000.0 / t.elapsed().as_secs_f64();
        println!("3. 1000 tasks x 20 reads ({label:<11}): {ops_sec:>8.0} ops/s");
    }

    // 4. Streaming 64 MiB write + read via `SandboxWriter` / `SandboxReader`.
    let ws_stream = sb.workspace(root.join("d0"), Access::ReadWrite)?;
    let chunk = vec![0x5au8; 1 << 20];
    let t_write = Instant::now();
    let mut writer = ws_stream.open_write("large-64m.bin").await?;
    for _ in 0..64 {
        writer.write_all(&chunk).await?;
    }
    writer.commit().await?;
    let write_mb_s = 64.0 / t_write.elapsed().as_secs_f64();

    let t_read = Instant::now();
    let mut reader = ws_stream.open_read("large-64m.bin").await?;
    let mut buf = vec![0u8; 1 << 20];
    let mut total = 0usize;
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        total += n;
    }
    assert_eq!(total, 64 << 20);
    let read_mb_s = 64.0 / t_read.elapsed().as_secs_f64();
    println!(
        "4. 64 MiB streaming I/O:             write={write_mb_s:.0} MiB/s  read={read_mb_s:.0} MiB/s"
    );

    // 5. Isolated + seccomp-filtered one-shot `ws.exec("true")`.
    let mut exec_lat = Vec::with_capacity(50);
    for _ in 0..50 {
        let t = Instant::now();
        ws_stream.exec("true", Vec::<&str>::new()).await?;
        exec_lat.push(t.elapsed());
    }
    println!(
        "5. seccomp oneshot `exec true`:      p50={:?}  p99={:?}",
        pct(exec_lat.clone(), 0.5),
        pct(exec_lat, 0.99)
    );
    println!("final stats: {:?}", sb.stats());
    Ok(())
}
