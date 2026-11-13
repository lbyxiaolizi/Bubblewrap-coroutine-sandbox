//! Example: three Tokio tasks each scoped to a single directory.
//!
//! Run:
//! ```sh
//! BWRAP=bwrap cargo run --release --example demo -- /tmp/scratch
//! ```

use std::path::{Path, PathBuf};

use coroutine_sandbox::{Access, Limits, Sandbox, Workspace};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let root = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .expect("usage: demo <scratch-dir>");

    let sandbox = setup_demo_environment(&root)?;

    let mut tasks = Vec::new();
    for name in ["A", "B", "C"] {
        let ws = sandbox.workspace(root.join(name), Access::ReadWrite)?;
        tasks.push(tokio::spawn(run_task(name, ws)));
    }

    for task in tasks {
        println!("{}", task.await.expect("task panicked")?);
    }
    println!("stats: {:?}", sandbox.stats());
    Ok(())
}

#[allow(clippy::disallowed_methods)]
fn setup_demo_environment(root: &Path) -> std::io::Result<Sandbox> {
    let bwrap = std::env::var_os("BWRAP").unwrap_or_else(|| "bwrap".into());
    for name in ["A", "B", "C"] {
        let dir = root.join(name);
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("secret.txt"), format!("secret of {name}\n"))?;
    }
    Sandbox::new(bwrap, Limits::default())
}

async fn run_task(name: &str, ws: Workspace) -> std::io::Result<String> {
    let own = ws.read("secret.txt").await?;
    let own_text = String::from_utf8_lossy(&own).trim().to_string();

    let mut writer = ws.open_write("streamed.bin").await?;
    writer
        .write_all(format!("stream-{name}").as_bytes())
        .await?;
    writer.commit().await?;

    let mut reader = ws.open_read("streamed.bin").await?;
    let mut streamed = String::new();
    reader.read_to_string(&mut streamed).await?;

    let uname = ws.exec("uname", ["-s"]).await?;
    let sys = String::from_utf8_lossy(&uname.stdout).trim().to_string();

    let mut out =
        format!("task {name}: own={own_text:?}, streamed={streamed:?}, bwrap_exec={sys:?}");
    for other in ["A", "B", "C"].into_iter().filter(|&o| o != name) {
        let res = ws.read(format!("../{other}/secret.txt")).await;
        out.push_str(&format!(
            "; ../{other} -> {}",
            match res {
                Ok(_) => "ESCAPED".to_string(),
                Err(err) => format!("{:?}(errno={:?})", err.kind(), err.raw_os_error()),
            }
        ));
    }
    Ok(out)
}
