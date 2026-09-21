#![recursion_limit = "512"]
//! omarchy-yapperd: a per-user daemon that owns the Matrix session, keys and
//! sync loop, and exposes them over a Unix socket so the Omarchy shell plugin
//! (QML) never handles key material.
//!
//! Socket: `$XDG_RUNTIME_DIR/omarchy-yapper.sock`, mode 0600, and every
//! connection is checked against our own uid via SO_PEERCRED.

mod bridge;
mod core;
mod media;
mod protocol;
mod secrets;
mod verify;

use std::{io::IsTerminal, os::unix::fs::PermissionsExt, path::PathBuf, sync::Arc};

use anyhow::{Context, Result, bail};
use clap::Parser;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    signal::unix::{SignalKind, signal},
    sync::{broadcast, mpsc},
};
use tracing::{info, warn};

use crate::core::Core;

#[derive(Parser)]
#[command(name = "omarchy-yapperd", version, about)]
struct Args {
    /// Unix socket to listen on (default: $XDG_RUNTIME_DIR/omarchy-yapper.sock)
    #[arg(long)]
    socket: Option<PathBuf>,
    /// Where the session and encrypted store live (default: $XDG_DATA_HOME/omarchy-yapperd)
    #[arg(long)]
    data_dir: Option<PathBuf>,
}

fn default_socket() -> Result<PathBuf> {
    let dir = std::env::var_os("XDG_RUNTIME_DIR").context("XDG_RUNTIME_DIR is not set")?;
    Ok(PathBuf::from(dir).join("omarchy-yapper.sock"))
}

fn default_data_dir() -> Result<PathBuf> {
    if let Some(d) = std::env::var_os("XDG_DATA_HOME") {
        return Ok(PathBuf::from(d).join("omarchy-yapperd"));
    }
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home).join(".local/share/omarchy-yapperd"))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_ansi(std::io::stderr().is_terminal())
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,matrix_sdk=warn".into()),
        )
        .init();

    // Everything this process creates is private to the user.
    unsafe { libc::umask(0o077) };

    let args = Args::parse();
    let socket = match args.socket {
        Some(p) => p,
        None => default_socket()?,
    };
    let data_dir = match args.data_dir {
        Some(p) => p,
        None => default_data_dir()?,
    };

    // A live daemon answers on the socket; a dead one leaves a stale file.
    if socket.exists() {
        if UnixStream::connect(&socket).await.is_ok() {
            bail!(
                "another omarchy-yapperd is already listening on {}",
                socket.display()
            );
        }
        std::fs::remove_file(&socket)?;
    }
    let listener =
        UnixListener::bind(&socket).with_context(|| format!("binding {}", socket.display()))?;
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;

    let (events, _) = broadcast::channel(256);
    let core = Core::new(data_dir, events)?;
    if let Err(e) = core.restore().await {
        warn!("could not restore previous session: {e:#}");
    }
    info!(socket = %socket.display(), "listening");

    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let core = core.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_conn(stream, core).await {
                        warn!("connection: {e:#}");
                    }
                });
            }
            _ = term.recv() => break,
            _ = int.recv() => break,
        }
    }
    let _ = std::fs::remove_file(&socket);
    info!("stopped");
    Ok(())
}

async fn handle_conn(stream: UnixStream, core: Arc<Core>) -> Result<()> {
    let cred = stream.peer_cred()?;
    let me = unsafe { libc::getuid() };
    if cred.uid() != me {
        bail!("rejected connection from uid {}", cred.uid());
    }

    let (rd, mut wr) = stream.into_split();
    let (tx, mut rx) = mpsc::channel::<String>(64);

    // Single writer so responses and events never interleave mid-line.
    let writer = tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            if wr.write_all(line.as_bytes()).await.is_err() {
                break;
            }
        }
    });

    // Push events to this client for as long as it stays connected.
    let mut events = core.events().subscribe();
    let etx = tx.clone();
    let pusher = tokio::spawn(async move {
        loop {
            match events.recv().await {
                Ok(ev) => {
                    let Ok(mut line) = serde_json::to_string(&ev) else {
                        continue;
                    };
                    line.push('\n');
                    if etx.send(line).await.is_err() {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!("client lagged; dropped {n} events")
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    // Greet with the current state so the client needs no initial round-trip.
    {
        let mut line = serde_json::to_string(&protocol::Event::State(core.status().await))?;
        line.push('\n');
        let _ = tx.send(line).await;
    }

    let mut lines = BufReader::new(rd).lines();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let core = core.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            let resp = core.handle(&line).await;
            let Ok(mut out) = serde_json::to_string(&resp) else {
                return;
            };
            out.push('\n');
            let _ = tx.send(out).await;
        });
    }

    pusher.abort();
    drop(tx);
    let _ = writer.await;
    Ok(())
}
