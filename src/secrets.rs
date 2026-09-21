//! Where the session's secrets live: the desktop keyring (Secret Service,
//! `org.freedesktop.secrets`) when there is one, else the session file.
//!
//! The keyring item holds one JSON blob — the encrypted store's passphrase
//! and the Matrix tokens — under attributes that tie it to this daemon and
//! its data directory, so a test daemon with its own `--data-dir` gets its
//! own item. Everything else about the session (homeserver, user, device,
//! store path, sync token) is not secret and stays in `session.json`.

use std::{collections::HashMap, path::Path, time::Duration};

use anyhow::{Context, Result, anyhow};
use tracing::{info, warn};

/// How long to give the keyring before deciding it is not going to answer
/// (a locked keyring shows a prompt; an absent service fails fast).
const KEYRING_TIMEOUT: Duration = Duration::from_secs(20);

/// Which backend a session's secrets are in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Backend {
    /// The desktop keyring, unlocked with the login session.
    Keyring,
    /// `session.json` (mode 0600) — no keyring was available.
    File,
}

fn attributes(data_dir: &Path) -> HashMap<&'static str, String> {
    HashMap::from([
        ("application", "omarchy-yapperd".to_owned()),
        ("data_dir", data_dir.to_string_lossy().into_owned()),
    ])
}

async fn keyring() -> Result<oo7::Keyring> {
    let k = tokio::time::timeout(KEYRING_TIMEOUT, oo7::Keyring::new())
        .await
        .map_err(|_| anyhow!("the keyring did not answer"))?
        .context("connecting to the keyring")?;
    Ok(k)
}

/// Store the secret blob for `data_dir`, replacing any previous one.
pub async fn store(data_dir: &Path, label: &str, secret: &[u8]) -> Result<()> {
    let k = keyring().await?;
    tokio::time::timeout(
        KEYRING_TIMEOUT,
        k.create_item(label, &attributes(data_dir), secret, true),
    )
    .await
    .map_err(|_| anyhow!("the keyring did not answer"))?
    .context("storing the session in the keyring")?;
    Ok(())
}

/// The stored secret blob, `None` when the keyring has no item for us.
/// With `prompt`, a locked keyring is unlocked first, which shows the
/// desktop's unlock dialog; without it a locked keyring is an error, for
/// quiet retries in the background.
pub async fn load(data_dir: &Path, prompt: bool) -> Result<Option<Vec<u8>>> {
    let k = keyring().await?;
    if k.is_locked().await.unwrap_or(false) {
        if !prompt {
            return Err(anyhow!("the keyring is locked"));
        }
        info!("keyring is locked; asking to unlock it");
        tokio::time::timeout(KEYRING_TIMEOUT, k.unlock())
            .await
            .map_err(|_| anyhow!("the keyring stayed locked"))?
            .context("unlocking the keyring")?;
        if k.is_locked().await.unwrap_or(false) {
            return Err(anyhow!("the keyring is locked"));
        }
    }
    let items = tokio::time::timeout(KEYRING_TIMEOUT, k.search_items(&attributes(data_dir)))
        .await
        .map_err(|_| anyhow!("the keyring did not answer"))?
        .context("searching the keyring")?;
    let Some(item) = items.into_iter().next() else {
        return Ok(None);
    };
    if item.is_locked().await.unwrap_or(false) {
        if !prompt {
            return Err(anyhow!("the keyring is locked"));
        }
        item.unlock().await.context("unlocking the session item")?;
    }
    let secret = item
        .secret()
        .await
        .context("reading the session from the keyring")?;
    Ok(Some(secret.as_bytes().to_vec()))
}

/// Remove our item, ignoring an absent keyring: a session that was never
/// in it has nothing to delete.
pub async fn forget(data_dir: &Path) {
    match keyring().await {
        Ok(k) => {
            if let Err(e) = k.delete(&attributes(data_dir)).await {
                warn!("could not remove the session from the keyring: {e}");
            }
        }
        Err(e) => warn!("keyring unavailable while signing out: {e}"),
    }
}
