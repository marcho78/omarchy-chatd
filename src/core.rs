//! Matrix client lifecycle: session persistence, sync loop, and the commands
//! the socket exposes. All cryptography lives in matrix-sdk (vodozemac); this
//! file never sees a key.

use std::{
    fs::OpenOptions,
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, anyhow, bail};
use matrix_sdk::{
    Client, LoopCtrl, Room, RoomState,
    authentication::matrix::MatrixSession,
    config::SyncSettings,
    deserialized_responses::EncryptionInfo,
    event_handler::Ctx,
    room::MessagesOptions,
    ruma::{
        OwnedRoomId, RoomId, UInt,
        api::client::{filter::FilterDefinition, receipt::create_receipt::v3::ReceiptType},
        events::{
            AnySyncMessageLikeEvent, AnySyncTimelineEvent, SyncMessageLikeEvent,
            receipt::ReceiptThread,
            room::message::{OriginalSyncRoomMessageEvent, RoomMessageEventContent},
        },
    },
};
use rand::{RngExt, distr::Alphanumeric, rng};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::{sync::broadcast, task::JoinHandle};
use tracing::{info, warn};

use crate::protocol::{Command, Event, Message, Request, Response, RoomInfo, Status};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
const DEVICE_NAME: &str = "Omarchy Chat";

/// What survives a restart. Written to `<data_dir>/session.json` with mode
/// 0600. The store passphrase is random and only ever lives here; the user's
/// password is never stored.
#[derive(Serialize, Deserialize)]
struct PersistedSession {
    homeserver: String,
    store_path: PathBuf,
    store_passphrase: String,
    user_session: MatrixSession,
    #[serde(skip_serializing_if = "Option::is_none")]
    sync_token: Option<String>,
}

#[derive(Default)]
struct State {
    client: Option<Client>,
    sync_task: Option<JoinHandle<()>>,
    syncing: bool,
    error: Option<String>,
}

pub struct Core {
    data_dir: PathBuf,
    events: broadcast::Sender<Event>,
    state: tokio::sync::Mutex<State>,
}

#[derive(Clone)]
struct HandlerCtx {
    events: broadcast::Sender<Event>,
}

impl Core {
    pub fn new(data_dir: PathBuf, events: broadcast::Sender<Event>) -> Result<Arc<Self>> {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&data_dir)
            .with_context(|| format!("creating {}", data_dir.display()))?;
        Ok(Arc::new(Self { data_dir, events, state: Default::default() }))
    }

    pub fn events(&self) -> &broadcast::Sender<Event> {
        &self.events
    }

    fn session_file(&self) -> PathBuf {
        self.data_dir.join("session.json")
    }

    /// Restore a persisted session at startup, if there is one.
    pub async fn restore(self: &Arc<Self>) -> Result<()> {
        let file = self.session_file();
        if !file.exists() {
            return Ok(());
        }
        let text = tokio::fs::read_to_string(&file).await?;
        let saved: PersistedSession = serde_json::from_str(&text)?;
        let client = Client::builder()
            .homeserver_url(&saved.homeserver)
            .sqlite_store(&saved.store_path, Some(&saved.store_passphrase))
            .build()
            .await?;
        client.restore_session(saved.user_session).await?;
        info!(user = %client.user_id().map(|u| u.to_string()).unwrap_or_default(), "session restored");
        self.start(client, saved.sync_token).await;
        Ok(())
    }

    // ---------- request dispatch ----------

    pub async fn handle(self: &Arc<Self>, line: &str) -> Response {
        let req: Request = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(e) => return Response::err(Value::Null, format!("bad request: {e}")),
        };
        let id = req.id.clone();
        match self.dispatch(req.command).await {
            Ok(v) => Response::ok(id, v),
            Err(e) => Response::err(id, format!("{e:#}")),
        }
    }

    async fn dispatch(self: &Arc<Self>, cmd: Command) -> Result<Value> {
        match cmd {
            Command::Status => Ok(serde_json::to_value(self.status().await)?),
            Command::Login { homeserver, username, password } => {
                self.login(homeserver, username, password).await?;
                Ok(serde_json::to_value(self.status().await)?)
            }
            Command::Logout => {
                self.logout().await?;
                Ok(serde_json::to_value(self.status().await)?)
            }
            Command::Rooms => Ok(serde_json::to_value(self.rooms().await?)?),
            Command::Timeline { room, limit } => {
                Ok(serde_json::to_value(self.timeline(&room, limit).await?)?)
            }
            Command::Send { room, body } => {
                let event_id = self.send(&room, body).await?;
                Ok(json!({ "event_id": event_id }))
            }
            Command::MarkRead { room, event_id } => {
                self.mark_read(&room, &event_id).await?;
                Ok(json!({}))
            }
        }
    }

    // ---------- state ----------

    pub async fn status(&self) -> Status {
        let st = self.state.lock().await;
        Status {
            version: VERSION,
            logged_in: st.client.is_some(),
            syncing: st.syncing,
            user_id: st.client.as_ref().and_then(|c| c.user_id().map(|u| u.to_string())),
            homeserver: st.client.as_ref().map(|c| c.homeserver().to_string()),
            error: st.error.clone(),
        }
    }

    async fn broadcast_state(&self) {
        let _ = self.events.send(Event::State(self.status().await));
    }

    async fn client(&self) -> Result<Client> {
        self.state.lock().await.client.clone().ok_or_else(|| anyhow!("not logged in"))
    }

    async fn room(&self, id: &str) -> Result<Room> {
        let id: OwnedRoomId = RoomId::parse(id).context("invalid room id")?;
        self.client().await?.get_room(&id).ok_or_else(|| anyhow!("unknown room {id}"))
    }

    // ---------- login / logout ----------

    async fn login(self: &Arc<Self>, homeserver: String, username: String, password: String) -> Result<()> {
        if self.state.lock().await.client.is_some() {
            bail!("already logged in; log out first");
        }
        // ThreadRng is !Send, so it must not live across an await.
        let (store_name, store_passphrase) = {
            let mut r = rng();
            let name: String = (&mut r).sample_iter(Alphanumeric).take(8).map(char::from).collect();
            let pass: String = (&mut r).sample_iter(Alphanumeric).take(32).map(char::from).collect();
            (name, pass)
        };
        let store_path = self.data_dir.join(format!("store-{store_name}"));

        let client = Client::builder()
            .homeserver_url(&homeserver)
            .sqlite_store(&store_path, Some(&store_passphrase))
            .build()
            .await
            .context("connecting to homeserver")?;

        client
            .matrix_auth()
            .login_username(&username, &password)
            .initial_device_display_name(DEVICE_NAME)
            .await
            .context("login")?;
        drop(password);

        let user_session = client
            .matrix_auth()
            .session()
            .ok_or_else(|| anyhow!("login succeeded but no session was returned"))?;
        let saved = PersistedSession {
            homeserver: client.homeserver().to_string(),
            store_path,
            store_passphrase,
            user_session,
            sync_token: None,
        };
        write_private(&self.session_file(), &serde_json::to_vec(&saved)?)?;
        info!(user = %username, "logged in");
        self.start(client, None).await;
        Ok(())
    }

    async fn logout(self: &Arc<Self>) -> Result<()> {
        let (client, task) = {
            let mut st = self.state.lock().await;
            (st.client.take(), st.sync_task.take())
        };
        if let Some(task) = task {
            task.abort();
        }
        let Some(client) = client else { bail!("not logged in") };
        if let Err(e) = client.logout().await {
            // The token may already be dead; local state is wiped regardless.
            warn!("server logout failed: {e:#}");
        }
        let file = self.session_file();
        if let Ok(text) = std::fs::read_to_string(&file) {
            if let Ok(saved) = serde_json::from_str::<PersistedSession>(&text) {
                let _ = std::fs::remove_dir_all(&saved.store_path);
            }
        }
        let _ = std::fs::remove_file(&file);
        {
            let mut st = self.state.lock().await;
            st.syncing = false;
            st.error = None;
        }
        info!("logged out; local store wiped");
        self.broadcast_state().await;
        Ok(())
    }

    // ---------- sync loop ----------

    async fn start(self: &Arc<Self>, client: Client, sync_token: Option<String>) {
        client.add_event_handler_context(HandlerCtx { events: self.events.clone() });
        client.add_event_handler(on_room_message);

        let core = self.clone();
        let sync_client = client.clone();
        let task = tokio::spawn(async move { core.sync_loop(sync_client, sync_token).await });

        let mut st = self.state.lock().await;
        st.client = Some(client);
        st.sync_task = Some(task);
        st.error = None;
        drop(st);
        self.broadcast_state().await;
    }

    async fn sync_loop(self: Arc<Self>, client: Client, initial_token: Option<String>) {
        let filter = FilterDefinition::with_lazy_loading();
        let mut settings = SyncSettings::default().filter(filter.into());
        if let Some(token) = initial_token {
            settings = settings.token(token);
        }

        // Retry until the first sync succeeds so a laptop that wakes up
        // offline recovers on its own.
        let mut backoff = 2u64;
        loop {
            match client.sync_once(settings.clone()).await {
                Ok(resp) => {
                    settings = settings.token(resp.next_batch.clone());
                    let _ = self.persist_sync_token(resp.next_batch);
                    break;
                }
                Err(e) => {
                    warn!("initial sync failed: {e:#}; retrying in {backoff}s");
                    self.set_error(Some(format!("sync: {e}"))).await;
                    tokio::time::sleep(std::time::Duration::from_secs(backoff)).await;
                    backoff = (backoff * 2).min(60);
                }
            }
        }
        self.set_syncing(true).await;

        let core = self.clone();
        let result = client
            .sync_with_result_callback(settings, |r| {
                let core = core.clone();
                async move {
                    let resp = r?;
                    let _ = core.persist_sync_token(resp.next_batch);
                    Ok(LoopCtrl::Continue)
                }
            })
            .await;
        warn!("sync loop ended: {result:?}");
        self.set_syncing(false).await;
        if let Err(e) = result {
            self.set_error(Some(format!("sync stopped: {e}"))).await;
        }
    }

    fn persist_sync_token(&self, token: String) -> Result<()> {
        let file = self.session_file();
        let text = std::fs::read_to_string(&file)?;
        let mut saved: PersistedSession = serde_json::from_str(&text)?;
        saved.sync_token = Some(token);
        write_private(&file, &serde_json::to_vec(&saved)?)
    }

    async fn set_syncing(&self, syncing: bool) {
        {
            let mut st = self.state.lock().await;
            st.syncing = syncing;
            if syncing {
                st.error = None;
            }
        }
        self.broadcast_state().await;
    }

    async fn set_error(&self, error: Option<String>) {
        self.state.lock().await.error = error;
        self.broadcast_state().await;
    }

    // ---------- rooms ----------

    async fn rooms(&self) -> Result<Vec<RoomInfo>> {
        let client = self.client().await?;
        let mut out = Vec::new();
        for room in client.joined_rooms() {
            let name = match room.display_name().await {
                Ok(n) => n.to_string(),
                Err(_) => room.room_id().to_string(),
            };
            let encrypted = room
                .latest_encryption_state()
                .await
                .map(|s| s.is_encrypted())
                .unwrap_or(false);
            let counts = room.unread_notification_counts();
            out.push(RoomInfo {
                id: room.room_id().to_string(),
                name,
                encrypted,
                direct: room.is_direct().await.unwrap_or(false),
                unread: counts.notification_count,
                highlights: counts.highlight_count,
            });
        }
        out.sort_by(|a, b| b.unread.cmp(&a.unread).then_with(|| a.name.cmp(&b.name)));
        Ok(out)
    }

    async fn timeline(&self, room_id: &str, limit: u32) -> Result<Vec<Message>> {
        let room = self.room(room_id).await?;
        let mut opts = MessagesOptions::backward();
        opts.limit = UInt::from(limit.clamp(1, 200));
        let page = room.messages(opts).await.context("fetching messages")?;

        let mut out = Vec::new();
        for ev in page.chunk {
            let encrypted = ev.encryption_info().is_some();
            let Ok(parsed) = ev.raw().deserialize() else { continue };
            let AnySyncTimelineEvent::MessageLike(AnySyncMessageLikeEvent::RoomMessage(
                SyncMessageLikeEvent::Original(msg),
            )) = parsed
            else {
                continue;
            };
            out.push(to_message(&room, msg, encrypted).await);
        }
        out.reverse(); // backward pagination yields newest first
        Ok(out)
    }

    async fn send(&self, room_id: &str, body: String) -> Result<String> {
        let room = self.room(room_id).await?;
        let resp = room.send(RoomMessageEventContent::text_plain(body)).await.context("sending")?;
        Ok(resp.response.event_id.to_string())
    }

    async fn mark_read(&self, room_id: &str, event_id: &str) -> Result<()> {
        let room = self.room(room_id).await?;
        let event_id = matrix_sdk::ruma::EventId::parse(event_id).context("invalid event id")?;
        room.send_single_receipt(ReceiptType::Read, ReceiptThread::Unthreaded, event_id)
            .await
            .context("sending read receipt")?;
        Ok(())
    }
}

/// Event handler registered on the client: forwards every incoming room
/// message to socket subscribers. The SDK hands us the already-decrypted
/// event; `EncryptionInfo` is present exactly when it was encrypted.
async fn on_room_message(
    event: OriginalSyncRoomMessageEvent,
    room: Room,
    encryption: Option<EncryptionInfo>,
    ctx: Ctx<HandlerCtx>,
) {
    if room.state() != RoomState::Joined {
        return;
    }
    let msg = to_message(&room, event, encryption.is_some()).await;
    let _ = ctx.events.send(Event::Message(msg));
}

async fn to_message(room: &Room, ev: OriginalSyncRoomMessageEvent, encrypted: bool) -> Message {
    let sender_name = match room.get_member_no_sync(&ev.sender).await {
        Ok(Some(m)) => m.name().to_owned(),
        _ => ev.sender.localpart().to_owned(),
    };
    Message {
        room: room.room_id().to_string(),
        event_id: ev.event_id.to_string(),
        sender: ev.sender.to_string(),
        sender_name,
        body: ev.content.body().to_owned(),
        msgtype: ev.content.msgtype.msgtype().to_owned(),
        ts: ev.origin_server_ts.0.into(),
        encrypted,
    }
}

/// Write a file readable only by this user, replacing any previous content.
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("writing {}", path.display()))?;
    f.write_all(bytes)?;
    Ok(())
}
