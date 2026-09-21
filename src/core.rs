//! Matrix client lifecycle: session persistence, sync loop, and the commands
//! the socket exposes. All cryptography lives in matrix-sdk (vodozemac); this
//! file never sees a key.

use std::{
    fs::OpenOptions,
    io::Write,
    net::{Ipv4Addr, Ipv6Addr},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use matrix_sdk::{
    Client, LoopCtrl, Room, RoomState, SessionChange,
    authentication::{
        matrix::MatrixSession,
        oauth::{
            ClientId, OAuthAuthorizationData, OAuthSession, UserSession,
            registration::{ApplicationType, ClientMetadata, Localized, OAuthGrantType},
        },
    },
    config::SyncSettings,
    deserialized_responses::EncryptionInfo,
    event_handler::Ctx,
    room::MessagesOptions,
    ruma::{
        OwnedRoomId, OwnedServerName, RoomId, RoomOrAliasId, UInt, UserId,
        api::client::{
            directory::get_public_rooms_filtered,
            filter::FilterDefinition,
            receipt::create_receipt::v3::ReceiptType,
            room::{Visibility, create_room},
        },
        directory::Filter,
        events::{
            AnySyncMessageLikeEvent, AnySyncTimelineEvent, EmptyStateKey, InitialStateEvent, SyncMessageLikeEvent,
            receipt::ReceiptThread,
            room::{
                encryption::RoomEncryptionEventContent,
                member::{MembershipState, OriginalSyncRoomMemberEvent, StrippedRoomMemberEvent},
                message::{OriginalSyncRoomMessageEvent, RoomMessageEventContent},
            },
        },
        serde::Raw,
    },
    utils::local_server::LocalServerBuilder,
};
use rand::{RngExt, distr::Alphanumeric, rng};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::{sync::broadcast, task::JoinHandle};
use tracing::{info, warn};
use url::Url;

use crate::protocol::{
    Command, DirectoryRoom, DirectoryUser, Event, InviteInfo, Message, Request, Response, RoomInfo, Status,
};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
const DEVICE_NAME: &str = "Yapper";
const CLIENT_URI: &str = "https://github.com/marcho78/omarchy-yapper";
/// How long a browser sign-in may sit waiting for the redirect.
const OAUTH_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// Directory searches, especially on a remote server, can stall on federation.
const SEARCH_TIMEOUT: Duration = Duration::from_secs(20);

/// What survives a restart. Written to `<data_dir>/session.json` with mode
/// 0600. The store passphrase is random and only ever lives here; the user's
/// password is never stored.
#[derive(Serialize, Deserialize)]
struct PersistedSession {
    homeserver: String,
    store_path: PathBuf,
    store_passphrase: String,
    auth: StoredAuth,
    #[serde(skip_serializing_if = "Option::is_none")]
    sync_token: Option<String>,
}

/// The two ways a session can have been obtained. OAuth sessions carry a
/// refresh token and the client id registered with the homeserver.
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum StoredAuth {
    Password { session: MatrixSession },
    Oauth { client_id: ClientId, user: UserSession },
}

/// A browser sign-in that is waiting for the redirect.
struct PendingLogin {
    task: JoinHandle<()>,
    store_path: PathBuf,
}

#[derive(Default)]
struct State {
    client: Option<Client>,
    sync_task: Option<JoinHandle<()>>,
    pending: Option<PendingLogin>,
    syncing: bool,
    error: Option<String>,
}

impl State {
    fn login_pending(&self) -> bool {
        self.pending.as_ref().is_some_and(|p| !p.task.is_finished())
    }
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
            .handle_refresh_tokens()
            .sqlite_store(&saved.store_path, Some(&saved.store_passphrase))
            .build()
            .await?;
        match saved.auth {
            StoredAuth::Password { session } => client.restore_session(session).await?,
            StoredAuth::Oauth { client_id, user } => {
                client.restore_session(OAuthSession { client_id, user }).await?
            }
        }
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
            Command::LoginOauth { homeserver } => {
                let url = self.login_oauth(homeserver).await?;
                Ok(json!({ "url": url }))
            }
            Command::LoginCancel => {
                self.login_cancel().await?;
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
            Command::SearchRooms { query, server, limit } => {
                Ok(serde_json::to_value(self.search_rooms(&query, server.as_deref(), limit).await?)?)
            }
            Command::Join { room } => {
                let room = self.join(&room).await?;
                Ok(serde_json::to_value(self.room_info(&room).await)?)
            }
            Command::SearchUsers { query, limit } => {
                Ok(serde_json::to_value(self.search_users(&query, limit).await?)?)
            }
            Command::Dm { user } => {
                let room = self.dm(&user).await?;
                Ok(serde_json::to_value(self.room_info(&room).await)?)
            }
            Command::CreateRoom { name, topic, encrypted, private } => {
                let room = self.create_room(name, topic, encrypted, private).await?;
                Ok(serde_json::to_value(self.room_info(&room).await)?)
            }
            Command::Invites => Ok(serde_json::to_value(self.invites().await?)?),
            Command::AcceptInvite { room } => {
                let room = self.room(&room).await?;
                room.join().await.context("accepting invite")?;
                Ok(serde_json::to_value(self.room_info(&room).await)?)
            }
            Command::DeclineInvite { room } | Command::Leave { room } => {
                let room = self.room(&room).await?;
                room.leave().await.context("leaving room")?;
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
            pending_login: st.login_pending(),
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

    /// Build a client with a fresh encrypted store. Returns the store path
    /// and passphrase so the caller can persist or discard them.
    async fn build_client(&self, homeserver: &str) -> Result<(Client, PathBuf, String)> {
        // ThreadRng is !Send, so it must not live across an await.
        let (store_name, store_passphrase) = {
            let mut r = rng();
            let name: String = (&mut r).sample_iter(Alphanumeric).take(8).map(char::from).collect();
            let pass: String = (&mut r).sample_iter(Alphanumeric).take(32).map(char::from).collect();
            (name, pass)
        };
        let store_path = self.data_dir.join(format!("store-{store_name}"));
        let client = Client::builder()
            .server_name_or_homeserver_url(homeserver)
            .handle_refresh_tokens()
            .sqlite_store(&store_path, Some(&store_passphrase))
            .build()
            .await;
        match client {
            Ok(client) => Ok((client, store_path, store_passphrase)),
            Err(e) => {
                let _ = std::fs::remove_dir_all(&store_path);
                Err(e).context("connecting to homeserver")
            }
        }
    }

    async fn ensure_signed_out(&self) -> Result<()> {
        let st = self.state.lock().await;
        if st.client.is_some() {
            bail!("already logged in; log out first");
        }
        if st.login_pending() {
            bail!("a browser sign-in is already in progress; cancel it first");
        }
        Ok(())
    }

    async fn login(self: &Arc<Self>, homeserver: String, username: String, password: String) -> Result<()> {
        self.ensure_signed_out().await?;
        let (client, store_path, store_passphrase) = self.build_client(&homeserver).await?;

        let login = client
            .matrix_auth()
            .login_username(&username, &password)
            .initial_device_display_name(DEVICE_NAME)
            .await;
        drop(password);
        if let Err(e) = login {
            let _ = std::fs::remove_dir_all(&store_path);
            return Err(e).context("login");
        }

        let session = client
            .matrix_auth()
            .session()
            .ok_or_else(|| anyhow!("login succeeded but no session was returned"))?;
        let saved = PersistedSession {
            homeserver: client.homeserver().to_string(),
            store_path,
            store_passphrase,
            auth: StoredAuth::Password { session },
            sync_token: None,
        };
        write_private(&self.session_file(), &serde_json::to_vec(&saved)?)?;
        info!(user = %username, "logged in with password");
        self.start(client, None).await;
        Ok(())
    }

    /// Start a browser sign-in. Returns the URL to open; a background task
    /// waits for the redirect on a loopback listener and finishes the login.
    async fn login_oauth(self: &Arc<Self>, homeserver: String) -> Result<String> {
        self.ensure_signed_out().await?;
        let (client, store_path, store_passphrase) = self.build_client(&homeserver).await?;

        let oauth = client.oauth();
        if let Err(e) = oauth.server_metadata().await {
            let _ = std::fs::remove_dir_all(&store_path);
            if e.is_not_supported() {
                bail!("this homeserver does not support browser sign-in; use a password instead");
            }
            return Err(e).context("fetching the homeserver's OAuth metadata");
        }

        let (redirect_uri, redirect) = match LocalServerBuilder::new().spawn().await {
            Ok(v) => v,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&store_path);
                return Err(e).context("starting the local redirect listener");
            }
        };
        let auth = oauth
            .login(redirect_uri, None, Some(client_metadata().into()), None)
            .build()
            .await;
        let OAuthAuthorizationData { url, .. } = match auth {
            Ok(v) => v,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&store_path);
                return Err(e).context("starting browser sign-in");
            }
        };

        let core = self.clone();
        let task_store = store_path.clone();
        let task = tokio::spawn(async move {
            let outcome: Result<()> = async {
                let query = match tokio::time::timeout(OAUTH_TIMEOUT, redirect).await {
                    Err(_) => bail!("browser sign-in timed out"),
                    Ok(None) => bail!("the browser returned without sign-in data"),
                    Ok(Some(q)) => q,
                };
                client.oauth().finish_login(query.into()).await.context("finishing browser sign-in")?;
                let full = client
                    .oauth()
                    .full_session()
                    .ok_or_else(|| anyhow!("sign-in succeeded but no session was returned"))?;
                let saved = PersistedSession {
                    homeserver: client.homeserver().to_string(),
                    store_path: task_store.clone(),
                    store_passphrase: store_passphrase.clone(),
                    auth: StoredAuth::Oauth { client_id: full.client_id, user: full.user },
                    sync_token: None,
                };
                write_private(&core.session_file(), &serde_json::to_vec(&saved)?)?;
                Ok(())
            }
            .await;
            match outcome {
                Ok(()) => {
                    info!(user = %client.user_id().map(|u| u.to_string()).unwrap_or_default(), "logged in via browser");
                    core.start(client, None).await;
                }
                Err(e) => {
                    warn!("browser sign-in failed: {e:#}");
                    let _ = std::fs::remove_dir_all(&task_store);
                    core.set_error(Some(format!("{e:#}"))).await;
                }
            }
        });

        self.state.lock().await.pending = Some(PendingLogin { task, store_path });
        self.broadcast_state().await;
        Ok(url.to_string())
    }

    async fn login_cancel(&self) -> Result<()> {
        let pending = self.state.lock().await.pending.take();
        let Some(p) = pending else { bail!("no browser sign-in in progress") };
        if p.task.is_finished() {
            return Ok(());
        }
        p.task.abort();
        let _ = std::fs::remove_dir_all(&p.store_path);
        info!("browser sign-in cancelled");
        self.broadcast_state().await;
        Ok(())
    }

    async fn logout(self: &Arc<Self>) -> Result<()> {
        let (client, task, pending) = {
            let mut st = self.state.lock().await;
            (st.client.take(), st.sync_task.take(), st.pending.take())
        };
        if let Some(task) = task {
            task.abort();
        }
        if let Some(p) = pending {
            p.task.abort();
            let _ = std::fs::remove_dir_all(&p.store_path);
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
        client.add_event_handler(on_stripped_member);
        client.add_event_handler(on_member);

        let core = self.clone();
        let sync_client = client.clone();
        let task = tokio::spawn(async move { core.sync_loop(sync_client, sync_token).await });

        // OAuth access tokens are short-lived; the SDK refreshes them and we
        // must persist the new pair or the next restart is signed out.
        let core = self.clone();
        let watch_client = client.clone();
        let mut changes = client.subscribe_to_session_changes();
        tokio::spawn(async move {
            while let Ok(change) = changes.recv().await {
                match change {
                    SessionChange::TokensRefreshed => {
                        if let Err(e) = core.persist_tokens(&watch_client) {
                            warn!("could not persist refreshed tokens: {e:#}");
                        }
                    }
                    SessionChange::UnknownToken(info) => {
                        warn!(soft_logout = info.soft_logout, "homeserver rejected our token");
                        core.set_error(Some("session expired; sign out and sign in again".into())).await;
                    }
                }
            }
        });

        let mut st = self.state.lock().await;
        st.client = Some(client);
        st.sync_task = Some(task);
        st.pending = None;
        st.error = None;
        drop(st);
        self.broadcast_state().await;
    }

    fn persist_tokens(&self, client: &Client) -> Result<()> {
        let file = self.session_file();
        let text = std::fs::read_to_string(&file)?;
        let mut saved: PersistedSession = serde_json::from_str(&text)?;
        saved.auth = match saved.auth {
            StoredAuth::Password { .. } => StoredAuth::Password {
                session: client.matrix_auth().session().ok_or_else(|| anyhow!("no session"))?,
            },
            StoredAuth::Oauth { client_id, .. } => StoredAuth::Oauth {
                client_id,
                user: client.oauth().user_session().ok_or_else(|| anyhow!("no session"))?,
            },
        };
        write_private(&file, &serde_json::to_vec(&saved)?)
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
            out.push(self.room_info(&room).await);
        }
        out.sort_by(|a, b| b.unread.cmp(&a.unread).then_with(|| a.name.cmp(&b.name)));
        Ok(out)
    }

    async fn room_info(&self, room: &Room) -> RoomInfo {
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
        RoomInfo {
            id: room.room_id().to_string(),
            name,
            topic: room.topic(),
            encrypted,
            direct: room.is_direct().await.unwrap_or(false),
            unread: counts.notification_count,
            highlights: counts.highlight_count,
        }
    }

    // ---------- discovery ----------

    async fn search_rooms(&self, query: &str, server: Option<&str>, limit: u32) -> Result<Vec<DirectoryRoom>> {
        let client = self.client().await?;
        let mut req = get_public_rooms_filtered::v3::Request::new();
        req.limit = Some(UInt::from(limit.clamp(1, 100)));
        let mut filter = Filter::new();
        filter.generic_search_term = Some(query.trim().to_owned());
        req.filter = filter;
        if let Some(server) = server.map(str::trim).filter(|s| !s.is_empty()) {
            req.server = Some(OwnedServerName::try_from(server).context("invalid server name")?);
        }
        let resp = tokio::time::timeout(SEARCH_TIMEOUT, client.public_rooms_filtered(req))
            .await
            .map_err(|_| anyhow!("the room directory did not answer in time"))?
            .context("searching the room directory")?;
        Ok(resp
            .chunk
            .into_iter()
            .map(|r| DirectoryRoom {
                joined: client.get_room(&r.room_id).is_some_and(|room| room.state() == RoomState::Joined),
                id: r.room_id.to_string(),
                name: r
                    .name
                    .clone()
                    .or_else(|| r.canonical_alias.as_ref().map(|a| a.to_string()))
                    .unwrap_or_else(|| r.room_id.to_string()),
                alias: r.canonical_alias.map(|a| a.to_string()),
                topic: r.topic,
                members: r.num_joined_members.into(),
            })
            .collect())
    }

    async fn join(&self, id_or_alias: &str) -> Result<Room> {
        let client = self.client().await?;
        let target = RoomOrAliasId::parse(id_or_alias.trim()).context("expected #alias:server or !id:server")?;
        let via: Vec<OwnedServerName> = target.server_name().map(|s| vec![s.to_owned()]).unwrap_or_default();
        client.join_room_by_id_or_alias(&target, &via).await.context("joining room")
    }

    async fn search_users(&self, query: &str, limit: u32) -> Result<Vec<DirectoryUser>> {
        let client = self.client().await?;
        let resp = tokio::time::timeout(SEARCH_TIMEOUT, client.search_users(query.trim(), u64::from(limit.clamp(1, 50))))
            .await
            .map_err(|_| anyhow!("the user directory did not answer in time"))?
            .context("searching users")?;
        Ok(resp
            .results
            .into_iter()
            .map(|u| DirectoryUser { id: u.user_id.to_string(), name: u.display_name })
            .collect())
    }

    async fn dm(&self, user: &str) -> Result<Room> {
        let client = self.client().await?;
        let user_id = UserId::parse(user.trim()).context("expected @user:server")?;
        if let Some(room) = client.get_dm_room(&user_id) {
            if room.state() == RoomState::Joined {
                return Ok(room);
            }
        }
        client.create_dm(&user_id).await.context("creating direct chat")
    }

    async fn create_room(&self, name: String, topic: Option<String>, encrypted: bool, private: bool) -> Result<Room> {
        let client = self.client().await?;
        let name = name.trim().to_owned();
        if name.is_empty() {
            bail!("a room needs a name");
        }
        let mut req = create_room::v3::Request::new();
        req.name = Some(name);
        req.topic = topic.map(|t| t.trim().to_owned()).filter(|t| !t.is_empty());
        req.preset = Some(if private { create_room::v3::RoomPreset::PrivateChat } else { create_room::v3::RoomPreset::PublicChat });
        req.visibility = if private { Visibility::Private } else { Visibility::Public };
        if encrypted {
            let content = RoomEncryptionEventContent::with_recommended_defaults();
            req.initial_state = vec![InitialStateEvent::new(EmptyStateKey, content).to_raw_any()];
        }
        client.create_room(req).await.context("creating room")
    }

    async fn invites(&self) -> Result<Vec<InviteInfo>> {
        let client = self.client().await?;
        let mut out = Vec::new();
        for room in client.invited_rooms() {
            out.push(invite_info(&room).await);
        }
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

/// How this daemon introduces itself to the homeserver's OAuth server when
/// registering dynamically. Redirects go to a loopback listener.
fn client_metadata() -> Raw<ClientMetadata> {
    let v4 = Url::parse(&format!("http://{}/", Ipv4Addr::LOCALHOST)).expect("valid redirect URI");
    let v6 = Url::parse(&format!("http://[{}]/", Ipv6Addr::LOCALHOST)).expect("valid redirect URI");
    let client_uri = Localized::new(Url::parse(CLIENT_URI).expect("valid client URI"), None);
    let metadata = ClientMetadata {
        client_name: Some(Localized::new(DEVICE_NAME.to_owned(), [])),
        policy_uri: Some(client_uri.clone()),
        tos_uri: Some(client_uri.clone()),
        ..ClientMetadata::new(
            ApplicationType::Native,
            vec![OAuthGrantType::AuthorizationCode { redirect_uris: vec![v4, v6] }],
            client_uri,
        )
    };
    Raw::new(&metadata).expect("client metadata serializes")
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

/// Invites arrive as stripped state; announce the ones addressed to us.
async fn on_stripped_member(event: StrippedRoomMemberEvent, room: Room, client: Client, ctx: Ctx<HandlerCtx>) {
    if event.content.membership != MembershipState::Invite {
        return;
    }
    if client.user_id().is_none_or(|me| me != event.state_key) {
        return;
    }
    if room.state() != RoomState::Invited {
        return;
    }
    let _ = ctx.events.send(Event::Invite(invite_info(&room).await));
}

/// Our own membership changed in a room we are in: joined, left, kicked.
async fn on_member(event: OriginalSyncRoomMemberEvent, client: Client, ctx: Ctx<HandlerCtx>) {
    if client.user_id().is_none_or(|me| me != event.state_key) {
        return;
    }
    let _ = ctx.events.send(Event::RoomsChanged);
}

async fn invite_info(room: &Room) -> InviteInfo {
    let name = match room.display_name().await {
        Ok(n) => n.to_string(),
        Err(_) => room.room_id().to_string(),
    };
    let inviter = match room.invite_details().await {
        Ok(details) => details.inviter,
        Err(_) => None,
    };
    InviteInfo {
        room: room.room_id().to_string(),
        name,
        inviter: inviter.as_ref().map(|m| m.user_id().to_string()),
        inviter_name: inviter.as_ref().map(|m| m.name().to_owned()),
        direct: room.is_direct().await.unwrap_or(false),
    }
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
