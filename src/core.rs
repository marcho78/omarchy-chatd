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
            room::{Visibility, create_room},
        },
        events::receipt::ReceiptType as StoreReceiptType,
        directory::Filter,
        events::{
            AnySyncMessageLikeEvent, AnySyncTimelineEvent, EmptyStateKey, InitialStateEvent, SyncMessageLikeEvent,
            receipt::ReceiptThread,
            reaction::{OriginalSyncReactionEvent, ReactionEventContent},
            receipt::{ReceiptType as EphemeralReceiptType, SyncReceiptEvent},
            relation::{Annotation, Replacement},
            typing::SyncTypingEvent,
            room::{
                redaction::OriginalSyncRoomRedactionEvent,
                encryption::RoomEncryptionEventContent,
                member::{MembershipState, OriginalSyncRoomMemberEvent, StrippedRoomMemberEvent},
                message::{
                    AddMentions, MessageFormat, MessageType, OriginalSyncRoomMessageEvent, Relation,
                    RoomMessageEventContent, RoomMessageEventContentWithoutRelation,
                },
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
    Command, DirectoryRoom, DirectoryUser, Event, InviteInfo, MemberInfo, Message, MessageEdit, Reaction,
    ReactionEvent, ReactionSender, ReceiptInfo, Redaction, ReplyPreview, Request, Response, RoomDetails, RoomInfo,
    Status, TimelinePage, TypingInfo, UserRef,
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
    /// Verification flows we are tracking: flow id -> other user.
    pub(crate) flows: tokio::sync::Mutex<std::collections::HashMap<String, matrix_sdk::ruma::OwnedUserId>>,
    /// Reactions seen on a page whose target message was not on it: they
    /// come from a newer page than the message they belong to, so keep
    /// them per room until the target's page is loaded.
    /// room -> target event -> (key, sender, reaction event id)
    pending_reactions: tokio::sync::Mutex<std::collections::HashMap<String, std::collections::HashMap<String, Vec<(String, matrix_sdk::ruma::OwnedUserId, String)>>>>,
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
        Ok(Arc::new(Self { data_dir, events, state: Default::default(), flows: Default::default(), pending_reactions: Default::default() }))
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
            Command::Timeline { room, limit, before } => {
                Ok(serde_json::to_value(self.timeline(&room, limit, before).await?)?)
            }
            Command::Send { room, body, reply_to } => {
                let event_id = self.send(&room, body, reply_to).await?;
                Ok(json!({ "event_id": event_id }))
            }
            Command::Edit { room, event_id, body } => {
                let id = self.edit(&room, &event_id, body).await?;
                Ok(json!({ "event_id": id }))
            }
            Command::Delete { room, event_id } => {
                let r = self.room(&room).await?;
                let id = matrix_sdk::ruma::EventId::parse(&event_id).context("invalid event id")?;
                r.redact(&id, None, None).await.context("deleting")?;
                Ok(json!({}))
            }
            Command::React { room, event_id, key } => {
                let r = self.room(&room).await?;
                let id = matrix_sdk::ruma::EventId::parse(&event_id).context("invalid event id")?;
                let resp = r.send(ReactionEventContent::new(Annotation::new(id, key))).await.context("reacting")?;
                Ok(json!({ "reaction_id": resp.response.event_id.to_string() }))
            }
            Command::Unreact { room, reaction_id } => {
                let r = self.room(&room).await?;
                let id = matrix_sdk::ruma::EventId::parse(&reaction_id).context("invalid event id")?;
                r.redact(&id, None, None).await.context("removing reaction")?;
                Ok(json!({}))
            }
            Command::Typing { room, typing } => {
                let r = self.room(&room).await?;
                r.typing_notice(typing).await.context("typing notice")?;
                Ok(json!({}))
            }
            Command::RoomDetails { room } => Ok(serde_json::to_value(self.room_details(&room).await?)?),
            Command::Members { room, query, limit } => Ok(serde_json::to_value(self.members(&room, &query, limit).await?)?),
            Command::Avatar { url } => {
                let path = self.avatar(&url).await?;
                Ok(json!({ "path": path }))
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
            Command::VerificationStatus => Ok(serde_json::to_value(self.verification_status().await?)?),
            Command::VerifyRequest => {
                let flow_id = self.verify_request().await?;
                Ok(json!({ "flow_id": flow_id }))
            }
            Command::VerifyAccept { flow_id } => { self.verify_accept(&flow_id).await?; Ok(json!({})) }
            Command::VerifyConfirm { flow_id } => { self.verify_confirm(&flow_id).await?; Ok(json!({})) }
            Command::VerifyCancel { flow_id } => { self.verify_cancel(&flow_id).await?; Ok(json!({})) }
            Command::Recover { key } => {
                self.recover(&key).await?;
                Ok(serde_json::to_value(self.verification_status().await?)?)
            }
            Command::SetupRecovery => {
                let key = self.setup_recovery().await?;
                Ok(json!({ "recovery_key": key }))
            }
            Command::ResetRecoveryKey => {
                let key = self.reset_recovery_key().await?;
                Ok(json!({ "recovery_key": key }))
            }
            Command::Download { room, event_id, thumbnail } => {
                let (path, mime) = self.download(&room, &event_id, thumbnail).await?;
                Ok(json!({ "path": path, "mime": mime }))
            }
            Command::SendFile { room, path, caption } => {
                let event_id = self.send_file(&room, &path, caption).await?;
                Ok(json!({ "event_id": event_id }))
            }
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

    pub(crate) async fn client(&self) -> Result<Client> {
        self.state.lock().await.client.clone().ok_or_else(|| anyhow!("not logged in"))
    }

    pub(crate) async fn room(&self, id: &str) -> Result<Room> {
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
        // The event cache keeps a synced timeline per room; the unread fallback reads it.
        if let Err(e) = client.event_cache().subscribe() {
            warn!("event cache: {e:#}");
        }
        client.add_event_handler_context(HandlerCtx { events: self.events.clone() });
        client.add_event_handler(on_room_message);
        client.add_event_handler(on_stripped_member);
        client.add_event_handler(on_member);
        client.add_event_handler(on_reaction);
        client.add_event_handler(on_redaction);
        client.add_event_handler(on_typing);
        client.add_event_handler(on_receipt);
        crate::verify::install_handlers(self, &client);

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

        // Receipts (ours from another device, theirs), unread flags and new
        // latest events all change what the room list shows; coalesce them.
        let core = self.clone();
        let mut updates = client.room_info_notable_update_receiver();
        tokio::spawn(async move {
            use matrix_sdk_base::RoomInfoNotableUpdateReasons as R;
            let mut pending = false;
            loop {
                let wait = if pending { Duration::from_millis(300) } else { Duration::from_secs(3600) };
                match tokio::time::timeout(wait, updates.recv()).await {
                    Ok(Ok(u)) => {
                        if u.reasons.intersects(R::READ_RECEIPT | R::UNREAD_MARKER | R::LATEST_EVENT) {
                            pending = true;
                        }
                    }
                    Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => pending = true,
                    Ok(Err(_)) => break,
                    Err(_) => {
                        if pending {
                            pending = false;
                            let _ = core.events().send(Event::RoomsChanged);
                        }
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
        let me = room.client().user_id().map(|u| u.to_owned());
        let mut read_marker = None;
        let mut read_at: Option<u64> = None;
        if let Some(me) = me.as_deref() {
            for thread in [ReceiptThread::Unthreaded, ReceiptThread::Main] {
                if let Ok(Some((eid, receipt))) = room.load_user_receipt(StoreReceiptType::Read, &thread, me).await {
                    read_marker = Some(eid.to_string());
                    read_at = receipt.ts.map(|t| t.0.into());
                    break;
                }
            }
        }
        // The SDK's counter only resolves once the receipt's event has come
        // through sync; a receipt placed on paged history leaves it at 0. So
        // also count what the cache holds from others after we last read.
        let mut unread = room.num_unread_messages();
        if let (Some(me), Some(at)) = (me.as_deref(), read_at) {
            if let Ok((cache, _guard)) = room.event_cache().await {
                if let Ok(events) = cache.events().await {
                    let mut n = 0u64;
                    for ev in events {
                        if let Ok(AnySyncTimelineEvent::MessageLike(m)) = ev.raw().deserialize() {
                            let is_msg = matches!(m, AnySyncMessageLikeEvent::RoomMessage(_) | AnySyncMessageLikeEvent::RoomEncrypted(_));
                            if is_msg && m.sender() != me && u64::from(m.origin_server_ts().0) > at {
                                n += 1;
                            }
                        }
                    }
                    unread = unread.max(n);
                }
            }
        }
        RoomInfo {
            id: room.room_id().to_string(),
            name,
            topic: room.topic(),
            encrypted,
            direct: room.is_direct().await.unwrap_or(false),
            avatar: room.avatar_url().map(|u| u.to_string()),
            unread,
            highlights: room.num_unread_mentions().max(counts.highlight_count),
            notifications: counts.notification_count,
            read_marker,
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

    async fn timeline(&self, room_id: &str, limit: u32, before: Option<String>) -> Result<TimelinePage> {
        let room = self.room(room_id).await?;
        let mut from = before.filter(|t| !t.is_empty());
        let mut out = Vec::new();
        let mut next: Option<String> = None;
        // A chunk can be nothing but state events (room creation, joins);
        // keep going so a page always carries messages or the real end.
        // Reactions on this page keyed by their target; plus any carried
        // over from newer pages whose targets we are about to see.
        let mut reactions: std::collections::HashMap<String, Vec<(String, matrix_sdk::ruma::OwnedUserId, String)>> = {
            let mut p = self.pending_reactions.lock().await;
            p.remove(room_id).unwrap_or_default()
        };
        let mut redacted: std::collections::HashSet<String> = Default::default();
        for _ in 0..6 {
            let mut opts = MessagesOptions::backward();
            opts.limit = UInt::from(limit.clamp(1, 200));
            opts.from = from.clone();
            let page = room.messages(opts).await.context("fetching messages")?;
            let raw_count = page.chunk.len();
            for ev in page.chunk {
                if let Ok(AnySyncTimelineEvent::MessageLike(AnySyncMessageLikeEvent::Reaction(
                    SyncMessageLikeEvent::Original(r),
                ))) = ev.raw().deserialize()
                {
                    let a = &r.content.relates_to;
                    reactions.entry(a.event_id.to_string()).or_default().push((a.key.clone(), r.sender.clone(), r.event_id.to_string()));
                    continue;
                }
                if let Ok(AnySyncTimelineEvent::MessageLike(AnySyncMessageLikeEvent::RoomRedaction(
                    matrix_sdk::ruma::events::room::redaction::SyncRoomRedactionEvent::Original(rd),
                ))) = ev.raw().deserialize()
                {
                    redacted.insert(rd.redacts(&room.clone_info().room_version_rules_or_default().redaction).to_string());
                    continue;
                }
                if let Some(m) = self.message_from_event(&room, ev).await {
                    out.push(m);
                }
            }
            // The server omits `end` when there is nothing further back, and
            // under-fills a chunk only at the start of history — matrix.org
            // sends a cursor either way, so use the fill as the signal.
            next = if raw_count < limit.clamp(1, 200) as usize { None } else { page.end.clone() };
            if !out.is_empty() || next.is_none() {
                break;
            }
            from = next.clone();
        }
        let me = room.client().user_id().map(|u| u.to_owned());
        for m in out.iter_mut() {
            if let Some(mut list) = reactions.remove(&m.event_id) {
                list.reverse(); // collected newest-first; chips read oldest-first
                m.reactions = aggregate_reactions(&room, list, me.as_deref(), &redacted).await;
            }
            m.read_by = read_by(&room, &m.event_id, me.as_deref()).await;
        }
        // Whatever is left targets messages on an older page.
        if !reactions.is_empty() {
            self.pending_reactions.lock().await.insert(room_id.to_owned(), reactions);
        }
        out.reverse(); // backward pagination yields newest first
        Ok(TimelinePage { messages: out, next })
    }

    /// A timeline event as a message, or None for anything that is not one.
    async fn message_from_event(&self, room: &Room, ev: matrix_sdk::deserialized_responses::TimelineEvent) -> Option<Message> {
        let encrypted = ev.encryption_info().is_some();
        let parsed = ev.raw().deserialize().ok()?;
        match parsed {
            AnySyncTimelineEvent::MessageLike(AnySyncMessageLikeEvent::RoomMessage(
                SyncMessageLikeEvent::Original(msg),
            )) => {
                // An edit event itself is not shown; its target carries it.
                if matches!(msg.content.relates_to, Some(Relation::Replacement(_))) {
                    return None;
                }
                let mut m = to_message(room, msg, encrypted).await;
                // The server bundles the latest edit under unsigned.m.relations.
                if let Some((body, html)) = bundled_edit(ev.raw()) {
                    m.body = body;
                    m.html = html;
                    m.edited = true;
                }
                Some(m)
            }
            // Joins, leaves, invites, kicks, name changes: small system lines.
            AnySyncTimelineEvent::State(matrix_sdk::ruma::events::AnySyncStateEvent::RoomMember(
                matrix_sdk::ruma::events::SyncStateEvent::Original(m),
            )) => {
                let text = membership_line(room, &m).await?;
                Some(Message {
                    room: room.room_id().to_string(),
                    event_id: m.event_id.to_string(),
                    sender: m.sender.to_string(),
                    sender_name: String::new(),
                    sender_avatar: None,
                    body: text,
                    html: None,
                    msgtype: "system".to_owned(),
                    ts: m.origin_server_ts.0.into(),
                    encrypted: false,
                    attachment: None,
                    reply_to: None,
                    edited: false,
                    reactions: Vec::new(),
                    read_by: Vec::new(),
                    deleted: false,
                })
            }
            // A redacted message keeps its place with empty content — in an
            // encrypted room the shell that remains is an m.room.encrypted.
            AnySyncTimelineEvent::MessageLike(AnySyncMessageLikeEvent::RoomMessage(
                SyncMessageLikeEvent::Redacted(r),
            )) => Some(deleted_placeholder(room, &r.sender, &r.event_id, r.origin_server_ts, encrypted).await),
            AnySyncTimelineEvent::MessageLike(AnySyncMessageLikeEvent::RoomEncrypted(
                SyncMessageLikeEvent::Redacted(r),
            )) => Some(deleted_placeholder(room, &r.sender, &r.event_id, r.origin_server_ts, true).await),
            // Still encrypted: we have no key (yet). Show a placeholder so
            // the gap is visible; backup or key sharing may fill it later.
            AnySyncTimelineEvent::MessageLike(AnySyncMessageLikeEvent::RoomEncrypted(
                SyncMessageLikeEvent::Original(enc),
            )) => {
                let sender_name = match room.get_member_no_sync(&enc.sender).await {
                    Ok(Some(m)) => m.name().to_owned(),
                    _ => enc.sender.localpart().to_owned(),
                };
                Some(Message {
                    room: room.room_id().to_string(),
                    event_id: enc.event_id.to_string(),
                    sender: enc.sender.to_string(),
                    sender_name,
                    sender_avatar: None,
                    body: "Unable to decrypt this message".to_owned(),
                    html: None,
                    msgtype: "unable_to_decrypt".to_owned(),
                    ts: enc.origin_server_ts.0.into(),
                    encrypted: true,
                    attachment: None,
                    reply_to: None,
                    edited: false,
                    reactions: Vec::new(),
                    read_by: Vec::new(),
                    deleted: false,
                })
            }
            _ => None,
        }
    }

    async fn send(&self, room_id: &str, body: String, reply_to: Option<String>) -> Result<String> {
        let room = self.room(room_id).await?;
        let content = match reply_to.filter(|r| !r.is_empty()) {
            Some(target) => {
                let target = matrix_sdk::ruma::EventId::parse(&target).context("invalid reply target")?;
                let reply = matrix_sdk::room::reply::Reply {
                    event_id: target,
                    enforce_thread: matrix_sdk::room::reply::EnforceThread::MaybeThreaded,
                    add_mentions: AddMentions::Yes,
                };
                room.make_reply_event(RoomMessageEventContentWithoutRelation::text_plain(body), reply)
                    .await
                    .context("building the reply")?
            }
            None => RoomMessageEventContent::text_plain(body),
        };
        let resp = room.send(content).await.context("sending")?;
        Ok(resp.response.event_id.to_string())
    }

    async fn edit(&self, room_id: &str, event_id: &str, body: String) -> Result<String> {
        let room = self.room(room_id).await?;
        let target = matrix_sdk::ruma::EventId::parse(event_id).context("invalid event id")?;
        let content = room
            .make_edit_event(
                &target,
                matrix_sdk::room::edit::EditedContent::RoomMessage(RoomMessageEventContentWithoutRelation::text_plain(body)),
            )
            .await
            .context("building the edit")?;
        let resp = room.send(content).await.context("sending the edit")?;
        Ok(resp.response.event_id.to_string())
    }

    async fn mark_read(&self, room_id: &str, event_id: &str) -> Result<()> {
        let room = self.room(room_id).await?;
        let event_id = matrix_sdk::ruma::EventId::parse(event_id).context("invalid event id")?;
        let receipts = matrix_sdk::room::Receipts::new()
            .fully_read_marker(event_id.clone())
            .public_read_receipt(event_id);
        room.send_multiple_receipts(receipts).await.context("sending read receipt")?;
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
    if let Some(Relation::Replacement(Replacement { event_id, new_content, .. })) = &event.content.relates_to {
        let html = formatted_html(&new_content.msgtype);
        let _ = ctx.events.send(Event::MessageEdited(MessageEdit {
            room: room.room_id().to_string(),
            event_id: event_id.to_string(),
            body: new_content.msgtype.body().to_owned(),
            html,
        }));
        return;
    }
    let msg = to_message(&room, event, encryption.is_some()).await;
    let _ = ctx.events.send(Event::Message(msg));
}

fn formatted_html(msgtype: &MessageType) -> Option<String> {
    match msgtype {
        MessageType::Text(t) => t.formatted.as_ref(),
        MessageType::Notice(n) => n.formatted.as_ref(),
        MessageType::Emote(e) => e.formatted.as_ref(),
        _ => None,
    }
    .filter(|f| f.format == MessageFormat::Html)
    .map(|f| f.body.clone())
}

/// The newest edit the server attached to an event, if any.
fn bundled_edit(raw: &matrix_sdk::ruma::serde::Raw<AnySyncTimelineEvent>) -> Option<(String, Option<String>)> {
    let unsigned: serde_json::Value = raw.get_field("unsigned").ok().flatten()?;
    let replace = unsigned.get("m.relations")?.get("m.replace")?;
    let new_content = replace.get("content")?.get("m.new_content")?;
    let body = new_content.get("body")?.as_str()?.to_owned();
    let html = match (new_content.get("format").and_then(|f| f.as_str()), new_content.get("formatted_body").and_then(|b| b.as_str())) {
        (Some("org.matrix.custom.html"), Some(h)) => Some(h.to_owned()),
        _ => None,
    };
    Some((body, html))
}

/// Matrix used to put a quoted fallback of the replied-to message at the top
/// of a reply's body; strip it so the quote is rendered once, properly.
fn strip_reply_fallback(body: &str) -> String {
    if !body.starts_with("> ") {
        return body.to_owned();
    }
    let mut lines = body.lines();
    for line in lines.by_ref() {
        if line.is_empty() {
            break;
        }
    }
    let rest: Vec<&str> = lines.collect();
    if rest.is_empty() { body.to_owned() } else { rest.join("\n") }
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
    let (sender_name, sender_avatar) = match room.get_member_no_sync(&ev.sender).await {
        Ok(Some(m)) => (m.name().to_owned(), m.avatar_url().map(|u| u.to_string())),
        _ => (ev.sender.localpart().to_owned(), None),
    };
    let html = formatted_html(&ev.content.msgtype);
    let reply_to = match &ev.content.relates_to {
        Some(Relation::Reply(in_reply_to)) => reply_preview(room, &in_reply_to.in_reply_to.event_id).await,
        _ => None,
    };
    let body = if reply_to.is_some() { strip_reply_fallback(ev.content.body()) } else { ev.content.body().to_owned() };
    // The HTML fallback carries the quote in <mx-reply>, which the client strips.
    Message {
        room: room.room_id().to_string(),
        event_id: ev.event_id.to_string(),
        sender: ev.sender.to_string(),
        sender_name,
        sender_avatar,
        body,
        html,
        msgtype: ev.content.msgtype.msgtype().to_owned(),
        ts: ev.origin_server_ts.0.into(),
        encrypted,
        attachment: crate::media::attachment_of(&ev.content.msgtype),
        reply_to,
        edited: false,
        reactions: Vec::new(),
        read_by: Vec::new(),
        deleted: false,
    }
}

async fn deleted_placeholder(
    room: &Room,
    sender: &matrix_sdk::ruma::UserId,
    event_id: &matrix_sdk::ruma::EventId,
    ts: matrix_sdk::ruma::MilliSecondsSinceUnixEpoch,
    encrypted: bool,
) -> Message {
    let sender_name = match room.get_member_no_sync(sender).await {
        Ok(Some(m)) => m.name().to_owned(),
        _ => sender.localpart().to_owned(),
    };
    Message {
        room: room.room_id().to_string(),
        event_id: event_id.to_string(),
        sender: sender.to_string(),
        sender_name,
        sender_avatar: None,
        body: String::new(),
        html: None,
        msgtype: "m.text".to_owned(),
        ts: ts.0.into(),
        encrypted,
        attachment: None,
        reply_to: None,
        edited: false,
        reactions: Vec::new(),
        read_by: Vec::new(),
        deleted: true,
    }
}

async fn user_ref(room: &Room, user: &matrix_sdk::ruma::UserId) -> UserRef {
    let name = match room.get_member_no_sync(user).await {
        Ok(Some(m)) => m.name().to_owned(),
        _ => user.localpart().to_owned(),
    };
    UserRef { id: user.to_string(), name }
}

/// Group raw reactions by key, count them, and remember our own event id.
async fn aggregate_reactions(
    room: &Room,
    list: Vec<(String, matrix_sdk::ruma::OwnedUserId, String)>,
    me: Option<&matrix_sdk::ruma::UserId>,
    redacted: &std::collections::HashSet<String>,
) -> Vec<Reaction> {
    let mut order: Vec<String> = Vec::new();
    let mut by_key: std::collections::HashMap<String, Reaction> = Default::default();
    for (key, sender, id) in list {
        if redacted.contains(&id) {
            continue;
        }
        let entry = by_key.entry(key.clone()).or_insert_with(|| {
            order.push(key.clone());
            Reaction { key: key.clone(), count: 0, senders: Vec::new(), mine: None }
        });
        // One reaction per user per key.
        if entry.senders.iter().any(|u| u.id == sender.as_str()) {
            continue;
        }
        entry.count += 1;
        if me == Some(sender.as_ref()) {
            entry.mine = Some(id.clone());
        }
        let u = user_ref(room, &sender).await;
        entry.senders.push(ReactionSender { id: u.id, name: u.name, reaction_id: id });
    }
    order.into_iter().filter_map(|k| by_key.remove(&k)).collect()
}

/// Others whose read receipt sits on this event. Clients send receipts
/// either unthreaded or on the main thread; both mean "read up to here".
async fn read_by(room: &Room, event_id: &str, me: Option<&matrix_sdk::ruma::UserId>) -> Vec<UserRef> {
    let Ok(id) = matrix_sdk::ruma::EventId::parse(event_id) else { return Vec::new() };
    let mut out: Vec<UserRef> = Vec::new();
    for thread in [ReceiptThread::Unthreaded, ReceiptThread::Main] {
        let Ok(list) = room.load_event_receipts(StoreReceiptType::Read, &thread, &id).await else { continue };
        for (user, _) in list {
            if me == Some(user.as_ref()) || out.iter().any(|u| u.id == user.as_str()) {
                continue;
            }
            out.push(user_ref(room, &user).await);
        }
    }
    out
}

async fn on_reaction(event: OriginalSyncReactionEvent, room: Room, ctx: Ctx<HandlerCtx>) {
    if room.state() != RoomState::Joined {
        return;
    }
    let a = &event.content.relates_to;
    let _ = ctx.events.send(Event::Reaction(ReactionEvent {
        room: room.room_id().to_string(),
        event_id: a.event_id.to_string(),
        key: a.key.clone(),
        sender: user_ref(&room, &event.sender).await,
        reaction_id: event.event_id.to_string(),
    }));
}

async fn on_redaction(event: OriginalSyncRoomRedactionEvent, room: Room, ctx: Ctx<HandlerCtx>) {
    if room.state() != RoomState::Joined {
        return;
    }
    let rules = room.clone_info().room_version_rules_or_default();
    let target = event.redacts(&rules.redaction);
    let _ = ctx.events.send(Event::Redacted(Redaction { room: room.room_id().to_string(), event_id: target.to_string() }));
}

async fn on_typing(event: SyncTypingEvent, room: Room, client: Client, ctx: Ctx<HandlerCtx>) {
    let mut users = Vec::new();
    for u in &event.content.user_ids {
        if client.user_id().is_some_and(|me| me == u) {
            continue;
        }
        users.push(user_ref(&room, u).await);
    }
    let _ = ctx.events.send(Event::Typing(TypingInfo { room: room.room_id().to_string(), users }));
}

async fn on_receipt(event: SyncReceiptEvent, room: Room, client: Client, ctx: Ctx<HandlerCtx>) {
    // One event can carry receipts for several messages; group by message.
    let mut by_event: std::collections::HashMap<String, Vec<UserRef>> = Default::default();
    for (event_id, receipts) in event.content.0.iter() {
        if let Some(users) = receipts.get(&EphemeralReceiptType::Read) {
            for (user, _) in users {
                if client.user_id().is_some_and(|me| me == user) {
                    continue;
                }
                by_event.entry(event_id.to_string()).or_default().push(user_ref(&room, user).await);
            }
        }
    }
    for (event_id, users) in by_event {
        let _ = ctx.events.send(Event::Receipt(ReceiptInfo { room: room.room_id().to_string(), event_id, users }));
    }
}

/// "X joined", "X left", … for a member event, or None for changes not worth a line.
async fn membership_line(room: &Room, ev: &matrix_sdk::ruma::events::room::member::OriginalSyncRoomMemberEvent) -> Option<String> {
    use matrix_sdk::ruma::events::room::member::MembershipChange as C;
    let who = |name: &Option<String>, id: &matrix_sdk::ruma::UserId| name.clone().unwrap_or_else(|| id.localpart().to_owned());
    let target_name = ev.content.displayname.clone();
    let target = who(&target_name, &ev.state_key);
    let sender_name = match room.get_member_no_sync(&ev.sender).await {
        Ok(Some(m)) => m.name().to_owned(),
        _ => ev.sender.localpart().to_owned(),
    };
    let text = match ev.membership_change() {
        C::Joined => format!("{target} joined"),
        C::Left => format!("{target} left"),
        C::Invited => format!("{sender_name} invited {target}"),
        C::InvitationAccepted => format!("{target} accepted the invitation"),
        C::InvitationRejected => format!("{target} declined the invitation"),
        C::InvitationRevoked => format!("{sender_name} withdrew the invitation for {target}"),
        C::Kicked => format!("{sender_name} removed {target}"),
        C::Banned => format!("{sender_name} banned {target}"),
        C::Unbanned => format!("{sender_name} unbanned {target}"),
        C::KickedAndBanned => format!("{sender_name} removed and banned {target}"),
        C::Knocked => format!("{target} asked to join"),
        C::ProfileChanged { displayname_change, avatar_url_change } => {
            match (displayname_change, avatar_url_change) {
                (Some(c), _) => {
                    let old = c.old.map(str::to_owned).unwrap_or_else(|| ev.state_key.localpart().to_owned());
                    let new = c.new.map(str::to_owned).unwrap_or_else(|| ev.state_key.localpart().to_owned());
                    format!("{old} is now known as {new}")
                }
                (None, Some(_)) => format!("{target} changed their avatar"),
                _ => return None,
            }
        }
        _ => return None,
    };
    Some(text)
}

fn role_of(power: i64) -> &'static str {
    if power >= 100 { "admin" } else if power >= 50 { "moderator" } else { "member" }
}

fn power_i64(p: matrix_sdk::ruma::events::room::power_levels::UserPowerLevel) -> i64 {
    match p {
        matrix_sdk::ruma::events::room::power_levels::UserPowerLevel::Infinite => i64::MAX,
        matrix_sdk::ruma::events::room::power_levels::UserPowerLevel::Int(i) => i.into(),
        _ => 0,
    }
}

impl Core {
    pub(crate) async fn room_details(&self, room_id: &str) -> Result<RoomDetails> {
        let room = self.room(room_id).await?;
        let name = match room.display_name().await {
            Ok(n) => n.to_string(),
            Err(_) => room.room_id().to_string(),
        };
        let client = room.client();
        let me = client.user_id().ok_or_else(|| anyhow!("no user id"))?;
        let own = room.get_member_no_sync(me).await.ok().flatten();
        let (can_invite, can_kick, can_ban, can_set_name, can_set_topic, can_redact_other) = match own {
            Some(m) => (
                m.can_invite(),
                m.can_kick(),
                m.can_ban(),
                m.can_send_state(matrix_sdk::ruma::events::StateEventType::RoomName),
                m.can_send_state(matrix_sdk::ruma::events::StateEventType::RoomTopic),
                m.can_redact_other(),
            ),
            None => (false, false, false, false, false, false),
        };
        use matrix_sdk::ruma::room::JoinRuleKind as J;
        let join_rule = match room.join_rule().map(|r| r.kind()) {
            Some(J::Public) => "public",
            Some(J::Invite) => "invite",
            Some(J::Knock) => "knock",
            Some(J::Restricted) | Some(J::KnockRestricted) => "restricted",
            _ => "other",
        }
        .to_owned();
        Ok(RoomDetails {
            id: room.room_id().to_string(),
            name,
            topic: room.topic(),
            avatar: room.avatar_url().map(|u| u.to_string()),
            alias: room.canonical_alias().map(|a| a.to_string()),
            encrypted: room.latest_encryption_state().await.map(|s| s.is_encrypted()).unwrap_or(false),
            direct: room.is_direct().await.unwrap_or(false),
            join_rule,
            member_count: room.joined_members_count(),
            can_invite,
            can_kick,
            can_ban,
            can_set_name,
            can_set_topic,
            can_redact_other,
        })
    }

    pub(crate) async fn members(&self, room_id: &str, query: &str, limit: u32) -> Result<Vec<MemberInfo>> {
        let room = self.room(room_id).await?;
        let members = room.members(matrix_sdk::RoomMemberships::JOIN).await.context("loading members")?;
        let q = query.trim().to_lowercase();
        let mut out: Vec<MemberInfo> = members
            .iter()
            .filter(|m| q.is_empty() || m.name().to_lowercase().contains(&q) || m.user_id().as_str().to_lowercase().contains(&q))
            .map(|m| {
                let power = power_i64(m.power_level());
                MemberInfo {
                    id: m.user_id().to_string(),
                    name: m.name().to_owned(),
                    avatar: m.avatar_url().map(|u| u.to_string()),
                    power,
                    role: role_of(power).to_owned(),
                }
            })
            .collect();
        out.sort_by(|a, b| b.power.cmp(&a.power).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())));
        out.truncate(limit.clamp(1, 2000) as usize);
        Ok(out)
    }

    /// Small square avatar into the media cache, keyed by the mxc URL.
    pub(crate) async fn avatar(&self, url: &str) -> Result<String> {
        let client = self.client().await?;
        let mxc = matrix_sdk::ruma::OwnedMxcUri::from(url);
        mxc.validate().map_err(|e| anyhow!("invalid avatar url: {e}"))?;
        let dir = crate::media::avatar_cache_dir()?;
        let path = dir.join(format!("{}.png", crate::media::hash_of(url)));
        if path.exists() {
            return Ok(path.to_string_lossy().into_owned());
        }
        let bytes = client
            .media()
            .get_media_content(
                &matrix_sdk::media::MediaRequestParameters {
                    source: matrix_sdk::ruma::events::room::MediaSource::Plain(mxc),
                    format: matrix_sdk::media::MediaFormat::Thumbnail(matrix_sdk::media::MediaThumbnailSettings::new(
                        UInt::from(96u32),
                        UInt::from(96u32),
                    )),
                },
                true,
            )
            .await
            .context("fetching avatar")?;
        std::fs::write(&path, &bytes).with_context(|| format!("writing {}", path.display()))?;
        Ok(path.to_string_lossy().into_owned())
    }
}

/// A one-line preview of the message a reply points at.
async fn reply_preview(room: &Room, event_id: &matrix_sdk::ruma::EventId) -> Option<ReplyPreview> {
    let ev = room.event(event_id, None).await.ok()?;
    let parsed: AnySyncTimelineEvent = ev.raw().deserialize().ok()?;
    let edited = bundled_edit(ev.raw()).map(|(b, _)| b);
    let (sender, body) = match parsed {
        AnySyncTimelineEvent::MessageLike(AnySyncMessageLikeEvent::RoomMessage(SyncMessageLikeEvent::Original(m))) => {
            let text = match crate::media::attachment_of(&m.content.msgtype) {
                Some(a) => format!("{} {}", match a.kind.as_str() { "image" => "🖼", "video" => "🎞", "audio" => "🎵", _ => "📎" }, a.caption.unwrap_or(a.name)),
                None => edited.unwrap_or_else(|| strip_reply_fallback(m.content.body())),
            };
            (m.sender, text)
        }
        AnySyncTimelineEvent::MessageLike(AnySyncMessageLikeEvent::RoomEncrypted(SyncMessageLikeEvent::Original(e))) => {
            (e.sender, "Unable to decrypt".to_owned())
        }
        _ => return None,
    };
    let sender_name = match room.get_member_no_sync(&sender).await {
        Ok(Some(m)) => m.name().to_owned(),
        _ => sender.localpart().to_owned(),
    };
    let one_line: String = body.split_whitespace().collect::<Vec<_>>().join(" ");
    let body = if one_line.chars().count() > 160 { format!("{}…", one_line.chars().take(160).collect::<String>()) } else { one_line };
    Some(ReplyPreview { event_id: event_id.to_string(), sender: sender.to_string(), sender_name, body })
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
