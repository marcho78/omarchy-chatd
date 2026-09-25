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
    deserialized_responses::TimelineEvent,
    event_handler::Ctx,
    room::MessagesOptions,
    ruma::{
        OwnedRoomId, OwnedServerName, RoomId, RoomOrAliasId, UInt, UserId,
        api::client::{
            directory::get_public_rooms_filtered,
            filter::FilterDefinition,
            room::{Visibility, create_room},
        },
        directory::Filter,
        events::receipt::ReceiptType as StoreReceiptType,
        events::{
            AnySyncMessageLikeEvent, AnySyncTimelineEvent, EmptyStateKey, InitialStateEvent,
            SyncMessageLikeEvent,
            reaction::{OriginalSyncReactionEvent, ReactionEventContent},
            receipt::ReceiptThread,
            receipt::{ReceiptType as EphemeralReceiptType, SyncReceiptEvent},
            relation::RelationType,
            relation::{Annotation, Replacement},
            room::{
                encryption::RoomEncryptionEventContent,
                member::{MembershipState, OriginalSyncRoomMemberEvent, StrippedRoomMemberEvent},
                message::{
                    AddMentions, MessageFormat, MessageType, OriginalSyncRoomMessageEvent,
                    Relation, RoomMessageEventContent, RoomMessageEventContentWithoutRelation,
                },
                redaction::OriginalSyncRoomRedactionEvent,
            },
            typing::SyncTypingEvent,
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
    Command, DirectoryPage, DirectoryRoom, DirectoryUser, Event, InviteInfo, LinkPreview,
    MemberInfo, Message, MessageEdit, Reaction, ReactionEvent, ReactionSender, ReceiptInfo,
    Redaction, ReplyPreview, Request, Response, RoomDetails, RoomInfo, SearchHit, SearchResults,
    SpaceInfo, Status, ThreadInfo, TimelinePage, TypingInfo, UserRef,
};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
const DEVICE_NAME: &str = "Yapper";
const CLIENT_URI: &str = "https://github.com/marcho78/omarchy-yapper";
/// How long a browser sign-in may sit waiting for the redirect.
const OAUTH_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// Directory searches, especially on a remote server, can stall on federation.
const SEARCH_TIMEOUT: Duration = Duration::from_secs(20);
/// Full-text search on a big homeserver can take a while on first use.
const MESSAGE_SEARCH_TIMEOUT: Duration = Duration::from_secs(45);
/// Encrypted rooms scanned locally by a search without a room, most recent first.
const MAX_SEARCH_ROOMS: usize = 40;
/// Reply previews kept in memory; the map is cleared when it fills.
const MAX_REPLY_CACHE: usize = 4096;
/// A reaction key longer than this is not an emoji.
const MAX_REACTION_KEY: usize = 64;

/// What survives a restart, written to `<data_dir>/session.json` (mode
/// 0600). The secrets — the store passphrase and the Matrix tokens — go to
/// the desktop keyring when there is one ([`crate::secrets`]); `secrets`
/// says where they are. Files from before the keyring carried them inline,
/// and are migrated on first load. The user's password is never stored.
#[derive(Serialize, Deserialize)]
struct PersistedSession {
    homeserver: String,
    store_path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sync_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    secrets: Option<crate::secrets::Backend>,
    // Inline secrets: the file backend, or a pre-keyring file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    store_passphrase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    auth: Option<StoredAuth>,
}

/// The secret half of a session: one blob in the keyring.
#[derive(Clone, Serialize, Deserialize)]
struct SessionSecrets {
    store_passphrase: String,
    auth: StoredAuth,
}

/// The two ways a session can have been obtained. OAuth sessions carry a
/// refresh token and the client id registered with the homeserver.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum StoredAuth {
    Password {
        session: MatrixSession,
    },
    Oauth {
        client_id: ClientId,
        user: UserSession,
    },
}

/// A browser sign-in that is waiting for the redirect.
struct PendingLogin {
    task: JoinHandle<()>,
    store_path: PathBuf,
}

#[derive(Default)]
struct State {
    client: Option<Client>,
    /// One instance for the session: it applies its own writes locally, so
    /// reads right after a change are consistent (a fresh instance would
    /// be built from account data that only refreshes with the next sync).
    notification_settings: Option<matrix_sdk::notification_settings::NotificationSettings>,
    sync_task: Option<JoinHandle<()>>,
    pending: Option<PendingLogin>,
    syncing: bool,
    error: Option<String>,
    /// Where this session's secrets are kept, once known.
    secrets_backend: Option<crate::secrets::Backend>,
    /// The store passphrase, so refreshed tokens can be re-saved beside it.
    store_passphrase: Option<String>,
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
    pub(crate) flows:
        tokio::sync::Mutex<std::collections::HashMap<String, matrix_sdk::ruma::OwnedUserId>>,
    /// room -> timestamp of its latest message: seeded from the server the
    /// first time a room is listed, then kept current by incoming events.
    activity: Arc<tokio::sync::Mutex<std::collections::HashMap<String, u64>>>,
    /// DM policy and community space, persisted in `<data_dir>/prefs.json`.
    prefs: Arc<tokio::sync::Mutex<crate::community::Prefs>>,
    /// Cached space hierarchy and the background joiner.
    community: Arc<crate::community::CommunityState>,
}

#[derive(Clone)]
struct HandlerCtx {
    events: broadcast::Sender<Event>,
    activity: Arc<tokio::sync::Mutex<std::collections::HashMap<String, u64>>>,
    prefs: Arc<tokio::sync::Mutex<crate::community::Prefs>>,
}

impl Core {
    pub fn new(data_dir: PathBuf, events: broadcast::Sender<Event>) -> Result<Arc<Self>> {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&data_dir)
            .with_context(|| format!("creating {}", data_dir.display()))?;
        let prefs = Arc::new(tokio::sync::Mutex::new(load_prefs(&data_dir)));
        Ok(Arc::new(Self {
            data_dir,
            events,
            state: Default::default(),
            flows: Default::default(),
            activity: Default::default(),
            prefs,
            community: Default::default(),
        }))
    }

    fn prefs_file(&self) -> PathBuf {
        self.data_dir.join("prefs.json")
    }

    pub fn events(&self) -> &broadcast::Sender<Event> {
        &self.events
    }

    fn session_file(&self) -> PathBuf {
        self.data_dir.join("session.json")
    }

    /// Restore a persisted session at startup, if there is one. A keyring
    /// that is locked or not answering is retried in the background rather
    /// than treated as "signed out".
    pub async fn restore(self: &Arc<Self>) -> Result<()> {
        if !self.session_file().exists() {
            return Ok(());
        }
        match self.load_session(true).await {
            Ok((saved, secrets)) => self.restore_with(saved, secrets).await,
            Err(e) => {
                warn!("session not restored yet: {e:#}");
                self.set_error(Some(format!("Could not read the saved session: {e}")))
                    .await;
                // Quiet retries: no unlock prompt until the user asks for one.
                let core = self.clone();
                tokio::spawn(async move {
                    let mut wait = 5u64;
                    loop {
                        tokio::time::sleep(Duration::from_secs(wait)).await;
                        if core.state.lock().await.client.is_some() || !core.session_file().exists()
                        {
                            return;
                        }
                        match core.load_session(false).await {
                            Ok((saved, secrets)) => {
                                if let Err(e) = core.restore_with(saved, secrets).await {
                                    warn!("restoring the session: {e:#}");
                                    core.set_error(Some(format!(
                                        "Could not restore the session: {e}"
                                    )))
                                    .await;
                                }
                                return;
                            }
                            Err(e) => {
                                warn!("session still not restored: {e:#}");
                                wait = (wait * 2).min(60);
                            }
                        }
                    }
                });
                Ok(())
            }
        }
    }

    async fn restore_with(
        self: &Arc<Self>,
        saved: PersistedSession,
        secrets: SessionSecrets,
    ) -> Result<()> {
        let client = Client::builder()
            .homeserver_url(&saved.homeserver)
            .with_threading_support(matrix_sdk::ThreadingSupport::Enabled {
                with_subscriptions: false,
            })
            // A request retries a few times with the server's suggested
            // wait, then fails; nothing blocks a socket call for minutes.
            .request_config(matrix_sdk::config::RequestConfig::new().retry_limit(3))
            // Media downloads are capped in size and time (see media.rs).
            .media_fetcher(crate::media::bounded_media_fetcher())
            .handle_refresh_tokens()
            .sqlite_store(&saved.store_path, Some(&secrets.store_passphrase))
            .build()
            .await?;
        match secrets.auth {
            StoredAuth::Password { session } => client.restore_session(session).await?,
            StoredAuth::Oauth { client_id, user } => {
                client
                    .restore_session(OAuthSession { client_id, user })
                    .await?
            }
        }
        {
            let mut st = self.state.lock().await;
            st.secrets_backend = saved.secrets;
            st.store_passphrase = Some(secrets.store_passphrase);
            st.error = None;
        }
        info!(
            user = %client.user_id().map(|u| u.to_string()).unwrap_or_default(),
            secrets = ?saved.secrets,
            "session restored"
        );
        self.start(client, saved.sync_token).await;
        Ok(())
    }

    /// Read `session.json` and fetch its secrets from wherever they are.
    /// A file that still carries them inline is moved to the keyring here.
    async fn load_session(&self, prompt: bool) -> Result<(PersistedSession, SessionSecrets)> {
        let text = tokio::fs::read_to_string(self.session_file()).await?;
        let mut saved: PersistedSession =
            serde_json::from_str(&text).context("reading session.json")?;
        if let (Some(pass), Some(auth)) = (saved.store_passphrase.take(), saved.auth.take()) {
            let secrets = SessionSecrets {
                store_passphrase: pass,
                auth,
            };
            // Inline secrets (a pre-keyring file, or the file fallback):
            // try the keyring again — it may be available now.
            saved = self.save_session(saved, &secrets).await?;
            return Ok((saved, secrets));
        }
        match saved.secrets {
            Some(crate::secrets::Backend::Keyring) => {
                let blob = crate::secrets::load(&self.data_dir, prompt)
                    .await?
                    .ok_or_else(|| anyhow!("the keyring has no entry for this session"))?;
                let secrets: SessionSecrets =
                    serde_json::from_slice(&blob).context("reading the keyring entry")?;
                Ok((saved, secrets))
            }
            _ => bail!("session.json has no secrets"),
        }
    }

    /// Write the session: secrets to the keyring when it works (the file
    /// then only points there), else inline in the 0600 file.
    async fn save_session(
        &self,
        mut saved: PersistedSession,
        secrets: &SessionSecrets,
    ) -> Result<PersistedSession> {
        let user = match &secrets.auth {
            StoredAuth::Password { session } => session.meta.user_id.to_string(),
            StoredAuth::Oauth { user, .. } => user.meta.user_id.to_string(),
        };
        let label = format!("Yapper Matrix session ({user})");
        let blob = serde_json::to_vec(secrets)?;
        match crate::secrets::store(&self.data_dir, &label, &blob).await {
            Ok(()) => {
                saved.secrets = Some(crate::secrets::Backend::Keyring);
                saved.store_passphrase = None;
                saved.auth = None;
            }
            Err(e) => {
                warn!("no keyring for the session secrets ({e:#}); keeping them in session.json");
                saved.secrets = Some(crate::secrets::Backend::File);
                saved.store_passphrase = Some(secrets.store_passphrase.clone());
                saved.auth = Some(secrets.auth.clone());
            }
        }
        write_private(&self.session_file(), &serde_json::to_vec(&saved)?)?;
        self.state.lock().await.secrets_backend = saved.secrets;
        Ok(saved)
    }

    // ---------- request dispatch ----------

    pub async fn handle(self: &Arc<Self>, line: &str) -> Response {
        let req: Request = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(e) => {
                // Still echo the id so the client can match the error to its request.
                let id = serde_json::from_str::<Value>(line)
                    .ok()
                    .and_then(|v| v.get("id").cloned())
                    .unwrap_or(Value::Null);
                return Response::err(id, format!("bad request: {e}"));
            }
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
            Command::Login {
                homeserver,
                username,
                password,
            } => {
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
            Command::RetrySession => {
                self.ensure_signed_out().await?;
                if !self.session_file().exists() {
                    bail!("there is no saved session");
                }
                let (saved, secrets) = self.load_session(true).await?;
                self.restore_with(saved, secrets).await?;
                Ok(serde_json::to_value(self.status().await)?)
            }
            Command::ForgetSession => {
                self.ensure_signed_out().await?;
                self.forget_session().await;
                Ok(serde_json::to_value(self.status().await)?)
            }
            Command::Logout => {
                self.logout().await?;
                Ok(serde_json::to_value(self.status().await)?)
            }
            Command::Rooms => Ok(serde_json::to_value(self.rooms().await?)?),
            Command::Timeline {
                room,
                limit,
                before,
            } => Ok(serde_json::to_value(
                self.timeline(&room, limit, before).await?,
            )?),
            Command::Send {
                room,
                body,
                reply_to,
                thread,
            } => {
                let event_id = self.send(&room, body, reply_to, thread).await?;
                Ok(json!({ "event_id": event_id }))
            }
            Command::Thread {
                room,
                root,
                limit,
                before,
            } => Ok(serde_json::to_value(
                self.thread(&room, &root, limit, before).await?,
            )?),
            Command::Edit {
                room,
                event_id,
                body,
            } => {
                let id = self.edit(&room, &event_id, body).await?;
                Ok(json!({ "event_id": id }))
            }
            Command::Delete { room, event_id } => {
                let r = self.room(&room).await?;
                let id = matrix_sdk::ruma::EventId::parse(&event_id).context("invalid event id")?;
                r.redact(&id, None, None).await.context("deleting")?;
                Ok(json!({}))
            }
            Command::React {
                room,
                event_id,
                key,
            } => {
                let r = self.room(&room).await?;
                let id = matrix_sdk::ruma::EventId::parse(&event_id).context("invalid event id")?;
                let resp = r
                    .send(ReactionEventContent::new(Annotation::new(id, key)))
                    .await
                    .context("reacting")?;
                Ok(json!({ "reaction_id": resp.response.event_id.to_string() }))
            }
            Command::Unreact { room, reaction_id } => {
                let r = self.room(&room).await?;
                let id =
                    matrix_sdk::ruma::EventId::parse(&reaction_id).context("invalid event id")?;
                r.redact(&id, None, None)
                    .await
                    .context("removing reaction")?;
                Ok(json!({}))
            }
            Command::Typing { room, typing } => {
                let r = self.room(&room).await?;
                r.typing_notice(typing).await.context("typing notice")?;
                Ok(json!({}))
            }
            Command::RoomDetails { room } => {
                Ok(serde_json::to_value(self.room_details(&room).await?)?)
            }
            Command::Members { room, query, limit } => Ok(serde_json::to_value(
                self.members(&room, &query, limit).await?,
            )?),
            Command::Avatar { url, size } => {
                let path = self.avatar(&url, size.unwrap_or(96)).await?;
                Ok(json!({ "path": path }))
            }
            Command::Invite { room, user } => {
                let r = self.room(&room).await?;
                let u = UserId::parse(user.trim()).context("expected @user:server")?;
                r.invite_user_by_id(&u).await.context("inviting")?;
                Ok(json!({}))
            }
            Command::Kick { room, user, reason } => {
                let r = self.room(&room).await?;
                let u = UserId::parse(user.trim()).context("expected @user:server")?;
                r.kick_user(&u, reason.as_deref().filter(|s| !s.trim().is_empty()))
                    .await
                    .context("removing")?;
                Ok(json!({}))
            }
            Command::Ban { room, user, reason } => {
                let r = self.room(&room).await?;
                let u = UserId::parse(user.trim()).context("expected @user:server")?;
                r.ban_user(&u, reason.as_deref().filter(|s| !s.trim().is_empty()))
                    .await
                    .context("banning")?;
                Ok(json!({}))
            }
            Command::SetName { room, name } => {
                let r = self.room(&room).await?;
                let n = name.trim().to_owned();
                if n.is_empty() {
                    bail!("a room needs a name");
                }
                r.set_name(n).await.context("renaming")?;
                Ok(json!({}))
            }
            Command::SetTopic { room, topic } => {
                let r = self.room(&room).await?;
                r.set_room_topic(topic.trim())
                    .await
                    .context("setting topic")?;
                Ok(json!({}))
            }
            Command::SetNotificationMode { room, mode } => {
                self.set_notification_mode(&room, &mode).await?;
                Ok(serde_json::to_value(self.room_details(&room).await?)?)
            }
            Command::SetFavourite { room, favourite } => {
                let r = self.room(&room).await?;
                r.set_is_favourite(favourite, None)
                    .await
                    .context("updating favourite")?;
                let _ = self.events().send(Event::RoomsChanged);
                Ok(json!({}))
            }
            Command::Spaces => Ok(serde_json::to_value(self.spaces().await?)?),
            Command::Search { query, room, limit } => Ok(serde_json::to_value(
                self.search(&query, room.as_deref(), limit).await?,
            )?),
            Command::Preview { url } => Ok(serde_json::to_value(self.preview(&url).await?)?),
            Command::MarkRead {
                room,
                event_id,
                thread,
            } => {
                self.mark_read(&room, &event_id, thread).await?;
                Ok(json!({}))
            }
            Command::CommunityStatus { alias } => {
                let client = self.client().await?;
                let prefs = self.prefs.lock().await.clone();
                Ok(serde_json::to_value(
                    crate::community::status(&client, &self.community, &alias, &prefs).await?,
                )?)
            }
            Command::CommunityJoin { alias } => {
                let client = self.client().await?;
                let space = crate::community::join_space(&client, &self.community, &alias).await?;
                let prefs = {
                    let mut p = self.prefs.lock().await;
                    p.community = alias.clone();
                    write_private(&self.prefs_file(), &serde_json::to_vec(&*p)?)?;
                    p.clone()
                };
                // The rooms follow in the background; one joiner at a time.
                let mut joiner = self.community.joiner.lock().await;
                if joiner.as_ref().is_none_or(|t| t.is_finished()) {
                    *joiner = Some(tokio::spawn(crate::community::join_rooms(
                        client.clone(),
                        self.community.clone(),
                        alias.clone(),
                        space.room_id().to_owned(),
                        self.events.clone(),
                    )));
                }
                drop(joiner);
                let _ = self.events.send(Event::RoomsChanged);
                Ok(serde_json::to_value(
                    crate::community::status(&client, &self.community, &alias, &prefs).await?,
                )?)
            }
            Command::CommunityLeave { alias } => {
                let client = self.client().await?;
                crate::community::leave(&client, &self.community, &alias).await?;
                let _ = self.events.send(Event::RoomsChanged);
                Ok(json!({}))
            }
            Command::PublishProfile {
                alias,
                bio,
                open_to_dm,
                theme,
            } => {
                let client = self.client().await?;
                Ok(serde_json::to_value(
                    crate::community::publish_profile(&client, &alias, bio, open_to_dm, theme)
                        .await?,
                )?)
            }
            Command::ClearProfile { alias } => {
                let client = self.client().await?;
                crate::community::clear_profile(&client, &alias).await?;
                Ok(json!({}))
            }
            Command::People {
                alias,
                query,
                limit,
            } => {
                let client = self.client().await?;
                Ok(serde_json::to_value(
                    crate::community::people(&client, &alias, &query, limit as usize).await?,
                )?)
            }
            Command::Ignore { user } => {
                let client = self.client().await?;
                crate::community::ignore(&client, &user).await?;
                Ok(json!({}))
            }
            Command::Unignore { user } => {
                let client = self.client().await?;
                crate::community::unignore(&client, &user).await?;
                Ok(json!({}))
            }
            Command::Ignored => {
                let client = self.client().await?;
                Ok(serde_json::to_value(
                    crate::community::ignored(&client).await?,
                )?)
            }
            Command::SetDmPolicy { policy, community } => {
                let mut p = self.prefs.lock().await;
                p.dm_policy = policy;
                if !community.is_empty() {
                    p.community = community;
                }
                write_private(&self.prefs_file(), &serde_json::to_vec(&*p)?)?;
                Ok(serde_json::to_value(&*p)?)
            }
            Command::CreateSpace { name, topic, alias } => {
                let client = self.client().await?;
                let room = crate::community::create_space(
                    &client,
                    &name,
                    topic.as_deref(),
                    alias.as_deref(),
                )
                .await?;
                Ok(json!({ "id": room.room_id().to_string() }))
            }
            Command::AddSpaceChild {
                space,
                room,
                suggested,
            } => {
                let client = self.client().await?;
                let space = matrix_sdk::ruma::RoomId::parse(&space).context("invalid space id")?;
                let room = matrix_sdk::ruma::RoomId::parse(&room).context("invalid room id")?;
                crate::community::add_child(&client, &space, &room, suggested).await?;
                Ok(json!({}))
            }
            Command::Explore {
                query,
                server,
                limit,
                since,
            } => Ok(serde_json::to_value(
                self.directory(&query, server.as_deref(), limit, since.as_deref())
                    .await?,
            )?),
            Command::SearchRooms {
                query,
                server,
                limit,
            } => Ok(serde_json::to_value(
                self.search_rooms(&query, server.as_deref(), limit).await?,
            )?),
            Command::Join { room } => {
                let room = self.join(&room).await?;
                Ok(serde_json::to_value(self.room_info(&room).await)?)
            }
            Command::SearchUsers { query, limit } => Ok(serde_json::to_value(
                self.search_users(&query, limit).await?,
            )?),
            Command::Dm { user } => {
                let room = self.dm(&user).await?;
                Ok(serde_json::to_value(self.room_info(&room).await)?)
            }
            Command::CreateRoom {
                name,
                topic,
                encrypted,
                private,
            } => {
                let room = self.create_room(name, topic, encrypted, private).await?;
                Ok(serde_json::to_value(self.room_info(&room).await)?)
            }
            Command::Invites => Ok(serde_json::to_value(self.invites().await?)?),
            Command::VerificationStatus => {
                Ok(serde_json::to_value(self.verification_status().await?)?)
            }
            Command::VerifyRequest => {
                let flow_id = self.verify_request().await?;
                Ok(json!({ "flow_id": flow_id }))
            }
            Command::VerifyAccept { flow_id } => {
                self.verify_accept(&flow_id).await?;
                Ok(json!({}))
            }
            Command::VerifyConfirm { flow_id } => {
                self.verify_confirm(&flow_id).await?;
                Ok(json!({}))
            }
            Command::VerifyCancel { flow_id } => {
                self.verify_cancel(&flow_id).await?;
                Ok(json!({}))
            }
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
            Command::Download {
                room,
                event_id,
                thumbnail,
            } => {
                let (path, mime) = self.download(&room, &event_id, thumbnail).await?;
                Ok(json!({ "path": path, "mime": mime }))
            }
            Command::SendFile {
                room,
                path,
                caption,
            } => {
                let event_id = self.send_file(&room, &path, caption).await?;
                Ok(json!({ "event_id": event_id }))
            }
            Command::SendVoice { room, path } => {
                let event_id = self.send_voice(&room, &path).await?;
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
            user_id: st
                .client
                .as_ref()
                .and_then(|c| c.user_id().map(|u| u.to_string())),
            homeserver: st.client.as_ref().map(|c| c.homeserver().to_string()),
            error: st.error.clone(),
            secrets: st.secrets_backend,
            saved_session: st.client.is_none() && self.session_file().exists(),
        }
    }

    /// Drop the saved session and its store without talking to the server:
    /// for a session that cannot be restored (keyring gone) or after logout.
    async fn forget_session(&self) {
        let file = self.session_file();
        let mut in_keyring = false;
        if let Ok(text) = std::fs::read_to_string(&file)
            && let Ok(saved) = serde_json::from_str::<PersistedSession>(&text)
        {
            let _ = std::fs::remove_dir_all(&saved.store_path);
            in_keyring = saved.secrets != Some(crate::secrets::Backend::File);
        }
        let _ = std::fs::remove_file(&file);
        if in_keyring {
            crate::secrets::forget(&self.data_dir).await;
        }
        {
            let mut st = self.state.lock().await;
            st.syncing = false;
            st.error = None;
            st.secrets_backend = None;
            st.store_passphrase = None;
        }
        self.broadcast_state().await;
    }

    async fn broadcast_state(&self) {
        let _ = self.events.send(Event::State(self.status().await));
    }

    pub(crate) async fn client(&self) -> Result<Client> {
        self.state
            .lock()
            .await
            .client
            .clone()
            .ok_or_else(|| anyhow!("not logged in"))
    }

    pub(crate) async fn room(&self, id: &str) -> Result<Room> {
        let id: OwnedRoomId = RoomId::parse(id).context("invalid room id")?;
        self.client()
            .await?
            .get_room(&id)
            .ok_or_else(|| anyhow!("unknown room {id}"))
    }

    // ---------- login / logout ----------

    /// Build a client with a fresh encrypted store. Returns the store path
    /// and passphrase so the caller can persist or discard them.
    async fn build_client(&self, homeserver: &str) -> Result<(Client, PathBuf, String)> {
        // ThreadRng is !Send, so it must not live across an await.
        let (store_name, store_passphrase) = {
            let mut r = rng();
            let name: String = (&mut r)
                .sample_iter(Alphanumeric)
                .take(8)
                .map(char::from)
                .collect();
            let pass: String = (&mut r)
                .sample_iter(Alphanumeric)
                .take(32)
                .map(char::from)
                .collect();
            (name, pass)
        };
        let store_path = self.data_dir.join(format!("store-{store_name}"));
        let client = Client::builder()
            .server_name_or_homeserver_url(homeserver)
            .with_threading_support(matrix_sdk::ThreadingSupport::Enabled {
                with_subscriptions: false,
            })
            // A request retries a few times with the server's suggested
            // wait, then fails; nothing blocks a socket call for minutes.
            .request_config(matrix_sdk::config::RequestConfig::new().retry_limit(3))
            // Media downloads are capped in size and time (see media.rs).
            .media_fetcher(crate::media::bounded_media_fetcher())
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

    async fn login(
        self: &Arc<Self>,
        homeserver: String,
        username: String,
        password: String,
    ) -> Result<()> {
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
            sync_token: None,
            secrets: None,
            store_passphrase: None,
            auth: None,
        };
        let secrets = SessionSecrets {
            store_passphrase,
            auth: StoredAuth::Password { session },
        };
        self.save_session(saved, &secrets).await?;
        self.state.lock().await.store_passphrase = Some(secrets.store_passphrase);
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
                client
                    .oauth()
                    .finish_login(query.into())
                    .await
                    .context("finishing browser sign-in")?;
                let full = client
                    .oauth()
                    .full_session()
                    .ok_or_else(|| anyhow!("sign-in succeeded but no session was returned"))?;
                let saved = PersistedSession {
                    homeserver: client.homeserver().to_string(),
                    store_path: task_store.clone(),
                    sync_token: None,
                    secrets: None,
                    store_passphrase: None,
                    auth: None,
                };
                let secrets = SessionSecrets {
                    store_passphrase: store_passphrase.clone(),
                    auth: StoredAuth::Oauth {
                        client_id: full.client_id,
                        user: full.user,
                    },
                };
                core.save_session(saved, &secrets).await?;
                core.state.lock().await.store_passphrase = Some(secrets.store_passphrase);
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
        let Some(p) = pending else {
            bail!("no browser sign-in in progress")
        };
        if p.task.is_finished() {
            return Ok(());
        }
        p.task.abort();
        let _ = std::fs::remove_dir_all(&p.store_path);
        info!("browser sign-in cancelled");
        self.broadcast_state().await;
        Ok(())
    }

    /// Orderly stop for the process: end the sync loop and any pending
    /// sign-in, then release the client so its SQLite stores checkpoint
    /// and close. Without this the stores are left with -wal and -shm
    /// files that the next start has to recover.
    pub async fn shutdown(self: &Arc<Self>) {
        let (client, task, pending) = {
            let mut st = self.state.lock().await;
            st.notification_settings = None;
            st.syncing = false;
            (st.client.take(), st.sync_task.take(), st.pending.take())
        };
        if let Some(task) = task {
            task.abort();
            let _ = task.await;
        }
        if let Some(p) = pending {
            p.task.abort();
            let _ = p.task.await;
        }
        drop(client);
        // Tasks the client spawned (event handlers, send queue) let go of
        // their handles as they wind down; give them a moment.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    }

    async fn logout(self: &Arc<Self>) -> Result<()> {
        let (client, task, pending) = {
            let mut st = self.state.lock().await;
            st.notification_settings = None;
            (st.client.take(), st.sync_task.take(), st.pending.take())
        };
        if let Some(task) = task {
            task.abort();
        }
        if let Some(p) = pending {
            p.task.abort();
            let _ = std::fs::remove_dir_all(&p.store_path);
        }
        let Some(client) = client else {
            bail!("not logged in")
        };
        if let Err(e) = client.logout().await {
            // The token may already be dead; local state is wiped regardless.
            warn!("server logout failed: {e:#}");
        }
        self.forget_session().await;
        info!("logged out; local store wiped");
        Ok(())
    }

    // ---------- sync loop ----------

    async fn start(self: &Arc<Self>, client: Client, sync_token: Option<String>) {
        // The event cache keeps a synced timeline per room; the unread fallback reads it.
        if let Err(e) = client.event_cache().subscribe() {
            warn!("event cache: {e:#}");
        }
        client.add_event_handler_context(HandlerCtx {
            prefs: self.prefs.clone(),
            events: self.events.clone(),
            activity: self.activity.clone(),
        });
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
                        if let Err(e) = core.persist_tokens(&watch_client).await {
                            warn!("could not persist refreshed tokens: {e:#}");
                        }
                    }
                    SessionChange::UnknownToken(info) => {
                        warn!(
                            soft_logout = info.soft_logout,
                            "homeserver rejected our token"
                        );
                        core.set_error(Some("session expired; sign out and sign in again".into()))
                            .await;
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
                let wait = if pending {
                    Duration::from_millis(300)
                } else {
                    Duration::from_secs(3600)
                };
                match tokio::time::timeout(wait, updates.recv()).await {
                    Ok(Ok(u)) => {
                        if u.reasons
                            .intersects(R::READ_RECEIPT | R::UNREAD_MARKER | R::LATEST_EVENT)
                        {
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

        let notification_settings = client.notification_settings().await;
        let mut st = self.state.lock().await;
        st.client = Some(client);
        st.notification_settings = Some(notification_settings);
        st.sync_task = Some(task);
        st.pending = None;
        st.error = None;
        drop(st);
        self.broadcast_state().await;
    }

    async fn persist_tokens(&self, client: &Client) -> Result<()> {
        let text = std::fs::read_to_string(self.session_file())?;
        let saved: PersistedSession = serde_json::from_str(&text)?;
        let store_passphrase = self
            .state
            .lock()
            .await
            .store_passphrase
            .clone()
            .ok_or_else(|| anyhow!("no store passphrase in memory"))?;
        // The client knows which kind of session it holds.
        let auth = match client.oauth().full_session() {
            Some(full) => StoredAuth::Oauth {
                client_id: full.client_id,
                user: full.user,
            },
            None => StoredAuth::Password {
                session: client
                    .matrix_auth()
                    .session()
                    .ok_or_else(|| anyhow!("no session"))?,
            },
        };
        let secrets = SessionSecrets {
            store_passphrase,
            auth,
        };
        self.save_session(saved, &secrets).await?;
        Ok(())
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

        // A failed sync (network gone, laptop asleep, server hiccup) must
        // not end live updates: back off and keep going. Sends still work
        // meanwhile because they use their own requests; `syncing` tells
        // the client when we are behind.
        let core = self.clone();
        let failures = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let result = client
            .sync_with_result_callback(settings, |r| {
                let core = core.clone();
                let failures = failures.clone();
                async move {
                    use std::sync::atomic::Ordering;
                    match r {
                        Ok(resp) => {
                            if failures.swap(0, Ordering::Relaxed) > 0 {
                                info!("sync recovered");
                                core.set_syncing(true).await;
                            }
                            let _ = core.persist_sync_token(resp.next_batch);
                        }
                        Err(e) => {
                            let n = failures.fetch_add(1, Ordering::Relaxed) + 1;
                            let wait = (2u64 << n.min(5)).min(60);
                            warn!("sync failed ({n}): {e:#}; retrying in {wait}s");
                            if n == 1 {
                                core.set_syncing(false).await;
                            }
                            core.set_error(Some(format!("Reconnecting… ({e})"))).await;
                            tokio::time::sleep(Duration::from_secs(wait)).await;
                        }
                    }
                    Ok(LoopCtrl::Continue)
                }
            })
            .await;
        // Only reached when the loop is told to stop (never, today) or the
        // SDK gives up outright.
        warn!("sync loop ended: {result:?}");
        self.set_syncing(false).await;
        if let Err(e) = result {
            self.set_error(Some(format!("sync stopped: {e}"))).await;
        }
    }

    /// The sync token is not secret and changes every sync: file only.
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
            // Spaces are folders, not chats; they come from `spaces`.
            if room.is_space() {
                continue;
            }
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
                if let Ok(Some((eid, receipt))) = room
                    .load_user_receipt(StoreReceiptType::Read, &thread, me)
                    .await
                {
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
        let mut last_activity: Option<u64> = None;
        if let Ok((cache, _guard)) = room.event_cache().await {
            if let Ok(events) = cache.events().await {
                let mut n = 0u64;
                for ev in events {
                    if let Ok(AnySyncTimelineEvent::MessageLike(m)) = ev.raw().deserialize() {
                        let ts = u64::from(m.origin_server_ts().0);
                        let is_msg = matches!(
                            m,
                            AnySyncMessageLikeEvent::RoomMessage(_)
                                | AnySyncMessageLikeEvent::RoomEncrypted(_)
                        );
                        // Thread replies count in their thread, not the room.
                        let in_thread = ev
                            .raw()
                            .get_field::<serde_json::Value>("content")
                            .ok()
                            .flatten()
                            .and_then(|c| {
                                c.get("m.relates_to")?
                                    .get("rel_type")?
                                    .as_str()
                                    .map(|t| t == "m.thread")
                            })
                            .unwrap_or(false);
                        if is_msg && !in_thread {
                            last_activity = Some(last_activity.map_or(ts, |t| t.max(ts)));
                            if let (Some(me), Some(at)) = (me.as_deref(), read_at)
                                && m.sender() != me
                                && ts > at
                            {
                                n += 1;
                            }
                        }
                    }
                }
                unread = unread.max(n);
            }
        }
        let direct = room.is_direct().await.unwrap_or(false);
        let (notification_mode, _) = self.notification_mode(&room, encrypted, direct).await;
        RoomInfo {
            id: room.room_id().to_string(),
            name,
            topic: room.topic(),
            encrypted,
            direct,
            avatar: room.avatar_url().map(|u| u.to_string()),
            notification_mode,
            favourite: room.is_favourite(),
            low_priority: room.is_low_priority(),
            last_activity: room
                .recency_stamp()
                .map(u64::from)
                .or(self.activity_of(&room, last_activity).await),
            unread,
            highlights: room.num_unread_mentions().max(counts.highlight_count),
            notifications: counts.notification_count,
            read_marker,
            bridge: crate::bridge::detect(room).await,
        }
    }

    // ---------- discovery ----------

    async fn search_rooms(
        &self,
        query: &str,
        server: Option<&str>,
        limit: u32,
    ) -> Result<Vec<DirectoryRoom>> {
        Ok(self.directory(query, server, limit, None).await?.rooms)
    }

    /// One page of a public room directory: the server's own unless
    /// `server` names another; an empty query lists everything, most
    /// joined first.
    async fn directory(
        &self,
        query: &str,
        server: Option<&str>,
        limit: u32,
        since: Option<&str>,
    ) -> Result<DirectoryPage> {
        let client = self.client().await?;
        let mut req = get_public_rooms_filtered::v3::Request::new();
        req.limit = Some(UInt::from(limit.clamp(1, 100)));
        let query = query.trim();
        if !query.is_empty() {
            let mut filter = Filter::new();
            filter.generic_search_term = Some(query.to_owned());
            req.filter = filter;
        }
        req.since = since
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        let server = server.map(str::trim).filter(|s| !s.is_empty());
        if let Some(server) = server {
            req.server = Some(OwnedServerName::try_from(server).context("invalid server name")?);
        }
        let resp = tokio::time::timeout(SEARCH_TIMEOUT, client.public_rooms_filtered(req))
            .await
            .map_err(|_| anyhow!("the room directory did not answer in time"))?
            .context("reading the room directory")?;
        let own_server = client
            .user_id()
            .map(|u| u.server_name().to_string())
            .unwrap_or_default();
        Ok(DirectoryPage {
            server: server.map(str::to_owned).unwrap_or(own_server),
            rooms: resp
                .chunk
                .into_iter()
                .map(|r| DirectoryRoom {
                    joined: client
                        .get_room(&r.room_id)
                        .is_some_and(|room| room.state() == RoomState::Joined),
                    id: r.room_id.to_string(),
                    name: r
                        .name
                        .clone()
                        .or_else(|| r.canonical_alias.as_ref().map(|a| a.to_string()))
                        .unwrap_or_else(|| r.room_id.to_string()),
                    alias: r.canonical_alias.map(|a| a.to_string()),
                    topic: r.topic,
                    avatar: r.avatar_url.map(|u| u.to_string()),
                    members: r.num_joined_members.into(),
                })
                .collect(),
            next: resp.next_batch,
            total: resp.total_room_count_estimate.map(u64::from),
        })
    }

    async fn join(&self, id_or_alias: &str) -> Result<Room> {
        let client = self.client().await?;
        let target = RoomOrAliasId::parse(id_or_alias.trim())
            .context("expected #alias:server or !id:server")?;
        let via: Vec<OwnedServerName> = target
            .server_name()
            .map(|s| vec![s.to_owned()])
            .unwrap_or_default();
        client
            .join_room_by_id_or_alias(&target, &via)
            .await
            .context("joining room")
    }

    async fn search_users(&self, query: &str, limit: u32) -> Result<Vec<DirectoryUser>> {
        let client = self.client().await?;
        let resp = tokio::time::timeout(
            SEARCH_TIMEOUT,
            client.search_users(query.trim(), u64::from(limit.clamp(1, 50))),
        )
        .await
        .map_err(|_| anyhow!("the user directory did not answer in time"))?
        .context("searching users")?;
        Ok(resp
            .results
            .into_iter()
            .map(|u| DirectoryUser {
                id: u.user_id.to_string(),
                name: u.display_name,
            })
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
        client
            .create_dm(&user_id)
            .await
            .context("creating direct chat")
    }

    async fn create_room(
        &self,
        name: String,
        topic: Option<String>,
        encrypted: bool,
        private: bool,
    ) -> Result<Room> {
        let client = self.client().await?;
        let name = name.trim().to_owned();
        if name.is_empty() {
            bail!("a room needs a name");
        }
        let mut req = create_room::v3::Request::new();
        req.name = Some(name);
        req.topic = topic.map(|t| t.trim().to_owned()).filter(|t| !t.is_empty());
        req.preset = Some(if private {
            create_room::v3::RoomPreset::PrivateChat
        } else {
            create_room::v3::RoomPreset::PublicChat
        });
        req.visibility = if private {
            Visibility::Private
        } else {
            Visibility::Public
        };
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

    /// One page of a room's history, newest page first, from the SDK's
    /// event cache. The cache already holds what sync delivered (persisted
    /// across restarts), so opening a room is a local read; only history we
    /// have never seen goes to the server, through the cache's own
    /// back-pagination, which also fills any gap sync left behind.
    ///
    /// `before` is the id of the oldest event on the previous page; `next`
    /// hands back the id to pass for the page after this one.
    async fn timeline(
        &self,
        room_id: &str,
        limit: u32,
        before: Option<String>,
    ) -> Result<TimelinePage> {
        let started = std::time::Instant::now();
        let room = self.room(room_id).await?;
        let limit = limit.clamp(1, 200) as usize;
        let before = before.filter(|t| !t.is_empty());
        let (cache, _handles) = room
            .event_cache()
            .await
            .context("opening the event cache")?;

        // Load until the events before the anchor hold a page's worth of
        // messages with no gap between them and the live end.
        let mut reached_start = false;
        let mut rounds = 0;
        let events: Vec<TimelineEvent> = loop {
            let all = cache.events().await.context("reading the event cache")?;
            // Only the events after the most recent unresolved gap are known
            // to run straight up to the live end.
            let tail = contiguous_tail(&cache.debug_string().await).min(all.len());
            let all = &all[all.len() - tail..];
            let cut = match &before {
                Some(id) => all
                    .iter()
                    .position(|e| e.event_id().is_some_and(|x| x.as_str() == id)),
                None => Some(all.len()),
            };
            if let Some(cut) = cut {
                let slice = &all[..cut];
                let have = slice
                    .iter()
                    .rev()
                    .filter(|e| is_message_like(e))
                    .take(limit)
                    .count();
                if have >= limit || reached_start {
                    break slice.to_vec();
                }
            } else if reached_start {
                bail!("the earlier messages are no longer loaded; reopen the room");
            }
            rounds += 1;
            if rounds > 12 {
                // Enough history for anyone in one go; the next page continues.
                break cut.map(|c| all[..c].to_vec()).unwrap_or_default();
            }
            let t = std::time::Instant::now();
            let outcome = cache
                .pagination()
                .run_backwards_once(limit.max(40) as u16)
                .await
                .context("loading earlier messages")?;
            tracing::debug!(
                room = room_id,
                loaded = outcome.events.len(),
                reached_start = outcome.reached_start,
                ms = t.elapsed().as_millis() as u64,
                "timeline: back-paginated"
            );
            reached_start = outcome.reached_start;
        };

        // Walk newest-first, converting message-like events until the page
        // is full. Everything older stays for the next page.
        let mut to_convert = Vec::new();
        let mut redacted: std::collections::HashSet<String> = Default::default();
        let mut consumed = 0usize;
        let mut messages = 0usize;
        for ev in events.iter().rev() {
            if messages >= limit {
                break;
            }
            consumed += 1;
            if let Ok(AnySyncTimelineEvent::MessageLike(AnySyncMessageLikeEvent::RoomRedaction(
                matrix_sdk::ruma::events::room::redaction::SyncRoomRedactionEvent::Original(rd),
            ))) = ev.raw().deserialize()
            {
                redacted.insert(
                    rd.redacts(&room.clone_info().room_version_rules_or_default().redaction)
                        .to_string(),
                );
                continue;
            }
            if is_message_like(ev) {
                messages += 1;
                to_convert.push(ev.clone());
            }
        }
        let exhausted = consumed >= events.len();
        let next = if (exhausted && reached_start) || consumed == 0 {
            None
        } else {
            events[events.len() - consumed]
                .event_id()
                .map(|e| e.to_string())
        };

        // Each message may need a member or a quoted event looked up; do
        // them together rather than one after another.
        let converted = futures_util::future::join_all(
            to_convert
                .iter()
                .map(|ev| self.message_from_event(&room, ev.clone())),
        )
        .await;
        let mut to_convert_ids = Vec::with_capacity(to_convert.len());
        let mut out: Vec<Message> = Vec::with_capacity(to_convert.len());
        for (ev, m) in to_convert.into_iter().zip(converted) {
            if let Some(m) = m {
                to_convert_ids.push(ev);
                out.push(m);
            }
        }
        tracing::debug!(
            room = room_id,
            messages = out.len(),
            ms = started.elapsed().as_millis() as u64,
            "timeline: converted"
        );

        // Reactions, edits and receipts come from the cache's relation index:
        // anything relating to a message on this page is newer than it, so
        // it is already loaded.
        let me = room.client().user_id().map(|u| u.to_owned());
        let decorated = futures_util::future::join_all(out.iter().map(|m| {
            let (room, cache, redacted, me) = (&room, &cache, &redacted, me.as_deref());
            let event_id = m.event_id.clone();
            async move {
                let Ok(id) = matrix_sdk::ruma::OwnedEventId::try_from(event_id.as_str()) else {
                    return (Vec::new(), None, Vec::new());
                };
                let (reactions, edit) = cached_relations(cache, &id).await;
                let reactions = aggregate_reactions(room, reactions, me, redacted).await;
                (reactions, edit, read_by(room, &event_id, me, None).await)
            }
        }))
        .await;
        for (m, (reactions, edit, read_by)) in out.iter_mut().zip(decorated) {
            m.reactions = reactions;
            m.read_by = read_by;
            if let Some((_, body, html)) = edit
                && !m.deleted
            {
                m.body = body;
                m.html = html;
                m.edited = true;
            }
        }
        // Thread summaries: the cache keeps one on every root it knows of.
        for (m, ev) in out.iter_mut().zip(to_convert_ids.iter()) {
            if let Some(summary) = ev.thread_summary.summary()
                && let Ok(id) = matrix_sdk::ruma::OwnedEventId::try_from(m.event_id.as_str())
            {
                m.thread = Some(thread_info(&room, &cache, &id, summary).await);
            }
        }
        tracing::debug!(
            room = room_id,
            ms = started.elapsed().as_millis() as u64,
            "timeline: done"
        );
        out.reverse(); // newest-first walk; the page reads oldest-first
        Ok(TimelinePage {
            messages: out,
            next,
        })
    }

    /// A thread: its root, then the replies oldest first, from the SDK's
    /// thread cache (sync-fed, back-paginated through /relations).
    async fn thread(
        &self,
        room_id: &str,
        root_id: &str,
        limit: u32,
        before: Option<String>,
    ) -> Result<TimelinePage> {
        let room = self.room(room_id).await?;
        let client = room.client();
        let root = matrix_sdk::ruma::EventId::parse(root_id).context("invalid thread root")?;
        let limit = limit.clamp(1, 200) as usize;
        let before = before.filter(|t| !t.is_empty());
        let (cache, _handles) = client
            .event_cache()
            .thread(room.room_id(), &root)
            .await
            .context("opening the thread")?;

        // Hold one subscriber for the whole read: dropping one lets the
        // cache shrink its in-memory chunk, which would discard replies
        // loaded a moment ago. Older pages are taken straight from the
        // pagination outcome rather than re-read.
        let (initial, _subscriber) = cache.subscribe().await.context("reading the thread")?;
        let mut all: Vec<TimelineEvent> = initial
            .into_iter()
            .filter(|e| e.event_id().as_deref() != Some(&root))
            .collect();
        let mut reached_start = false;
        let mut rounds = 0;
        let events: Vec<TimelineEvent> = loop {
            tracing::debug!(
                room = room_id,
                root = root_id,
                cached = all.len(),
                rounds,
                reached_start,
                "thread: cache"
            );
            let cut = match &before {
                Some(id) => all
                    .iter()
                    .position(|e| e.event_id().is_some_and(|x| x.as_str() == id)),
                None => Some(all.len()),
            };
            if let Some(cut) = cut {
                let slice = &all[..cut];
                let have = slice
                    .iter()
                    .rev()
                    .filter(|e| is_thread_reply(e))
                    .take(limit)
                    .count();
                if have >= limit || reached_start {
                    break slice.to_vec();
                }
            } else if reached_start {
                bail!("the earlier replies are no longer loaded; reopen the thread");
            }
            rounds += 1;
            if rounds > 12 {
                break cut.map(|c| all[..c].to_vec()).unwrap_or_default();
            }
            let outcome = cache
                .pagination()
                .run_backwards_once(limit.max(40) as u16)
                .await
                .context("loading earlier replies")?;
            reached_start = outcome.reached_start;
            // Newest-first from the server; prepend in timeline order.
            let mut older: Vec<TimelineEvent> = outcome
                .events
                .into_iter()
                .filter(|e| {
                    let id = e.event_id();
                    id.as_deref() != Some(&root) && !all.iter().any(|x| x.event_id() == id)
                })
                .collect();
            older.reverse();
            older.append(&mut all);
            all = older;
        };

        let mut to_convert = Vec::new();
        let mut redacted: std::collections::HashSet<String> = Default::default();
        let mut consumed = 0usize;
        let mut messages = 0usize;
        for ev in events.iter().rev() {
            if messages >= limit {
                break;
            }
            consumed += 1;
            if let Ok(AnySyncTimelineEvent::MessageLike(AnySyncMessageLikeEvent::RoomRedaction(
                matrix_sdk::ruma::events::room::redaction::SyncRoomRedactionEvent::Original(rd),
            ))) = ev.raw().deserialize()
            {
                redacted.insert(
                    rd.redacts(&room.clone_info().room_version_rules_or_default().redaction)
                        .to_string(),
                );
                continue;
            }
            if is_thread_reply(ev) {
                messages += 1;
                to_convert.push(ev.clone());
            }
        }
        let exhausted = consumed >= events.len();
        let at_start = exhausted && reached_start;
        let next = if at_start || consumed == 0 {
            None
        } else {
            events[events.len() - consumed]
                .event_id()
                .map(|e| e.to_string())
        };

        let converted = futures_util::future::join_all(
            to_convert
                .into_iter()
                .map(|ev| self.message_from_event(&room, ev)),
        )
        .await;
        let mut out: Vec<Message> = converted.into_iter().flatten().collect();
        let me = room.client().user_id().map(|u| u.to_owned());
        let (room_cache, _h) = room
            .event_cache()
            .await
            .context("opening the event cache")?;
        let decorated = futures_util::future::join_all(out.iter().map(|m| {
            let (room, cache, redacted, me, root) =
                (&room, &room_cache, &redacted, me.as_deref(), &root);
            let event_id = m.event_id.clone();
            async move {
                let Ok(id) = matrix_sdk::ruma::OwnedEventId::try_from(event_id.as_str()) else {
                    return (Vec::new(), None, Vec::new());
                };
                let (reactions, edit) = cached_relations(cache, &id).await;
                let reactions = aggregate_reactions(room, reactions, me, redacted).await;
                (
                    reactions,
                    edit,
                    read_by(room, &event_id, me, Some(root)).await,
                )
            }
        }))
        .await;
        for (m, (reactions, edit, read_by)) in out.iter_mut().zip(decorated) {
            m.reactions = reactions;
            m.read_by = read_by;
            if let Some((_, body, html)) = edit
                && !m.deleted
            {
                m.body = body;
                m.html = html;
                m.edited = true;
            }
        }
        out.reverse();

        // The root leads the first page.
        if at_start || before.is_none() && out.is_empty() {
            if let Ok(ev) = room.load_or_fetch_event(&root, None).await
                && let Some(mut m) = self.message_from_event(&room, ev.clone()).await
            {
                let (reactions, edit) = cached_relations(&room_cache, &root).await;
                m.reactions = aggregate_reactions(&room, reactions, me.as_deref(), &redacted).await;
                m.read_by = read_by(&room, &m.event_id, me.as_deref(), None).await;
                if let Some((_, body, html)) = edit
                    && !m.deleted
                {
                    m.body = body;
                    m.html = html;
                    m.edited = true;
                }
                if let Some(summary) = ev.thread_summary.summary() {
                    m.thread = Some(thread_info(&room, &room_cache, &root, summary).await);
                }
                out.insert(0, m);
            }
        }
        Ok(TimelinePage {
            messages: out,
            next,
        })
    }

    /// A timeline event as a message, or None for anything that is not one.
    async fn message_from_event(
        &self,
        room: &Room,
        ev: matrix_sdk::deserialized_responses::TimelineEvent,
    ) -> Option<Message> {
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
            AnySyncTimelineEvent::State(
                matrix_sdk::ruma::events::AnySyncStateEvent::RoomMember(
                    matrix_sdk::ruma::events::SyncStateEvent::Original(m),
                ),
            ) => {
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
                    notify: None,
                    highlight: None,
                    thread_root: None,
                    thread: None,
                    via: None,
                })
            }
            // A redacted message keeps its place with empty content — in an
            // encrypted room the shell that remains is an m.room.encrypted.
            AnySyncTimelineEvent::MessageLike(AnySyncMessageLikeEvent::RoomMessage(
                SyncMessageLikeEvent::Redacted(r),
            )) => Some(
                deleted_placeholder(room, &r.sender, &r.event_id, r.origin_server_ts, encrypted)
                    .await,
            ),
            AnySyncTimelineEvent::MessageLike(AnySyncMessageLikeEvent::RoomEncrypted(
                SyncMessageLikeEvent::Redacted(r),
            )) => Some(
                deleted_placeholder(room, &r.sender, &r.event_id, r.origin_server_ts, true).await,
            ),
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
                    notify: None,
                    highlight: None,
                    thread_root: None,
                    thread: None,
                    via: None,
                })
            }
            _ => None,
        }
    }

    async fn send(
        &self,
        room_id: &str,
        body: String,
        reply_to: Option<String>,
        thread: Option<String>,
    ) -> Result<String> {
        use matrix_sdk::room::reply::{EnforceThread, Reply};
        use matrix_sdk::ruma::events::room::message::ReplyWithinThread;
        let room = self.room(room_id).await?;
        let reply_to = reply_to.filter(|r| !r.is_empty());
        let thread = thread.filter(|r| !r.is_empty());
        // In a thread, a plain message relates to the root; a reply relates
        // to its target and stays in the thread.
        let target = match (&reply_to, &thread) {
            (Some(r), _) => Some((r.clone(), thread.is_some())),
            (None, Some(root)) => Some((root.clone(), false)),
            (None, None) => None,
        };
        let content = match target {
            Some((target, within_thread)) => {
                let target =
                    matrix_sdk::ruma::EventId::parse(&target).context("invalid reply target")?;
                let reply = Reply {
                    event_id: target,
                    enforce_thread: if thread.is_some() {
                        EnforceThread::Threaded(if within_thread {
                            ReplyWithinThread::Yes
                        } else {
                            ReplyWithinThread::No
                        })
                    } else {
                        EnforceThread::MaybeThreaded
                    },
                    add_mentions: AddMentions::Yes,
                };
                room.make_reply_event(
                    RoomMessageEventContentWithoutRelation::text_markdown(body),
                    reply,
                )
                .await
                .context("building the reply")?
            }
            None => RoomMessageEventContent::text_markdown(body),
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
                matrix_sdk::room::edit::EditedContent::RoomMessage(
                    RoomMessageEventContentWithoutRelation::text_markdown(body),
                ),
            )
            .await
            .context("building the edit")?;
        let resp = room.send(content).await.context("sending the edit")?;
        Ok(resp.response.event_id.to_string())
    }

    async fn mark_read(&self, room_id: &str, event_id: &str, thread: Option<String>) -> Result<()> {
        let room = self.room(room_id).await?;
        let event_id = matrix_sdk::ruma::EventId::parse(event_id).context("invalid event id")?;
        if let Some(root) = thread.filter(|t| !t.is_empty()) {
            // A threaded receipt: the room's own marker is untouched.
            let root = matrix_sdk::ruma::EventId::parse(&root).context("invalid thread root")?;
            room.send_single_receipt(
                matrix_sdk::ruma::api::client::receipt::create_receipt::v3::ReceiptType::Read,
                ReceiptThread::Thread(root),
                event_id,
            )
            .await
            .context("sending threaded read receipt")?;
            return Ok(());
        }
        let receipts = matrix_sdk::room::Receipts::new()
            .fully_read_marker(event_id.clone())
            .public_read_receipt(event_id);
        room.send_multiple_receipts(receipts)
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
            vec![OAuthGrantType::AuthorizationCode {
                redirect_uris: vec![v4, v6],
            }],
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
    actions: Vec<matrix_sdk::ruma::push::Action>,
    ctx: Ctx<HandlerCtx>,
) {
    if room.state() != RoomState::Joined {
        return;
    }
    // The SDK evaluates the account's push rules for every event; muted
    // rooms, mentions and keyword rules all land here.
    let notify = Some(actions.iter().any(|a| a.should_notify()));
    let highlight = Some(actions.iter().any(|a| a.is_highlight()));
    if let Some(Relation::Replacement(Replacement {
        event_id,
        new_content,
        ..
    })) = &event.content.relates_to
    {
        // An edit counts only when it comes from whoever wrote the original
        // (the server checks this only for the edits it bundles itself).
        let original_sender = room
            .load_or_fetch_event(event_id, None)
            .await
            .ok()
            .and_then(|ev| ev.raw().deserialize().ok())
            .map(|ev: AnySyncTimelineEvent| ev.sender().to_owned());
        if original_sender.as_deref() != Some(event.sender.as_ref()) {
            warn!(
                "ignoring an edit of {} by {} who did not send it",
                event_id, event.sender
            );
            return;
        }
        let html = formatted_html(&new_content.msgtype);
        forget_reply_preview(&room, event_id.as_str());
        let _ = ctx.events.send(Event::MessageEdited(MessageEdit {
            room: room.room_id().to_string(),
            event_id: event_id.to_string(),
            body: new_content.msgtype.body().to_owned(),
            html,
        }));
        return;
    }
    let mut msg = to_message(&room, event, encryption.is_some()).await;
    msg.notify = notify;
    msg.highlight = highlight;
    {
        let mut a = ctx.activity.lock().await;
        let e = a.entry(room.room_id().to_string()).or_insert(0);
        *e = (*e).max(msg.ts);
    }
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
fn bundled_edit(
    raw: &matrix_sdk::ruma::serde::Raw<AnySyncTimelineEvent>,
) -> Option<(String, Option<String>)> {
    let unsigned: serde_json::Value = raw.get_field("unsigned").ok().flatten()?;
    let replace = unsigned.get("m.relations")?.get("m.replace")?;
    let new_content = replace.get("content")?.get("m.new_content")?;
    let body = new_content.get("body")?.as_str()?.to_owned();
    let html = match (
        new_content.get("format").and_then(|f| f.as_str()),
        new_content.get("formatted_body").and_then(|b| b.as_str()),
    ) {
        (Some("org.matrix.custom.html"), Some(h)) => Some(h.to_owned()),
        _ => None,
    };
    Some((body, html))
}

/// How many events at the end of the cache's linked chunk sit after its
/// last gap, read from the cache's chunk listing (one line per chunk:
/// `chunk #n: gap['token']` or `chunk #n: [#order: $id, …]`). Sync
/// back-pagination resolves gaps newest-first, so this run is the part of
/// history that is complete up to the live end.
fn contiguous_tail(chunks: &[String]) -> usize {
    let mut n = 0;
    for line in chunks {
        let Some((_, body)) = line.split_once(": ") else {
            continue;
        };
        if body.starts_with("gap[") {
            n = 0;
        } else {
            n += body.matches('#').count();
        }
    }
    n
}

/// Reactions and the latest edit of a message, from the event cache's
/// relation index. Anything relating to a message is newer than it, so once
/// the message is loaded its relations are too.
async fn cached_relations(
    cache: &matrix_sdk::event_cache::RoomEventCache,
    event_id: &matrix_sdk::ruma::EventId,
) -> (
    Vec<(String, matrix_sdk::ruma::OwnedUserId, String)>,
    Option<(u64, String, Option<String>)>,
) {
    let related = cache
        .find_event_relations(
            event_id,
            Some(vec![RelationType::Annotation, RelationType::Replacement]),
        )
        .await
        .unwrap_or_default();
    // Edits by anyone but the original sender are not edits.
    let original_sender = match cache.find_event(event_id).await {
        Ok(Some(ev)) => ev
            .raw()
            .deserialize()
            .ok()
            .map(|ev: AnySyncTimelineEvent| ev.sender().to_owned()),
        _ => None,
    };
    let mut reactions = Vec::new();
    let mut edit: Option<(u64, String, Option<String>)> = None;
    for rel in related {
        match rel.raw().deserialize() {
            Ok(AnySyncTimelineEvent::MessageLike(AnySyncMessageLikeEvent::Reaction(
                SyncMessageLikeEvent::Original(r),
            ))) => reactions.push((
                r.content.relates_to.key.chars().take(MAX_REACTION_KEY).collect(),
                r.sender.clone(),
                r.event_id.to_string(),
            )),
            Ok(AnySyncTimelineEvent::MessageLike(AnySyncMessageLikeEvent::RoomMessage(
                SyncMessageLikeEvent::Original(e),
            ))) => {
                if let Some(Relation::Replacement(rep)) = &e.content.relates_to {
                    if original_sender.as_deref() != Some(e.sender.as_ref()) {
                        continue;
                    }
                    let ts = u64::from(e.origin_server_ts.0);
                    if edit.as_ref().is_none_or(|(t, _, _)| ts >= *t) {
                        edit = Some((
                            ts,
                            rep.new_content.msgtype.body().to_owned(),
                            formatted_html(&rep.new_content.msgtype),
                        ));
                    }
                }
            }
            _ => {}
        }
    }
    (reactions, edit)
}

/// A message inside a thread (not an edit, reaction or redaction).
fn is_thread_reply(ev: &TimelineEvent) -> bool {
    let raw = ev.raw();
    let Ok(Some(kind)) = raw.get_field::<String>("type") else {
        return false;
    };
    match kind.as_str() {
        "m.room.encrypted" | "m.sticker" => true,
        "m.room.message" => {
            let rel: Option<serde_json::Value> = raw.get_field("content").ok().flatten();
            rel.as_ref()
                .and_then(|c| c.get("m.relates_to"))
                .and_then(|r| r.get("rel_type"))
                .and_then(|t| t.as_str())
                != Some("m.replace")
        }
        _ => false,
    }
}

/// What the timeline shows under a thread root, from the cache's summary.
async fn thread_info(
    room: &Room,
    cache: &matrix_sdk::event_cache::RoomEventCache,
    root: &matrix_sdk::ruma::EventId,
    summary: &matrix_sdk::deserialized_responses::ThreadSummary,
) -> ThreadInfo {
    // The thread cache counts replies from others after our threaded receipt.
    let unread = match room
        .client()
        .event_cache()
        .thread(room.room_id(), root)
        .await
    {
        Ok((thread, _h)) => thread.num_unread_messages().await.unwrap_or(0) as u32,
        Err(_) => 0,
    };
    let mut info = ThreadInfo {
        replies: summary.num_replies,
        unread,
        latest_ts: None,
        latest_sender: None,
        latest_sender_name: None,
    };
    if let Some(latest) = &summary.latest_reply
        && let Ok(Some(ev)) = cache.find_event(latest).await
        && let Ok(AnySyncTimelineEvent::MessageLike(m)) = ev.raw().deserialize()
    {
        info.latest_ts = Some(u64::from(m.origin_server_ts().0));
        info.latest_sender = Some(m.sender().to_string());
        info.latest_sender_name = Some(user_ref(room, m.sender()).await.name);
    }
    info
}

/// Whether an event becomes a line in the timeline: a message (not an
/// edit), an encrypted event, or a membership change.
fn is_message_like(ev: &TimelineEvent) -> bool {
    let raw = ev.raw();
    let Ok(Some(kind)) = raw.get_field::<String>("type") else {
        return false;
    };
    match kind.as_str() {
        "m.room.encrypted" | "m.room.member" | "m.sticker" => true,
        "m.room.message" => {
            let rel: Option<serde_json::Value> = raw.get_field("content").ok().flatten();
            let rel_type = rel
                .as_ref()
                .and_then(|c| c.get("m.relates_to"))
                .and_then(|r| r.get("rel_type"))
                .and_then(|t| t.as_str());
            rel_type != Some("m.replace") && rel_type != Some("m.thread")
        }
        _ => false,
    }
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
    if rest.is_empty() {
        body.to_owned()
    } else {
        rest.join("\n")
    }
}

/// Invites arrive as stripped state; announce the ones addressed to us.
async fn on_stripped_member(
    event: StrippedRoomMemberEvent,
    room: Room,
    client: Client,
    ctx: Ctx<HandlerCtx>,
) {
    if event.content.membership != MembershipState::Invite {
        return;
    }
    if client.user_id().is_none_or(|me| me != event.state_key) {
        return;
    }
    if room.state() != RoomState::Invited {
        return;
    }
    // The DM policy is judged here, before the client hears of the invite.
    let info = invite_info(&room).await;
    let prefs = ctx.prefs.lock().await.clone();
    if let Some(inviter) = info
        .inviter
        .as_deref()
        .and_then(|i| matrix_sdk::ruma::UserId::parse(i).ok())
        && !crate::community::invite_allowed(&client, &prefs, &inviter, info.direct).await
    {
        info!(room = %room.room_id(), %inviter, policy = ?prefs.dm_policy, "declining a direct-chat invite");
        if let Err(e) = room.leave().await {
            warn!("declining the invite: {e:#}");
        }
        return;
    }
    let _ = ctx.events.send(Event::Invite(info));
}

fn load_prefs(data_dir: &Path) -> crate::community::Prefs {
    std::fs::read_to_string(data_dir.join("prefs.json"))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
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
    // A thread reply quotes only when it is a real reply within the thread;
    // the fallback in_reply_to (the thread's latest message) is not one.
    let (reply_to, thread_root) = match &ev.content.relates_to {
        Some(Relation::Reply(in_reply_to)) => (
            reply_preview(room, &in_reply_to.in_reply_to.event_id).await,
            None,
        ),
        Some(Relation::Thread(t)) => (
            match &t.in_reply_to {
                Some(r) if !t.is_falling_back => reply_preview(room, &r.event_id).await,
                _ => None,
            },
            Some(t.event_id.to_string()),
        ),
        _ => (None, None),
    };
    let body = if reply_to.is_some() {
        strip_reply_fallback(ev.content.body())
    } else {
        ev.content.body().to_owned()
    };
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
        notify: None,
        highlight: None,
        thread_root,
        thread: None,
        via: crate::bridge::protocol_of_user(&ev.sender).map(crate::bridge::display_name),
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
        notify: None,
        highlight: None,
        thread_root: None,
        thread: None,
        via: None,
    }
}

async fn user_ref(room: &Room, user: &matrix_sdk::ruma::UserId) -> UserRef {
    let name = match room.get_member_no_sync(user).await {
        Ok(Some(m)) => m.name().to_owned(),
        _ => user.localpart().to_owned(),
    };
    UserRef {
        id: user.to_string(),
        name,
    }
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
            Reaction {
                key: key.clone(),
                count: 0,
                senders: Vec::new(),
                mine: None,
            }
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
        entry.senders.push(ReactionSender {
            id: u.id,
            name: u.name,
            reaction_id: id,
        });
    }
    order
        .into_iter()
        .filter_map(|k| by_key.remove(&k))
        .collect()
}

/// Others whose read receipt sits on this event. Clients send receipts
/// either unthreaded or on the main thread; both mean "read up to here".
async fn read_by(
    room: &Room,
    event_id: &str,
    me: Option<&matrix_sdk::ruma::UserId>,
    thread_root: Option<&matrix_sdk::ruma::EventId>,
) -> Vec<UserRef> {
    let Ok(id) = matrix_sdk::ruma::EventId::parse(event_id) else {
        return Vec::new();
    };
    let mut out: Vec<UserRef> = Vec::new();
    let mut threads = vec![ReceiptThread::Unthreaded, ReceiptThread::Main];
    if let Some(root) = thread_root {
        threads.push(ReceiptThread::Thread(root.to_owned()));
    }
    for thread in threads {
        let Ok(list) = room
            .load_event_receipts(StoreReceiptType::Read, &thread, &id)
            .await
        else {
            continue;
        };
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
        key: a.key.chars().take(MAX_REACTION_KEY).collect(),
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
    let _ = ctx.events.send(Event::Redacted(Redaction {
        room: room.room_id().to_string(),
        event_id: target.to_string(),
    }));
}

async fn on_typing(event: SyncTypingEvent, room: Room, client: Client, ctx: Ctx<HandlerCtx>) {
    let mut users = Vec::new();
    for u in &event.content.user_ids {
        if client.user_id().is_some_and(|me| me == u) {
            continue;
        }
        users.push(user_ref(&room, u).await);
    }
    let _ = ctx.events.send(Event::Typing(TypingInfo {
        room: room.room_id().to_string(),
        users,
    }));
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
                by_event
                    .entry(event_id.to_string())
                    .or_default()
                    .push(user_ref(&room, user).await);
            }
        }
    }
    for (event_id, users) in by_event {
        let _ = ctx.events.send(Event::Receipt(ReceiptInfo {
            room: room.room_id().to_string(),
            event_id,
            users,
        }));
    }
}

/// "X joined", "X left", … for a member event, or None for changes not worth a line.
async fn membership_line(
    room: &Room,
    ev: &matrix_sdk::ruma::events::room::member::OriginalSyncRoomMemberEvent,
) -> Option<String> {
    use matrix_sdk::ruma::events::room::member::MembershipChange as C;
    let who = |name: &Option<String>, id: &matrix_sdk::ruma::UserId| {
        name.clone().unwrap_or_else(|| id.localpart().to_owned())
    };
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
        C::ProfileChanged {
            displayname_change,
            avatar_url_change,
        } => match (displayname_change, avatar_url_change) {
            (Some(c), _) => {
                let old = c
                    .old
                    .map(str::to_owned)
                    .unwrap_or_else(|| ev.state_key.localpart().to_owned());
                let new = c
                    .new
                    .map(str::to_owned)
                    .unwrap_or_else(|| ev.state_key.localpart().to_owned());
                format!("{old} is now known as {new}")
            }
            (None, Some(_)) => format!("{target} changed their avatar"),
            _ => return None,
        },
        _ => return None,
    };
    Some(text)
}

fn role_of(power: i64) -> &'static str {
    if power >= 100 {
        "admin"
    } else if power >= 50 {
        "moderator"
    } else {
        "member"
    }
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
        let (can_invite, can_kick, can_ban, can_set_name, can_set_topic, can_redact_other) =
            match own {
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
        let encrypted = room
            .latest_encryption_state()
            .await
            .map(|s| s.is_encrypted())
            .unwrap_or(false);
        let direct = room.is_direct().await.unwrap_or(false);
        let (notification_mode, notification_custom) =
            self.notification_mode(&room, encrypted, direct).await;
        let bridge = crate::bridge::detect(&room).await;
        Ok(RoomDetails {
            id: room.room_id().to_string(),
            name,
            topic: room.topic(),
            avatar: room.avatar_url().map(|u| u.to_string()),
            alias: room.canonical_alias().map(|a| a.to_string()),
            encrypted,
            direct,
            notification_mode,
            notification_custom,
            bridge,
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

    /// Latest message time for the room list's ordering. The event cache is
    /// empty at startup, so the first look at a room asks the server for
    /// its last message; incoming events keep the value fresh after that.
    async fn activity_of(&self, room: &Room, from_cache: Option<u64>) -> Option<u64> {
        let key = room.room_id().to_string();
        let known = self.activity.lock().await.get(&key).copied();
        let mut best = match (known, from_cache) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };
        if known.is_none() {
            let mut opts = MessagesOptions::backward();
            opts.limit = UInt::from(20u32);
            if let Ok(page) = room.messages(opts).await {
                for ev in page.chunk {
                    if let Ok(AnySyncTimelineEvent::MessageLike(m)) = ev.raw().deserialize() {
                        if matches!(
                            m,
                            AnySyncMessageLikeEvent::RoomMessage(_)
                                | AnySyncMessageLikeEvent::RoomEncrypted(_)
                        ) {
                            let ts = u64::from(m.origin_server_ts().0);
                            best = Some(best.map_or(ts, |b| b.max(ts)));
                            break;
                        }
                    }
                }
            }
            self.activity.lock().await.insert(key, best.unwrap_or(0));
        }
        best.filter(|&t| t > 0)
    }

    /// The room's effective notification mode and whether it is room-specific.
    async fn settings(&self) -> Result<matrix_sdk::notification_settings::NotificationSettings> {
        self.state
            .lock()
            .await
            .notification_settings
            .clone()
            .ok_or_else(|| anyhow!("not logged in"))
    }

    async fn notification_mode(
        &self,
        room: &Room,
        encrypted: bool,
        direct: bool,
    ) -> (String, bool) {
        use matrix_sdk::notification_settings::{
            IsEncrypted, IsOneToOne, RoomNotificationMode as M,
        };
        let Ok(settings) = self.settings().await else {
            return ("all".to_owned(), false);
        };
        let (mode, custom) = match settings
            .get_user_defined_room_notification_mode(room.room_id())
            .await
        {
            Some(m) => (m, true),
            None => (
                settings
                    .get_default_room_notification_mode(
                        IsEncrypted::from(encrypted),
                        IsOneToOne::from(direct),
                    )
                    .await,
                false,
            ),
        };
        let name = match mode {
            M::AllMessages => "all",
            M::MentionsAndKeywordsOnly => "mentions",
            M::Mute => "mute",
        };
        (name.to_owned(), custom)
    }

    pub(crate) async fn set_notification_mode(&self, room_id: &str, mode: &str) -> Result<()> {
        use matrix_sdk::notification_settings::RoomNotificationMode as M;
        let room = self.room(room_id).await?;
        let settings = self.settings().await?;
        let result = match mode {
            "all" => {
                settings
                    .set_room_notification_mode(room.room_id(), M::AllMessages)
                    .await
            }
            "mentions" => {
                settings
                    .set_room_notification_mode(room.room_id(), M::MentionsAndKeywordsOnly)
                    .await
            }
            "mute" => {
                settings
                    .set_room_notification_mode(room.room_id(), M::Mute)
                    .await
            }
            "default" => {
                settings
                    .delete_user_defined_room_rules(room.room_id())
                    .await
            }
            other => bail!("unknown mode {other}; use all, mentions, mute or default"),
        };
        match result {
            Ok(()) => {}
            // Resetting when one of the rules is already gone is still a reset.
            Err(e) if mode == "default" && e.to_string().contains("M_NOT_FOUND") => {
                warn!("notification rules partly missing while resetting: {e}");
            }
            Err(e) => return Err(e).context("updating notification settings"),
        }
        let _ = self.events().send(Event::RoomsChanged);
        Ok(())
    }

    /// Server-side search covers unencrypted rooms. Encrypted rooms are
    /// scanned locally through their decrypted history, a bounded number of
    /// pages back, so a search there means "the recent past", not all time.
    pub(crate) async fn search(
        &self,
        query: &str,
        room_id: Option<&str>,
        limit: u32,
    ) -> Result<SearchResults> {
        use matrix_sdk::ruma::api::client::search::search_events::v3::{
            Categories, Criteria, Request,
        };
        let client = self.client().await?;
        let q = query.trim();
        if q.is_empty() {
            bail!("nothing to search for");
        }
        let limit = limit.clamp(1, 200) as usize;
        let rooms: Vec<Room> = match room_id {
            Some(id) => vec![self.room(id).await?],
            None => client
                .joined_rooms()
                .into_iter()
                .filter(|r| !r.is_space())
                .collect(),
        };
        let mut plain: Vec<matrix_sdk::ruma::OwnedRoomId> = Vec::new();
        let mut encrypted: Vec<Room> = Vec::new();
        for r in rooms {
            if r.latest_encryption_state()
                .await
                .map(|s| s.is_encrypted())
                .unwrap_or(false)
            {
                encrypted.push(r);
            } else {
                plain.push(r.room_id().to_owned());
            }
        }
        let mut hits: Vec<SearchHit> = Vec::new();

        // Server search for the unencrypted set.
        let server_rooms = plain.len() as u32;
        if !plain.is_empty() {
            let mut criteria = Criteria::new(q.to_owned());
            criteria.filter.rooms = Some(plain);
            criteria.filter.limit = Some(UInt::from(limit as u32));
            let mut cats = Categories::new();
            cats.room_events = Some(criteria);
            match tokio::time::timeout(MESSAGE_SEARCH_TIMEOUT, client.send(Request::new(cats)))
                .await
            {
                Ok(Ok(resp)) => {
                    for r in resp.search_categories.room_events.results {
                        let Some(raw) = r.result else { continue };
                        let Ok(ev) = raw.deserialize() else { continue };
                        if let matrix_sdk::ruma::events::AnyTimelineEvent::MessageLike(
                            matrix_sdk::ruma::events::AnyMessageLikeEvent::RoomMessage(
                                matrix_sdk::ruma::events::MessageLikeEvent::Original(m),
                            ),
                        ) = ev
                        {
                            // An edit is a revision of another hit, not a message of its own.
                            if matches!(m.content.relates_to, Some(Relation::Replacement(_))) {
                                continue;
                            }
                            let room = client.get_room(&m.room_id);
                            let (room_name, sender_name) = match &room {
                                Some(room) => (
                                    room.display_name()
                                        .await
                                        .map(|n| n.to_string())
                                        .unwrap_or_else(|_| m.room_id.to_string()),
                                    room.get_member_no_sync(&m.sender)
                                        .await
                                        .ok()
                                        .flatten()
                                        .map(|mm| mm.name().to_owned())
                                        .unwrap_or_else(|| m.sender.localpart().to_owned()),
                                ),
                                None => (m.room_id.to_string(), m.sender.localpart().to_owned()),
                            };
                            hits.push(SearchHit {
                                room: m.room_id.to_string(),
                                room_name,
                                event_id: m.event_id.to_string(),
                                sender: m.sender.to_string(),
                                sender_name,
                                body: m.content.body().to_owned(),
                                ts: m.origin_server_ts.0.into(),
                            });
                        }
                    }
                }
                Ok(Err(e)) => warn!("server search: {e:#}"),
                Err(_) => warn!("server search timed out"),
            }
        }

        // Local scan for encrypted rooms: recent pages, decrypted by the SDK. The whole
        // scan has one deadline and covers at most the most recently active rooms.
        let needle = q.to_lowercase();
        let mut scanned_messages = 0u32;
        let pages_per_room = if room_id.is_some() { 12 } else { 3 };
        let scan_deadline = tokio::time::Instant::now() + MESSAGE_SEARCH_TIMEOUT;
        let encrypted: Vec<Room> = encrypted.into_iter().take(MAX_SEARCH_ROOMS).collect();
        'rooms: for room in &encrypted {
            let room_name = room
                .display_name()
                .await
                .map(|n| n.to_string())
                .unwrap_or_else(|_| room.room_id().to_string());
            let mut from: Option<String> = None;
            for _ in 0..pages_per_room {
                let mut opts = MessagesOptions::backward();
                opts.limit = UInt::from(100u32);
                opts.from = from.clone();
                let Ok(Ok(page)) = tokio::time::timeout_at(scan_deadline, room.messages(opts)).await else {
                    if tokio::time::Instant::now() >= scan_deadline {
                        warn!("local search stopped at the {} s deadline", MESSAGE_SEARCH_TIMEOUT.as_secs());
                        break 'rooms;
                    }
                    break;
                };
                let raw_count = page.chunk.len();
                for ev in page.chunk {
                    if let Ok(AnySyncTimelineEvent::MessageLike(
                        AnySyncMessageLikeEvent::RoomMessage(SyncMessageLikeEvent::Original(m)),
                    )) = ev.raw().deserialize()
                    {
                        if matches!(m.content.relates_to, Some(Relation::Replacement(_))) {
                            continue;
                        }
                        scanned_messages += 1;
                        // Search the text as it reads now, after any edit.
                        let edited = bundled_edit(ev.raw()).map(|(b, _)| b);
                        let body = edited.as_deref().unwrap_or_else(|| m.content.body());
                        if body.to_lowercase().contains(&needle) {
                            let sender_name = room
                                .get_member_no_sync(&m.sender)
                                .await
                                .ok()
                                .flatten()
                                .map(|mm| mm.name().to_owned())
                                .unwrap_or_else(|| m.sender.localpart().to_owned());
                            hits.push(SearchHit {
                                room: room.room_id().to_string(),
                                room_name: room_name.clone(),
                                event_id: m.event_id.to_string(),
                                sender: m.sender.to_string(),
                                sender_name,
                                body: body.to_owned(),
                                ts: m.origin_server_ts.0.into(),
                            });
                        }
                    }
                }
                if raw_count < 100 {
                    break;
                }
                from = page.end;
                if from.is_none() {
                    break;
                }
            }
        }

        hits.sort_by(|a, b| b.ts.cmp(&a.ts));
        hits.dedup_by(|a, b| a.event_id == b.event_id);
        hits.truncate(limit);
        Ok(SearchResults {
            hits,
            scanned_rooms: encrypted.len() as u32,
            scanned_messages,
            server_rooms,
        })
    }

    /// Link preview through the homeserver (it fetches the page, not us).
    pub(crate) async fn preview(&self, url: &str) -> Result<LinkPreview> {
        let client = self.client().await?;
        let url = url.trim();
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            bail!("only http(s) links can be previewed");
        }
        let raw = tokio::time::timeout(SEARCH_TIMEOUT, client.media().get_media_preview(url, None))
            .await
            .map_err(|_| anyhow!("the preview did not arrive in time"))?
            .context("fetching preview")?;
        let v: serde_json::Value = match raw {
            Some(r) => serde_json::from_str(r.get()).context("reading preview")?,
            None => serde_json::Value::Null,
        };
        let get = |k: &str| {
            v.get(k)
                .and_then(|x| x.as_str())
                .map(|x| x.trim().to_owned())
                .filter(|x| !x.is_empty())
        };
        Ok(LinkPreview {
            url: url.to_owned(),
            title: get("og:title").map(|t| t.chars().take(200).collect()),
            description: get("og:description").map(|d| d.chars().take(300).collect()),
            site: get("og:site_name").map(|s| s.chars().take(100).collect()),
            image: get("og:image").filter(|i| i.starts_with("mxc://")),
        })
    }

    pub(crate) async fn spaces(&self) -> Result<Vec<SpaceInfo>> {
        use matrix_sdk::ruma::events::space::child::SpaceChildEventContent;
        let client = self.client().await?;
        let mut out = Vec::new();
        for room in client.joined_rooms() {
            if !room.is_space() {
                continue;
            }
            let name = match room.display_name().await {
                Ok(n) => n.to_string(),
                Err(_) => room.room_id().to_string(),
            };
            let mut children = Vec::new();
            if let Ok(events) = room
                .get_state_events_static::<SpaceChildEventContent>()
                .await
            {
                for ev in events {
                    use matrix_sdk::deserialized_responses::SyncOrStrippedState;
                    // A child with an empty `via` has been removed from the space.
                    if let Ok(SyncOrStrippedState::Sync(sync)) = ev.deserialize() {
                        if let Some(o) = sync.as_original() {
                            if !o.content.via.is_empty() {
                                children.push(o.state_key.to_string());
                            }
                        }
                    }
                }
            }
            out.push(SpaceInfo {
                id: room.room_id().to_string(),
                name,
                avatar: room.avatar_url().map(|u| u.to_string()),
                children,
            });
        }
        out.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
        Ok(out)
    }

    pub(crate) async fn members(
        &self,
        room_id: &str,
        query: &str,
        limit: u32,
    ) -> Result<Vec<MemberInfo>> {
        let room = self.room(room_id).await?;
        let members = room
            .members(matrix_sdk::RoomMemberships::JOIN)
            .await
            .context("loading members")?;
        let q = query.trim().to_lowercase();
        let mut out: Vec<MemberInfo> = members
            .iter()
            .filter(|m| {
                q.is_empty()
                    || m.name().to_lowercase().contains(&q)
                    || m.user_id().as_str().to_lowercase().contains(&q)
            })
            .map(|m| {
                let power = power_i64(m.power_level());
                MemberInfo {
                    id: m.user_id().to_string(),
                    name: m.name().to_owned(),
                    avatar: m.avatar_url().map(|u| u.to_string()),
                    power,
                    role: role_of(power).to_owned(),
                    via: crate::bridge::protocol_of_user(m.user_id())
                        .map(crate::bridge::display_name),
                }
            })
            .collect();
        out.sort_by(|a, b| {
            b.power
                .cmp(&a.power)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        out.truncate(limit.clamp(1, 2000) as usize);
        Ok(out)
    }

    /// Small square avatar into the media cache, keyed by the mxc URL.
    pub(crate) async fn avatar(&self, url: &str, size: u32) -> Result<String> {
        let client = self.client().await?;
        let mxc = matrix_sdk::ruma::OwnedMxcUri::from(url);
        mxc.validate()
            .map_err(|e| anyhow!("invalid avatar url: {e}"))?;
        let size = size.clamp(16, 640);
        let dir = crate::media::avatar_cache_dir()?;
        // The default size keeps its historical file name so existing caches stay valid.
        let path = if size == 96 {
            dir.join(format!("{}.png", crate::media::hash_of(url)))
        } else {
            dir.join(format!("{}-{size}.png", crate::media::hash_of(url)))
        };
        if path.exists() {
            return Ok(path.to_string_lossy().into_owned());
        }
        let bytes = client
            .media()
            .get_media_content(
                &matrix_sdk::media::MediaRequestParameters {
                    source: matrix_sdk::ruma::events::room::MediaSource::Plain(mxc),
                    format: matrix_sdk::media::MediaFormat::Thumbnail(
                        matrix_sdk::media::MediaThumbnailSettings::new(
                            UInt::from(size),
                            UInt::from(size),
                        ),
                    ),
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
/// Reply previews already built, keyed by "room|event". A quoted message
/// rarely changes (an edit invalidates it), and fetching each one from the
/// server was what made reply-heavy rooms take seconds to open.
static REPLY_CACHE: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<String, ReplyPreview>>,
> = std::sync::OnceLock::new();

fn reply_cache() -> &'static std::sync::Mutex<std::collections::HashMap<String, ReplyPreview>> {
    REPLY_CACHE.get_or_init(Default::default)
}

fn forget_reply_preview(room: &Room, event_id: &str) {
    if let Ok(mut c) = reply_cache().lock() {
        c.remove(&format!("{}|{}", room.room_id(), event_id));
    }
}

async fn reply_preview(room: &Room, event_id: &matrix_sdk::ruma::EventId) -> Option<ReplyPreview> {
    let key = format!("{}|{}", room.room_id(), event_id);
    if let Some(p) = reply_cache().lock().ok().and_then(|c| c.get(&key).cloned()) {
        return Some(p);
    }
    let preview = build_reply_preview(room, event_id).await?;
    if let Ok(mut c) = reply_cache().lock() {
        // Bounded: remote messages decide the keys, so the map cannot grow forever.
        if c.len() >= MAX_REPLY_CACHE {
            c.clear();
        }
        c.insert(key, preview.clone());
    }
    Some(preview)
}

async fn build_reply_preview(
    room: &Room,
    event_id: &matrix_sdk::ruma::EventId,
) -> Option<ReplyPreview> {
    // The event cache (sync + earlier pages) answers instantly; only fall
    // back to the server for something we have never seen.
    let ev = tokio::time::timeout(
        Duration::from_secs(5),
        room.load_or_fetch_event(event_id, None),
    )
    .await
    .ok()?
    .ok()?;
    let parsed: AnySyncTimelineEvent = ev.raw().deserialize().ok()?;
    // The quote shows the message as it reads now: the newest edit the
    // cache knows of, else the one the server bundled.
    let mut edited = bundled_edit(ev.raw()).map(|(b, _)| b);
    if let Ok((cache, _handles)) = room.event_cache().await
        && let (_, Some((_, body, _))) = cached_relations(&cache, event_id).await
    {
        edited = Some(body);
    }
    let (sender, body) = match parsed {
        AnySyncTimelineEvent::MessageLike(AnySyncMessageLikeEvent::RoomMessage(
            SyncMessageLikeEvent::Original(m),
        )) => {
            let text = match crate::media::attachment_of(&m.content.msgtype) {
                Some(a) => format!(
                    "{} {}",
                    match a.kind.as_str() {
                        "image" => "🖼",
                        "video" => "🎞",
                        "audio" => "🎵",
                        _ => "📎",
                    },
                    a.caption.unwrap_or(a.name)
                ),
                None => edited.unwrap_or_else(|| strip_reply_fallback(m.content.body())),
            };
            (m.sender, text)
        }
        AnySyncTimelineEvent::MessageLike(AnySyncMessageLikeEvent::RoomEncrypted(
            SyncMessageLikeEvent::Original(e),
        )) => (e.sender, "Unable to decrypt".to_owned()),
        _ => return None,
    };
    let sender_name = match room.get_member_no_sync(&sender).await {
        Ok(Some(m)) => m.name().to_owned(),
        _ => sender.localpart().to_owned(),
    };
    let one_line: String = body.split_whitespace().collect::<Vec<_>>().join(" ");
    let body = if one_line.chars().count() > 160 {
        format!("{}…", one_line.chars().take(160).collect::<String>())
    } else {
        one_line
    };
    Some(ReplyPreview {
        event_id: event_id.to_string(),
        sender: sender.to_string(),
        sender_name,
        body,
    })
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
