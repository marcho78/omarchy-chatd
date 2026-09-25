//! The Omarchy community: a public Matrix space and what members choose to
//! say about themselves in it. Nothing here needs a server of ours — the
//! space is an ordinary room on the members' homeservers.
//!
//! A member's card is a state event `org.omarchy.profile` in the space
//! whose `state_key` is their own user id. Matrix only lets a user write
//! state keyed on their own id, so a card is the member's alone to publish,
//! change or withdraw (an empty content withdraws it). The space's power
//! levels allow that event type at level 0 so every member can.
//!
//! The DM policy is enforced here too: an invite to a direct chat from
//! someone the policy does not allow is declined before the client sees it.

use anyhow::{Context, Result, anyhow};
use matrix_sdk::{
    Client, Room, RoomState,
    ruma::{
        OwnedRoomId, OwnedUserId, RoomAliasId, RoomId, UserId,
        api::client::space::get_hierarchy,
        events::{StateEventType, ignored_user_list::IgnoredUserListEventContent},
    },
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::{Duration, Instant},
};
use tracing::{info, warn};

pub const PROFILE_TYPE: &str = "org.omarchy.profile";

/// How long a fetched space hierarchy is reused before asking the server again.
const HIERARCHY_TTL: Duration = Duration::from_secs(5 * 60);
/// How long a refused listing (not a member, space not readable) is
/// remembered, so status refreshes do not ask again every time.
const HIERARCHY_FAILURE_TTL: Duration = Duration::from_secs(60);
/// Pause between joining one community room and the next: matrix.org allows a
/// short burst of joins, then about one every ten seconds.
const JOIN_SPACING: Duration = Duration::from_secs(5);
/// Longest wait honoured from a 429 before giving up on that room.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(5 * 60);
const JOIN_ATTEMPTS: u32 = 5;

/// What the daemon keeps about the community between requests.
#[derive(Default)]
pub struct CommunityState {
    /// Space hierarchies by alias, with when they were fetched.
    hierarchy: tokio::sync::Mutex<HashMap<String, CachedHierarchy>>,
    /// Rooms the background joiner still has to join.
    joining: AtomicU32,
    /// The background joiner, so a leave can stop it.
    pub(crate) joiner: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

#[derive(Clone)]
struct CachedHierarchy {
    fetched: Instant,
    /// Set when the last attempt was refused; the entry then only says
    /// "do not ask again yet".
    failure: Option<String>,
    name: Option<String>,
    topic: Option<String>,
    member_count: u64,
    rooms: Vec<CommunityRoom>,
}

impl CommunityState {
    pub fn joining(&self) -> u32 {
        self.joining.load(Ordering::Relaxed)
    }
    async fn forget(&self, alias: &str) {
        self.hierarchy.lock().await.remove(alias);
    }
    /// Stop a joiner that is still working (on leave).
    async fn stop_joiner(&self) {
        if let Some(task) = self.joiner.lock().await.take() {
            task.abort();
        }
        self.joining.store(0, Ordering::Relaxed);
    }
}

/// Who may open a direct chat with us. Anything else is declined quietly.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DmPolicy {
    /// Any Matrix user (the protocol's default).
    #[default]
    Anyone,
    /// Members of the community space, and anyone we already share a room with.
    Community,
    /// Only people we already share a room with.
    Contacts,
    /// Nobody: every direct-chat invite is declined.
    Nobody,
}

/// Daemon-side preferences that must hold even when the shell is not
/// running (invites are judged as they arrive).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Prefs {
    #[serde(default)]
    pub dm_policy: DmPolicy,
    /// The community space, as an alias.
    #[serde(default)]
    pub community: String,
}

/// A member's card.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Profile {
    pub user_id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar: Option<String>,
    #[serde(default)]
    pub bio: String,
    #[serde(default)]
    pub open_to_dm: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub theme: Option<String>,
    /// Milliseconds since the epoch, when the card was last published.
    #[serde(default)]
    pub updated: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct CommunityRoom {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    pub joined: bool,
    pub members: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct CommunityStatus {
    pub alias: String,
    /// The space resolves on the server (someone created it).
    pub exists: bool,
    pub joined: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    pub member_count: u64,
    pub rooms: Vec<CommunityRoom>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<Profile>,
    pub dm_policy: DmPolicy,
    /// Community rooms still being joined in the background after a join.
    pub joining: u32,
}

fn alias_of(alias: &str) -> Result<matrix_sdk::ruma::OwnedRoomAliasId> {
    RoomAliasId::parse(alias).map_err(|e| anyhow!("invalid space alias {alias:?}: {e}"))
}

/// The space's room id, joined or not.
pub async fn space_id(client: &Client, alias: &str) -> Result<Option<OwnedRoomId>> {
    let alias = alias_of(alias)?;
    if let Some(room) = client.joined_rooms().into_iter().find(|r| {
        r.canonical_alias().as_deref() == Some(alias.as_ref())
            || r.alt_aliases().iter().any(|a| *a == alias)
    }) {
        return Ok(Some(room.room_id().to_owned()));
    }
    match client.resolve_room_alias(&alias).await {
        Ok(resp) => Ok(Some(resp.room_id)),
        Err(e)
            if e.as_client_api_error()
                .is_some_and(|e| e.status_code.as_u16() == 404) =>
        {
            Ok(None)
        }
        Err(e) => Err(e).context("resolving the space alias"),
    }
}

/// The space's summary and children: one hierarchy request, reused for
/// [`HIERARCHY_TTL`]. Works before joining when the space is world-readable.
async fn hierarchy(
    client: &Client,
    state: &CommunityState,
    alias: &str,
    space_id: &RoomId,
) -> Result<CachedHierarchy> {
    if let Some(cached) = state.hierarchy.lock().await.get(alias) {
        match &cached.failure {
            None if cached.fetched.elapsed() < HIERARCHY_TTL => return Ok(cached.clone()),
            Some(why) if cached.fetched.elapsed() < HIERARCHY_FAILURE_TTL => {
                return Err(anyhow!("{why} (not asked again for a minute)"));
            }
            _ => {}
        }
    }
    let mut req = get_hierarchy::v1::Request::new(space_id.to_owned());
    req.max_depth = Some(1u32.into());
    req.limit = Some(50u32.into());
    let resp = match client.send(req).await {
        Ok(resp) => resp,
        Err(e) => {
            let why = format!("reading the space: {e}");
            state.hierarchy.lock().await.insert(
                alias.to_owned(),
                CachedHierarchy {
                    fetched: Instant::now(),
                    failure: Some(why.clone()),
                    name: None,
                    topic: None,
                    member_count: 0,
                    rooms: Vec::new(),
                },
            );
            return Err(anyhow!(why));
        }
    };
    let mut fresh = CachedHierarchy {
        fetched: Instant::now(),
        failure: None,
        name: None,
        topic: None,
        member_count: 0,
        rooms: Vec::new(),
    };
    for chunk in resp.rooms {
        let s = chunk.summary;
        if s.room_id == space_id {
            fresh.name = s.name.clone();
            fresh.topic = s.topic.clone();
            fresh.member_count = u64::from(s.num_joined_members);
            continue;
        }
        fresh.rooms.push(CommunityRoom {
            id: s.room_id.to_string(),
            name: s.name.clone().unwrap_or_else(|| s.room_id.to_string()),
            topic: s.topic.clone(),
            joined: false, // filled in by the caller from local state
            members: u64::from(s.num_joined_members),
        });
    }
    // A listing with no rooms is either a fresh space the server has not
    // caught up with or a wrong alias; ask again next time rather than
    // remembering it.
    if !fresh.rooms.is_empty() {
        state
            .hierarchy
            .lock()
            .await
            .insert(alias.to_owned(), fresh.clone());
    }
    Ok(fresh)
}

/// Everything the client shows about the community at once.
pub async fn status(
    client: &Client,
    state: &CommunityState,
    alias: &str,
    prefs: &Prefs,
) -> Result<CommunityStatus> {
    let mut out = CommunityStatus {
        alias: alias.to_owned(),
        exists: false,
        joined: false,
        space_id: None,
        name: None,
        topic: None,
        member_count: 0,
        rooms: Vec::new(),
        profile: None,
        dm_policy: prefs.dm_policy,
        joining: state.joining(),
    };
    let Some(id) = space_id(client, alias).await? else {
        return Ok(out);
    };
    out.exists = true;
    out.space_id = Some(id.to_string());
    let space = client.get_room(&id);
    out.joined = space
        .as_ref()
        .is_some_and(|r| r.state() == RoomState::Joined);
    match hierarchy(client, state, alias, &id).await {
        Ok(h) => {
            out.name = h.name;
            out.topic = h.topic;
            out.member_count = h.member_count;
            out.rooms = h.rooms;
            for room in out.rooms.iter_mut() {
                room.joined = RoomId::parse(&room.id)
                    .ok()
                    .and_then(|rid| client.get_room(&rid))
                    .is_some_and(|r| r.state() == RoomState::Joined);
            }
        }
        // Not fatal: a space that is not world-readable shows no detail
        // until joined.
        Err(e) => warn!("space hierarchy: {e:#}"),
    }
    if let (true, Some(space), Some(me)) = (out.joined, space, client.user_id()) {
        out.profile = read_profile(&space, me).await;
        if out.name.is_none() {
            out.name = space.name();
        }
        if out.member_count == 0 {
            out.member_count = space.joined_members_count();
        }
    }
    Ok(out)
}

/// Join the space — one request — and return. The rooms under it are
/// joined by [`join_rooms`] in the background, one at a time.
pub async fn join_space(client: &Client, state: &CommunityState, alias: &str) -> Result<Room> {
    let alias_id = alias_of(alias)?;
    let space = client
        .join_room_by_id_or_alias((&*alias_id).into(), &[])
        .await
        .context("joining the community space")?;
    state.forget(alias).await;
    info!(space = %space.room_id(), "joined the community space");
    Ok(space)
}

/// The wait a 429 asks for, if the error is one.
fn retry_after_of(err: &matrix_sdk::Error) -> Option<Duration> {
    use matrix_sdk::ruma::api::error::{ErrorKind, RetryAfter};
    let kind = err.as_client_api_error()?.error_kind()?;
    let ErrorKind::LimitExceeded(data) = kind else {
        return None;
    };
    let wait = match data.retry_after {
        Some(RetryAfter::Delay(d)) => d,
        Some(RetryAfter::DateTime(at)) => at
            .duration_since(std::time::SystemTime::now())
            .unwrap_or(Duration::from_secs(1)),
        None => Duration::from_secs(30),
    };
    Some(wait.min(MAX_RETRY_AFTER) + Duration::from_secs(1))
}

/// Join one room, waiting out rate limits the server asks for.
async fn join_patiently(client: &Client, room: &RoomId) -> Result<()> {
    for attempt in 1..=JOIN_ATTEMPTS {
        match client.join_room_by_id(room).await {
            Ok(_) => return Ok(()),
            Err(e) => match retry_after_of(&e) {
                Some(wait) if attempt < JOIN_ATTEMPTS => {
                    info!(%room, attempt, secs = wait.as_secs(), "rate limited; waiting before joining");
                    tokio::time::sleep(wait).await;
                }
                _ => return Err(e).context("joining a community room"),
            },
        }
    }
    Err(anyhow!(
        "gave up joining {room} after {JOIN_ATTEMPTS} attempts"
    ))
}

/// Join the space's rooms one after another, spaced out so the server's
/// join limit is never hit in normal use, announcing each as it lands.
/// Runs as a background task; `state.joining` counts what is left.
pub async fn join_rooms(
    client: Client,
    state: Arc<CommunityState>,
    alias: String,
    space_id: OwnedRoomId,
    events: tokio::sync::broadcast::Sender<crate::protocol::Event>,
) {
    let pending: Vec<OwnedRoomId> = match hierarchy(&client, &state, &alias, &space_id).await {
        Ok(h) => h
            .rooms
            .iter()
            .filter_map(|r| RoomId::parse(&r.id).ok())
            .filter(|id| {
                !client
                    .get_room(id)
                    .is_some_and(|r| r.state() == RoomState::Joined)
            })
            .collect(),
        Err(e) => {
            warn!("community rooms: {e:#}");
            Vec::new()
        }
    };
    state.joining.store(pending.len() as u32, Ordering::Relaxed);
    for (i, room) in pending.iter().enumerate() {
        if i > 0 {
            tokio::time::sleep(JOIN_SPACING).await;
        }
        match join_patiently(&client, room).await {
            Ok(()) => {
                info!(%room, "joined a community room");
                let _ = events.send(crate::protocol::Event::RoomsChanged);
            }
            Err(e) => warn!(%room, "{e:#}"),
        }
        state.joining.fetch_sub(1, Ordering::Relaxed);
    }
    state.forget(&alias).await;
    let _ = events.send(crate::protocol::Event::RoomsChanged);
}

/// Withdraw the card, leave the rooms, leave the space.
pub async fn leave(client: &Client, state: &CommunityState, alias: &str) -> Result<()> {
    state.stop_joiner().await;
    state.forget(alias).await;
    let Some(id) = space_id(client, alias).await? else {
        return Ok(());
    };
    let Some(space) = client.get_room(&id) else {
        return Ok(());
    };
    if space.state() == RoomState::Joined {
        // A room nobody is in can never be joined again; the last member
        // leaving would abandon the whole space.
        if space.joined_members_count() <= 1 {
            anyhow::bail!(
                "you are the only member; leaving would abandon the space and nobody could join it again"
            );
        }
        let _ = clear_profile(client, alias).await;
        for child in children(&space).await {
            if let Some(room) = client.get_room(&child)
                && room.state() == RoomState::Joined
            {
                let _ = room.leave().await;
            }
        }
        space.leave().await.context("leaving the space")?;
    }
    Ok(())
}

/// Room ids listed as the space's children.
async fn children(space: &Room) -> Vec<OwnedRoomId> {
    let mut out = Vec::new();
    if let Ok(events) = space.get_state_events(StateEventType::SpaceChild).await {
        for ev in events {
            use matrix_sdk::deserialized_responses::RawAnySyncOrStrippedState as R;
            let json = match &ev {
                R::Sync(raw) => raw.json().get().to_owned(),
                R::Stripped(raw) => raw.json().get().to_owned(),
            };
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&json)
                && v.get("content")
                    .and_then(|c| c.get("via"))
                    .is_some_and(|via| !via.as_array().is_none_or(|a| a.is_empty()))
                && let Some(key) = v.get("state_key").and_then(|k| k.as_str())
                && let Ok(id) = RoomId::parse(key)
            {
                out.push(id);
            }
        }
    }
    out
}

async fn joined_space(client: &Client, alias: &str) -> Result<Room> {
    let id = space_id(client, alias)
        .await?
        .ok_or_else(|| anyhow!("the community space does not exist"))?;
    let space = client
        .get_room(&id)
        .filter(|r| r.state() == RoomState::Joined)
        .ok_or_else(|| anyhow!("join the community first"))?;
    Ok(space)
}

/// Publish (or update) our card in the space.
pub async fn publish_profile(
    client: &Client,
    alias: &str,
    bio: String,
    open_to_dm: bool,
    theme: Option<String>,
) -> Result<Profile> {
    let space = joined_space(client, alias).await?;
    let me = client.user_id().ok_or_else(|| anyhow!("not signed in"))?;
    let member = space.get_member_no_sync(me).await.ok().flatten();
    let profile = Profile {
        user_id: me.to_string(),
        name: member
            .as_ref()
            .map(|m| m.name().to_owned())
            .unwrap_or_else(|| me.localpart().to_owned()),
        avatar: member
            .as_ref()
            .and_then(|m| m.avatar_url().map(|u| u.to_string())),
        bio: bio.trim().chars().take(280).collect(),
        open_to_dm,
        theme: theme.map(|t| t.trim().to_owned()).filter(|t| !t.is_empty()),
        updated: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0),
    };
    let content = serde_json::to_value(&profile)?;
    space
        .send_state_event_raw(PROFILE_TYPE, me.as_str(), content)
        .await
        .context("publishing the card")?;
    Ok(profile)
}

/// Withdraw our card: an empty content is how state is cleared in Matrix.
pub async fn clear_profile(client: &Client, alias: &str) -> Result<()> {
    let space = joined_space(client, alias).await?;
    let me = client.user_id().ok_or_else(|| anyhow!("not signed in"))?;
    space
        .send_state_event_raw(PROFILE_TYPE, me.as_str(), serde_json::json!({}))
        .await
        .context("withdrawing the card")?;
    Ok(())
}

async fn read_profile(space: &Room, user: &UserId) -> Option<Profile> {
    let raw = space
        .get_state_event(StateEventType::from(PROFILE_TYPE), user.as_str())
        .await
        .ok()
        .flatten()?;
    profile_from(&raw)
}

fn profile_from(
    ev: &matrix_sdk::deserialized_responses::RawAnySyncOrStrippedState,
) -> Option<Profile> {
    use matrix_sdk::deserialized_responses::RawAnySyncOrStrippedState as R;
    let json = match ev {
        R::Sync(raw) => raw.json().get().to_owned(),
        R::Stripped(raw) => raw.json().get().to_owned(),
    };
    let v: serde_json::Value = serde_json::from_str(&json).ok()?;
    let content = v.get("content")?;
    if content.as_object().is_none_or(|c| c.is_empty()) {
        return None;
    }
    let mut p: Profile = serde_json::from_value(content.clone()).ok()?;
    // Whatever was published, the card shows at most what the publisher may write.
    p.name = p.name.chars().take(128).collect();
    p.bio = p.bio.chars().take(280).collect();
    p.theme = p.theme.map(|t| t.chars().take(64).collect());
    // The state key is the authority on who this is.
    if let Some(key) = v.get("state_key").and_then(|k| k.as_str()) {
        p.user_id = key.to_owned();
    }
    Some(p)
}

/// Everyone who published a card, newest first.
pub async fn people(
    client: &Client,
    alias: &str,
    query: &str,
    limit: usize,
) -> Result<Vec<Profile>> {
    let space = joined_space(client, alias).await?;
    let events = space
        .get_state_events(StateEventType::from(PROFILE_TYPE))
        .await
        .context("reading the cards")?;
    let q = query.trim().to_lowercase();
    let mut out: Vec<Profile> = events
        .iter()
        .filter_map(profile_from)
        .filter(|p| {
            q.is_empty()
                || p.name.to_lowercase().contains(&q)
                || p.user_id.to_lowercase().contains(&q)
                || p.bio.to_lowercase().contains(&q)
                || p.theme
                    .as_deref()
                    .is_some_and(|t| t.to_lowercase().contains(&q))
        })
        .collect();
    // Freshen names and avatars from membership, which the member may have changed since.
    for p in out.iter_mut() {
        if let Ok(id) = UserId::parse(&p.user_id)
            && let Ok(Some(m)) = space.get_member_no_sync(&id).await
        {
            p.name = m.name().to_owned();
            p.avatar = m.avatar_url().map(|u| u.to_string());
        }
    }
    out.sort_by(|a, b| b.updated.cmp(&a.updated));
    out.truncate(limit.clamp(1, 500));
    Ok(out)
}

// ---------- blocking ----------

pub async fn ignore(client: &Client, user: &str) -> Result<()> {
    let user = UserId::parse(user).context("invalid user id")?;
    client
        .account()
        .ignore_user(&user)
        .await
        .context("blocking")?;
    Ok(())
}

pub async fn unignore(client: &Client, user: &str) -> Result<()> {
    let user = UserId::parse(user).context("invalid user id")?;
    client
        .account()
        .unignore_user(&user)
        .await
        .context("unblocking")?;
    Ok(())
}

pub async fn ignored(client: &Client) -> Result<Vec<String>> {
    let Some(raw) = client
        .account()
        .account_data::<IgnoredUserListEventContent>()
        .await
        .context("reading the block list")?
    else {
        return Ok(Vec::new());
    };
    let content = raw.deserialize().context("reading the block list")?;
    Ok(content
        .ignored_users
        .keys()
        .map(|u| u.to_string())
        .collect())
}

// ---------- DM policy ----------

/// Whether an invite to a direct chat from `inviter` is allowed under the
/// policy. Group invites are always allowed; the user sees those.
pub async fn invite_allowed(
    client: &Client,
    prefs: &Prefs,
    inviter: &UserId,
    direct: bool,
) -> bool {
    if !direct || prefs.dm_policy == DmPolicy::Anyone {
        return true;
    }
    if prefs.dm_policy == DmPolicy::Nobody {
        return false;
    }
    // Someone we already talk to is always fine.
    let shares_room = client
        .joined_rooms()
        .iter()
        .any(|r| r.get_member_no_sync_blocking(inviter));
    if shares_room {
        return true;
    }
    if prefs.dm_policy == DmPolicy::Community && !prefs.community.is_empty() {
        if let Ok(Some(id)) = space_id(client, &prefs.community).await
            && let Some(space) = client.get_room(&id)
            && let Ok(Some(m)) = space.get_member_no_sync(inviter).await
        {
            return m.membership()
                == &matrix_sdk::ruma::events::room::member::MembershipState::Join;
        }
    }
    false
}

/// Small helper: membership lookups are async, but a quick "is this user
/// in the room's known members" is enough here.
trait QuickMember {
    fn get_member_no_sync_blocking(&self, user: &UserId) -> bool;
}

impl QuickMember for Room {
    fn get_member_no_sync_blocking(&self, user: &UserId) -> bool {
        // Heroes and the direct-target list cover DMs and small rooms without
        // touching the store; larger rooms are not "contacts" anyway.
        self.direct_targets()
            .iter()
            .any(|t| t.as_str() == user.as_str())
            || self.clone_info().heroes().iter().any(|h| h.user_id == user)
    }
}

/// A space, public and listed, with a card type every member may write.
pub async fn create_space(
    client: &Client,
    name: &str,
    topic: Option<&str>,
    alias_local: Option<&str>,
) -> Result<Room> {
    use matrix_sdk::ruma::{
        api::client::room::{Visibility, create_room},
        events::room::power_levels::RoomPowerLevelsEventContent,
        room::RoomType,
    };
    let mut req = create_room::v3::Request::new();
    req.name = Some(name.to_owned());
    req.topic = topic.map(str::to_owned);
    req.preset = Some(create_room::v3::RoomPreset::PublicChat);
    req.visibility = Visibility::Public;
    req.room_alias_name = alias_local.map(str::to_owned);
    let mut creation = matrix_sdk::ruma::api::client::room::create_room::v3::CreationContent::new();
    creation.room_type = Some(RoomType::Space);
    req.creation_content = Some(matrix_sdk::ruma::serde::Raw::new(&creation)?);
    let mut pl = RoomPowerLevelsEventContent::new(
        &matrix_sdk::ruma::room_version_rules::AuthorizationRules::V11,
    );
    pl.events.insert(PROFILE_TYPE.into(), 0.into());
    req.power_level_content_override = Some(matrix_sdk::ruma::serde::Raw::new(&pl)?.cast());
    // World-readable, so the space's summary and rooms show before joining
    // (matrix.org refuses previews of anything else).
    use matrix_sdk::ruma::events::{
        EmptyStateKey, InitialStateEvent,
        room::history_visibility::{HistoryVisibility, RoomHistoryVisibilityEventContent},
    };
    req.initial_state = vec![
        InitialStateEvent::new(
            EmptyStateKey,
            RoomHistoryVisibilityEventContent::new(HistoryVisibility::WorldReadable),
        )
        .to_raw_any(),
    ];
    client.create_room(req).await.context("creating the space")
}

/// List `room` under `space` (and point the room back at the space).
pub async fn add_child(
    client: &Client,
    space_id: &RoomId,
    room_id: &RoomId,
    suggested: bool,
) -> Result<()> {
    use matrix_sdk::ruma::events::space::{
        child::SpaceChildEventContent, parent::SpaceParentEventContent,
    };
    let space = client
        .get_room(space_id)
        .ok_or_else(|| anyhow!("unknown space"))?;
    let room = client
        .get_room(room_id)
        .ok_or_else(|| anyhow!("unknown room"))?;
    let via = vec![
        space_id
            .server_name()
            .ok_or_else(|| anyhow!("space id without a server"))?
            .to_owned(),
    ];
    let mut child = SpaceChildEventContent::new(via.clone());
    child.suggested = suggested;
    space
        .send_state_event_for_key(room_id, child)
        .await
        .context("listing the room in the space")?;
    let mut parent = SpaceParentEventContent::new(via);
    parent.canonical = true;
    if let Err(e) = room.send_state_event_for_key(space_id, parent).await {
        warn!("setting the room's parent space: {e:#}");
    }
    Ok(())
}

/// Ids the server knows for a joined user list; kept for tests of the policy.
#[allow(dead_code)]
pub fn user_ids(list: &[String]) -> Vec<OwnedUserId> {
    list.iter().filter_map(|s| UserId::parse(s).ok()).collect()
}
