//! Wire format spoken over the Unix socket: one JSON object per line, both ways.
//!
//! Client → daemon: `{"id": <any>, "cmd": "<name>", ...fields}`
//! Daemon → client: `{"id": <same>, "ok": true, "result": {...}}`
//!                  `{"id": <same>, "ok": false, "error": "<text>"}`
//! Daemon → client (unsolicited): `{"event": "<name>", ...fields}`

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Deserialize)]
pub struct Request {
    #[serde(default)]
    pub id: Value,
    #[serde(flatten)]
    pub command: Command,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Command {
    /// Daemon and session state.
    Status,
    /// Password login. The password is used once and dropped; only the
    /// resulting access token and store passphrase are persisted (mode 0600).
    Login {
        homeserver: String,
        username: String,
        password: String,
    },
    /// Browser sign-in (OAuth 2.0 / OIDC, e.g. matrix.org accounts made with
    /// Google or GitHub). Returns `{url}` to open; login completes in the
    /// background and is announced by a `state` event.
    LoginOauth {
        homeserver: String,
    },
    /// Abandon a browser sign-in that has not completed.
    LoginCancel,
    /// Invalidate the access token and wipe the local store.
    Logout,
    /// Joined rooms with names, encryption flag and unread counts.
    Rooms,
    /// A page of messages in a room, oldest first. Without `before` it is
    /// the most recent page; pass the previous page's `next` to go further
    /// back. `next` is absent when history is exhausted.
    Timeline {
        room: String,
        #[serde(default = "default_limit")]
        limit: u32,
        #[serde(default)]
        before: Option<String>,
    },
    /// Send a plain-text message, optionally as a reply. Encrypted
    /// automatically in encrypted rooms.
    Send {
        room: String,
        body: String,
        #[serde(default)]
        reply_to: Option<String>,
    },
    /// Replace the text of one of our own messages.
    Edit {
        room: String,
        event_id: String,
        body: String,
    },
    /// Remove one of our own messages (a redaction).
    Delete {
        room: String,
        event_id: String,
    },
    /// Add an emoji reaction to a message.
    React {
        room: String,
        event_id: String,
        key: String,
    },
    /// Remove our reaction (its own event id, from the aggregate).
    Unreact {
        room: String,
        reaction_id: String,
    },
    /// Tell the room we are typing (or stopped).
    Typing {
        room: String,
        typing: bool,
    },
    /// Details for a room's info panel.
    RoomDetails {
        room: String,
    },
    /// Joined members, optionally filtered by name, most powerful first.
    Members {
        room: String,
        #[serde(default)]
        query: String,
        #[serde(default = "default_members_limit")]
        limit: u32,
    },
    /// Fetch an avatar (a user's or a room's mxc:// URL) into the media cache
    /// as a small square; returns `{path}`.
    /// Cached thumbnail of an mxc URL; `size` (px, default 96, max 640) picks
    /// the server-side thumbnail edge. Used for avatars and preview images.
    Avatar {
        url: String,
        #[serde(default)]
        size: Option<u32>,
    },
    /// Invite a user to a room.
    Invite {
        room: String,
        user: String,
    },
    /// Remove a user from a room (they may rejoin).
    Kick {
        room: String,
        user: String,
        #[serde(default)]
        reason: Option<String>,
    },
    /// Ban a user from a room.
    Ban {
        room: String,
        user: String,
        #[serde(default)]
        reason: Option<String>,
    },
    /// Rename a room.
    SetName {
        room: String,
        name: String,
    },
    /// Change a room's topic.
    SetTopic {
        room: String,
        topic: String,
    },
    /// Per-room notification mode: all | mentions | mute | default.
    SetNotificationMode {
        room: String,
        mode: String,
    },
    /// Star / unstar a room.
    SetFavourite {
        room: String,
        favourite: bool,
    },
    /// Joined spaces with the rooms they contain.
    Spaces,
    /// Open Graph preview of a link, fetched by the homeserver.
    Preview {
        url: String,
    },
    /// Search messages: the server for unencrypted rooms, a bounded local
    /// scan for encrypted ones. `room` limits to one room.
    Search {
        query: String,
        #[serde(default)]
        room: Option<String>,
        #[serde(default = "default_search_results")]
        limit: u32,
    },
    /// Mark the room read up to the given event: public read receipt plus
    /// the fully-read marker, so every client and device agrees.
    MarkRead {
        room: String,
        event_id: String,
    },
    /// Search a server's public room directory (our own homeserver unless
    /// `server` names another).
    SearchRooms {
        query: String,
        #[serde(default)]
        server: Option<String>,
        #[serde(default = "default_search_limit")]
        limit: u32,
    },
    /// Join a room by `#alias:server` or `!id:server`.
    Join {
        room: String,
    },
    /// Search the user directory.
    SearchUsers {
        query: String,
        #[serde(default = "default_search_limit")]
        limit: u32,
    },
    /// Open a direct chat with a user: the existing DM if there is one,
    /// otherwise a new encrypted one.
    Dm {
        user: String,
    },
    /// Create a room. Encrypted and private unless told otherwise.
    CreateRoom {
        name: String,
        #[serde(default)]
        topic: Option<String>,
        #[serde(default = "default_true")]
        encrypted: bool,
        #[serde(default = "default_true")]
        private: bool,
    },
    /// Pending invitations.
    Invites,
    /// Cross-signing / backup / recovery state and our other devices.
    VerificationStatus,
    /// Ask our other devices to verify this one (SAS emoji). Progress
    /// arrives as `verification` events keyed by `flow_id`.
    VerifyRequest,
    /// Accept an incoming request (from another of our devices or a user).
    VerifyAccept {
        flow_id: String,
    },
    /// The emoji matched on both sides.
    VerifyConfirm {
        flow_id: String,
    },
    /// They did not match, or the user gave up.
    VerifyCancel {
        flow_id: String,
    },
    /// Restore cross-signing and backup secrets with the recovery key.
    Recover {
        key: String,
    },
    /// First device: set up cross-signing, secret storage and backup.
    /// Returns the recovery key, shown once.
    SetupRecovery,
    /// Replace the recovery key with a new one (the old one stops working).
    /// Returns the new key, shown once.
    ResetRecoveryKey,
    /// Fetch (and decrypt) an attachment or its thumbnail into the media
    /// cache. Returns `{path, mime}`.
    Download {
        room: String,
        event_id: String,
        #[serde(default)]
        thumbnail: bool,
    },
    /// Upload a local file as an attachment (encrypted in encrypted rooms).
    SendFile {
        room: String,
        path: String,
        #[serde(default)]
        caption: Option<String>,
    },
    AcceptInvite {
        room: String,
    },
    DeclineInvite {
        room: String,
    },
    Leave {
        room: String,
    },
}

fn default_limit() -> u32 {
    50
}

fn default_search_limit() -> u32 {
    20
}

fn default_true() -> bool {
    true
}

fn default_members_limit() -> u32 {
    200
}

fn default_search_results() -> u32 {
    50
}

#[derive(Debug, Serialize)]
pub struct Response {
    pub id: Value,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Response {
    pub fn ok(id: Value, result: Value) -> Self {
        Self {
            id,
            ok: true,
            result: Some(result),
            error: None,
        }
    }
    pub fn err(id: Value, error: impl ToString) -> Self {
        Self {
            id,
            ok: false,
            result: None,
            error: Some(error.to_string()),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    /// Session state changed (login, logout, sync started/stopped, error).
    State(Status),
    /// A message arrived in a joined room.
    Message(Message),
    /// We were invited to a room.
    Invite(InviteInfo),
    /// Our own membership changed somewhere (joined, left, kicked): the
    /// room list should be fetched again.
    RoomsChanged,
    /// One of the messages in a room was edited; replace its text.
    MessageEdited(MessageEdit),
    /// Someone reacted to a message.
    Reaction(ReactionEvent),
    /// A message or reaction was removed.
    Redacted(Redaction),
    /// Who is typing in a room right now (empty when nobody).
    Typing(TypingInfo),
    /// Read receipts from others moved.
    Receipt(ReceiptInfo),
    /// A verification flow changed state.
    Verification(VerificationInfo),
    /// Cross-signing or backup state changed; fetch verification_status.
    VerificationStatusChanged,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerificationInfo {
    pub flow_id: String,
    pub other_user: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub other_device: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub other_device_name: Option<String>,
    /// Whether we started it.
    pub outgoing: bool,
    /// requested | ready | emoji | confirmed | done | cancelled
    pub state: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub emojis: Vec<EmojiInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EmojiInfo {
    pub symbol: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerificationStatus {
    /// This device is signed by our own cross-signing identity.
    pub device_verified: bool,
    /// The account has a cross-signing identity at all.
    pub cross_signing: bool,
    /// unknown | enabled | disabled | incomplete
    pub recovery: String,
    /// unknown | enabled | disabled | creating | enabling | resuming | downloading
    pub backup: String,
    pub device_id: String,
    pub other_devices: Vec<DeviceInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeviceInfo {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct InviteInfo {
    pub room: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inviter: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inviter_name: Option<String>,
    pub direct: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DirectoryRoom {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    pub members: u64,
    pub joined: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DirectoryUser {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub version: &'static str,
    pub logged_in: bool,
    pub syncing: bool,
    /// A browser sign-in is waiting for the redirect.
    pub pending_login: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub homeserver: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RoomInfo {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    pub encrypted: bool,
    pub direct: bool,
    /// Room avatar (for a DM, the other person's), as an mxc:// URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar: Option<String>,
    /// Messages after our read receipt, as counted locally: drops as you read.
    pub unread: u64,
    /// Mentions / keyword hits among those.
    pub highlights: u64,
    /// What the server would push about (its notification count).
    pub notifications: u64,
    /// all | mentions | mute — how this room should notify.
    pub notification_mode: String,
    pub favourite: bool,
    pub low_priority: bool,
    /// Milliseconds of the latest activity the server told us about.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_activity: Option<u64>,
    /// Our read receipt / fully-read marker, if we have one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_marker: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TimelinePage {
    pub messages: Vec<Message>,
    /// Cursor for the page before this one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Message {
    pub room: String,
    pub event_id: String,
    pub sender: String,
    pub sender_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_avatar: Option<String>,
    pub body: String,
    /// The HTML rendering when the sender provided one (formatted_body,
    /// org.matrix.custom.html); clients fall back to `body`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub html: Option<String>,
    pub msgtype: String,
    /// Milliseconds since the Unix epoch, as reported by the origin server.
    pub ts: u64,
    /// True when this message arrived encrypted and was decrypted locally.
    pub encrypted: bool,
    /// Present for m.image / m.file / m.video / m.audio.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachment: Option<Attachment>,
    /// The message this one replies to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<ReplyPreview>,
    /// True when the body shown is a later edit of the original.
    pub edited: bool,
    /// Emoji reactions, aggregated.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub reactions: Vec<Reaction>,
    /// Others whose read receipt points at this message.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub read_by: Vec<UserRef>,
    /// True when the message was deleted (redacted).
    pub deleted: bool,
    /// What the account's push rules say about this event: whether it
    /// should notify at all, and whether it is a highlight (mention,
    /// keyword). Live messages only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notify: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub highlight: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Reaction {
    pub key: String,
    pub count: u32,
    pub senders: Vec<ReactionSender>,
    /// Our own reaction's event id, so it can be removed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mine: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReactionSender {
    pub id: String,
    pub name: String,
    /// That user's reaction event, so a redaction of it can be matched.
    pub reaction_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserRef {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReactionEvent {
    pub room: String,
    /// The message reacted to.
    pub event_id: String,
    pub key: String,
    pub sender: UserRef,
    /// The reaction event itself (needed to remove it).
    pub reaction_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Redaction {
    pub room: String,
    /// The event that was removed: a message or a reaction.
    pub event_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TypingInfo {
    pub room: String,
    pub users: Vec<UserRef>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReceiptInfo {
    pub room: String,
    /// Users whose read receipt moved, and the event it now points at.
    pub event_id: String,
    pub users: Vec<UserRef>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LinkPreview {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site: Option<String>,
    /// mxc:// of the preview image, fetchable with `avatar`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchHit {
    pub room: String,
    pub room_name: String,
    pub event_id: String,
    pub sender: String,
    pub sender_name: String,
    pub body: String,
    pub ts: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchResults {
    pub hits: Vec<SearchHit>,
    /// Encrypted rooms searched locally, and how far back that went.
    pub scanned_rooms: u32,
    pub scanned_messages: u32,
    pub server_rooms: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct SpaceInfo {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar: Option<String>,
    /// Room ids this space lists as children (rooms and sub-spaces).
    pub children: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RoomDetails {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    pub encrypted: bool,
    pub direct: bool,
    /// public | invite | knock | restricted | other
    pub join_rule: String,
    pub member_count: u64,
    /// What we may do here.
    pub can_invite: bool,
    pub can_kick: bool,
    pub can_ban: bool,
    pub can_set_name: bool,
    pub can_set_topic: bool,
    pub can_redact_other: bool,
    /// all | mentions | mute; `custom` is false when it is the account default.
    pub notification_mode: String,
    pub notification_custom: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct MemberInfo {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar: Option<String>,
    pub power: i64,
    /// admin | moderator | member
    pub role: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReplyPreview {
    pub event_id: String,
    pub sender: String,
    pub sender_name: String,
    /// One line of the original, trimmed.
    pub body: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MessageEdit {
    pub room: String,
    /// The message that was edited.
    pub event_id: String,
    pub body: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub html: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Attachment {
    /// image | file | video | audio
    pub kind: String,
    pub name: String,
    /// The sender's caption, when the body is more than the filename.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caption: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub width: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: Option<u64>,
    pub has_thumbnail: bool,
}
