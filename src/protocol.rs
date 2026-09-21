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
    LoginOauth { homeserver: String },
    /// Abandon a browser sign-in that has not completed.
    LoginCancel,
    /// Invalidate the access token and wipe the local store.
    Logout,
    /// Joined rooms with names, encryption flag and unread counts.
    Rooms,
    /// Most recent messages in a room, oldest first.
    Timeline {
        room: String,
        #[serde(default = "default_limit")]
        limit: u32,
    },
    /// Send a plain-text message. Encrypted automatically in encrypted rooms.
    Send { room: String, body: String },
    /// Send a read receipt up to the given event.
    MarkRead { room: String, event_id: String },
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
    Join { room: String },
    /// Search the user directory.
    SearchUsers {
        query: String,
        #[serde(default = "default_search_limit")]
        limit: u32,
    },
    /// Open a direct chat with a user: the existing DM if there is one,
    /// otherwise a new encrypted one.
    Dm { user: String },
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
    VerifyAccept { flow_id: String },
    /// The emoji matched on both sides.
    VerifyConfirm { flow_id: String },
    /// They did not match, or the user gave up.
    VerifyCancel { flow_id: String },
    /// Restore cross-signing and backup secrets with the recovery key.
    Recover { key: String },
    /// First device: set up cross-signing, secret storage and backup.
    /// Returns the recovery key, shown once.
    SetupRecovery,
    /// Replace the recovery key with a new one (the old one stops working).
    /// Returns the new key, shown once.
    ResetRecoveryKey,
    AcceptInvite { room: String },
    DeclineInvite { room: String },
    Leave { room: String },
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
        Self { id, ok: true, result: Some(result), error: None }
    }
    pub fn err(id: Value, error: impl ToString) -> Self {
        Self { id, ok: false, result: None, error: Some(error.to_string()) }
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
    pub unread: u64,
    pub highlights: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Message {
    pub room: String,
    pub event_id: String,
    pub sender: String,
    pub sender_name: String,
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
}
