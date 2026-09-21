//! Recognising bridged rooms and users. A bridge (mautrix-*, the matrix-
//! appservice-* family, Beeper's hosted ones) mirrors another network's
//! chats into ordinary Matrix rooms, with the other side's people as
//! "puppet" users. Nothing here talks to a bridge; it only reads what one
//! leaves behind: the `m.bridge` room state (MSC2346, also seen under its
//! draft name `uk.half-shot.bridge`), the bridge bot's membership, and the
//! puppet user-id patterns.

use matrix_sdk::{Room, ruma::UserId};
use serde::Serialize;

/// What a bridged room is bridged to.
#[derive(Debug, Clone, Serialize)]
pub struct BridgeInfo {
    /// Protocol id: `whatsapp`, `telegram`, `signal`, `discord`, …
    pub protocol: String,
    /// Human name for it: "WhatsApp".
    pub name: String,
    /// The bridge software, when the state says: "mautrix-whatsapp".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bridge: Option<String>,
    /// The bridge bot to talk to for login/logout.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bot: Option<String>,
    /// The channel's name on the other side, when given.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
}

/// Puppet/bot localpart prefixes and the protocol they belong to, most
/// specific first. Covers mautrix, matrix-appservice-* and Beeper naming.
const PREFIXES: &[(&str, &str)] = &[
    ("whatsapp", "whatsapp"),
    ("telegram", "telegram"),
    ("signal", "signal"),
    ("discord", "discord"),
    ("slack", "slack"),
    ("instagram", "instagram"),
    ("facebook", "facebook"),
    ("messenger", "facebook"),
    ("imessage", "imessage"),
    ("googlechat", "googlechat"),
    ("gchat", "googlechat"),
    ("linkedin", "linkedin"),
    ("twitter", "twitter"),
    ("xmpp", "xmpp"),
    ("irc", "irc"),
    ("sms", "sms"),
    ("gmessages", "sms"),
    ("bluesky", "bluesky"),
    ("meta", "facebook"),
];

/// Display name for a protocol id.
pub fn display_name(protocol: &str) -> String {
    match protocol {
        "whatsapp" => "WhatsApp",
        "telegram" => "Telegram",
        "signal" => "Signal",
        "discord" => "Discord",
        "slack" => "Slack",
        "instagram" => "Instagram",
        "facebook" => "Messenger",
        "imessage" => "iMessage",
        "googlechat" => "Google Chat",
        "linkedin" => "LinkedIn",
        "twitter" => "X",
        "xmpp" => "XMPP",
        "irc" => "IRC",
        "sms" => "SMS",
        "bluesky" => "Bluesky",
        other => return capitalise(other),
    }
    .to_owned()
}

fn capitalise(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

/// `whatsapp_4915551234` / `_discord_1234` / `whatsappbot` → the protocol
/// id; `None` for an ordinary user. Bots and puppets both match: the bot
/// is `<protocol>bot`, puppets are `<protocol>_<id>` (optionally with a
/// leading underscore, as matrix-appservice-* do).
pub fn protocol_of_user(user_id: &UserId) -> Option<&'static str> {
    let local = user_id
        .localpart()
        .trim_start_matches('_')
        .to_ascii_lowercase();
    PREFIXES.iter().find_map(|(prefix, protocol)| {
        let rest = local.strip_prefix(prefix)?;
        if rest == "bot" || rest.starts_with('_') {
            Some(*protocol)
        } else {
            None
        }
    })
}

/// The user id looks like a bridge bot.
pub fn is_bridge_bot(user_id: &UserId) -> bool {
    let local = user_id
        .localpart()
        .trim_start_matches('_')
        .to_ascii_lowercase();
    PREFIXES
        .iter()
        .any(|(prefix, _)| local == format!("{prefix}bot"))
}

/// What a room is bridged to, from its `m.bridge` state first; else from
/// a bridge bot or puppets among its members when the room is small
/// enough to look (bridged chats are DMs and small groups).
pub async fn detect(room: &Room) -> Option<BridgeInfo> {
    use matrix_sdk::ruma::events::StateEventType;
    for kind in ["m.bridge", "uk.half-shot.bridge"] {
        let Ok(events) = room.get_state_events(StateEventType::from(kind)).await else {
            continue;
        };
        for ev in events {
            use matrix_sdk::deserialized_responses::RawAnySyncOrStrippedState as R;
            let json = match &ev {
                R::Sync(raw) => raw.json().get().to_owned(),
                R::Stripped(raw) => raw.json().get().to_owned(),
            };
            let Ok(raw) = serde_json::from_str::<serde_json::Value>(&json) else {
                continue;
            };
            let content = raw.get("content")?;
            // An emptied event means the bridge was removed.
            if content.as_object().is_none_or(|c| c.is_empty()) {
                continue;
            }
            let protocol = content.get("protocol");
            let id = protocol
                .and_then(|p| p.get("id"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_ascii_lowercase())
                .or_else(|| {
                    // No protocol block: guess from the bot's name.
                    content
                        .get("bridgebot")
                        .and_then(|b| b.as_str())
                        .and_then(|b| UserId::parse(b).ok())
                        .and_then(|b: matrix_sdk::ruma::OwnedUserId| {
                            protocol_of_user(&b).map(|p| p.to_owned())
                        })
                })?;
            let name = protocol
                .and_then(|p| p.get("displayname"))
                .and_then(|v| v.as_str())
                .map(str::to_owned)
                .unwrap_or_else(|| display_name(&id));
            let text = |k: &str| {
                content
                    .get(k)
                    .and_then(|v| v.get("displayname").or(v.get("id")))
                    .and_then(|v| v.as_str())
                    .map(str::to_owned)
            };
            return Some(BridgeInfo {
                protocol: id,
                name,
                bridge: raw
                    .get("state_key")
                    .and_then(|v| v.as_str())
                    .and_then(|k| k.split("://").next())
                    .map(|k| k.rsplit('.').next().unwrap_or(k).to_owned())
                    .filter(|k| !k.is_empty()),
                bot: content
                    .get("bridgebot")
                    .and_then(|v| v.as_str())
                    .map(str::to_owned),
                channel: text("channel"),
            });
        }
    }

    // No state: look for a bot or puppets among a small membership.
    if room.joined_members_count() > 64 {
        return None;
    }
    let members = room
        .members_no_sync(matrix_sdk::RoomMemberships::JOIN)
        .await
        .ok()?;
    let mut bot = None;
    let mut protocol = None;
    for m in &members {
        if let Some(p) = protocol_of_user(m.user_id()) {
            protocol.get_or_insert(p);
            if is_bridge_bot(m.user_id()) {
                bot = Some(m.user_id().to_string());
            }
        }
    }
    let protocol = protocol?;
    Some(BridgeInfo {
        protocol: protocol.to_owned(),
        name: display_name(protocol),
        bridge: None,
        bot,
        channel: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use matrix_sdk::ruma::user_id;

    #[test]
    fn puppets_and_bots() {
        assert_eq!(
            protocol_of_user(user_id!("@whatsapp_4915551234:beeper.local")),
            Some("whatsapp")
        );
        assert_eq!(
            protocol_of_user(user_id!("@_discord_1234:example.org")),
            Some("discord")
        );
        assert_eq!(
            protocol_of_user(user_id!("@telegrambot:example.org")),
            Some("telegram")
        );
        assert_eq!(
            protocol_of_user(user_id!("@signal_uuid:example.org")),
            Some("signal")
        );
        assert_eq!(protocol_of_user(user_id!("@alice:example.org")), None);
        // A real person whose name starts like a protocol is not a puppet.
        assert_eq!(protocol_of_user(user_id!("@slacker:example.org")), None);
        assert!(is_bridge_bot(user_id!("@whatsappbot:beeper.local")));
        assert!(!is_bridge_bot(user_id!("@whatsapp_1:beeper.local")));
        assert_eq!(display_name("whatsapp"), "WhatsApp");
        assert_eq!(display_name("matterbridge"), "Matterbridge");
    }
}
