# omarchy-yapperd

The daemon behind [Yapper](https://github.com/marcho78/omarchy-yapper),
an end-to-end encrypted Matrix chat that lives in the Omarchy bar.

It owns the Matrix session, the encryption keys and the sync loop, and talks
to the shell plugin over a local Unix socket. The plugin — QML running inside
`omarchy-shell` — never sees key material.

End-to-end encryption is [matrix-rust-sdk](https://github.com/matrix-org/matrix-rust-sdk)
(Olm/Megolm via [vodozemac](https://github.com/matrix-org/vodozemac)), the
same stack as Element X. This daemon adds no cryptography of its own.

```
┌──────────────────────────┐   JSON lines    ┌──────────────────────┐   HTTPS    ┌────────────┐
│ omarchy-shell            │  over a 0600    │ omarchy-yapperd        │  (Matrix   │ homeserver │
│  └ marcho78.yapper (QML) │◄──────────────►│  matrix-rust-sdk     │◄─────────►│            │
│    renders, forwards     │  Unix socket    │  keys, store, sync   │  client-   │ sees only  │
│    what you type         │                 │                      │  server)   │ ciphertext │
└──────────────────────────┘                 └──────────────────────┘            └────────────┘
```

## Install

No binaries are shipped. You build it from this source with `makepkg`:

```bash
git clone https://github.com/marcho78/omarchy-yapperd && cd omarchy-yapperd && git checkout "$(git tag -l 'v*' --sort=-v:refname | head -1)" && cd packaging && makepkg -si
```

`makepkg -s` installs `cargo` from the Arch repos if it is missing, builds the
daemon (several minutes the first time — matrix-rust-sdk is large), and
`-i` installs the resulting pacman package. The package contains the binary,
a systemd user unit, this README and the license; it depends only on
`gcc-libs`, `glibc` and `sqlite`.

The Yapper plugin starts the daemon on demand. To run it at login instead:

```bash
systemctl --user enable --now omarchy-yapperd
```

| | |
|---|---|
| Update | `git fetch --tags && git checkout "$(git tag -l 'v*' --sort=-v:refname | head -1)" && cd packaging && makepkg -si` — or press Update in Yapper |
| Remove | `pacman -R omarchy-yapperd`, then `rm -rf ~/.local/share/omarchy-yapperd` to drop the session and keys |
| Logs | `journalctl --user -u omarchy-yapperd -f` |

Why not the AUR? It is a distribution channel, not a trust mechanism; the
`PKGBUILD` here does exactly what an AUR helper would do, minus the lookup. If
the package appears in the AUR or the Omarchy package repository later, the
same `PKGBUILD` ships there.

## Security model

**What the daemon protects:** message content. Everything is encrypted on this
machine before it reaches the homeserver, which stores and relays ciphertext.

**What it does not hide:** metadata. The homeserver knows your account, who
you talk to, when, and in which rooms. That is inherent to Matrix.

**On disk**, under `~/.local/share/omarchy-yapperd/` (mode 0700):

| File | Mode | Contents |
|---|---|---|
| `session.json` | 0600 | homeserver, store path, sync token, and where the secrets are (`"secrets": "keyring"` or `"file"`) |
| `store-<random>/` | 0700 | the SDK's SQLite store: room state, message cache, Olm/Megolm keys — encrypted with a random passphrase |
| your keyring | — | one item, *Yapper Matrix session (@you:server)*: the store passphrase and the access/refresh tokens |

The secrets go to the desktop keyring (Secret Service, `org.freedesktop.secrets`
— gnome-keyring on Omarchy), unlocked with your login session like any other
app's. With no keyring reachable they stay inline in `session.json` and
`status` reports `"secrets": "file"`; the daemon tries the keyring again on
every start and moves them when it can. A session saved before the keyring
existed is migrated the same way. If the keyring is locked at startup the
session is retried quietly in the background; `retry_session` asks for the
unlock prompt and `forget_session` discards a session that cannot be opened.

Your password is used once for `login` and dropped. `logout` revokes the
token on the server and deletes the file, the store and the keyring item.

**On the socket** (`$XDG_RUNTIME_DIR/omarchy-yapper.sock`):

* created with mode 0600 under a 0077 umask;
* every connection is checked with `SO_PEERCRED` and refused unless the peer
  uid is the daemon's own;
* the password crosses it exactly once, inside the `login` request.

**In the process:** a single daemon per user session; a second instance
refuses to start while the first answers on the socket. The unit runs with
`NoNewPrivileges`, `PrivateTmp` and `ProtectSystem=full`.

**Verification.** `setup_recovery` creates the account's cross-signing
identity (signing this device), secret storage and key backup, and returns
the recovery key once. `verify_request` runs SAS emoji verification against
another of the user's devices; incoming requests are announced and never
auto-accepted. `recover` restores the secrets on a new device from the key.

The sync loop keeps going through network loss: a failed sync backs off
(2 s doubling to 60 s) and retries with the same token; `status` reports
`syncing: false` and `error: "Reconnecting… (…)"` meanwhile, and clears
them when a sync succeeds. Sends use their own requests and keep working.

## Socket protocol

One JSON object per line in each direction. Requests carry any `id`, which
the response echoes.

| `cmd` | fields | result |
|---|---|---|
| `status` | | `{version, logged_in, syncing, pending_login, user_id?, homeserver?, error?, secrets?, saved_session}` — `secrets` is `keyring` or `file`; `saved_session` means a session exists but is not open yet |
| `login` | `homeserver`, `username`, `password` | status |
| `retry_session` | | status — open the saved session again, unlocking the keyring (shows the desktop prompt) |
| `forget_session` | | status — discard a saved session that cannot be opened, with its store and keyring item |
| `logout` | | status |
| `rooms` | | `[{id, name, topic?, encrypted, direct, unread, highlights, notifications, read_marker?}]`, unread first — `unread` is the local count since our receipt, `notifications` the server's |
| `timeline` | `room`, `limit` (default 50, max 200), `before?` | `{messages, next?}` — oldest first; pass `next` as `before` for the page before; no `next` at the start of history. Served from the SDK's event cache (persisted across restarts): opening a room is a local read, and only history never seen goes to the server |
| `send` | `room`, `body` (CommonMark; markup becomes `formatted_body`), `reply_to?`, `thread?` (root event id: send into that thread; with `reply_to`, a reply within it) | `{event_id}` |
| `thread` | `room`, `root`, `limit`, `before?` | `{messages, next?}` — the root first (on the last page), then replies oldest first, from the SDK's thread cache; same paging as `timeline` |
| `edit` | `room`, `event_id`, `body` | `{event_id}` — replaces one of our messages |
| `delete` | `room`, `event_id` | `{}` — redacts one of our messages |
| `react` / `unreact` | `room`, `event_id`, `key` / `room`, `reaction_id` | `{reaction_id}` / `{}` |
| `typing` | `room`, `typing` | `{}` |
| `room_details` | `room` | `{id, name, topic?, avatar?, alias?, encrypted, direct, join_rule, member_count, can_invite, can_kick, can_ban, can_set_name, can_set_topic, can_redact_other}` |
| `members` | `room`, `query?`, `limit` | `[{id, name, avatar?, power, role}]`, most powerful first |
| `avatar` | `url` (mxc), `size?` (px, default 96, max 640) | `{path}` — square thumbnail in `~/.cache/omarchy-yapper/avatars/` |
| `invite` / `kick` / `ban` | `room`, `user`, `reason?` | `{}` |
| `set_name` / `set_topic` | `room`, `name` / `topic` | `{}` |
| `set_notification_mode` | `room`, `mode` (all, mentions, mute, default) | room details |
| `set_favourite` | `room`, `favourite` | `{}` |
| `spaces` | | `[{id, name, avatar?, children}]` — joined spaces (excluded from `rooms`) |
| `search` | `query`, `room?`, `limit` | `{hits: [{room, room_name, event_id, sender, sender_name, body, ts}], server_rooms, scanned_rooms, scanned_messages}` — server search for unencrypted rooms, a bounded local scan of decrypted history for encrypted ones |
| `preview` | `url` (http/https) | `{url, title?, description?, site?, image?}` — Open Graph data fetched by the homeserver (`image` is an mxc for `avatar`) |
| `explore` | `query?`, `server?`, `limit` (default 30, max 100), `since?` | `{server, rooms: [{id, name, alias?, topic?, avatar?, members, joined}], next?, total?}` — one page of a public room directory, most joined first; an empty query lists everything; pass `next` as `since` for the following page |
| `community_status` | `alias` | `{alias, exists, joined, space_id?, name?, topic?, member_count, rooms: [{id, name, topic?, joined, members}], profile?, dm_policy, joining}` — the space's listing is cached for 5 minutes (a refusal for 1); `joining` counts rooms the background joiner still has to join |
| `community_join` | `alias` | status — joins the space (one request) and returns; the rooms under it are joined one at a time in the background, 5 s apart, honouring the server's `retry_after` on a 429 |
| `community_leave` | `alias` | `{}` — withdraws the card, leaves the rooms and the space; refused when you are the space's only member (an empty room can never be joined again) |
| `publish_profile` | `alias`, `bio?`, `open_to_dm?`, `theme?` | the card — an `org.omarchy.profile` state event keyed on your user id in the space; only you can write it |
| `clear_profile` | `alias` | `{}` — withdraws the card |
| `people` | `alias`, `query?`, `limit` | `[{user_id, name, avatar?, bio, open_to_dm, theme?, updated}]` — members who published a card, newest first |
| `ignore` / `unignore` | `user` | `{}` — the account's ignore list (`m.ignored_user_list`), honoured by every client |
| `ignored` | — | `[user_id]` |
| `set_dm_policy` | `policy` (`anyone` \| `community` \| `contacts` \| `nobody`), `community?` (space alias) | the saved prefs — persisted in `<data_dir>/prefs.json` and enforced on incoming direct-chat invites even while the shell is closed |
| `create_space` | `name`, `topic?`, `alias?` | `{id}` — a public, world-readable space whose members may publish cards |
| `add_space_child` | `space`, `room`, `suggested?` | `{}` — lists a room under a space |
| `mark_read` | `room`, `event_id`, `thread?` (root id: a threaded receipt for that thread instead of the room's marker) | `{}` |
| `search_rooms` | `query`, `server?`, `limit` | `[{id, name, alias?, topic?, members, joined}]` |
| `join` | `room` (alias or id) | room info |
| `search_users` | `query`, `limit` | `[{id, name?}]` |
| `dm` | `user` | room info (existing DM or a new encrypted one) |
| `create_room` | `name`, `topic?`, `encrypted`, `private` | room info |
| `invites` | | `[{room, name, inviter?, inviter_name?, direct}]` |
| `accept_invite` / `decline_invite` / `leave` | `room` | |
| `verification_status` | | `{device_verified, cross_signing, recovery, backup, device_id, other_devices}` |
| `verify_request` | | `{flow_id}` — asks our other devices; progress as `verification` events |
| `verify_accept` / `verify_confirm` / `verify_cancel` | `flow_id` | |
| `recover` | `key` | verification status |
| `setup_recovery` | | `{recovery_key}` — first device: cross-signing, secret storage, backup |
| `reset_recovery_key` | | `{recovery_key}` — the old key stops working |
| `download` | `room`, `event_id`, `thumbnail?` | `{path, mime}` — decrypted into `~/.cache/omarchy-yapper/media/` (0600) |
| `send_file` | `room`, `path`, `caption?` | `{event_id}` — encrypted in encrypted rooms; images carry their dimensions |
| `send_voice` | `room`, `path` (a 16-bit PCM WAV, e.g. from `pw-record --format=s16`) | `{event_id}` — loudness-normalised to speech level and encoded to Ogg/Opus with ffmpeg (the WAV is sent as-is without it), sent as an MSC3245 voice message with duration and a 100-point waveform; the file is deleted afterwards |

Responses: `{"id":…, "ok":true, "result":…}` or `{"id":…, "ok":false, "error":"…"}`.

A `message` is `{room, event_id, sender, sender_name, body, html?, msgtype, ts, encrypted, attachment?, reply_to?, edited, reactions, read_by, deleted}`
— `reply_to` is `{event_id, sender, sender_name, body}`; an edited message carries its latest
text; `reactions` is `[{key, count, senders: [{id, name, reaction_id}], mine?}]`; `read_by`
lists others whose read receipt points here; a deleted message keeps its place with `deleted: true`.
Rooms and senders carry `avatar` / `sender_avatar` mxc URLs. Live messages carry the
push-rule verdict as `notify` and `highlight`; rooms carry `notification_mode`, `favourite`,
`low_priority` and `last_activity` (ms of the latest message, seeded from the server once per room). Membership changes come as
`msgtype: "system"` messages whose body is the line to show ("X joined").
— `attachment` is `{kind, name, caption?, mime?, size?, width?, height?, has_thumbnail}` for
`m.image`, `m.file`, `m.video` and `m.audio`
— `ts` in milliseconds since the epoch, `encrypted` true when the event
arrived as `m.room.encrypted` and was decrypted locally, `html` the sender's
formatted body when there is one.

Unsolicited events; the first line on every new connection is a `state`:

| `event` | when | fields |
|---|---|---|
| `state` | connect, login, logout, sync start/stop, sync error | the status fields |
| `message` | a message arrives in a joined room | a message |
| `invite` | we were invited | `{room, name, inviter?, inviter_name?, direct}` |
| `rooms_changed` | our membership, a receipt, an unread flag or a latest event changed | |
| `message_edited` | one of a room's messages was edited | `{room, event_id, body, html?}` |
| `reaction` | someone reacted | `{room, event_id, key, sender: {id, name}, reaction_id}` |
| `redacted` | a message or reaction was removed | `{room, event_id}` |
| `typing` | who is typing in a room (empty when nobody) | `{room, users: [{id, name}]}` |
| `receipt` | others' read receipts moved | `{room, event_id, users}` |
| `verification` | a verification flow moved | `{flow_id, other_user, other_device?, outgoing, state, emojis?, reason?}` — state is requested, ready, emoji, confirmed, done or cancelled |
| `verification_status_changed` | identity, backup or recovery changed | |

Sending into an encrypted room encrypts automatically; the SDK shares the
room key with every device in the room first. Messages the daemon has no key
for come back with `msgtype: "unable_to_decrypt"`; they fill in once key
backup or another device supplies the key.

Try it by hand:

```bash
scripts/smoke.py                                  # status + rooms
scripts/smoke.py '{"cmd":"timeline","room":"!abc:matrix.org","limit":5}'
socat - UNIX-CONNECT:$XDG_RUNTIME_DIR/omarchy-yapper.sock   # or interactively
```

## Releases

`scripts/release.sh X.Y.Z` bumps the version in `Cargo.toml`, `Cargo.lock` and the
`PKGBUILD`, commits, tags `vX.Y.Z` and pushes. The Yapper plugin checks the
newest `v*` tag against the running daemon's version and offers the update.

## Development

```bash
cargo check                              # fast, catches API drift
cargo build --release                    # target/release/omarchy-yapperd
target/release/omarchy-yapperd --socket /tmp/yapper-test.sock --data-dir /tmp/yapper-test-data
scripts/smoke.py --socket /tmp/yapper-test.sock
RUST_LOG=debug,matrix_sdk=info omarchy-yapperd   # log filter, default info,matrix_sdk=warn
```

Layout:

```
src/main.rs        socket server, peer check, per-connection writer, signals
src/core.rs        Client lifecycle: session file, login/logout, sync loop, commands
src/protocol.rs    request / response / event types
packaging/PKGBUILD builds from a clean checkout of this repo (git+file://)
omarchy-yapperd.service   systemd user unit installed by the package
```

`packaging/` is separate because makepkg's `$srcdir` is `./src` next to the
`PKGBUILD` — the Rust source tree. Building there sources the enclosing repo's
committed `HEAD`, so commit before `makepkg`.

MSRV follows matrix-sdk (currently 1.96). `Cargo.lock` is committed and the
package builds `--frozen`.

## Roadmap

2. **Multiple accounts** — one daemon, several sessions.

## License

MIT
