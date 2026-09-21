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
| `session.json` | 0600 | homeserver, access token, device id, sync token, and the random passphrase for the store |
| `store-<random>/` | 0700 | the SDK's SQLite store: room state, message cache, Olm/Megolm keys — encrypted with that passphrase |

Your password is used once for `login` and dropped. `logout` revokes the
token on the server and deletes both entries.

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

**Known gap** (see Roadmap): the store passphrase sits in `session.json`
instead of the keyring.

## Socket protocol

One JSON object per line in each direction. Requests carry any `id`, which
the response echoes.

| `cmd` | fields | result |
|---|---|---|
| `status` | | `{version, logged_in, syncing, user_id?, homeserver?, error?}` |
| `login` | `homeserver`, `username`, `password` | status |
| `logout` | | status |
| `rooms` | | `[{id, name, encrypted, direct, unread, highlights}]`, unread first |
| `timeline` | `room`, `limit` (default 50, max 200), `before?` | `{messages, next?}` — oldest first; pass `next` as `before` for the page before; no `next` at the start of history |
| `send` | `room`, `body` | `{event_id}` |
| `mark_read` | `room`, `event_id` | `{}` |
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

Responses: `{"id":…, "ok":true, "result":…}` or `{"id":…, "ok":false, "error":"…"}`.

A `message` is `{room, event_id, sender, sender_name, body, html?, msgtype, ts, encrypted, attachment?}`
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
| `rooms_changed` | our own membership changed | |
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

1. Read markers, replies, edits.
3. **Keyring** — store passphrase in the Secret Service instead of `session.json`.

## License

MIT
