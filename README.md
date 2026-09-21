# omarchy-chatd

The daemon behind the [Omarchy chat plugin](https://github.com/marcho78/omarchy-chat).
It owns the Matrix session, the encryption keys and the sync loop, and talks
to the shell plugin over a local Unix socket. The plugin (QML, inside
`omarchy-shell`) never sees key material.

End-to-end encryption is [matrix-rust-sdk](https://github.com/matrix-org/matrix-rust-sdk)
(Olm/Megolm via vodozemac) — the same stack as Element X. This daemon adds no
cryptography of its own.

## Install

No binaries are shipped. You build it from this source:

```bash
git clone https://github.com/marcho78/omarchy-chatd && cd omarchy-chatd/packaging && makepkg -si
```

`makepkg` pulls `cargo` if needed, compiles the daemon (several minutes the
first time — matrix-rust-sdk is large), and installs a normal pacman package
with a systemd user unit. The plugin starts the unit on demand; to run it at
login instead:

```bash
systemctl --user enable --now omarchy-chatd
```

Update: `git pull && cd packaging && makepkg -si`. Remove: `pacman -R omarchy-chatd`.

## What it stores

`~/.local/share/omarchy-chatd/` (mode 0700):

* `session.json` (0600) — homeserver, access token, device id and the random
  passphrase for the encrypted store. Your password is never written.
* `store-*/` — the SDK's SQLite store: room state, message cache and the
  encryption keys, encrypted with that passphrase.

`logout` revokes the token on the server and deletes both.

## Socket protocol

`$XDG_RUNTIME_DIR/omarchy-chat.sock`, mode 0600, peer uid checked. One JSON
object per line in each direction.

Requests carry any `id`, which the response echoes:

| `cmd` | fields | result |
|---|---|---|
| `status` | | `{version, logged_in, syncing, user_id?, homeserver?, error?}` |
| `login` | `homeserver`, `username`, `password` | status |
| `logout` | | status |
| `rooms` | | `[{id, name, encrypted, direct, unread, highlights}]` |
| `timeline` | `room`, `limit` (default 50) | `[message]`, oldest first |
| `send` | `room`, `body` | `{event_id}` |
| `mark_read` | `room`, `event_id` | `{}` |

Responses: `{"id":…, "ok":true, "result":…}` or `{"id":…, "ok":false, "error":"…"}`.

Unsolicited events (the first thing a new connection receives is a `state`):

* `{"event":"state", …status fields}` — on login, logout, sync start/stop, errors
* `{"event":"message", "room", "event_id", "sender", "sender_name", "body", "msgtype", "ts", "encrypted"}`

Try it by hand:

```bash
socat - UNIX-CONNECT:$XDG_RUNTIME_DIR/omarchy-chat.sock
{"id":1,"cmd":"status"}
{"id":2,"cmd":"login","homeserver":"https://matrix.org","username":"you","password":"…"}
{"id":3,"cmd":"rooms"}
```

## Roadmap

1. Device verification (SAS emoji) and key backup — until then, other clients
   will show this device as unverified and history from before login is not
   readable.
2. Read the store passphrase from the Secret Service instead of `session.json`.
3. Attachments.

## License

MIT
