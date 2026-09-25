# Changelog

All notable changes to omarchy-yapperd. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.0.1]

### Security
- Media downloads (attachments, thumbnails, avatars, link-preview images) go
  through a bounded fetcher: refused when the server declares more than the
  cap, dropped the moment they exceed it (100 MiB for files, 16 MiB for
  thumbnails), abandoned after 300 s. Attachments whose event declares a size
  over the cap are never requested.
- ffmpeg runs by absolute path with a 120 s deadline, `-t 900`, local-file
  input only, a pinned demuxer for recordings, and is killed if the daemon
  drops the request; voice notes that are not audio by their bytes are not
  handed to it.
- Cached attachments get an extension from an allowlist per kind; images
  from their bytes only. A file declared `text/html` is `.bin`, not `.html`.
- Message edits are applied only when the edit comes from the original
  message's sender, live and from the cache.
- The local search scan has one 45 s deadline and covers at most 40 rooms.
- Socket request lines are capped at 1 MiB and eight requests run at once per
  connection.
- The reply-preview cache is bounded; reaction keys, waveforms, community
  cards, bridge names and link-preview titles are capped in length.
- Release workflow actions are pinned to commits and the Rust release is
  pinned in `rust-toolchain.toml`.

## [1.0.0]

### Fixed
- On stop the daemon now ends the sync loop and closes its SQLite stores
  before exiting, so no `-wal` and `-shm` files are left for the next start
  to recover.

### Changed
- First stable release; the plugin's install, update and removal flows are
  built around the two packages (`omarchy-yapperd`, `omarchy-yapperd-bin`).

## [0.22.0]

### Added
- A Release workflow that builds the daemon for x86_64 and aarch64 on every
  tag, attaches the tarballs with a SHA256SUMS file and a build provenance
  attestation to the GitHub release.
- `packaging/bin/PKGBUILD`: the `omarchy-yapperd-bin` package installs that
  prebuilt binary through pacman without a compile. It replaces and is
  replaced by the source package.
- `scripts/release.sh` waits for the workflow, records the checksums, and tags
  the packaging commit `pkg-vX.Y.Z` for the plugin to pin.

## [0.21.1]

### Changed
- The source PKGBUILD depends on `rust` rather than the virtual `cargo`, so
  makepkg no longer asks "rust or rustup?".

## [0.21.0]

### Added
- Omarchy community space, directory browsing, bounded request retries.

[Unreleased]: https://github.com/marcho78/omarchy-yapperd/compare/v1.0.1...HEAD
[1.0.1]: https://github.com/marcho78/omarchy-yapperd/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/marcho78/omarchy-yapperd/compare/v0.22.0...v1.0.0
[0.22.0]: https://github.com/marcho78/omarchy-yapperd/compare/v0.21.1...v0.22.0
[0.21.1]: https://github.com/marcho78/omarchy-yapperd/compare/v0.21.0...v0.21.1
[0.21.0]: https://github.com/marcho78/omarchy-yapperd/compare/v0.20.0...v0.21.0
