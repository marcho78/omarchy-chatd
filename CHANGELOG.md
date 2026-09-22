# Changelog

All notable changes to omarchy-yapperd. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/marcho78/omarchy-yapperd/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/marcho78/omarchy-yapperd/compare/v0.22.0...v1.0.0
[0.22.0]: https://github.com/marcho78/omarchy-yapperd/compare/v0.21.1...v0.22.0
[0.21.1]: https://github.com/marcho78/omarchy-yapperd/compare/v0.21.0...v0.21.1
[0.21.0]: https://github.com/marcho78/omarchy-yapperd/compare/v0.20.0...v0.21.0
