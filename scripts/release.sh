#!/usr/bin/env bash
# Cut a release: bump the version in Cargo.toml, Cargo.lock and the PKGBUILD,
# commit, tag vX.Y.Z and push. The Yapper plugin compares the daemon's
# reported version against the newest v* tag to offer updates.
#
#   scripts/release.sh 0.2.0
set -euo pipefail
v="${1:-}"
[[ $v =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "usage: $0 X.Y.Z" >&2; exit 2; }
cd "$(dirname "$0")/.."
[[ -z $(git status --porcelain) ]] || { echo "working tree not clean" >&2; exit 1; }
sed -i "0,/^version = \".*\"/s//version = \"$v\"/" Cargo.toml
sed -i "s/^pkgver=.*/pkgver=$v/; s/^pkgrel=.*/pkgrel=1/" packaging/PKGBUILD
cargo check --quiet   # refreshes Cargo.lock
git add Cargo.toml Cargo.lock packaging/PKGBUILD
git commit -qm "Release $v"
git tag -a "v$v" -m "omarchy-yapperd $v"
git push -q && git push -q --tags
echo "released v$v"
