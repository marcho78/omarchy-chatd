#!/usr/bin/env bash
# Cut a release.
#
#   scripts/release.sh 0.22.0
#
# 1. Requires a "## [X.Y.Z]" section in CHANGELOG.md.
# 2. Bumps the version in Cargo.toml, Cargo.lock and both PKGBUILDs, commits,
#    tags vX.Y.Z and pushes. The Release workflow then builds the binaries
#    and attaches them to the GitHub release.
# 3. Waits for that workflow, writes its SHA256SUMS into packaging/bin/PKGBUILD,
#    commits, tags pkg-vX.Y.Z and pushes. The Yapper plugin pins that commit:
#    it holds both PKGBUILDs for X.Y.Z with the checksums filled in.
set -euo pipefail
v="${1:-}"
[[ $v =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "usage: $0 X.Y.Z" >&2; exit 2; }
cd "$(dirname "$0")/.."
[[ -z $(git status --porcelain) ]] || { echo "working tree not clean" >&2; exit 1; }
grep -q "^## \[$v\]" CHANGELOG.md || { echo "CHANGELOG.md has no \"## [$v]\" section" >&2; exit 1; }
command -v gh >/dev/null || { echo "gh is required" >&2; exit 1; }

sed -i "0,/^version = \".*\"/s//version = \"$v\"/" Cargo.toml
sed -i "s/^pkgver=.*/pkgver=$v/; s/^pkgrel=.*/pkgrel=1/" packaging/PKGBUILD packaging/bin/PKGBUILD
sed -i "s/^sha256sums_x86_64=.*/sha256sums_x86_64=('SKIP')/; s/^sha256sums_aarch64=.*/sha256sums_aarch64=('SKIP')/" packaging/bin/PKGBUILD
cargo check --quiet   # refreshes Cargo.lock
git add Cargo.toml Cargo.lock packaging/PKGBUILD packaging/bin/PKGBUILD
git commit -qm "Release $v"
git tag -a "v$v" -m "omarchy-yapperd $v"
git push -q && git push -q origin "v$v"
echo "tagged v$v; waiting for the Release workflow"

run=""
for _ in $(seq 60); do
  run=$(gh run list --workflow=release.yml --event=push --json databaseId,headBranch --jq ".[] | select(.headBranch == \"v$v\") | .databaseId" | head -1)
  [[ -n $run ]] && break
  sleep 5
done
[[ -n $run ]] || { echo "the Release workflow did not start" >&2; exit 1; }
gh run watch "$run" --exit-status

sums=$(gh release download "v$v" -p SHA256SUMS -O -)
x=$(echo "$sums" | awk -v f="omarchy-yapperd-$v-x86_64.tar.gz" '$2 == f { print $1 }')
a=$(echo "$sums" | awk -v f="omarchy-yapperd-$v-aarch64.tar.gz" '$2 == f { print $1 }')
[[ ${#x} -eq 64 && ${#a} -eq 64 ]] || { echo "SHA256SUMS is missing an architecture:"; echo "$sums"; exit 1; } >&2
sed -i "s/^sha256sums_x86_64=.*/sha256sums_x86_64=('$x')/; s/^sha256sums_aarch64=.*/sha256sums_aarch64=('$a')/" packaging/bin/PKGBUILD
git add packaging/bin/PKGBUILD
git commit -qm "Package $v"
git tag -a "pkg-v$v" -m "omarchy-yapperd-bin $v"
git push -q && git push -q origin "pkg-v$v"
echo "released v$v"
echo "plugin pin: daemonPinVersion \"$v\", daemonPinCommit \"$(git rev-parse HEAD)\""
