# Maintainer: marcho78
#
# Builds omarchy-chatd from this checkout. Install with:
#
#   git clone https://github.com/marcho78/omarchy-chatd && cd omarchy-chatd && makepkg -si
#
# Nothing is downloaded except crates (verified against Cargo.lock); the
# binary you install is compiled from the source you can read here.

pkgname=omarchy-chatd
pkgver=0.1.0
pkgrel=1
pkgdesc="End-to-end encrypted Matrix daemon behind the Omarchy chat plugin"
arch=(x86_64 aarch64)
url="https://github.com/marcho78/omarchy-chatd"
license=(MIT)
depends=(gcc-libs glibc sqlite openssl)
makedepends=(cargo git)
options=(!lto) # cargo's own thin LTO is configured in Cargo.toml

pkgver() {
  cd "$startdir"
  local tag
  tag=$(git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//')
  local rev
  rev=$(git rev-parse --short HEAD 2>/dev/null)
  local dirty=""
  git diff --quiet 2>/dev/null || dirty=".dirty"
  echo "${tag:-0.1.0}.r$(git rev-list --count HEAD 2>/dev/null || echo 0).g${rev:-local}${dirty}"
}

prepare() {
  cd "$startdir"
  export CARGO_HOME="$srcdir/cargo-home"
  cargo fetch --locked --target "$(rustc -vV | sed -n 's/host: //p')"
}

build() {
  cd "$startdir"
  export CARGO_HOME="$srcdir/cargo-home"
  export CARGO_TARGET_DIR="$srcdir/target"
  export RUSTUP_TOOLCHAIN=stable
  cargo build --frozen --release
}

package() {
  install -Dm755 "$srcdir/target/release/omarchy-chatd" "$pkgdir/usr/bin/omarchy-chatd"
  install -Dm644 "$startdir/omarchy-chatd.service" "$pkgdir/usr/lib/systemd/user/omarchy-chatd.service"
  install -Dm644 "$startdir/LICENSE" "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
  install -Dm644 "$startdir/README.md" "$pkgdir/usr/share/doc/$pkgname/README.md"
}
