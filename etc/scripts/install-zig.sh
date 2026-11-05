#!/usr/bin/env sh
# Install the pinned Zig toolchain into $1 (used by CI and `just test-linux`).
set -eu
dest="${1:-.cache/zig}"
version="0.17.1"
arch="$(uname -m)"
case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=macos ;;
  *) echo "unsupported OS" >&2; exit 1 ;;
esac
case "$arch" in
  arm64) arch=aarch64 ;;
esac
name="zig-${arch}-${os}-${version}"
mkdir -p "$dest"
curl -fsSL "https://ziglang.org/download/${version}/${name}.tar.xz" \
  | tar -xJ -C "$dest" --strip-components=1
"$dest/zig" version
