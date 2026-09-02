#!/usr/bin/env bash
# Refuses to pack/publish a tarball without the prebuilt Rust archives.
# They are gitignored, so a fresh checkout does not have them: run
# `bun run rust:all` (or let the Release workflow do it) before `npm publish`.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
missing=0
for f in \
  "ios/RnsshFFI.xcframework/ios-arm64/librnssh_ffi.a" \
  "ios/RnsshFFI.xcframework/ios-arm64_x86_64-simulator/librnssh_ffi.a" \
  "android/rust-libs/arm64-v8a/librnssh_ffi.a" \
  "android/rust-libs/x86_64/librnssh_ffi.a"; do
  if [ ! -s "$ROOT/$f" ]; then
    echo "missing prebuilt archive: $f" >&2
    missing=1
  fi
done
if [ "$missing" = "1" ]; then
  echo "Refusing to pack: run 'bun run rust:all' first (needs rustup targets, cargo-ndk, Xcode, Android NDK)." >&2
  exit 1
fi
# The archives must match the current C ABI: the header is committed, the
# archives are not, so a stale build is easy to ship by accident.
header_syms="$(grep -oE '\brnssh_[a-z_]+\(' "$ROOT/cpp/rnssh.h" | tr -d '(' | sort -u)"
ios_syms="$(nm -gU "$ROOT/ios/RnsshFFI.xcframework/ios-arm64/librnssh_ffi.a" 2>/dev/null | grep -oE '_rnssh_[a-z_]+$' | sed 's/^_//' | sort -u)"
if [ -n "$ios_syms" ] && [ "$header_syms" != "$ios_syms" ]; then
  echo "prebuilt iOS archive does not match cpp/rnssh.h (stale build?)" >&2
  diff <(echo "$header_syms") <(echo "$ios_syms") >&2 || true
  exit 1
fi
echo "prebuilt archives present and matching cpp/rnssh.h"
