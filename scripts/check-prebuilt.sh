#!/usr/bin/env bash
# Refuses to pack/publish a tarball without the prebuilt Rust archives.
# They are gitignored, so a fresh checkout does not have them: run
# `bun run rust:all` (or let the Release workflow do it) before `npm publish`.
#
# With RNSSH_STRICT=1 the exported `rnssh_*` symbols of the iOS archive must
# also match cpp/rnssh.h (guards against publishing a stale build). The
# Release workflow runs that as a visible step; `prepack` only checks presence.
set -uo pipefail
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
  else
    echo "ok: $f ($(wc -c < "$ROOT/$f" | tr -d ' ') bytes)"
  fi
done
if [ "$missing" = "1" ]; then
  echo "Refusing to pack: run 'bun run rust:all' first (needs rustup targets, cargo-ndk, Xcode, Android NDK)." >&2
  exit 1
fi

if [ "${RNSSH_STRICT:-0}" = "1" ]; then
  header_syms="$(grep -oE 'rnssh_[a-z_]+\(' "$ROOT/cpp/rnssh.h" | tr -d '(' | sort -u || true)"
  ios_syms="$(nm -gU "$ROOT/ios/RnsshFFI.xcframework/ios-arm64/librnssh_ffi.a" 2>/dev/null | awk '{print $NF}' | grep -E '^_rnssh_' | sed 's/^_//' | sort -u || true)"
  echo "header exports: $(echo "$header_syms" | grep -c . || true), archive exports: $(echo "$ios_syms" | grep -c . || true)"
  if [ -z "$header_syms" ] || [ -z "$ios_syms" ]; then
    echo "could not read symbols (header or nm output empty)" >&2
    exit 1
  fi
  if [ "$header_syms" != "$ios_syms" ]; then
    echo "prebuilt iOS archive does not match cpp/rnssh.h (stale build?)" >&2
    diff <(echo "$header_syms") <(echo "$ios_syms") >&2 || true
    exit 1
  fi
  echo "archive exports match cpp/rnssh.h"
fi
echo "prebuilt archives present"
