#!/usr/bin/env bash
# Builds rust/rnssh-ffi as static archives for Android (arm64-v8a, x86_64) into
# android/rust-libs/<abi>/librnssh_ffi.a. The Nitro CMake project links them
# into libOsukiSsh.so.
#
# Requirements: cargo-ndk, an Android NDK (r27+; r28+ recommended for 16 KB
# pages), rustup targets aarch64-linux-android and x86_64-linux-android.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/android/rust-libs"
PROFILE="${RNSSH_PROFILE:-release}"
API="${RNSSH_ANDROID_API:-24}"

if [ -z "${ANDROID_NDK_HOME:-}" ]; then
  SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}}"
  if [ -d "$SDK/ndk" ]; then
    # Prefer the newest r27/r28 line present (RN 0.86 pins 27.1; 28+ is also fine).
    ANDROID_NDK_HOME="$(ls -d "$SDK"/ndk/* | sort -V | tail -n 1)"
    export ANDROID_NDK_HOME
  fi
fi
[ -n "${ANDROID_NDK_HOME:-}" ] || { echo "ANDROID_NDK_HOME is not set and no NDK was found" >&2; exit 1; }
echo "▸ NDK: $ANDROID_NDK_HOME"

HOST_TAG="$(uname -s | tr '[:upper:]' '[:lower:]')-x86_64"
LLVM_BIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$HOST_TAG/bin"
[ -x "$LLVM_BIN/llvm-strip" ] || { echo "llvm-strip not found in $LLVM_BIN" >&2; exit 1; }

cd "$ROOT/rust"
rustup target add aarch64-linux-android x86_64-linux-android >/dev/null

PROFILE_DIR="$PROFILE"
[ "$PROFILE" = "dev" ] && PROFILE_DIR="debug"

for pair in "arm64-v8a:aarch64-linux-android" "x86_64:x86_64-linux-android"; do
  ABI="${pair%%:*}"
  TRIPLE="${pair##*:}"
  echo "▸ cargo ndk ($ABI)"
  cargo ndk --platform "$API" --target "$ABI" build -p rnssh-ffi --profile "$PROFILE"
  mkdir -p "$OUT/$ABI"
  cp "target/$TRIPLE/$PROFILE_DIR/librnssh_ffi.a" "$OUT/$ABI/librnssh_ffi.a.tmp"
  # Drop DWARF and any embedded bitcode; the final .so is linked with --gc-sections anyway.
  "$LLVM_BIN/llvm-strip" --strip-debug "$OUT/$ABI/librnssh_ffi.a.tmp"
  "$LLVM_BIN/llvm-objcopy" --remove-section=.llvmbc --remove-section=.llvmcmd "$OUT/$ABI/librnssh_ffi.a.tmp" 2>/dev/null || true
  mv "$OUT/$ABI/librnssh_ffi.a.tmp" "$OUT/$ABI/librnssh_ffi.a"
done

echo "✔ $OUT"
du -sh "$OUT"/*/librnssh_ffi.a
