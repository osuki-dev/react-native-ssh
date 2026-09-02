#!/usr/bin/env bash
# Builds rust/rnssh-ffi for iOS device + simulator and packages the static
# archives (plus cpp/rnssh.h) into ios/RnsshFFI.xcframework.
#
# Requirements: Xcode, rustup targets aarch64-apple-ios, aarch64-apple-ios-sim
# (x86_64-apple-ios is added when available for Intel simulators).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/ios/RnsshFFI.xcframework"
PROFILE="${RNSSH_PROFILE:-release}"
export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-15.1}"

cd "$ROOT/rust"

rustup target add aarch64-apple-ios aarch64-apple-ios-sim >/dev/null
HAVE_X86_SIM=0
if rustup target list --installed | grep -q '^x86_64-apple-ios$'; then
  HAVE_X86_SIM=1
fi

echo "▸ cargo build (aarch64-apple-ios)"
cargo build -p rnssh-ffi --profile "$PROFILE" --target aarch64-apple-ios
echo "▸ cargo build (aarch64-apple-ios-sim)"
cargo build -p rnssh-ffi --profile "$PROFILE" --target aarch64-apple-ios-sim
if [ "$HAVE_X86_SIM" = "1" ]; then
  echo "▸ cargo build (x86_64-apple-ios)"
  cargo build -p rnssh-ffi --profile "$PROFILE" --target x86_64-apple-ios
fi

PROFILE_DIR="$PROFILE"
[ "$PROFILE" = "dev" ] && PROFILE_DIR="debug"

STAGE="$ROOT/rust/target/xcframework-stage"
rm -rf "$STAGE"
mkdir -p "$STAGE/include" "$STAGE/device" "$STAGE/sim"
cp "$ROOT/cpp/rnssh.h" "$STAGE/include/rnssh.h"

# Rust's prebuilt std and aws-lc's C objects carry DWARF; nothing downstream needs it.
strip_archive() { strip -S -x "$1" 2>/dev/null || strip -S "$1"; }

cp "target/aarch64-apple-ios/$PROFILE_DIR/librnssh_ffi.a" "$STAGE/device/librnssh_ffi.a"
strip_archive "$STAGE/device/librnssh_ffi.a"
if [ "$HAVE_X86_SIM" = "1" ]; then
  lipo -create \
    "target/aarch64-apple-ios-sim/$PROFILE_DIR/librnssh_ffi.a" \
    "target/x86_64-apple-ios/$PROFILE_DIR/librnssh_ffi.a" \
    -output "$STAGE/sim/librnssh_ffi.a"
else
  cp "target/aarch64-apple-ios-sim/$PROFILE_DIR/librnssh_ffi.a" "$STAGE/sim/librnssh_ffi.a"
fi
strip_archive "$STAGE/sim/librnssh_ffi.a"

rm -rf "$OUT"
xcodebuild -create-xcframework \
  -library "$STAGE/device/librnssh_ffi.a" -headers "$STAGE/include" \
  -library "$STAGE/sim/librnssh_ffi.a" -headers "$STAGE/include" \
  -output "$OUT"

echo "✔ $OUT"
du -sh "$OUT"/*/librnssh_ffi.a
