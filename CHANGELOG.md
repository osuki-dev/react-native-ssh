# @osuki-dev/react-native-ssh

## 0.1.1

### Patch Changes

- [`7512b51`](https://github.com/osuki-dev/react-native-ssh/commit/7512b51a8ec09fa8b071113c795f7e3ae3105148) Thanks [@BANG88](https://github.com/BANG88)! - Republish with the prebuilt Rust archives. `0.1.0` was published from a checkout without them (they are gitignored), so it cannot link on either platform. `npm pack` / `npm publish` now refuse to run when the archives are missing or do not match `cpp/rnssh.h`.

## 0.1.0

### Minor Changes

- [`51c0ce1`](https://github.com/osuki-dev/react-native-ssh/commit/51c0ce113a265d999e510aec76ac1e8a36f2e0be) Thanks [@BANG88](https://github.com/BANG88)! - First release.

  - Connections: password, public key (OpenSSH / PKCS#8 / PKCS#1 / PPK, encrypted or not), keyboard-interactive (including second factors after password or key), `none`; host key verification callback; `hostKeyAlgorithms` to re-offer a pinned key type; `signal` (AbortSignal) to cancel an attempt; keepalives; typed errors.
  - Interactive shells with PTY (write / resize / EOF / close, stdout + stderr, exit code) and one-off `exec` (text or raw bytes).
  - Key generation (Ed25519, ECDSA P-256/P-384, RSA 3072/4096) and inspection.
  - Security posture: modern-only algorithm policy (no SHA-1, no CBC, no compression, RSA ≥ 2048), confirmed channel requests, bounded queues and output, user-decision-aware timeouts, `forbid(unsafe_code)` core, strict lints.
  - Performance: AES-GCM preferred (hardware AES), native output coalescing for bulk transfers, interactive chunks delivered immediately, size-tuned build profile.
  - Prebuilt Rust archives for iOS (device + simulator) and Android (arm64-v8a, x86_64, 16 KB page aligned) shipped in the npm package.

Releases are written here by changesets (see `.changeset/`).
