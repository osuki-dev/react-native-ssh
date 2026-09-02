---
"@osuki-dev/react-native-ssh": minor
---

First release.

- Connections: password, public key (OpenSSH / PKCS#8 / PKCS#1 / PPK, encrypted or not), keyboard-interactive (including second factors after password or key), `none`; host key verification callback; `hostKeyAlgorithms` to re-offer a pinned key type; `signal` (AbortSignal) to cancel an attempt; keepalives; typed errors.
- Interactive shells with PTY (write / resize / EOF / close, stdout + stderr, exit code) and one-off `exec` (text or raw bytes).
- Key generation (Ed25519, ECDSA P-256/P-384, RSA 3072/4096) and inspection.
- Security posture: modern-only algorithm policy (no SHA-1, no CBC, no compression, RSA ≥ 2048), confirmed channel requests, bounded queues and output, user-decision-aware timeouts, `forbid(unsafe_code)` core, strict lints.
- Performance: AES-GCM preferred (hardware AES), native output coalescing for bulk transfers, interactive chunks delivered immediately, size-tuned build profile.
- Prebuilt Rust archives for iOS (device + simulator) and Android (arm64-v8a, x86_64, 16 KB page aligned) shipped in the npm package.
