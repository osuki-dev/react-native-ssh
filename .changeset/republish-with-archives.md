---
"@osuki-dev/react-native-ssh": patch
---

Republish with the prebuilt Rust archives. `0.1.0` was published from a checkout without them (they are gitignored), so it cannot link on either platform. `npm pack` / `npm publish` now refuse to run when the archives are missing or do not match `cpp/rnssh.h`.
