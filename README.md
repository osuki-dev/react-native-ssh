# @osuki-dev/react-native-ssh

Native SSH client for React Native and Expo. [russh](https://github.com/Eugeny/russh)
(Rust) wrapped in [Nitro Modules](https://nitro.margelo.com): connections,
interactive shells, one-off commands and key management — **bring your own
terminal**.

- Memory-safe SSH in Rust, one prebuilt binary per platform; **no Rust
  toolchain needed to use it**.
- Zero-copy output: shell bytes arrive as native-owned `ArrayBuffer`s, with
  bursts coalesced natively so bulk output never floods the JS thread.
- Password, public key (OpenSSH / PKCS#8 / PPK, encrypted or not),
  keyboard-interactive (2FA), automatic password → keyboard-interactive fallback.
- Host key verification is a callback you control; nothing is stored for you.
- Typed errors (`SshError.code`: `AUTH_FAILED`, `HOST_KEY_REJECTED`, `TIMEOUT`, …).
- Local port forwarding (`direct-tcpip`): a loopback listener tunnelled through
  the session, so an HTTP/WebSocket client on the phone can reach a service
  bound to the server's loopback without exposing it. The same listener over
  plain TCP (`forwardTcp`) gives an already-reachable service a `127.0.0.1`
  address, which is what makes a web view a secure context.
- Ed25519 / ECDSA / RSA key generation and inspection (Ed25519 by default;
  RSA user keys are supported for legacy servers but not recommended, see
  Security notes).
- iOS 15.1+ (Expo SDK 57 itself requires 16.4), Android 7 (API 24)+ on `arm64-v8a` / `x86_64`, 16 KB page ready.

## Requirements

- React Native ≥ 0.79 with the New Architecture, or Expo SDK ≥ 53.
- `react-native-nitro-modules` as a peer dependency.
- Expo: needs a development build (`expo-dev-client` / `expo prebuild` /
  EAS Build). Expo Go cannot load native modules.

## Install

```sh
bun add @osuki-dev/react-native-ssh react-native-nitro-modules
# Expo
npx expo prebuild
# bare RN
cd ios && pod install
```

No config plugin is needed; autolinking picks up the podspec and the Gradle
project. After upgrading the package, run `pod install` again (a new version
can add generated Nitro headers) — `expo prebuild` does that for you.

## Usage

```ts
import { connect, SshError } from '@osuki-dev/react-native-ssh'

const conn = await connect({
  host: 'example.com',
  port: 22,
  username: 'me',
  auth: { type: 'password', password: '…' },
  // or: { type: 'privateKey', privateKey: pem, passphrase: '…' }
  // or: { type: 'keyboardInteractive' } + onKeyboardInteractive
  verifyHostKey: async (key) => {
    // key.algorithm, key.fingerprint ("SHA256:…"), key.publicKey (base64)
    return (await trustStore.get(host)) === key.fingerprint
  },
  // Offer the pinned key type first so the server presents the same key again.
  hostKeyAlgorithms: [pinned.algorithm],
  onKeyboardInteractive: async ({ prompts }) => prompts.map(() => otpCode),
  onDisconnected: (reason) => console.log('dropped:', reason),
  signal: abortController.signal, // a Cancel button while your host-key / 2FA UI is up
})

// one-off command, UTF-8 decoded
const { stdout, stderr, exitCode } = await conn.exec('uname -a')

// interactive shell with a PTY
const shell = await conn.openShell(
  { term: 'xterm-256color', cols: 80, rows: 24 },
  {
    onData: (bytes: ArrayBuffer) => terminal.write(new Uint8Array(bytes)),
    onClosed: (exitCode) => console.log('shell exited', exitCode),
  },
)
shell.write('ls -la\n')          // string | ArrayBuffer | Uint8Array, never blocks
shell.resize(120, 40)
await shell.close()
await conn.disconnect()
```

Port forwarding (e.g. a gateway that only listens on the server's loopback):

```ts
const tunnel = await conn.forwardLocal(
  { remoteHost: '127.0.0.1', remotePort: 8787 },   // as seen from the server
  { onClosed: (reason) => console.log('tunnel closed', reason) },
)
const res = await fetch(`${tunnel.httpUrl}/api/health`)   // http://127.0.0.1:<localPort>
await tunnel.close()
```

The listener binds a loopback address only (anything else is refused), caps
concurrent tunnelled connections (64 by default), applies SSH window flow
control end to end, and closes itself when the connection drops.

The same listener is available without SSH, piped over plain TCP to a host
this device can already reach. It exists for one reason: a web view is a
secure context only on `127.0.0.1` / `localhost`, so a plain-http page
served from a LAN or tailnet address has no WebCodecs, `crypto.subtle` and
the like. `forwardTcp` gives such a page a loopback address and nothing else
— it neither encrypts nor authenticates, so use it only for services the
network already vouches for:

```ts
import { forwardTcp } from '@osuki-dev/react-native-ssh'

const loop = await forwardTcp({ remoteHost: '100.99.165.54', remotePort: 8801 })
const uri = `${loop.httpUrl}/`                      // http://127.0.0.1:<localPort>/
await loop.close()
```

Errors:

```ts
try {
  await connect(…)
} catch (e) {
  if (SshError.is(e, 'AUTH_FAILED')) …
  if (SshError.is(e, 'HOST_KEY_REJECTED')) …
}
```

Keys:

```ts
import { generateKeyPair, inspectPrivateKey } from '@osuki-dev/react-native-ssh'

const { privateKey, publicKey, fingerprint } = await generateKeyPair({
  type: 'ed25519',          // 'ecdsaP256' | 'ecdsaP384' | 'rsa3072' | 'rsa4096'
  comment: 'phone',
  passphrase: '…',          // optional, encrypts the PEM
})
const info = inspectPrivateKey(privateKey, '…') // algorithm, publicKey, fingerprint, comment, encrypted
```

Full API: see the exported types in `src/index.ts`. Design notes: `ARCHITECTURE.md`.

## Not yet supported

Planned, in rough order: remote port forwarding, SFTP, jump hosts
(ProxyJump), OpenSSH certificate authentication for users, stdin for `exec`,
and an explicit opt-in for legacy algorithms (SHA-1 / CBC) for old devices.
SSH agent forwarding is out of scope on mobile.

## Security notes

- Crypto backend is `aws-lc-rs`; SSH compression is compiled out; legacy
  3DES/DSA are never enabled. See `ARCHITECTURE.md` for the reasoning.
- Store trusted host keys and private keys yourself, in the platform keychain
  (`expo-secure-store`, Keychain, Keystore). The library never persists anything.
- Prefer Ed25519 or ECDSA user keys. RSA private-key operations in the
  upstream `rsa` crate carry an unfixed timing side-channel advisory
  (RUSTSEC-2023-0071); RSA *host* keys are unaffected and fully supported.
- Apps that ship SSH use encryption: on iOS set
  `ITSAppUsesNonExemptEncryption` accordingly and file the export compliance
  self-classification.

## Development

```sh
bun install                   # nitrogen, TypeScript
bun run build                 # lib/: ESM via `bun build` + .d.ts via tsc (ESM-only package)
bun run specs                 # regenerate nitrogen/generated from src/specs
bun run header                # regenerate cpp/rnssh.h from rust/rnssh-ffi (cbindgen)
bun run rust:test             # Rust unit + in-process server e2e tests
bun run rust:ios              # ios/RnsshFFI.xcframework
bun run rust:android          # android/rust-libs/<abi>/librnssh_ffi.a
cd rust && cargo run -p rnssh-testserver   # local SSH server on :2222 (test/test)
cd example && bun install && npx expo prebuild && npx expo run:ios   # or run:android
```

Contributor toolchain: `rustup` (targets `aarch64-apple-ios`,
`aarch64-apple-ios-sim`, `x86_64-apple-ios`, `aarch64-linux-android`,
`x86_64-linux-android`), `cargo-ndk`, `cbindgen`, Xcode, Android NDK r27+.

## Releasing

Same flow as `osuki-dev/kit`: add a changeset with each change
(`bun changeset`); on `main` the Release workflow opens a "Version Packages"
PR; merging it is the release: only then does a macOS job build the prebuilt
archives and publish to npm via trusted publishing (no token in the repo).
Other pushes to main stop after a cheap check. Publishing by hand works too,
but only from a checkout that has run `bun run rust:all`: `prepack` refuses a
tarball without the archives (they are gitignored). The native cross-compile also
runs on pull requests that touch `rust/`, the build scripts or `cpp/rnssh.h`.

## License

Apache-2.0. russh is Apache-2.0; aws-lc is ISC / Apache-2.0; Nitro Modules is MIT.
