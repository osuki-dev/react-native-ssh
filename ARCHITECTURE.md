# Architecture

`@osuki-dev/react-native-ssh` does one thing: SSH connections for React Native
and Expo apps. It deliberately contains **no terminal emulator** and **no
persistence** — bytes in, bytes out, and the app decides how to render them
and which host keys to trust.

```
 JS (src/index.ts)          thin ergonomic wrapper: SshConnection / SshShell / SshError
   │  Nitro HybridObjects (JSI, zero-copy ArrayBuffers, Promises, async callbacks)
 C++ (cpp/)                 HybridSshClient / HybridSshConnection / HybridSshShell
   │  C ABI (cpp/rnssh.h, generated from rust/rnssh-ffi by cbindgen)
 Rust (rust/rnssh-ffi)      handle registry, callback marshalling, ownership rules
   │  plain Rust types + two event traits
 Rust (rust/rnssh-core)     russh + tokio: connect, host key, auth, shell, exec, keys
```

One native binary per platform: `libOsukiSsh.so` on Android, the `OsukiSsh`
pod on iOS. The Rust code is linked in as a static archive, so nothing Rust
is exported from the shared object.

## Layers

### `rust/rnssh-core` — binding-agnostic

* `runtime.rs` — one process-wide tokio runtime (2 workers). Nothing is ever
  tied to the JS thread.
* `connection.rs` — `Connection::connect(options, events)`. Handshake → host
  key decision → auth → `Connection`. Auth methods: none, password (with
  automatic keyboard-interactive fallback when the server only offers that),
  public key (OpenSSH / PKCS#8 / PKCS#1 / PPK, encrypted or not), explicit
  keyboard-interactive. `exec()` runs a command without a PTY; `open_shell()`
  returns a `Shell`.
* `shell.rs` — one tokio task owns the channel. Callers push `Data` /
  `Resize` / `Eof` / `Close` commands through a bounded queue, so `write`
  and `resize` are synchronous and never block. Output goes to a `ShellEvents`
  sink as owned `Vec<u8>`.
* `forward.rs` — local port forwarding (`direct-tcpip`): a loopback
  `TcpListener`; each accepted socket becomes one SSH channel and a single
  `copy_bidirectional`, so SSH window flow control is the back-pressure.
  Loopback-only bind, concurrent-connection cap, and a 1 s liveness check that
  closes the forward when the transport is gone.
* `hostkey.rs` — `HostKey { algorithm, fingerprint: "SHA256:…", public_key }`.
* `keys.rs` — generation (Ed25519, ECDSA P-256/P-384, RSA 3072/4096) and
  inspection. Private key material is `Zeroizing`.
* `error.rs` — `ErrorCode` (numeric, stable) + `SshError`.

Interactive decisions are modelled as *request + one-shot responder*
(`oneshot::Sender`). The UI can take as long as it wants; no thread waits.

Tested against an in-process russh **server** (`tests/e2e.rs`): password,
kbi fallback, explicit kbi, public key (right/wrong passphrase, unauthorized
key), host key rejection, connection refused, handshake timeout, shell
echo/resize/exit code, exec stdout/stderr/exit code, server-drop detection.

### `rust/rnssh-ffi` — the C boundary

* Every export is `rnssh_*`; the header is generated (`scripts/gen-header.sh`).
* Connections and shells are addressed by opaque `u64` handles in a
  `DashMap` registry. A stale handle is an error code, never a crash.
* Callback structs carry `void* user` + `release(user)`. Rust calls `release`
  exactly once, after the last other callback. That is the C++ side's signal to
  free its context. Contexts therefore live exactly as long as Rust can still
  call back.
* Shell output crosses as `(ptr, len, cap)` of a Rust `Vec<u8>`; the receiver
  frees it with `rnssh_bytes_free`. This is what makes `onData` zero-copy.
* Strings in are NUL-terminated UTF-8 and copied before the call returns;
  strings out are valid only during the callback.
* Callbacks fire on tokio worker threads and must not block.

### `cpp/` — Nitro HybridObjects

* `HybridSshClient` — `connect`, `generateKeyPair` (runs on Nitro's thread
  pool), `inspectPrivateKey`.
* `HybridSshConnection` — `openShell`, `exec` (raw bytes), `execText` (UTF-8,
  lossy — Hermes has no `TextDecoder`), `disconnect`, read-only props.
* `HybridSshShell` — `write` / `writeString` (sync, copy on the JS thread),
  `resize`, `sendEof`, `close`.
* `HybridSshForward` — `localPort`, `isOpen`, `activeConnections`, `close`;
  created by `HybridSshConnection::forwardLocal`.
* `RnsshBridge.hpp` — error mapping, string helpers, `adoptRustBytes`
  (wraps a Rust buffer in a `NativeArrayBuffer` whose deleter calls
  `rnssh_bytes_free`), UTF-8 sanitizer.

Threading: Nitro's `Promise::resolve/reject` and async JS callbacks may be
called from any thread — Nitro hops back to the JS thread through its
Dispatcher. The only place that must be on the JS thread is reading a
JS-owned `ArrayBuffer`, which happens inside the synchronous `write` call.

Errors cross into JS as `Error("RNSSH_<CODE>: detail")`; `src/errors.ts`
parses that prefix into `SshError` with a typed `.code`.

### `src/` — public API

`src/specs/Ssh.nitro.ts` is the Nitro spec (internal). `src/index.ts` is the
API people use: discriminated-union auth, sensible defaults, `write` accepting
`string | ArrayBuffer | Uint8Array`, `exec` returning strings, and all handlers
passed in one options object.

## Security decisions

What *this* package guarantees, independent of upstream:

* **Algorithm policy is explicit** (`connection::preferred_algorithms`): kex
  `mlkem768x25519` / `curve25519` / `dh-gex-sha256` / `dh-group{14,16,18}` /
  `ecdh-nistp*`; host keys Ed25519 / ECDSA / `rsa-sha2-{512,256}`; ciphers
  AES-GCM / ChaCha20-Poly1305 / AES-CTR; MACs SHA-2 (ETM preferred); no
  compression. **No SHA-1 anywhere** — not for kex, not for MACs, not for
  `ssh-rsa` signatures (an RSA key against a server that only accepts SHA-1
  signatures fails with `AUTH_FAILED` and a clear message). OpenSSH strict
  kex (Terrapin mitigation) is advertised. DH group exchange demands ≥ 3072-bit
  groups (preferred 8192); the fixed 2048-bit `dh-group14` is offered last.
* **RSA keys below 2048 bits are refused outright** — a weak server host key
  is never shown to the user for trust (fails with `PROTOCOL`), and a weak
  user private key fails with `KEY` before any packet is sent.
* **Host key decisions are never rushed, but always cancellable.** Time spent
  waiting for `verifyHostKey` / keyboard-interactive answers is excluded from
  `connectTimeoutMs` (hard ceiling 10 min), and `connect({ signal })` aborts
  the attempt at any point (`rnssh_connection_cancel`: unparks the prompt,
  aborts the task, reports `CANCELLED`, releases the context exactly once). A thrown or dropped callback is a
  rejection. russh consults the host key only on the initial key exchange;
  later re-keys happen inside the already authenticated transport and are not
  re-verified by upstream — nothing this layer can hook.
* **Channel requests are confirmed.** russh only *sends* PTY / shell / exec
  requests; this layer waits for the server's accept/refuse reply (with a
  timeout) and turns a refusal into `PROTOCOL` instead of a silently dead
  channel. Data that arrives during setup is not lost.
* **Bounded resources against a hostile or stalled server**: shell write queue
  capped at 4 MiB (`QUEUE_FULL`), `exec` output capped at 16 MiB
  (`TOO_LARGE`), channel setup capped at 30 s (`TIMEOUT`),
  keyboard-interactive capped at 16 rounds, prompt answers must match the
  prompt count.
* **Password → keyboard-interactive fallback** only fills prompts the server
  marks as non-echo; echoed prompts (e.g. "Username:") get an empty answer, so
  the password is never typed into something that is not a password field.
* **The C boundary is defensive**: handles are registry ids (a stale handle is
  an error, never a dangling pointer), the auth-method enum is read as a raw
  integer and validated, every callback carries its own handle so the C++
  side never writes into a context after the call that handed it over,
  `release` fires exactly once. `rnssh-core` is `#![forbid(unsafe_code)]`;
  both Rust crates deny `unwrap` / `expect` / indexing / `panic` in non-test
  code (clippy, enforced in CI) and are built with `panic = "abort"`.
* Every one of the above has a test in `rnssh-core/tests/e2e.rs` or
  `rnssh-ffi/src/tests.rs` against an in-process russh server.

Upstream choices:

* **Crypto backend: aws-lc-rs** (russh default; AWS maintained). Non-FIPS
  builds need only a C compiler — no CMake, Go or bindgen.
* **Compression is off** (`flate2` not enabled). No benefit on mobile links
  and it removes the decompression-bomb class (CVE-2026-46702) entirely.
* `des` / `dsa` features are never enabled.
* russh floor: **0.63.1** (covers every 2025–2026 advisory). CI runs
  `cargo audit`.
* Known upstream quirk (server side only, affects our test server, not real
  sshd): russh's server never signals `partial_success`, so the client's
  second-factor branch (password/key accepted → keyboard-interactive OTP via
  `onKeyboardInteractive`) is covered by code review and the fallback path,
  not by an in-process test.
* **Known upstream advisory, accepted with mitigation:** RUSTSEC-2023-0071,
  the Marvin timing side-channel in the `rsa` crate, has no fixed release.
  It affects RSA *private key* operations only. We keep russh's `rsa`
  feature because verifying RSA **host** keys (a public operation, not
  affected) is unavoidable in practice. Consequently: `generateKeyPair`
  defaults to Ed25519, and RSA *user* keys are supported for legacy servers
  but documented as not recommended. CI ignores exactly this advisory id.
* Host key policy belongs to the app. The library hands over the fingerprint
  and full key and waits for a yes/no; it stores nothing.
* Secrets (`password`, private key PEM, passphrase) are `Zeroizing` in Rust
  and wiped in `rnssh_key_result_free`.
* `panic = "abort"` in every profile: a Rust panic can never unwind across the
  C boundary. russh itself denies `unwrap`/`expect`/indexing/panic via clippy.
* Android: `-Wl,--exclude-libs,ALL --gc-sections`, 16 KB page alignment via
  NDK r28+ / explicit linker flag, only `arm64-v8a` and `x86_64` are shipped.

## Performance decisions

Measured with `cargo test --release -p rnssh-core --test e2e perf_shell -- --ignored --nocapture`
(64 MiB through a shell, loopback, both ends encrypting, Apple silicon):

| profile | throughput | arm64 code segment |
|---|---|---|
| all `-O3` | ~770 MB/s | 5.31 MB |
| `-Os` + crypto crates and aws-lc at `-O3` (**shipped**) | ~760 MB/s | 4.49 MB |
| `-Os` everywhere | ~735 MB/s | 3.63 MB |

Output coalescing (4 ms window, 256 KiB cap, bulk-sized chunks only):
2048 → 257 sink callbacks for the same 64 MiB at unchanged throughput, i.e.
~8× fewer JS-thread dispatches under bulk output. Interactive chunks
(< 4 KiB) are never held back: echo round trip measured at **0.09 ms median**
on loopback (`perf_latency_and_ciphers`), connect at ~1 ms.

Cipher choice (same benchmark, hardware AES on Apple silicon; arm64 phones
behave alike): `aes128-gcm` 2.2 GB/s, `aes256-gcm` 2.0 GB/s,
`chacha20-poly1305` 0.75 GB/s, `aes*-ctr` ~0.5 GB/s. The client therefore
offers AES-GCM first and ChaCha20 as the fallback — equal security, a third
of the CPU per byte.

* JSI via Nitro: no bridge, no JSON. Shell output is one Rust allocation that
  becomes the JS `ArrayBuffer` without copying; bursts are coalesced in Rust
  (`ShellOptions::coalesce`) so a `cat` of a big file costs a few hundred JS
  dispatches per second, not one per SSH packet.
* `write` is synchronous: it copies into a queue and returns; the tokio task
  does the network I/O and honours SSH window back-pressure.
* One tokio runtime for the process; connections are cheap.
* Release profile: `opt-level = 3`, `lto = "fat"`, `codegen-units = 1`,
  stripped. `nodelay = true` on the socket for interactive latency.
* Keepalives default to 15 s × 3 so dead mobile links are detected in under a
  minute and surfaced through `onDisconnected`.

## Platform notes

* **Android `sdallocx` trap.** aws-lc weakly references jemalloc's `sdallocx`
  and calls it from `OPENSSL_free` when the symbol resolves. React Native's
  `libjsi.so` / `libreactnative.so` export a *data object* with that name
  (folly's jemalloc probe), so Bionic would bind the weak reference to
  non-executable memory → SIGSEGV on every aws-lc free (e.g. dropping an
  AES-GCM key on disconnect). `android/src/main/cpp/cpp-adapter.cpp` defines a
  hidden `sdallocx` that forwards to `free`, resolved at link time inside
  `libOsukiSsh.so`. Verified: no dynamic relocation for it remains.
* iOS is unaffected (no such symbol in the process).

## Build & release flow

```
src/specs/*.nitro.ts ──nitrogen──▶ nitrogen/generated/**   (committed)
rust/rnssh-ffi       ──cbindgen──▶ cpp/rnssh.h             (committed)
rust/                ──cargo─────▶ ios/RnsshFFI.xcframework (not committed, in npm tarball)
                                   android/rust-libs/<abi>/librnssh_ffi.a
```

`scripts/build-rust-ios.sh` and `scripts/build-rust-android.sh` produce the
prebuilt archives. They are published inside the npm package, so **app
developers never need a Rust toolchain**: `expo prebuild` / EAS Build just
link them. Only contributors touching `rust/` need `rustup`, `cargo-ndk`,
`cbindgen`.

`rust/rnssh-testserver` is a dev-only russh server used by the example app
and by automated verification; it is never published.

## What is intentionally out of scope

* Terminal emulation and rendering (use your own; bytes are yours).
* known_hosts persistence and key storage (use the platform keychain).
* SFTP / remote port forwarding / agent forwarding — planned; local
  forwarding landed in 0.2.0.
