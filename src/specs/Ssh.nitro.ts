/**
 * Nitro specs for @osuki-dev/react-native-ssh.
 *
 * These interfaces are the single source of truth for the native bindings:
 * `nitrogen` turns them into C++ `Hybrid*Spec` classes that `cpp/Hybrid*.cpp`
 * implement on top of the Rust core (`rust/`).
 *
 * Everything in this file is *internal*. The public, ergonomic API lives in
 * `src/index.ts` and wraps these objects.
 */
import type { HybridObject } from 'react-native-nitro-modules'

// ---------------------------------------------------------------------------
// Plain data
// ---------------------------------------------------------------------------

export type SshAuthMethod = 'none' | 'password' | 'publicKey' | 'keyboardInteractive'

export interface SshAuthSpec {
  method: SshAuthMethod
  password?: string
  privateKey?: string
  passphrase?: string
}

export interface SshConnectOptionsSpec {
  host: string
  port: number
  username: string
  auth: SshAuthSpec
  /** Milliseconds; covers TCP + handshake + host key decision + auth. */
  connectTimeoutMs: number
  /** Milliseconds; 0 disables keepalives. */
  keepaliveIntervalMs: number
  /** Unanswered keepalives before the connection is declared dead. */
  keepaliveMax: number
  /** Host key algorithms to offer first (e.g. the pinned key's `algorithm`). */
  hostKeyAlgorithms?: string[]
}

export interface SshHostKey {
  /** e.g. `ssh-ed25519`, `ecdsa-sha2-nistp256`, `ssh-ed25519-cert-v01@openssh.com` */
  algorithm: string
  /** OpenSSH style: `SHA256:<base64>` */
  fingerprint: string
  /** Raw key blob, base64 — the second column of a known_hosts line. */
  publicKey: string
}

export interface SshKeyboardInteractivePrompt {
  prompt: string
  /** false = the answer is secret (do not echo). */
  echo: boolean
}

export interface SshKeyboardInteractiveChallenge {
  name: string
  instruction: string
  prompts: SshKeyboardInteractivePrompt[]
}

export interface SshConnectionHandlers {
  /**
   * Called once per connection with the server's host key. Resolve `true` to
   * trust it (this attempt only — persistence is the app's job), `false` to
   * abort with HOST_KEY_REJECTED.
   */
  verifyHostKey: (key: SshHostKey) => Promise<boolean>
  /**
   * Answer a keyboard-interactive round. Return one string per prompt, or
   * `undefined` to cancel. Required for `auth.method === 'keyboardInteractive'`;
   * optional otherwise (password auth then answers prompts itself).
   */
  onKeyboardInteractive?: (challenge: SshKeyboardInteractiveChallenge) => Promise<string[] | undefined>
  /** Transport dropped after connect. Not called for `disconnect()`. */
  onDisconnected?: (reason: string) => void
  /** Fires with the connection id as soon as the attempt starts, for `cancelConnect`. */
  onStarted?: (id: number) => void
}

export interface SshShellOptionsSpec {
  /** TERM value. Empty string = no PTY. */
  term: string
  cols: number
  rows: number
  widthPx: number
  heightPx: number
  /** Best effort — servers only accept names listed in `AcceptEnv`. */
  env?: Record<string, string>
  /** Run this instead of the login shell (still with a PTY when `term` is set). */
  command?: string
}

export interface SshShellHandlers {
  /** Raw bytes from the remote side. Zero-copy: the buffer is owned by native memory. */
  onData: (data: ArrayBuffer) => void
  /** Only fires for non-PTY shells; with a PTY, stderr is merged into onData. */
  onStderr?: (data: ArrayBuffer) => void
  /** Exactly once. `exitCode` is undefined when the server closed without a status. */
  onClosed: (exitCode?: number) => void
}

export interface SshExecResult {
  stdout: ArrayBuffer
  stderr: ArrayBuffer
  /** -1 when the server closed without a status. */
  exitCode: number
}

/** Same as SshExecResult but decoded as UTF-8 natively (Hermes has no TextDecoder). */
export interface SshExecTextResult {
  stdout: string
  stderr: string
  exitCode: number
}

export interface SshForwardOptionsSpec {
  /** Loopback address to listen on. Anything else is refused. */
  bindAddress: string
  /** 0 = pick a free port. */
  localPort: number
  /** Destination as resolved by the server. */
  remoteHost: string
  remotePort: number
  /** 0 = default (64). */
  maxConnections: number
}

/**
 * Same shape as `SshForwardOptionsSpec`, but the destination is resolved by
 * this device over plain TCP: no SSH connection is involved. Exists so a web
 * view can reach an already-reachable service at a loopback address, where a
 * plain-http page is a secure context (WebCodecs and friends) and elsewhere
 * is not.
 */
export interface SshTcpForwardOptionsSpec {
  /** Loopback address to listen on. Anything else is refused. */
  bindAddress: string
  /** 0 = pick a free port. */
  localPort: number
  /** Destination as resolved by this device. */
  remoteHost: string
  remotePort: number
  /** 0 = default (64). */
  maxConnections: number
}

export interface SshForwardHandlers {
  /** Exactly once. `reason` is undefined for an app-initiated close. */
  onClosed: (reason?: string) => void
}

export type SshKeyType = 'ed25519' | 'ecdsaP256' | 'ecdsaP384' | 'rsa3072' | 'rsa4096'

export interface SshKeyPair {
  /** OpenSSH PEM (`-----BEGIN OPENSSH PRIVATE KEY-----`), encrypted if a passphrase was given. */
  privateKey: string
  /** One `authorized_keys` line. */
  publicKey: string
  fingerprint: string
}

export interface SshKeyInfo {
  algorithm: string
  publicKey: string
  fingerprint: string
  comment: string
  encrypted: boolean
}

// ---------------------------------------------------------------------------
// Hybrid objects
// ---------------------------------------------------------------------------

export interface SshShell extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  readonly id: number
  readonly isOpen: boolean
  /** Queue bytes for the remote side. Synchronous, never blocks. */
  write(data: ArrayBuffer): void
  /** Convenience for UTF-8 text. */
  writeString(data: string): void
  resize(cols: number, rows: number, widthPx: number, heightPx: number): void
  /** Send EOF on the channel (Ctrl-D at the transport level). */
  sendEof(): void
  /** Close the channel. Resolves after `onClosed` fired. Idempotent. */
  close(): Promise<void>
}

export interface SshLocalForward extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  readonly id: number
  /** The loopback port that is listening. */
  readonly localPort: number
  readonly isOpen: boolean
  /** Tunnelled TCP connections currently alive. */
  readonly activeConnections: number
  /** Stop listening and drop tunnelled connections. Idempotent. */
  close(): Promise<void>
}

export interface SshConnection extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  readonly id: number
  readonly isConnected: boolean
  readonly host: string
  readonly port: number
  readonly username: string
  /** The key that was accepted by `verifyHostKey`. */
  readonly hostKey: SshHostKey
  openShell(options: SshShellOptionsSpec, handlers: SshShellHandlers): Promise<SshShell>
  /** Run one command without a PTY and collect its output as raw bytes. */
  exec(command: string): Promise<SshExecResult>
  /** Like `exec`, output decoded as UTF-8 (invalid sequences become U+FFFD). */
  execText(command: string): Promise<SshExecTextResult>
  /** Local port forward (`direct-tcpip`): 127.0.0.1:localPort → remoteHost:remotePort via the server. */
  forwardLocal(options: SshForwardOptionsSpec, handlers: SshForwardHandlers): Promise<SshLocalForward>
  /** Close the transport. Idempotent. */
  disconnect(): Promise<void>
}

export interface SshClient extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  /** Version of the native core. */
  readonly version: string
  connect(options: SshConnectOptionsSpec, handlers: SshConnectionHandlers): Promise<SshConnection>
  /**
   * Abort a connect attempt (the promise rejects with CANCELLED) or, if it
   * already connected, disconnect it. Stale ids are ignored.
   */
  cancelConnect(id: number): void
  /** Runs off the JS thread (RSA can take seconds on a phone). */
  generateKeyPair(type: SshKeyType, comment?: string, passphrase?: string): Promise<SshKeyPair>
  /** Parse (and decrypt) a private key to validate it and show its public half. */
  inspectPrivateKey(privateKey: string, passphrase?: string): SshKeyInfo
  /**
   * Loopback listener piped over plain TCP to `remoteHost:remotePort`, with no
   * SSH involved. Same handle, caps and lifecycle as `SshConnection.forwardLocal`;
   * lives until `close()` or the process ends.
   */
  forwardTcp(options: SshTcpForwardOptionsSpec, handlers: SshForwardHandlers): Promise<SshLocalForward>
}
