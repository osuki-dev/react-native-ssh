/**
 * @osuki-dev/react-native-ssh — public API.
 *
 * ```ts
 * import { connect, SshError } from '@osuki-dev/react-native-ssh'
 *
 * const conn = await connect({
 *   host: 'example.com',
 *   username: 'me',
 *   auth: { type: 'password', password: '…' },
 *   verifyHostKey: async (key) => key.fingerprint === trustedFingerprint,
 * })
 * const shell = await conn.openShell(
 *   { cols: 80, rows: 24 },
 *   { onData: (bytes) => terminal.write(bytes), onClosed: () => {} },
 * )
 * shell.write('ls -la\n')
 * ```
 *
 * The library only does SSH. Bytes come out of a shell as `ArrayBuffer`s and
 * go in as `string | ArrayBuffer | Uint8Array`; rendering is up to you.
 */
import { NitroModules } from 'react-native-nitro-modules'

import { SshError, toSshError, wrapAsync, wrapSync } from './errors'
import type {
  SshClient as SshClientSpec,
  SshConnection as SshConnectionSpec,
  SshConnectionHandlers,
  SshConnectOptionsSpec,
  SshExecResult as SshExecResultSpec,
  SshForwardHandlers,
  SshForwardOptionsSpec,
  SshLocalForward as SshLocalForwardSpec,
  SshHostKey,
  SshKeyboardInteractiveChallenge,
  SshKeyboardInteractivePrompt,
  SshKeyInfo,
  SshKeyPair,
  SshKeyType,
  SshShell as SshShellSpec,
  SshShellHandlers,
  SshShellOptionsSpec,
  SshTcpForwardOptionsSpec,
} from './specs/Ssh.nitro'

export { SshError }
export type { SshErrorCode } from './errors'
export type { SshHostKey, SshKeyboardInteractiveChallenge, SshKeyboardInteractivePrompt, SshKeyInfo, SshKeyPair, SshKeyType }

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

export type SshAuth =
  /** Password. Falls back to keyboard-interactive automatically when the server only offers that. */
  | { type: 'password'; password: string }
  /** Private key in OpenSSH, PKCS#8, PKCS#1 PEM or PuTTY PPK format. */
  | { type: 'privateKey'; privateKey: string; passphrase?: string }
  /** Drive keyboard-interactive yourself via `onKeyboardInteractive`. */
  | { type: 'keyboardInteractive' }
  /** The `none` method. Only for servers that allow it. */
  | { type: 'none' }

export interface SshConnectOptions {
  host: string
  /** @default 22 */
  port?: number
  username: string
  auth: SshAuth
  /**
   * Decide whether to trust the server. Called once per connection. This
   * library never persists anything: store the fingerprint / public key in
   * your own secure storage and compare here.
   */
  verifyHostKey: (key: SshHostKey) => Promise<boolean> | boolean
  /**
   * Answer keyboard-interactive prompts (2FA codes, etc). Return one string
   * per prompt, or `undefined` to cancel. Required when `auth.type` is
   * `'keyboardInteractive'`.
   */
  onKeyboardInteractive?: (challenge: SshKeyboardInteractiveChallenge) => Promise<string[] | undefined> | string[] | undefined
  /** The transport dropped after connecting. Not fired for `disconnect()`. */
  onDisconnected?: (reason: string) => void
  /**
   * Abort the attempt: the returned promise rejects with `CANCELLED` (or the
   * connection is closed if it just succeeded). Wire this to a Cancel button,
   * especially while your `verifyHostKey` / `onKeyboardInteractive` UI is up.
   */
  signal?: AbortSignal
  /** Milliseconds for TCP + handshake + host key + auth. @default 30000 */
  connectTimeoutMs?: number
  /**
   * Milliseconds between keepalive probes when idle; 0 disables them.
   * Mobile networks drop silently, keep this on. @default 15000
   */
  keepaliveIntervalMs?: number
  /** Unanswered keepalives before the connection is declared dead. @default 3 */
  keepaliveMax?: number
  /**
   * Host key algorithms to offer first, most preferred first. Pass the
   * `algorithm` of the key you pinned for this host so the server presents
   * the same key type again instead of a different (also valid) one, which
   * would look like a changed host key. Unknown names are ignored.
   */
  hostKeyAlgorithms?: string[]
}

export interface SshShellOptions {
  /** TERM. Pass `''` for no PTY (raw stdout/stderr streams). @default 'xterm-256color' */
  term?: string
  /** @default 80 */
  cols?: number
  /** @default 24 */
  rows?: number
  widthPx?: number
  heightPx?: number
  /** Best effort — servers only accept names listed in their `AcceptEnv`. */
  env?: Record<string, string>
  /** Run this command instead of the login shell (with a PTY unless `term` is `''`). */
  command?: string
}

export interface SshShellEvents {
  /** Raw bytes from the remote side. The buffer is native-owned; copy it if you keep it. */
  onData: (data: ArrayBuffer) => void
  /** Only for shells opened without a PTY. With a PTY the server merges stderr into `onData`. */
  onStderr?: (data: ArrayBuffer) => void
  /** Fires exactly once. `exitCode` is undefined when the server gave none. */
  onClosed?: (exitCode: number | undefined) => void
}

export interface SshExecResult {
  stdout: string
  stderr: string
  /** -1 when the server closed the channel without reporting a status. */
  exitCode: number
}

export interface SshExecRawResult {
  stdout: ArrayBuffer
  stderr: ArrayBuffer
  exitCode: number
}

export interface SshForwardOptions {
  /** Destination host as resolved by the SSH server (often `127.0.0.1`). */
  remoteHost: string
  remotePort: number
  /** Loopback port to listen on. @default 0 (pick a free port) */
  localPort?: number
  /** Loopback address to listen on; anything else is refused. @default '127.0.0.1' */
  bindAddress?: string
  /** Cap on simultaneously tunnelled TCP connections. @default 64 */
  maxConnections?: number
}

export interface SshTcpForwardOptions {
  /** Destination host as resolved by this device (an IP or a name it can resolve). */
  remoteHost: string
  remotePort: number
  /** Loopback port to listen on. @default 0 (pick a free port) */
  localPort?: number
  /** Loopback address to listen on; anything else is refused. @default '127.0.0.1' */
  bindAddress?: string
  /** Cap on simultaneously piped TCP connections. @default 64 */
  maxConnections?: number
}

export interface SshForwardEvents {
  /** Fires exactly once. `reason` is undefined for an app-initiated close. */
  onClosed?: (reason: string | undefined) => void
}

export interface GenerateKeyPairOptions {
  /** @default 'ed25519' */
  type?: SshKeyType
  /** Appended to the public key line. */
  comment?: string
  /** Encrypts the private key with this passphrase. */
  passphrase?: string
}

// ---------------------------------------------------------------------------
// Native handle
// ---------------------------------------------------------------------------

let client: SshClientSpec | undefined

function native(): SshClientSpec {
  if (client === undefined) {
    client = NitroModules.createHybridObject<SshClientSpec>('SshClient')
  }
  return client
}

function toArrayBuffer(data: ArrayBuffer | Uint8Array): ArrayBuffer {
  if (data instanceof ArrayBuffer) return data
  if (data.byteOffset === 0 && data.byteLength === data.buffer.byteLength && data.buffer instanceof ArrayBuffer) {
    return data.buffer
  }
  return data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer
}

// ---------------------------------------------------------------------------
// Shell
// ---------------------------------------------------------------------------

export class SshShell {
  /** @internal */
  constructor(private readonly shell: SshShellSpec) {}

  get id(): number {
    return this.shell.id
  }

  get isOpen(): boolean {
    return this.shell.isOpen
  }

  /** Send input. Strings are UTF-8 encoded. Synchronous and never blocks. */
  write(data: string | ArrayBuffer | Uint8Array): void {
    wrapSync(() => {
      if (typeof data === 'string') {
        this.shell.writeString(data)
      } else {
        this.shell.write(toArrayBuffer(data))
      }
    })
  }

  resize(cols: number, rows: number, widthPx = 0, heightPx = 0): void {
    wrapSync(() => this.shell.resize(cols, rows, widthPx, heightPx))
  }

  /** Send EOF (like Ctrl-D at the transport level). */
  sendEof(): void {
    wrapSync(() => this.shell.sendEof())
  }

  /** Close the channel. Resolves after `onClosed` fired. Safe to call twice. */
  close(): Promise<void> {
    return wrapAsync(() => this.shell.close())
  }
}

// ---------------------------------------------------------------------------
// Local port forward
// ---------------------------------------------------------------------------

/**
 * A loopback listener whose connections are piped to `remoteHost:remotePort`
 * — through the SSH session for `conn.forwardLocal`, over plain TCP for
 * `forwardTcp`. Point any client (fetch, WebSocket, a web view, a gateway
 * SDK) at `http://127.0.0.1:${forward.localPort}`.
 */
export class SshLocalForward {
  /** @internal */
  constructor(private readonly forward: SshLocalForwardSpec) {}

  get id(): number {
    return this.forward.id
  }

  get localPort(): number {
    return this.forward.localPort
  }

  get isOpen(): boolean {
    return this.forward.isOpen
  }

  /** Tunnelled TCP connections currently alive. */
  get activeConnections(): number {
    return this.forward.activeConnections
  }

  /** Base URL for HTTP clients: `http://127.0.0.1:<localPort>`. */
  get httpUrl(): string {
    return `http://127.0.0.1:${this.localPort}`
  }

  /** Stop listening and drop tunnelled connections. Safe to call twice. */
  close(): Promise<void> {
    return wrapAsync(() => this.forward.close())
  }
}

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

export class SshConnection {
  /** @internal */
  constructor(private readonly conn: SshConnectionSpec) {}

  get id(): number {
    return this.conn.id
  }

  get isConnected(): boolean {
    return this.conn.isConnected
  }

  get host(): string {
    return this.conn.host
  }

  get port(): number {
    return this.conn.port
  }

  get username(): string {
    return this.conn.username
  }

  /** The host key that `verifyHostKey` accepted. */
  get hostKey(): SshHostKey {
    return this.conn.hostKey
  }

  /** Open an interactive shell (PTY by default). */
  async openShell(options: SshShellOptions = {}, events: SshShellEvents): Promise<SshShell> {
    const spec: SshShellOptionsSpec = {
      term: options.term ?? 'xterm-256color',
      cols: options.cols ?? 80,
      rows: options.rows ?? 24,
      widthPx: options.widthPx ?? 0,
      heightPx: options.heightPx ?? 0,
      env: options.env,
      command: options.command,
    }
    const handlers: SshShellHandlers = {
      onData: events.onData,
      onStderr: events.onStderr,
      onClosed: (exitCode) => events.onClosed?.(exitCode),
    }
    const shell = await wrapAsync(() => this.conn.openShell(spec, handlers))
    return new SshShell(shell)
  }

  /** Run one command without a PTY; output decoded as UTF-8. */
  exec(command: string): Promise<SshExecResult> {
    return wrapAsync(() => this.conn.execText(command))
  }

  /** Like `exec`, but returns raw bytes. */
  execRaw(command: string): Promise<SshExecRawResult> {
    return wrapAsync<SshExecResultSpec>(() => this.conn.exec(command))
  }

  /**
   * Local port forward (`direct-tcpip`). The forward closes itself when the
   * connection drops (`onClosed` with a reason).
   */
  async forwardLocal(options: SshForwardOptions, events: SshForwardEvents = {}): Promise<SshLocalForward> {
    const spec: SshForwardOptionsSpec = {
      bindAddress: options.bindAddress ?? '127.0.0.1',
      localPort: options.localPort ?? 0,
      remoteHost: options.remoteHost,
      remotePort: options.remotePort,
      maxConnections: options.maxConnections ?? 0,
    }
    const handlers: SshForwardHandlers = {
      onClosed: (reason) => events.onClosed?.(reason),
    }
    const forward = await wrapAsync(() => this.conn.forwardLocal(spec, handlers))
    return new SshLocalForward(forward)
  }

  /** Close the transport. Safe to call twice. */
  disconnect(): Promise<void> {
    return wrapAsync(() => this.conn.disconnect())
  }
}

// ---------------------------------------------------------------------------
// Top-level functions
// ---------------------------------------------------------------------------

/**
 * Open and authenticate a connection. Rejects with an `SshError` whose `code`
 * tells you what went wrong (`HOST_KEY_REJECTED`, `AUTH_FAILED`, `TIMEOUT`, …).
 */
export async function connect(options: SshConnectOptions): Promise<SshConnection> {
  const { auth } = options
  const spec: SshConnectOptionsSpec = {
    host: options.host,
    port: options.port ?? 22,
    username: options.username,
    auth:
      auth.type === 'password'
        ? { method: 'password', password: auth.password }
        : auth.type === 'privateKey'
          ? { method: 'publicKey', privateKey: auth.privateKey, passphrase: auth.passphrase }
          : auth.type === 'keyboardInteractive'
            ? { method: 'keyboardInteractive' }
            : { method: 'none' },
    connectTimeoutMs: options.connectTimeoutMs ?? 30_000,
    keepaliveIntervalMs: options.keepaliveIntervalMs ?? 15_000,
    keepaliveMax: options.keepaliveMax ?? 3,
    hostKeyAlgorithms: options.hostKeyAlgorithms,
  }

  const onKeyboardInteractive = options.onKeyboardInteractive
  const handlers: SshConnectionHandlers = {
    verifyHostKey: async (key) => {
      try {
        return (await options.verifyHostKey(key)) === true
      } catch {
        return false
      }
    },
    onKeyboardInteractive:
      onKeyboardInteractive === undefined
        ? undefined
        : async (challenge) => {
            try {
              return await onKeyboardInteractive(challenge)
            } catch {
              return undefined
            }
          },
    onDisconnected: options.onDisconnected,
  }

  if (auth.type === 'keyboardInteractive' && onKeyboardInteractive === undefined) {
    throw new SshError('INVALID_ARGUMENT', "auth.type 'keyboardInteractive' requires onKeyboardInteractive")
  }

  const signal = options.signal
  if (signal?.aborted) {
    throw new SshError('CANCELLED', 'connection cancelled before it started')
  }
  let cleanup: (() => void) | undefined
  if (signal !== undefined) {
    handlers.onStarted = (id) => {
      const cancel = () => native().cancelConnect(id)
      if (signal.aborted) {
        cancel()
        return
      }
      signal.addEventListener('abort', cancel, { once: true })
      cleanup = () => signal.removeEventListener('abort', cancel)
    }
  }

  try {
    const conn = await wrapAsync(() => native().connect(spec, handlers))
    return new SshConnection(conn)
  } finally {
    cleanup?.()
  }
}

/**
 * Loopback listener piped over plain TCP to `remoteHost:remotePort`, with no
 * SSH involved. For services this device can already reach but which must be
 * *addressed* as loopback: a web view is a secure context only on
 * `127.0.0.1` / `localhost`, so a plain-http page served from any other
 * address has no WebCodecs, no crypto.subtle and so on. The forward adds the
 * address and nothing else — it neither encrypts nor authenticates.
 *
 * Same handle, connection cap and lifecycle as `conn.forwardLocal`; the
 * listener lives until `close()` or the process ends. The `remoteHost` is
 * resolved by this device, not by any server.
 */
export async function forwardTcp(options: SshTcpForwardOptions, events: SshForwardEvents = {}): Promise<SshLocalForward> {
  const { remoteHost, remotePort } = options
  if (typeof remoteHost !== 'string' || remoteHost.trim() === '') {
    throw new SshError('INVALID_ARGUMENT', 'remoteHost must not be empty')
  }
  if (!Number.isInteger(remotePort) || remotePort < 1 || remotePort > 65535) {
    throw new SshError('INVALID_ARGUMENT', 'remotePort must be an integer in 1..65535')
  }
  const localPort = options.localPort ?? 0
  if (!Number.isInteger(localPort) || localPort < 0 || localPort > 65535) {
    throw new SshError('INVALID_ARGUMENT', 'localPort must be an integer in 0..65535')
  }
  const spec: SshTcpForwardOptionsSpec = {
    bindAddress: options.bindAddress ?? '127.0.0.1',
    localPort,
    remoteHost: remoteHost.trim(),
    remotePort,
    maxConnections: options.maxConnections ?? 0,
  }
  const handlers: SshForwardHandlers = {
    onClosed: (reason) => events.onClosed?.(reason),
  }
  const forward = await wrapAsync(() => native().forwardTcp(spec, handlers))
  return new SshLocalForward(forward)
}

/** Generate a new key pair. Ed25519 by default; RSA runs off the JS thread but still takes a while. */
export function generateKeyPair(options: GenerateKeyPairOptions = {}): Promise<SshKeyPair> {
  return wrapAsync(() => native().generateKeyPair(options.type ?? 'ed25519', options.comment, options.passphrase))
}

/**
 * Validate a private key and get its public half, fingerprint and comment.
 * Throws `SshError('KEY')` if the key cannot be parsed or the passphrase is wrong.
 */
export function inspectPrivateKey(privateKey: string, passphrase?: string): SshKeyInfo {
  return wrapSync(() => native().inspectPrivateKey(privateKey, passphrase))
}

/** Version of the native core. */
export function nativeVersion(): string {
  return native().version
}

/** Re-exported for callers that prefer `instanceof`-free checks. */
export const isSshError = SshError.is

// Keep the converter reachable for advanced users wrapping the raw hybrid objects.
export { toSshError }
