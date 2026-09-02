/**
 * Stable error codes. Numeric values mirror `rnssh-core::ErrorCode` in Rust;
 * the string names are what you match on in JS.
 */
export type SshErrorCode =
  | 'INVALID_ARGUMENT'
  | 'NOT_FOUND'
  | 'CONNECT'
  | 'TIMEOUT'
  | 'HOST_KEY_REJECTED'
  | 'AUTH_FAILED'
  | 'KEY'
  | 'CLOSED'
  | 'PROTOCOL'
  | 'IO'
  | 'CANCELLED'
  | 'INTERNAL'
  /** The shell's write queue is full: the server stopped reading input. */
  | 'QUEUE_FULL'
  /** `exec` output exceeded the 16 MiB cap. */
  | 'TOO_LARGE'

const KNOWN_CODES: ReadonlySet<string> = new Set<SshErrorCode>([
  'INVALID_ARGUMENT',
  'NOT_FOUND',
  'CONNECT',
  'TIMEOUT',
  'HOST_KEY_REJECTED',
  'AUTH_FAILED',
  'KEY',
  'CLOSED',
  'PROTOCOL',
  'IO',
  'CANCELLED',
  'INTERNAL',
  'QUEUE_FULL',
  'TOO_LARGE',
])

/** Every failure from this library is an `SshError`. */
export class SshError extends Error {
  override readonly name = 'SshError'
  readonly code: SshErrorCode

  constructor(code: SshErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options)
    this.code = code
  }

  static is(error: unknown, code?: SshErrorCode): error is SshError {
    return error instanceof SshError && (code === undefined || error.code === code)
  }
}

// Async rejections arrive as `RNSSH_<CODE>: detail`; exceptions from
// synchronous hybrid methods are prefixed by Nitro with the method name,
// e.g. `SshClient.inspectPrivateKey(...): RNSSH_KEY: detail`.
const NATIVE_PREFIX = /(?:^|: )RNSSH_([A-Z_]+): ?([\s\S]*)$/

/**
 * Native code throws plain `Error`s whose message contains `RNSSH_<CODE>: <detail>`
 * (see cpp/RnsshBridge.hpp). Turn them into typed `SshError`s; pass anything
 * else through unchanged.
 */
export function toSshError(error: unknown): unknown {
  if (error instanceof SshError) return error
  if (error instanceof Error) {
    const match = NATIVE_PREFIX.exec(error.message)
    if (match !== null) {
      const code = match[1] ?? 'INTERNAL'
      const detail = match[2] ?? ''
      return new SshError(KNOWN_CODES.has(code) ? (code as SshErrorCode) : 'INTERNAL', detail, { cause: error })
    }
    return error
  }
  return error
}

/** Run `fn`, converting native errors (sync or async) into `SshError`. */
export async function wrapAsync<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn()
  } catch (e) {
    throw toSshError(e)
  }
}

export function wrapSync<T>(fn: () => T): T {
  try {
    return fn()
  } catch (e) {
    throw toSshError(e)
  }
}
