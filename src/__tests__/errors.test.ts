import { describe, expect, test } from 'bun:test'

import { SshError, toSshError } from '../errors'

describe('toSshError', () => {
  test('parses async rejections', () => {
    const e = toSshError(new Error('RNSSH_AUTH_FAILED: password rejected'))
    expect(SshError.is(e, 'AUTH_FAILED')).toBe(true)
    expect((e as SshError).message).toBe('password rejected')
  })

  test('parses Nitro-prefixed sync throws', () => {
    const e = toSshError(new Error('SshClient.inspectPrivateKey(...): RNSSH_KEY: bad key'))
    expect(SshError.is(e, 'KEY')).toBe(true)
    expect((e as SshError).message).toBe('bad key')
  })

  test('maps unknown codes to INTERNAL and keeps the cause', () => {
    const cause = new Error('RNSSH_SOMETHING_NEW: x')
    const e = toSshError(cause) as SshError
    expect(e.code).toBe('INTERNAL')
    expect(e.cause).toBe(cause)
  })

  test('passes unrelated errors through untouched', () => {
    const plain = new Error('boom')
    expect(toSshError(plain)).toBe(plain)
    expect(toSshError('str')).toBe('str')
  })

  test('new codes are recognised', () => {
    expect(SshError.is(toSshError(new Error('RNSSH_QUEUE_FULL: full')), 'QUEUE_FULL')).toBe(true)
    expect(SshError.is(toSshError(new Error('RNSSH_TOO_LARGE: big')), 'TOO_LARGE')).toBe(true)
  })
})
