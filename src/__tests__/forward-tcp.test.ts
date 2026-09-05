import { beforeEach, describe, expect, mock, test } from 'bun:test'

// The native module is replaced by a fake that records what the wrapper
// hands it, so the wrapper's defaults and validation are pinned without a
// device: these are the only lines between `forwardTcp(options)` and the
// `RnsshForwardOptions` struct Rust sees.
type Call = { options: Record<string, unknown>; handlers: { onClosed: (reason?: string) => void } }
const calls: Call[] = []
let nextResult: (() => Promise<unknown>) | undefined

mock.module('react-native-nitro-modules', () => ({
  NitroModules: {
    createHybridObject: () => ({
      forwardTcp: (options: Record<string, unknown>, handlers: Call['handlers']) => {
        calls.push({ options, handlers })
        return (nextResult ?? (() => Promise.resolve(fakeForward)))()
      },
    }),
  },
}))

const fakeForward = {
  id: 7,
  localPort: 51234,
  isOpen: true,
  activeConnections: 0,
  close: () => Promise.resolve(),
}

const { forwardTcp, SshError, SshLocalForward } = await import('../index')

beforeEach(() => {
  calls.length = 0
  nextResult = undefined
})

describe('forwardTcp', () => {
  test('fills in the defaults the way forwardLocal does', async () => {
    const fwd = await forwardTcp({ remoteHost: '100.99.165.54', remotePort: 8801 })
    expect(calls).toHaveLength(1)
    expect(calls[0].options).toEqual({
      bindAddress: '127.0.0.1',
      localPort: 0,
      remoteHost: '100.99.165.54',
      remotePort: 8801,
      maxConnections: 0,
    })
    expect(fwd).toBeInstanceOf(SshLocalForward)
    expect(fwd.id).toBe(7)
    expect(fwd.localPort).toBe(51234)
    expect(fwd.httpUrl).toBe('http://127.0.0.1:51234')
  })

  test('passes explicit options through and trims the host', async () => {
    await forwardTcp({
      remoteHost: ' mac.local ',
      remotePort: 443,
      localPort: 4000,
      bindAddress: '::1',
      maxConnections: 8,
    })
    expect(calls[0].options).toEqual({
      bindAddress: '::1',
      localPort: 4000,
      remoteHost: 'mac.local',
      remotePort: 443,
      maxConnections: 8,
    })
  })

  test('refuses an empty host and out-of-range ports before touching native', async () => {
    for (const bad of [
      { remoteHost: '', remotePort: 80 },
      { remoteHost: '   ', remotePort: 80 },
      { remoteHost: 'h', remotePort: 0 },
      { remoteHost: 'h', remotePort: 65536 },
      { remoteHost: 'h', remotePort: 80.5 },
      { remoteHost: 'h', remotePort: 80, localPort: -1 },
      { remoteHost: 'h', remotePort: 80, localPort: 70000 },
    ]) {
      let thrown: unknown
      try {
        await forwardTcp(bad)
      } catch (e) {
        thrown = e
      }
      expect(SshError.is(thrown, 'INVALID_ARGUMENT')).toBe(true)
    }
    expect(calls).toHaveLength(0)
  })

  test('forwards onClosed and tolerates no handler', async () => {
    const reasons: (string | undefined)[] = []
    await forwardTcp({ remoteHost: 'h', remotePort: 1 }, { onClosed: (r) => reasons.push(r) })
    calls[0].handlers.onClosed('listener failed')
    calls[0].handlers.onClosed(undefined)
    expect(reasons).toEqual(['listener failed', undefined])

    await forwardTcp({ remoteHost: 'h', remotePort: 1 })
    expect(() => calls[1].handlers.onClosed('x')).not.toThrow()
  })

  test('turns a native rejection into a typed SshError', async () => {
    nextResult = () => Promise.reject(new Error('RNSSH_IO: cannot listen on 127.0.0.1:4000: address in use'))
    let thrown: unknown
    try {
      await forwardTcp({ remoteHost: 'h', remotePort: 1, localPort: 4000 })
    } catch (e) {
      thrown = e
    }
    expect(SshError.is(thrown, 'IO')).toBe(true)
    expect((thrown as Error).message).toContain('address in use')
  })
})
