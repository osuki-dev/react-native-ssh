/**
 * Minimal manual test bench for @osuki-dev/react-native-ssh.
 *
 * Fill in a host, connect, watch the raw shell output, type a command.
 * No terminal emulator here on purpose — the library only does SSH.
 */
import { useCallback, useEffect, useRef, useState } from 'react'
import {
  Alert,
  Modal,
  Platform,
  Pressable,
  SafeAreaView,
  ScrollView,
  StatusBar as RNStatusBar,
  StyleSheet,
  Text,
  TextInput,
  View,
} from 'react-native'
import { StatusBar } from 'expo-status-bar'
import {
  connect,
  generateKeyPair,
  inspectPrivateKey,
  nativeVersion,
  SshError,
  type SshConnection,
  type SshLocalForward,
  type SshShell,
} from '@osuki-dev/react-native-ssh'

function bytesToText(buffer: ArrayBuffer): string {
  // Good enough for a test bench: ASCII passthrough, everything else as \xNN.
  const bytes = new Uint8Array(buffer)
  let out = ''
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i]!
    if (b === 0x1b) out += '␛'
    else if (b >= 0x20 && b < 0x7f) out += String.fromCharCode(b)
    else if (b === 0x0a) out += '\n'
    else if (b === 0x0d) out += ''
    else if (b === 0x09) out += '\t'
    else out += `\\x${b.toString(16).padStart(2, '0')}`
  }
  return out
}

export default function App() {
  const [host, setHost] = useState('')
  const [port, setPort] = useState('22')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [authMode, setAuthMode] = useState<'password' | 'privateKey' | 'keyboardInteractive'>('password')
  const [pinnedKey, setPinnedKey] = useState<{ algorithm: string; fingerprint: string } | null>(null)
  const [input, setInput] = useState('')
  const [connecting, setConnecting] = useState<AbortController | null>(null)
  const [prompt, setPrompt] = useState<{ title: string; text: string; secure: boolean; input: boolean; resolve: (v: string | undefined) => void } | null>(null)
  const [promptValue, setPromptValue] = useState('')
  const [log, setLog] = useState<string[]>([])
  const [output, setOutput] = useState('')
  const [connection, setConnection] = useState<SshConnection | null>(null)
  const [shell, setShell] = useState<SshShell | null>(null)
  const [forward, setForward] = useState<SshLocalForward | null>(null)
  const scrollRef = useRef<ScrollView>(null)

  const append = useCallback((line: string) => {
    setLog((prev) => [...prev.slice(-60), line])
  }, [])

  useEffect(() => {
    append(`native core v${nativeVersion()}`)
  }, [append])

  const describe = (e: unknown): string =>
    e instanceof SshError ? `${e.code}: ${e.message}` : e instanceof Error ? e.message : String(e)

  const onConnect = async () => {
    const controller = new AbortController()
    setConnecting(controller)
    try {
      let auth: Parameters<typeof connect>[0]['auth']
      if (authMode === 'privateKey') {
        // The dev test server accepts any public key for user `key`.
        const pair = await generateKeyPair({ type: 'ed25519', comment: 'example', passphrase: 'pw' })
        append(`using fresh key ${pair.fingerprint}`)
        auth = { type: 'privateKey', privateKey: pair.privateKey, passphrase: 'pw' }
      } else if (authMode === 'keyboardInteractive') {
        auth = { type: 'keyboardInteractive' }
      } else {
        auth = { type: 'password', password }
      }
      const conn = await connect({
        host: host.trim(),
        port: Number(port) || 22,
        username: username.trim(),
        auth,
        // Once a key was trusted, ask the server for that key type again.
        hostKeyAlgorithms: pinnedKey ? [pinnedKey.algorithm] : undefined,
        verifyHostKey: (key) => {
          if (pinnedKey !== null) {
            const same = key.fingerprint === pinnedKey.fingerprint
            append(`host key ${same ? 'matches' : 'MISMATCH vs'} pinned ${pinnedKey.fingerprint}`)
            return same
          }
          // In-app Modal rather than a native Alert so the Cancel button stays
          // reachable while the decision is pending (and so both platforms behave alike).
          return new Promise<boolean>((resolve) => {
            setPrompt({
              title: 'Host key',
              text: `${key.algorithm}\n${key.fingerprint}`,
              secure: false,
              input: false,
              resolve: (value) => {
                setPrompt(null)
                const trust = value !== undefined
                if (trust) setPinnedKey({ algorithm: key.algorithm, fingerprint: key.fingerprint })
                resolve(trust)
              },
            })
          })
        },
        signal: controller.signal,
        onKeyboardInteractive: (challenge) =>
          new Promise<string[] | undefined>((resolve) => {
            // Alert.prompt is iOS-only; a Modal works on both platforms.
            const first = challenge.prompts[0]
            setPromptValue('')
            setPrompt({
              title: challenge.name || 'Keyboard-interactive',
              text: `${challenge.instruction}\n${first?.prompt ?? ''}`.trim(),
              secure: !(first?.echo ?? false),
              input: true,
              resolve: (value) => {
                setPrompt(null)
                resolve(value === undefined ? undefined : challenge.prompts.map(() => value))
              },
            })
          }),
        onDisconnected: (reason) => {
          append(`disconnected: ${reason}`)
          setConnection(null)
          setShell(null)
        },
      })
      setConnection(conn)
      append(`connected to ${conn.host}:${conn.port} as ${conn.username}`)
      append(`host key ${conn.hostKey.fingerprint}`)

      const result = await conn.exec('uname -a')
      append(`exec exit=${result.exitCode}: ${result.stdout.trim()}${result.stderr ? ` (stderr: ${result.stderr.trim()})` : ''}`)

      const sh = await conn.openShell(
        { cols: 80, rows: 24 },
        {
          onData: (data) => setOutput((prev) => (prev + bytesToText(data)).slice(-6000)),
          onClosed: (code) => {
            append(`shell closed (exit ${code ?? 'n/a'})`)
            setShell(null)
          },
        },
      )
      setShell(sh)
      append(`shell #${sh.id} open`)
    } catch (e) {
      append(`error ${describe(e)}`)
    } finally {
      setConnecting(null)
    }
  }

  const onCancel = () => {
    connecting?.abort()
    prompt?.resolve(undefined)
  }

  const onSend = () => {
    if (shell === null) return
    try {
      shell.write(input + '\n')
      setInput('')
    } catch (e) {
      append(`write failed ${describe(e)}`)
    }
  }

  const onDisconnect = async () => {
    try {
      await forward?.close()
      setForward(null)
      await shell?.close()
      await connection?.disconnect()
      append('disconnected by app')
    } catch (e) {
      append(`disconnect failed ${describe(e)}`)
    } finally {
      setShell(null)
      setConnection(null)
    }
  }

  // Tunnel to the test server's HTTP endpoint (ssh port + 1 on the server's
  // loopback) and fetch through it — what a gateway-over-SSH setup does.
  const onForward = async () => {
    if (connection === null) return
    try {
      if (forward !== null) {
        await forward.close()
        setForward(null)
        append('forward closed')
        return
      }
      const fwd = await connection.forwardLocal(
        { remoteHost: '127.0.0.1', remotePort: (Number(port) || 22) + 1 },
        { onClosed: (reason) => { append(`forward closed${reason ? `: ${reason}` : ''}`); setForward(null) } },
      )
      setForward(fwd)
      append(`forward 127.0.0.1:${fwd.localPort} → server:${(Number(port) || 22) + 1}`)
      const t0 = Date.now()
      const res = await fetch(`${fwd.httpUrl}/hello?via=tunnel`)
      const body = await res.text()
      append(`fetch ${res.status} in ${Date.now() - t0}ms: ${body.slice(0, 120)}`)
      append(`active tunnels: ${fwd.activeConnections}`)
    } catch (e) {
      append(`forward failed ${describe(e)}`)
    }
  }

  const onKeys = async () => {
    try {
      const t0 = Date.now()
      const pair = await generateKeyPair({ type: 'ed25519', comment: 'example@rnssh', passphrase: 'pw' })
      const info = inspectPrivateKey(pair.privateKey, 'pw')
      append(`keygen ${Date.now() - t0}ms ${info.algorithm} ${info.fingerprint} encrypted=${info.encrypted}`)
      try {
        inspectPrivateKey(pair.privateKey)
      } catch (e) {
        append(`expected failure without passphrase → ${describe(e)}`)
      }
    } catch (e) {
      append(`keygen failed ${describe(e)}`)
    }
  }

  return (
    <SafeAreaView style={styles.root}>
      <StatusBar style="auto" />
      <View style={styles.row}>
        <TextInput style={[styles.input, styles.grow]} placeholder="host" autoCapitalize="none" autoCorrect={false} value={host} onChangeText={setHost} />
        <TextInput style={[styles.input, styles.port]} placeholder="22" keyboardType="number-pad" value={port} onChangeText={setPort} />
      </View>
      <View style={styles.row}>
        <TextInput style={[styles.input, styles.grow]} placeholder="username" autoCapitalize="none" autoCorrect={false} value={username} onChangeText={setUsername} />
        <TextInput style={[styles.input, styles.grow]} placeholder="password" secureTextEntry value={password} onChangeText={setPassword} />
      </View>
      <View style={styles.row}>
        {(['password', 'privateKey', 'keyboardInteractive'] as const).map((mode) => (
          <Pressable
            key={mode}
            style={[styles.chip, authMode === mode && styles.chipActive]}
            onPress={() => setAuthMode(mode)}
            testID={`auth-${mode}`}
            accessibilityLabel={`auth ${mode}`}
          >
            <Text style={[styles.chipText, authMode === mode && styles.chipTextActive]}>{mode}</Text>
          </Pressable>
        ))}
        <Pressable style={[styles.chip, pinnedKey === null && styles.buttonDisabled]} onPress={() => { setPinnedKey(null); append('pin cleared') }} disabled={pinnedKey === null} testID="unpin">
          <Text style={styles.chipText}>unpin</Text>
        </Pressable>
      </View>
      <View style={styles.row}>
        <Pressable style={[styles.button, connection !== null && styles.buttonDisabled]} onPress={onConnect} disabled={connection !== null} testID="connect">
          <Text style={styles.buttonText}>Connect</Text>
        </Pressable>
        <Pressable style={[styles.button, connection === null && styles.buttonDisabled]} onPress={onDisconnect} disabled={connection === null} testID="disconnect">
          <Text style={styles.buttonText}>Disconnect</Text>
        </Pressable>
        <Pressable style={styles.button} onPress={onKeys} testID="keygen">
          <Text style={styles.buttonText}>Keygen</Text>
        </Pressable>
        <Pressable style={[styles.button, connecting === null && styles.buttonDisabled]} onPress={onCancel} disabled={connecting === null} testID="cancel">
          <Text style={styles.buttonText}>Cancel</Text>
        </Pressable>
        <Pressable style={[styles.button, connection === null && styles.buttonDisabled]} onPress={onForward} disabled={connection === null} testID="forward">
          <Text style={styles.buttonText}>{forward === null ? 'Forward' : 'Unforward'}</Text>
        </Pressable>
      </View>
      <Modal visible={prompt !== null} transparent animationType="fade" onRequestClose={() => prompt?.resolve(undefined)}>
        <View style={styles.modalBackdrop}>
          <View style={styles.modalCard}>
            <Text style={styles.modalTitle}>{prompt?.title}</Text>
            <Text style={styles.modalText}>{prompt?.text}</Text>
            {prompt?.input ? (
              <TextInput
                style={styles.input}
                autoFocus
                autoCapitalize="none"
                autoCorrect={false}
                secureTextEntry={prompt.secure}
                value={promptValue}
                onChangeText={setPromptValue}
                onSubmitEditing={() => prompt.resolve(promptValue)}
                testID="prompt-input"
                accessibilityLabel="prompt answer"
              />
            ) : null}
            <View style={styles.row}>
              <Pressable style={styles.button} onPress={() => prompt?.resolve(undefined)} testID="prompt-cancel">
                <Text style={styles.buttonText}>{prompt?.input ? 'Cancel' : 'Reject'}</Text>
              </Pressable>
              <Pressable style={styles.button} onPress={() => prompt?.resolve(promptValue)} testID="prompt-ok">
                <Text style={styles.buttonText}>{prompt?.input ? 'OK' : 'Trust'}</Text>
              </Pressable>
              {prompt?.input ? null : (
                <Pressable style={styles.button} onPress={onCancel} testID="prompt-abort">
                  <Text style={styles.buttonText}>Cancel connect</Text>
                </Pressable>
              )}
            </View>
          </View>
        </View>
      </Modal>
      <ScrollView
        ref={scrollRef}
        style={styles.output}
        onContentSizeChange={() => scrollRef.current?.scrollToEnd({ animated: false })}
      >
        <Text style={styles.mono} testID="output">{output}</Text>
      </ScrollView>
      <View style={styles.row}>
        <TextInput
          style={[styles.input, styles.grow]}
          placeholder="command"
          autoCapitalize="none"
          autoCorrect={false}
          value={input}
          onChangeText={setInput}
          onSubmitEditing={onSend}
          editable={shell !== null}
          testID="command"
        />
        <Pressable style={[styles.button, shell === null && styles.buttonDisabled]} onPress={onSend} disabled={shell === null} testID="send">
          <Text style={styles.buttonText}>Send</Text>
        </Pressable>
      </View>
      <ScrollView style={styles.log}>
        {log.map((line, i) => (
          <Text key={i} style={styles.logLine} testID={`log-${i}`}>
            {line}
          </Text>
        ))}
      </ScrollView>
    </SafeAreaView>
  )
}

const styles = StyleSheet.create({
  // RN's SafeAreaView does not inset on Android (edge-to-edge), so keep the
  // first row out from under the status bar there.
  root: { flex: 1, backgroundColor: '#f6f6f6', padding: 8, gap: 6, paddingTop: Platform.OS === 'android' ? 8 + (RNStatusBar.currentHeight ?? 24) : 8 },
  row: { flexDirection: 'row', gap: 6 },
  grow: { flex: 1 },
  port: { width: 64 },
  input: { borderWidth: 1, borderColor: '#ccc', borderRadius: 6, paddingHorizontal: 8, height: 36, backgroundColor: '#fff' },
  button: { backgroundColor: '#1f6feb', paddingHorizontal: 12, justifyContent: 'center', borderRadius: 6, height: 36 },
  buttonDisabled: { opacity: 0.4 },
  buttonText: { color: '#fff', fontWeight: '600' },
  chip: { borderWidth: 1, borderColor: '#1f6feb', borderRadius: 14, paddingHorizontal: 10, height: 28, justifyContent: 'center' },
  chipActive: { backgroundColor: '#1f6feb' },
  chipText: { color: '#1f6feb', fontSize: 12 },
  chipTextActive: { color: '#fff' },
  modalBackdrop: { flex: 1, backgroundColor: 'rgba(0,0,0,0.45)', justifyContent: 'center', padding: 24 },
  modalCard: { backgroundColor: '#fff', borderRadius: 10, padding: 16, gap: 10 },
  modalTitle: { fontWeight: '700', fontSize: 16 },
  modalText: { color: '#333' },
  output: { flex: 2, backgroundColor: '#111', borderRadius: 6, padding: 6 },
  mono: { color: '#dcdcdc', fontFamily: 'Menlo', fontSize: 11 },
  log: { flex: 1, backgroundColor: '#fff', borderRadius: 6, padding: 6, borderWidth: 1, borderColor: '#ddd' },
  logLine: { fontSize: 11, fontFamily: 'Menlo', color: '#333' },
})
