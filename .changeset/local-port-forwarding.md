---
"@osuki-dev/react-native-ssh": minor
---

Local port forwarding: `conn.forwardLocal({ remoteHost, remotePort, localPort?, bindAddress?, maxConnections? }, { onClosed? })` returns an `SshLocalForward` (`localPort`, `httpUrl`, `isOpen`, `activeConnections`, `close()`). The listener is loopback-only, capped at 64 concurrent tunnelled connections, back-pressured by SSH window flow control, and closes itself when the connection drops. The dev test server gained `direct-tcpip` support (loopback targets) and an HTTP endpoint on `port + 1` for exercising it.
