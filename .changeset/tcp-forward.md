---
"@osuki-dev/react-native-ssh": minor
---

Plain TCP loopback forwarding: `forwardTcp({ remoteHost, remotePort, localPort?, bindAddress?, maxConnections? }, { onClosed? })` returns the same `SshLocalForward` handle as `conn.forwardLocal`, but pipes each accepted loopback connection straight to `remoteHost:remotePort` over TCP with no SSH involved. It gives a service the device can already reach a `127.0.0.1` address, which is what makes a web view a secure context (WebCodecs, `crypto.subtle`). The listener lives until `close()` or the process ends. Internally the SSH and TCP forwards now share one listener, connection cap and lifecycle behind a small upstream trait; the connection count is released by a drop guard, so a forward closed while tunnels were live no longer reports stale `activeConnections`.
