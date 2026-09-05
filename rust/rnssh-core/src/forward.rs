//! Local port forwarding: a loopback TCP listener whose accepted connections
//! are piped to an *upstream* — either an SSH `direct-tcpip` channel
//! (`Connection::forward_local`) or a plain TCP connection to `host:port`
//! (`forward_tcp`).
//!
//! The SSH flavour is what lets an app keep talking plain HTTP/WebSocket to a
//! service on the server (e.g. a gateway bound to `127.0.0.1` there) without
//! exposing it: point the client at `http://127.0.0.1:<local_port>` and the
//! bytes ride the authenticated, encrypted SSH session.
//!
//! The TCP flavour involves no SSH at all. It exists for the case where a
//! service is already reachable (a tailnet host, say) but must be *addressed*
//! as loopback: a web view is only a secure context on `127.0.0.1` /
//! `localhost`, and APIs such as WebCodecs are missing on a plain-http page
//! served from any other address. The forward adds nothing but the address.
//!
//! Safety rails, shared by both: the listener only ever binds a loopback
//! address, the number of concurrent tunnelled connections is capped, each
//! connection is a single `copy_bidirectional` (so back-pressure applies end
//! to end), and an SSH forward closes itself when its connection goes away.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use russh::client::{Handle, Handler as ClientHandler};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;

use crate::error::{ErrorCode, Result, SshError};
use crate::runtime;

/// Default cap on simultaneously tunnelled TCP connections per forward.
pub const DEFAULT_MAX_FORWARD_CONNECTIONS: usize = 64;

/// How long a TCP forward waits for the upstream `connect` before giving up on
/// one accepted connection (the listener itself stays up).
pub const TCP_UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Implemented by the FFI layer. `on_closed` fires exactly once, after the
/// listener stopped and the last tunnelled connection finished.
pub trait ForwardEvents: Send + Sync + 'static {
    /// `reason` is `None` for an app-initiated close.
    fn on_closed(&self, reason: Option<String>);
}

#[derive(Debug, Clone)]
pub struct ForwardOptions {
    /// Loopback address to listen on. Anything else is refused.
    pub bind: String,
    /// `0` picks a free port; the chosen port is in [`LocalForward::local_port`].
    pub local_port: u16,
    /// Destination: as resolved *by the server* for an SSH forward, as
    /// resolved by this device for a TCP forward.
    pub remote_host: String,
    pub remote_port: u16,
    pub max_connections: usize,
}

impl Default for ForwardOptions {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1".into(),
            local_port: 0,
            remote_host: "127.0.0.1".into(),
            remote_port: 0,
            max_connections: DEFAULT_MAX_FORWARD_CONNECTIONS,
        }
    }
}

/// Handle to a running local forward. Cheap to clone.
#[derive(Clone)]
pub struct LocalForward {
    local_port: u16,
    open: Arc<AtomicBool>,
    active: Arc<AtomicUsize>,
    shutdown: Arc<Notify>,
    finished: Arc<Notify>,
}

impl LocalForward {
    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    pub fn is_open(&self) -> bool {
        self.open.load(Ordering::Acquire)
    }

    /// Tunnelled TCP connections currently alive.
    pub fn active_connections(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }

    /// Stop listening and drop every tunnelled connection. Resolves once
    /// `on_closed` has been delivered. Idempotent.
    pub async fn close(&self) {
        if !self.open.swap(false, Ordering::AcqRel) {
            return;
        }
        self.shutdown.notify_waiters();
        self.shutdown.notify_one();
        self.finished.notified().await;
    }
}

impl std::fmt::Debug for LocalForward {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalForward")
            .field("local_port", &self.local_port)
            .field("open", &self.is_open())
            .field("active", &self.active_connections())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Upstreams
// ---------------------------------------------------------------------------

/// Where an accepted loopback connection is piped to. One implementation per
/// transport; the listener, accounting and lifecycle above are shared.
pub(crate) trait Upstream: Send + Sync + 'static {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send;

    /// Open one upstream stream for the connection accepted from `peer`.
    /// An error drops that one connection; the listener stays up.
    fn open(
        &self,
        peer: SocketAddr,
    ) -> impl Future<Output = std::result::Result<Self::Stream, String>> + Send;

    /// Polled once a second. An `Err` closes the whole forward with that
    /// reason — used by the SSH flavour when its transport is gone.
    fn liveness(&self) -> std::result::Result<(), String> {
        Ok(())
    }
}

/// SSH `direct-tcpip`: the destination is resolved by the server.
struct SshUpstream<H: ClientHandler + 'static> {
    handle: Arc<Handle<H>>,
    remote_host: String,
    remote_port: u16,
}

impl<H: ClientHandler + 'static> Upstream for SshUpstream<H> {
    type Stream = russh::ChannelStream<russh::client::Msg>;

    async fn open(&self, peer: SocketAddr) -> std::result::Result<Self::Stream, String> {
        self.handle
            .channel_open_direct_tcpip(
                self.remote_host.as_str(),
                u32::from(self.remote_port),
                peer.ip().to_string(),
                u32::from(peer.port()),
            )
            .await
            .map(|channel| channel.into_stream())
            .map_err(|e| {
                format!(
                    "forward to {}:{} refused: {e}",
                    self.remote_host, self.remote_port
                )
            })
    }

    fn liveness(&self) -> std::result::Result<(), String> {
        if self.handle.is_closed() {
            Err("ssh connection closed".into())
        } else {
            Ok(())
        }
    }
}

/// Plain TCP: the destination is resolved by this device. No SSH involved.
struct TcpUpstream {
    host: String,
    port: u16,
}

impl Upstream for TcpUpstream {
    type Stream = TcpStream;

    async fn open(&self, _peer: SocketAddr) -> std::result::Result<Self::Stream, String> {
        let connect = TcpStream::connect((self.host.as_str(), self.port));
        let stream = tokio::time::timeout(TCP_UPSTREAM_CONNECT_TIMEOUT, connect)
            .await
            .map_err(|_| format!("connect to {}:{} timed out", self.host, self.port))?
            .map_err(|e| format!("connect to {}:{} failed: {e}", self.host, self.port))?;
        let _ = stream.set_nodelay(true);
        Ok(stream)
    }
}

// ---------------------------------------------------------------------------
// Starting
// ---------------------------------------------------------------------------

/// SSH local forward on an established connection (`Connection::forward_local`).
pub(crate) async fn start<H: ClientHandler + 'static>(
    handle: Arc<Handle<H>>,
    options: ForwardOptions,
    events: Arc<dyn ForwardEvents>,
) -> Result<LocalForward> {
    let upstream = SshUpstream {
        handle,
        remote_host: options.remote_host.clone(),
        remote_port: options.remote_port,
    };
    start_with(upstream, options, events).await
}

/// Loopback listener piped to `remote_host:remote_port` over plain TCP.
/// Independent of any SSH connection; lives until [`LocalForward::close`] or
/// the process ends.
pub async fn forward_tcp(
    options: ForwardOptions,
    events: Arc<dyn ForwardEvents>,
) -> Result<LocalForward> {
    let upstream = TcpUpstream {
        host: options.remote_host.clone(),
        port: options.remote_port,
    };
    start_with(upstream, options, events).await
}

async fn start_with<U: Upstream>(
    upstream: U,
    options: ForwardOptions,
    events: Arc<dyn ForwardEvents>,
) -> Result<LocalForward> {
    let ip: IpAddr = options.bind.parse().map_err(|_| {
        SshError::invalid(format!(
            "bind address {:?} is not an IP address",
            options.bind
        ))
    })?;
    if !ip.is_loopback() {
        return Err(SshError::invalid(
            "local forwards may only bind a loopback address (127.0.0.1 / ::1)",
        ));
    }
    if options.remote_host.trim().is_empty() || options.remote_port == 0 {
        return Err(SshError::invalid("remoteHost and remotePort are required"));
    }
    let listener = TcpListener::bind(SocketAddr::new(ip, options.local_port))
        .await
        .map_err(|e| {
            SshError::new(
                ErrorCode::Io,
                format!("cannot listen on {}:{}: {e}", ip, options.local_port),
            )
        })?;
    let local_port = listener.local_addr()?.port();

    let open = Arc::new(AtomicBool::new(true));
    let active = Arc::new(AtomicUsize::new(0));
    let shutdown = Arc::new(Notify::new());
    let finished = Arc::new(Notify::new());
    let forward = LocalForward {
        local_port,
        open: open.clone(),
        active: active.clone(),
        shutdown: shutdown.clone(),
        finished: finished.clone(),
    };

    runtime::spawn(accept_loop(
        Arc::new(upstream),
        listener,
        options,
        events,
        open,
        active,
        shutdown,
        finished,
    ));
    Ok(forward)
}

#[allow(clippy::too_many_arguments)]
async fn accept_loop<U: Upstream>(
    upstream: Arc<U>,
    listener: TcpListener,
    options: ForwardOptions,
    events: Arc<dyn ForwardEvents>,
    open: Arc<AtomicBool>,
    active: Arc<AtomicUsize>,
    shutdown: Arc<Notify>,
    finished: Arc<Notify>,
) {
    let tunnels = tokio_util_lite::TaskSet::new();
    let mut liveness = tokio::time::interval(Duration::from_secs(1));
    let mut reason: Option<String> = None;

    loop {
        tokio::select! {
            biased;
            _ = shutdown.notified() => break,
            _ = liveness.tick() => {
                if let Err(why) = upstream.liveness() {
                    reason = Some(why);
                    break;
                }
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((socket, peer)) => {
                        if active.load(Ordering::Acquire) >= options.max_connections {
                            log::warn!("forward :{}: connection limit reached, refusing {peer}", options.remote_port);
                            drop(socket);
                            continue;
                        }
                        // Counted down by a guard, not after the await: an
                        // aborted tunnel (close() with live connections) must
                        // leave the count at zero too.
                        let counted = Counted::new(&active);
                        let upstream = upstream.clone();
                        let target = format!("{}:{}", options.remote_host, options.remote_port);
                        tunnels.spawn(async move {
                            let _counted = counted;
                            tunnel(upstream, socket, peer, target).await;
                        });
                    }
                    Err(e) => {
                        reason = Some(format!("listener failed: {e}"));
                        break;
                    }
                }
            }
        }
    }

    open.store(false, Ordering::Release);
    drop(listener);
    tunnels.abort_all();
    events.on_closed(reason);
    finished.notify_waiters();
    finished.notify_one();
}

/// One live tunnel in `active`, released on drop (including task abort).
struct Counted(Arc<AtomicUsize>);

impl Counted {
    fn new(active: &Arc<AtomicUsize>) -> Self {
        active.fetch_add(1, Ordering::AcqRel);
        Self(active.clone())
    }
}

impl Drop for Counted {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

async fn tunnel<U: Upstream>(
    upstream: Arc<U>,
    mut socket: TcpStream,
    peer: SocketAddr,
    target: String,
) {
    let mut stream = match upstream.open(peer).await {
        Ok(s) => s,
        Err(why) => {
            log::warn!("{why}");
            return;
        }
    };
    let _ = socket.set_nodelay(true);
    if let Err(e) = tokio::io::copy_bidirectional(&mut socket, &mut stream).await {
        log::debug!("tunnel {peer} → {target} ended: {e}");
    }
}

/// Minimal task set: spawn tunnels, abort all on shutdown. (Avoids pulling
/// tokio-util in just for JoinSet-with-abort semantics on older MSRVs.)
mod tokio_util_lite {
    use std::sync::Mutex;
    use tokio::task::JoinHandle;

    pub struct TaskSet {
        handles: Mutex<Vec<JoinHandle<()>>>,
    }

    impl TaskSet {
        pub fn new() -> Self {
            Self {
                handles: Mutex::new(Vec::new()),
            }
        }

        pub fn spawn<F>(&self, fut: F)
        where
            F: std::future::Future<Output = ()> + Send + 'static,
        {
            let mut handles = self.handles.lock().unwrap_or_else(|e| e.into_inner());
            handles.retain(|h| !h.is_finished());
            handles.push(crate::runtime::spawn(fut));
        }

        pub fn abort_all(&self) {
            let handles = self.handles.lock().unwrap_or_else(|e| e.into_inner());
            for h in handles.iter() {
                h.abort();
            }
        }
    }
}
