//! Local port forwarding (`direct-tcpip`): a loopback TCP listener whose
//! accepted connections are tunnelled through the SSH transport to
//! `remote_host:remote_port` as seen from the server.
//!
//! This is what lets an app keep talking plain HTTP/WebSocket to a service on
//! the server (e.g. a gateway bound to `127.0.0.1` there) without exposing it:
//! point the client at `http://127.0.0.1:<local_port>` and the bytes ride the
//! authenticated, encrypted SSH session.
//!
//! Safety rails: the listener only ever binds a loopback address, the number
//! of concurrent tunnelled connections is capped, each connection is a single
//! `copy_bidirectional` (so SSH window flow control applies end to end), and
//! the forward closes itself when the SSH connection goes away.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use russh::client::{Handle, Handler as ClientHandler};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;

use crate::error::{ErrorCode, Result, SshError};
use crate::runtime;

/// Default cap on simultaneously tunnelled TCP connections per forward.
pub const DEFAULT_MAX_FORWARD_CONNECTIONS: usize = 64;

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
    /// Destination as resolved *by the server*.
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

pub(crate) async fn start<H: ClientHandler + 'static>(
    handle: Arc<Handle<H>>,
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
        handle, listener, options, events, open, active, shutdown, finished,
    ));
    Ok(forward)
}

#[allow(clippy::too_many_arguments)]
async fn accept_loop<H: ClientHandler + 'static>(
    handle: Arc<Handle<H>>,
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
                if handle.is_closed() {
                    reason = Some("ssh connection closed".into());
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
                        active.fetch_add(1, Ordering::AcqRel);
                        let active = active.clone();
                        let handle = handle.clone();
                        let host = options.remote_host.clone();
                        let port = options.remote_port;
                        tunnels.spawn(async move {
                            tunnel(handle, socket, peer, host, port).await;
                            active.fetch_sub(1, Ordering::AcqRel);
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

async fn tunnel<H: ClientHandler + 'static>(
    handle: Arc<Handle<H>>,
    mut socket: TcpStream,
    peer: SocketAddr,
    remote_host: String,
    remote_port: u16,
) {
    let channel = match handle
        .channel_open_direct_tcpip(
            remote_host.as_str(),
            u32::from(remote_port),
            peer.ip().to_string(),
            u32::from(peer.port()),
        )
        .await
    {
        Ok(c) => c,
        Err(e) => {
            log::warn!("forward to {remote_host}:{remote_port} refused: {e}");
            return;
        }
    };
    let _ = socket.set_nodelay(true);
    let mut stream = channel.into_stream();
    if let Err(e) = tokio::io::copy_bidirectional(&mut socket, &mut stream).await {
        log::debug!("tunnel {peer} → {remote_host}:{remote_port} ended: {e}");
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
