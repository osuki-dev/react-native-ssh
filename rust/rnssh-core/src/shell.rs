//! An interactive channel: PTY + shell (or PTY + command).
//!
//! The channel is owned by a single tokio task. Callers talk to it through a
//! bounded command queue, which makes `write` / `resize` synchronous and
//! lock-free from the JS thread's point of view. Output is pushed to a
//! [`ShellEvents`] sink as owned buffers.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use russh::client::Msg;
use russh::{Channel, ChannelMsg};
use tokio::sync::{mpsc, oneshot};

use crate::error::{ErrorCode, Result, SshError};
use crate::runtime;

/// Upper bound on bytes queued for the remote side before `write` refuses.
/// Interactive input is tiny; hitting this means the server stopped reading.
pub const MAX_PENDING_WRITE_BYTES: usize = 4 * 1024 * 1024;
/// Largest single buffer handed to the sink when coalescing.
pub const MAX_COALESCED_BYTES: usize = 256 * 1024;
/// Chunks smaller than this are interactive (echo, prompts) and are never
/// held back by the coalescing window; only bulk-sized packets are batched.
pub const INTERACTIVE_CHUNK_BYTES: usize = 4096;
const COMMAND_QUEUE_LEN: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum StreamKind {
    Stdout = 0,
    Stderr = 1,
}

/// Where shell output goes. Implemented by the FFI layer.
///
/// Both methods may be called from a tokio worker thread. `on_closed` is called
/// exactly once, after which no more `on_data` calls follow.
pub trait ShellEvents: Send + Sync + 'static {
    fn on_data(&self, stream: StreamKind, data: Vec<u8>);
    fn on_closed(&self, exit_code: Option<u32>);
}

#[derive(Debug, Clone)]
pub struct ShellOptions {
    /// `xterm-256color` etc. Empty disables the PTY request.
    pub term: String,
    pub cols: u32,
    pub rows: u32,
    pub width_px: u32,
    pub height_px: u32,
    /// Environment variables to request. Most servers only accept those listed
    /// in `AcceptEnv`, so treat this as best effort.
    pub env: HashMap<String, String>,
    /// If set, run this command instead of the login shell (still with a PTY
    /// when `term` is non-empty).
    pub command: Option<String>,
    /// Deadline for channel open + PTY + shell request.
    pub setup_timeout: Duration,
    /// Output coalescing window for bulk output. Interactive-sized chunks
    /// (< [`INTERACTIVE_CHUNK_BYTES`]) are always delivered immediately; the
    /// first bulk chunk after a quiet period is delivered immediately too, and
    /// bulk chunks arriving within this window afterwards are merged into one
    /// buffer (capped at [`MAX_COALESCED_BYTES`]) so a big transfer costs one
    /// JS dispatch per window instead of one per SSH packet. Zero disables.
    pub coalesce: Duration,
}

impl Default for ShellOptions {
    fn default() -> Self {
        Self {
            term: "xterm-256color".into(),
            cols: 80,
            rows: 24,
            width_px: 0,
            height_px: 0,
            env: HashMap::new(),
            command: None,
            setup_timeout: Duration::from_secs(30),
            coalesce: Duration::from_millis(4),
        }
    }
}

enum Command {
    Data(Vec<u8>),
    Resize {
        cols: u32,
        rows: u32,
        width_px: u32,
        height_px: u32,
    },
    Eof,
    Close(oneshot::Sender<()>),
}

/// Handle to a running shell. Cheap to clone; dropping it does not close the
/// channel (call [`Shell::close`]).
#[derive(Clone)]
pub struct Shell {
    tx: mpsc::Sender<Command>,
    open: Arc<AtomicBool>,
    pending_bytes: Arc<AtomicUsize>,
}

impl Shell {
    /// Requests PTY/env/shell on `channel`, then starts the pump task.
    /// Returns once the server has accepted the shell request.
    pub(crate) async fn start(
        mut channel: Channel<Msg>,
        options: ShellOptions,
        events: Arc<dyn ShellEvents>,
    ) -> Result<Shell> {
        // russh only *sends* channel requests; the server's accept/refuse comes
        // back later as ChannelMsg::Success / Failure. Wait for each reply so a
        // refused PTY or shell is an error instead of a silently dead channel.
        let mut early: Vec<(StreamKind, Vec<u8>)> = Vec::new();
        let setup = async {
            if !options.term.is_empty() {
                channel
                    .request_pty(
                        true,
                        &options.term,
                        options.cols,
                        options.rows,
                        options.width_px,
                        options.height_px,
                        &[],
                    )
                    .await?;
                if !await_reply(&mut channel, &mut early).await? {
                    return Err(SshError::new(
                        ErrorCode::Protocol,
                        "server refused the PTY request",
                    ));
                }
            }
            for (k, v) in &options.env {
                // Servers reject env vars outside AcceptEnv; do not fail the shell for it.
                if let Err(e) = channel.set_env(false, k.as_str(), v.as_str()).await {
                    log::debug!("set_env {k} failed: {e}");
                }
            }
            match &options.command {
                Some(cmd) => channel.exec(true, cmd.as_str()).await?,
                None => channel.request_shell(true).await?,
            }
            if !await_reply(&mut channel, &mut early).await? {
                return Err(SshError::new(
                    ErrorCode::Protocol,
                    match &options.command {
                        Some(_) => "server refused to run the command",
                        None => "server refused the shell request",
                    },
                ));
            }
            Ok::<(), SshError>(())
        };
        match tokio::time::timeout(options.setup_timeout, setup).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                let _ = channel.close().await;
                return Err(e);
            }
            Err(_) => {
                let _ = channel.close().await;
                return Err(SshError::new(
                    ErrorCode::Timeout,
                    "server did not accept the shell request in time",
                ));
            }
        }

        let (tx, rx) = mpsc::channel(COMMAND_QUEUE_LEN);
        let open = Arc::new(AtomicBool::new(true));
        let pending_bytes = Arc::new(AtomicUsize::new(0));
        for (kind, data) in early {
            events.on_data(kind, data);
        }
        runtime::spawn(pump(
            channel,
            rx,
            events,
            open.clone(),
            pending_bytes.clone(),
            options.coalesce,
        ));
        Ok(Shell {
            tx,
            open,
            pending_bytes,
        })
    }

    pub fn is_open(&self) -> bool {
        self.open.load(Ordering::Acquire)
    }

    /// Bytes accepted by `write` that have not yet been handed to the transport.
    pub fn pending_bytes(&self) -> usize {
        self.pending_bytes.load(Ordering::Acquire)
    }

    /// Queue bytes for the remote side. Never blocks; fails with
    /// [`ErrorCode::QueueFull`] once [`MAX_PENDING_WRITE_BYTES`] are pending.
    pub fn write(&self, data: Vec<u8>) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let len = data.len();
        let before = self.pending_bytes.fetch_add(len, Ordering::AcqRel);
        if before.saturating_add(len) > MAX_PENDING_WRITE_BYTES {
            self.pending_bytes.fetch_sub(len, Ordering::AcqRel);
            return Err(SshError::new(
                ErrorCode::QueueFull,
                "shell write queue is full; the server is not reading input",
            ));
        }
        if let Err(e) = self.send(Command::Data(data)) {
            self.pending_bytes.fetch_sub(len, Ordering::AcqRel);
            return Err(e);
        }
        Ok(())
    }

    pub fn resize(&self, cols: u32, rows: u32, width_px: u32, height_px: u32) -> Result<()> {
        self.send(Command::Resize {
            cols,
            rows,
            width_px,
            height_px,
        })
    }

    /// Send EOF on stdin (like Ctrl-D at the transport level).
    pub fn eof(&self) -> Result<()> {
        self.send(Command::Eof)
    }

    /// Close the channel. Resolves once the pump task has torn down. Idempotent.
    pub async fn close(&self) {
        let (done_tx, done_rx) = oneshot::channel();
        if self.tx.send(Command::Close(done_tx)).await.is_ok() {
            let _ = done_rx.await;
        }
    }

    fn send(&self, cmd: Command) -> Result<()> {
        if !self.is_open() {
            return Err(SshError::closed("shell"));
        }
        self.tx.try_send(cmd).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => SshError::new(
                ErrorCode::QueueFull,
                "shell command queue is full; the server is not reading input",
            ),
            mpsc::error::TrySendError::Closed(_) => SshError::closed("shell"),
        })
    }
}

/// Waits for the reply to the most recent `want_reply = true` request.
/// Output that arrives in the meantime is stashed in `early` so nothing is lost.
async fn await_reply(
    channel: &mut Channel<Msg>,
    early: &mut Vec<(StreamKind, Vec<u8>)>,
) -> Result<bool> {
    loop {
        match channel.wait().await {
            Some(ChannelMsg::Success) => return Ok(true),
            Some(ChannelMsg::Failure) => return Ok(false),
            Some(ChannelMsg::Data { data }) => early.push((StreamKind::Stdout, data.to_vec())),
            Some(ChannelMsg::ExtendedData { data, ext }) => {
                let kind = if ext == 1 {
                    StreamKind::Stderr
                } else {
                    StreamKind::Stdout
                };
                early.push((kind, data.to_vec()));
            }
            Some(ChannelMsg::Close) | Some(ChannelMsg::Eof) | None => {
                return Err(SshError::closed("channel"));
            }
            Some(_) => {}
        }
    }
}

/// Merges bursts of output into fewer, larger buffers. Interactive echo is
/// never delayed: a chunk that arrives after a quiet period goes out at once
/// and merely opens a window; only chunks *within* that window are batched.
struct Coalescer {
    window: Duration,
    window_until: Option<tokio::time::Instant>,
    kind: StreamKind,
    batch: Vec<u8>,
}

impl Coalescer {
    fn new(window: Duration) -> Self {
        Self {
            window,
            window_until: None,
            kind: StreamKind::Stdout,
            batch: Vec::new(),
        }
    }

    fn push(&mut self, events: &dyn ShellEvents, kind: StreamKind, data: &[u8]) {
        if self.window.is_zero() {
            events.on_data(kind, data.to_vec());
            return;
        }
        // Interactive-sized chunks never wait, as long as nothing bulk is
        // queued ahead of them (ordering must be preserved).
        if data.len() < INTERACTIVE_CHUNK_BYTES && self.batch.is_empty() {
            events.on_data(kind, data.to_vec());
            return;
        }
        if self.window_until.is_none() {
            // Quiet period just ended: deliver now, start batching what follows.
            events.on_data(kind, data.to_vec());
            self.window_until = Some(tokio::time::Instant::now() + self.window);
            return;
        }
        if !self.batch.is_empty()
            && (self.kind != kind || self.batch.len() + data.len() > MAX_COALESCED_BYTES)
        {
            self.flush(events);
            self.window_until = Some(tokio::time::Instant::now() + self.window);
        }
        if self.batch.is_empty() {
            self.kind = kind;
            self.batch.reserve(data.len().max(4096));
        }
        self.batch.extend_from_slice(data);
    }

    /// Called when the window deadline fires.
    fn tick(&mut self, events: &dyn ShellEvents) {
        if self.batch.is_empty() {
            self.window_until = None; // back to "quiet"
        } else {
            self.flush(events);
            self.window_until = Some(tokio::time::Instant::now() + self.window);
        }
    }

    fn flush(&mut self, events: &dyn ShellEvents) {
        if !self.batch.is_empty() {
            let out = std::mem::take(&mut self.batch);
            events.on_data(self.kind, out);
        }
    }
}

async fn pump(
    mut channel: Channel<Msg>,
    mut rx: mpsc::Receiver<Command>,
    events: Arc<dyn ShellEvents>,
    open: Arc<AtomicBool>,
    pending_bytes: Arc<AtomicUsize>,
    coalesce: Duration,
) {
    let mut exit_code: Option<u32> = None;
    let mut close_waiters: Vec<oneshot::Sender<()>> = Vec::new();
    let mut co = Coalescer::new(coalesce);

    loop {
        let deadline = co.window_until;
        tokio::select! {
            biased;
            _ = async {
                if let Some(at) = deadline { tokio::time::sleep_until(at).await }
            }, if deadline.is_some() => {
                co.tick(events.as_ref());
            }
            cmd = rx.recv() => {
                match cmd {
                    Some(Command::Data(bytes)) => {
                        let len = bytes.len();
                        let result = channel.data(bytes.as_slice()).await;
                        pending_bytes.fetch_sub(len, Ordering::AcqRel);
                        if let Err(e) = result {
                            log::warn!("shell write failed: {e}");
                            break;
                        }
                    }
                    Some(Command::Resize { cols, rows, width_px, height_px }) => {
                        if let Err(e) = channel.window_change(cols, rows, width_px, height_px).await {
                            log::debug!("window_change failed: {e}");
                        }
                    }
                    Some(Command::Eof) => {
                        let _ = channel.eof().await;
                    }
                    Some(Command::Close(done)) => {
                        close_waiters.push(done);
                        let _ = channel.close().await;
                        break;
                    }
                    None => break,
                }
            }
            msg = channel.wait() => {
                match msg {
                    Some(ChannelMsg::Data { data }) => {
                        co.push(events.as_ref(), StreamKind::Stdout, &data);
                    }
                    Some(ChannelMsg::ExtendedData { data, ext }) => {
                        let kind = if ext == 1 { StreamKind::Stderr } else { StreamKind::Stdout };
                        co.push(events.as_ref(), kind, &data);
                    }
                    Some(ChannelMsg::ExitStatus { exit_status }) => {
                        exit_code = Some(exit_status);
                    }
                    Some(ChannelMsg::ExitSignal { .. }) => {
                        exit_code.get_or_insert(128);
                    }
                    Some(ChannelMsg::Eof) => {
                        // Remote will not send more data; wait for Close.
                    }
                    Some(ChannelMsg::Close) | None => break,
                    Some(_) => {}
                }
            }
        }
    }

    co.flush(events.as_ref());
    open.store(false, Ordering::Release);
    // Drain any close requests that raced with the shutdown.
    while let Ok(cmd) = rx.try_recv() {
        if let Command::Close(done) = cmd {
            close_waiters.push(done);
        }
    }
    events.on_closed(exit_code);
    for w in close_waiters {
        let _ = w.send(());
    }
}

impl std::fmt::Debug for Shell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shell")
            .field("open", &self.is_open())
            .finish()
    }
}

impl From<ErrorCode> for SshError {
    fn from(code: ErrorCode) -> Self {
        SshError::new(code, code.as_str())
    }
}
