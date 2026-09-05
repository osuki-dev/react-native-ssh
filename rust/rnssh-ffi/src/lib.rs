//! C ABI over `rnssh-core`. This is the only surface the C++ Nitro layer sees.
//!
//! Conventions
//! -----------
//! * Every symbol is prefixed `rnssh_`. The header `cpp/rnssh.h` is generated
//!   from this file by cbindgen (`scripts/gen-header.sh`); never edit it by hand.
//! * Connections and shells are addressed by opaque `u64` handles that live in
//!   a process-wide registry. A stale handle is an error, never a crash.
//! * Strings passed *in* are NUL-terminated UTF-8 and are copied before the
//!   call returns. Strings passed *out* in callback structs are valid only for
//!   the duration of the callback.
//! * Callback structs carry a `void* user` plus a `release` function. Rust calls
//!   `release(user)` exactly once, after the last other callback, and never
//!   touches `user` again. That is the C++ side's signal to free its context.
//! * Callbacks may be invoked from any tokio worker thread and must not block.
//! * Shell output is handed over as an owned buffer (`ptr`, `len`, `cap`); the
//!   receiver must eventually call [`rnssh_bytes_free`] with the same triple.

#![allow(clippy::missing_safety_doc)]

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::ffi::{CStr, CString, c_char, c_void};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use dashmap::DashMap;
use rnssh_core::{
    Auth, ConnectOptions, Connection, ConnectionEvents, ErrorCode, ForwardEvents, ForwardOptions,
    HostKey, KeyType, KeyboardInteractiveChallenge, LocalForward, Shell, ShellEvents, ShellOptions,
    StreamKind, runtime,
};
use tokio::sync::oneshot;
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

struct ConnEntry {
    conn: Connection,
    /// Kept alive as long as the connection is registered so `release` fires
    /// exactly once, at unregister time.
    _events: Arc<ConnEvents>,
}

struct PendingConn {
    host_key: Mutex<Option<oneshot::Sender<bool>>>,
    kbi: Mutex<Option<oneshot::Sender<Option<Vec<String>>>>>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

struct Registry {
    next_id: AtomicU64,
    connections: DashMap<u64, ConnEntry>,
    /// Responders for in-flight interactive prompts, keyed by connection id.
    pending: DashMap<u64, Arc<PendingConn>>,
    /// Event bridges of connections that have not finished connecting yet.
    connecting: DashMap<u64, Arc<ConnEvents>>,
    /// Ids whose cancel arrived while the connect task was finishing.
    cancelled: dashmap::DashSet<u64>,
    shells: DashMap<u64, Shell>,
    forwards: DashMap<u64, LocalForward>,
}

fn registry() -> &'static Registry {
    static R: OnceLock<Registry> = OnceLock::new();
    R.get_or_init(|| Registry {
        next_id: AtomicU64::new(1),
        connections: DashMap::new(),
        pending: DashMap::new(),
        connecting: DashMap::new(),
        cancelled: dashmap::DashSet::new(),
        shells: DashMap::new(),
        forwards: DashMap::new(),
    })
}

fn next_id() -> u64 {
    registry().next_id.fetch_add(1, Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Types shared with C
// ---------------------------------------------------------------------------

/// Numeric error codes; see `ErrorCode` in rnssh-core. `0` is success.
pub type RnsshCode = u32;

pub const RNSSH_OK: RnsshCode = 0;

#[repr(u32)]
#[derive(Clone, Copy)]
pub enum RnsshAuthMethod {
    None = 0,
    Password = 1,
    PublicKey = 2,
    KeyboardInteractive = 3,
}

#[repr(C)]
pub struct RnsshConnectOptions {
    pub host: *const c_char,
    pub port: u16,
    pub username: *const c_char,
    /// One of the `RnsshAuthMethod_*` values. Read as a plain integer so an
    /// out-of-range value is an error instead of undefined behaviour.
    pub auth_method: u32,
    /// Password for `Password`; may be NULL otherwise.
    pub password: *const c_char,
    /// PEM for `PublicKey`; may be NULL otherwise.
    pub private_key: *const c_char,
    /// Optional passphrase for `private_key`.
    pub passphrase: *const c_char,
    pub connect_timeout_ms: u32,
    /// 0 disables keepalives.
    pub keepalive_interval_ms: u32,
    pub keepalive_max: u32,
    /// Host key algorithms to offer first (e.g. the pinned key's algorithm).
    /// May be NULL with `host_key_algorithm_count == 0`.
    pub host_key_algorithms: *const *const c_char,
    pub host_key_algorithm_count: usize,
}

#[repr(C)]
pub struct RnsshHostKey {
    pub algorithm: *const c_char,
    pub fingerprint: *const c_char,
    pub public_key: *const c_char,
}

#[repr(C)]
pub struct RnsshKbiPrompt {
    pub prompt: *const c_char,
    pub echo: bool,
}

#[repr(C)]
pub struct RnsshKbiChallenge {
    pub name: *const c_char,
    pub instruction: *const c_char,
    pub prompts: *const RnsshKbiPrompt,
    pub prompt_count: usize,
}

#[repr(C)]
pub struct RnsshConnectionCallbacks {
    pub user: *mut c_void,
    /// Answer with `rnssh_connection_respond_host_key`.
    pub on_host_key:
        Option<unsafe extern "C" fn(user: *mut c_void, conn: u64, key: *const RnsshHostKey)>,
    /// Answer with `rnssh_connection_respond_kbi`. NULL means the app has no
    /// handler; password auth then answers prompts itself.
    pub on_keyboard_interactive: Option<
        unsafe extern "C" fn(user: *mut c_void, conn: u64, challenge: *const RnsshKbiChallenge),
    >,
    /// Terminal: connect succeeded.
    pub on_connected:
        Option<unsafe extern "C" fn(user: *mut c_void, conn: u64, key: *const RnsshHostKey)>,
    /// Terminal: connect failed. `release` follows immediately.
    pub on_error: Option<
        unsafe extern "C" fn(user: *mut c_void, conn: u64, code: RnsshCode, message: *const c_char),
    >,
    /// Transport dropped after `on_connected`. Not called for app-initiated disconnects.
    pub on_disconnected:
        Option<unsafe extern "C" fn(user: *mut c_void, conn: u64, reason: *const c_char)>,
    pub release: Option<unsafe extern "C" fn(user: *mut c_void)>,
}

#[repr(C)]
pub struct RnsshShellOptions {
    /// Empty / NULL disables the PTY request.
    pub term: *const c_char,
    pub cols: u32,
    pub rows: u32,
    pub width_px: u32,
    pub height_px: u32,
    pub env_keys: *const *const c_char,
    pub env_values: *const *const c_char,
    pub env_count: usize,
    /// NULL for the login shell.
    pub command: *const c_char,
}

#[repr(C)]
pub struct RnsshShellCallbacks {
    pub user: *mut c_void,
    /// Fires exactly once: `code == 0` once the server accepted the shell,
    /// otherwise the error (and `release` follows immediately). Carries the
    /// shell handle so the callee never has to store the return value of
    /// `rnssh_shell_open` from another thread.
    pub on_opened: Option<
        unsafe extern "C" fn(
            user: *mut c_void,
            shell: u64,
            code: RnsshCode,
            message: *const c_char,
        ),
    >,
    /// `stream`: 0 = stdout, 1 = stderr. Ownership of `data` transfers to the
    /// callee; free it with `rnssh_bytes_free(data, len, cap)`.
    pub on_data: Option<
        unsafe extern "C" fn(
            user: *mut c_void,
            shell: u64,
            stream: u32,
            data: *mut u8,
            len: usize,
            cap: usize,
        ),
    >,
    /// Called once. `has_exit_code == false` means the server closed without a status.
    pub on_closed: Option<
        unsafe extern "C" fn(user: *mut c_void, shell: u64, has_exit_code: bool, exit_code: u32),
    >,
    pub release: Option<unsafe extern "C" fn(user: *mut c_void)>,
}

#[repr(C)]
pub struct RnsshForwardOptions {
    /// Loopback address to listen on; NULL = 127.0.0.1.
    pub bind: *const c_char,
    /// 0 = pick a free port.
    pub local_port: u16,
    pub remote_host: *const c_char,
    pub remote_port: u16,
    /// 0 = default (64).
    pub max_connections: u32,
}

#[repr(C)]
pub struct RnsshForwardCallbacks {
    pub user: *mut c_void,
    /// Fires exactly once: `code == 0` with the bound `local_port`, otherwise
    /// the error (and `release` follows immediately).
    pub on_opened: Option<
        unsafe extern "C" fn(
            user: *mut c_void,
            forward: u64,
            code: RnsshCode,
            message: *const c_char,
            local_port: u16,
        ),
    >,
    /// Fires exactly once after a successful open. `reason` is NULL for an
    /// app-initiated close.
    pub on_closed:
        Option<unsafe extern "C" fn(user: *mut c_void, forward: u64, reason: *const c_char)>,
    pub release: Option<unsafe extern "C" fn(user: *mut c_void)>,
}

/// One-shot completion for async calls that only succeed or fail.
#[repr(C)]
pub struct RnsshCompletion {
    pub user: *mut c_void,
    /// `code == 0` on success; `message` is NULL on success.
    pub on_complete:
        Option<unsafe extern "C" fn(user: *mut c_void, code: RnsshCode, message: *const c_char)>,
}

#[repr(C)]
pub struct RnsshExecResult {
    pub code: RnsshCode,
    pub message: *const c_char,
    pub stdout: *const u8,
    pub stdout_len: usize,
    pub stderr: *const u8,
    pub stderr_len: usize,
    pub has_exit_code: bool,
    pub exit_code: u32,
}

#[repr(C)]
pub struct RnsshExecCallback {
    pub user: *mut c_void,
    /// Buffers are valid only during the call; copy them.
    pub on_result: Option<unsafe extern "C" fn(user: *mut c_void, result: *const RnsshExecResult)>,
}

/// Output of key generation / inspection. Free with `rnssh_key_result_free`.
#[repr(C)]
pub struct RnsshKeyResult {
    pub code: RnsshCode,
    pub message: *mut c_char,
    pub private_key: *mut c_char,
    pub public_key: *mut c_char,
    pub fingerprint: *mut c_char,
    pub algorithm: *mut c_char,
    pub comment: *mut c_char,
    pub encrypted: bool,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Wraps a C `user` pointer so it can be sent across threads and released
/// exactly once on drop.
struct UserPtr {
    ptr: *mut c_void,
    release: Option<unsafe extern "C" fn(*mut c_void)>,
}
unsafe impl Send for UserPtr {}
unsafe impl Sync for UserPtr {}
impl Drop for UserPtr {
    fn drop(&mut self) {
        if let Some(f) = self.release {
            unsafe { f(self.ptr) }
        }
    }
}

/// Poisoning cannot happen with `panic = "abort"`, but never unwrap a lock.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

unsafe fn cstr_opt(p: *const c_char) -> Option<String> {
    if p.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
    }
}

unsafe fn cstr_or_empty(p: *const c_char) -> String {
    unsafe { cstr_opt(p) }.unwrap_or_default()
}

fn cstring(s: &str) -> CString {
    // Interior NULs cannot be represented; truncate rather than fail.
    CString::new(s.replace('\0', "")).unwrap_or_default()
}

fn into_raw(s: &str) -> *mut c_char {
    cstring(s).into_raw()
}

unsafe fn free_raw(p: *mut c_char) {
    if !p.is_null() {
        drop(unsafe { CString::from_raw(p) });
    }
}

struct CHostKey {
    _algorithm: CString,
    _fingerprint: CString,
    _public_key: CString,
    raw: RnsshHostKey,
}

impl CHostKey {
    fn new(k: &HostKey) -> Self {
        let algorithm = cstring(&k.algorithm);
        let fingerprint = cstring(&k.fingerprint);
        let public_key = cstring(&k.public_key);
        let raw = RnsshHostKey {
            algorithm: algorithm.as_ptr(),
            fingerprint: fingerprint.as_ptr(),
            public_key: public_key.as_ptr(),
        };
        Self {
            _algorithm: algorithm,
            _fingerprint: fingerprint,
            _public_key: public_key,
            raw,
        }
    }
}

fn complete(c: &RnsshCompletion, result: Result<(), rnssh_core::SshError>) {
    let Some(f) = c.on_complete else { return };
    match result {
        Ok(()) => unsafe { f(c.user, RNSSH_OK, std::ptr::null()) },
        Err(e) => {
            let msg = cstring(&e.message);
            unsafe { f(c.user, e.code as u32, msg.as_ptr()) }
        }
    }
}

/// Edition-2024 closures capture individual fields, which would strip the
/// `Send` marker; going through methods keeps the whole wrapper captured.
struct SendCompletion(RnsshCompletion);
unsafe impl Send for SendCompletion {}
impl SendCompletion {
    fn done(&self, result: Result<(), rnssh_core::SshError>) {
        complete(&self.0, result)
    }
}

struct SendExecCallback(RnsshExecCallback);
unsafe impl Send for SendExecCallback {}
impl SendExecCallback {
    fn call(&self, result: &RnsshExecResult) {
        if let Some(f) = self.0.on_result {
            unsafe { f(self.0.user, result) }
        }
    }
}

fn init_logging() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        #[cfg(target_os = "android")]
        {
            android_logger::init_once(
                android_logger::Config::default()
                    .with_max_level(log::LevelFilter::Info)
                    .with_tag("rnssh"),
            );
        }
        #[cfg(any(target_os = "ios", target_os = "macos"))]
        {
            let _ = oslog::OsLogger::new("dev.osuki.rnssh")
                .level_filter(log::LevelFilter::Info)
                .init();
        }
    });
}

// ---------------------------------------------------------------------------
// Connection events bridge
// ---------------------------------------------------------------------------

struct ConnEvents {
    id: u64,
    cbs: RnsshConnectionCallbacks,
    pending: Arc<PendingConn>,
    _user: UserPtr,
}
unsafe impl Send for ConnEvents {}
unsafe impl Sync for ConnEvents {}

impl ConnEvents {
    fn error(&self, code: ErrorCode, message: &str) {
        if let Some(f) = self.cbs.on_error {
            let msg = cstring(message);
            unsafe { f(self.cbs.user, self.id, code as u32, msg.as_ptr()) }
        }
    }
}

impl ConnectionEvents for ConnEvents {
    fn verify_host_key(&self, key: HostKey, respond: oneshot::Sender<bool>) {
        let Some(f) = self.cbs.on_host_key else {
            let _ = respond.send(false);
            return;
        };
        *lock(&self.pending.host_key) = Some(respond);
        let ck = CHostKey::new(&key);
        unsafe { f(self.cbs.user, self.id, &ck.raw) }
    }

    fn supports_keyboard_interactive(&self) -> bool {
        self.cbs.on_keyboard_interactive.is_some()
    }

    fn keyboard_interactive(
        &self,
        challenge: KeyboardInteractiveChallenge,
        respond: oneshot::Sender<Option<Vec<String>>>,
    ) {
        let Some(f) = self.cbs.on_keyboard_interactive else {
            let _ = respond.send(None);
            return;
        };
        *lock(&self.pending.kbi) = Some(respond);
        let name = cstring(&challenge.name);
        let instruction = cstring(&challenge.instruction);
        let prompt_strings: Vec<CString> = challenge
            .prompts
            .iter()
            .map(|p| cstring(&p.prompt))
            .collect();
        let prompts: Vec<RnsshKbiPrompt> = challenge
            .prompts
            .iter()
            .zip(prompt_strings.iter())
            .map(|(p, s)| RnsshKbiPrompt {
                prompt: s.as_ptr(),
                echo: p.echo,
            })
            .collect();
        let raw = RnsshKbiChallenge {
            name: name.as_ptr(),
            instruction: instruction.as_ptr(),
            prompts: prompts.as_ptr(),
            prompt_count: prompts.len(),
        };
        unsafe { f(self.cbs.user, self.id, &raw) }
    }

    fn disconnected(&self, reason: String) {
        // Unregister first so the handle is dead by the time JS hears about it.
        registry().connections.remove(&self.id);
        registry().pending.remove(&self.id);
        if let Some(f) = self.cbs.on_disconnected {
            let msg = cstring(&reason);
            unsafe { f(self.cbs.user, self.id, msg.as_ptr()) }
        }
    }
}

// ---------------------------------------------------------------------------
// Shell events bridge
// ---------------------------------------------------------------------------

struct ShellSink {
    id: u64,
    cbs: RnsshShellCallbacks,
    _user: UserPtr,
}
unsafe impl Send for ShellSink {}
unsafe impl Sync for ShellSink {}

impl ShellSink {
    fn opened(&self, result: Result<(), rnssh_core::SshError>) {
        let Some(f) = self.cbs.on_opened else { return };
        match result {
            Ok(()) => unsafe { f(self.cbs.user, self.id, RNSSH_OK, std::ptr::null()) },
            Err(e) => {
                let msg = cstring(&e.message);
                unsafe { f(self.cbs.user, self.id, e.code as u32, msg.as_ptr()) }
            }
        }
    }
}

impl ShellEvents for ShellSink {
    fn on_data(&self, stream: StreamKind, data: Vec<u8>) {
        let Some(f) = self.cbs.on_data else { return };
        let mut data = std::mem::ManuallyDrop::new(data);
        let (ptr, len, cap) = (data.as_mut_ptr(), data.len(), data.capacity());
        unsafe { f(self.cbs.user, self.id, stream as u32, ptr, len, cap) }
    }

    fn on_closed(&self, exit_code: Option<u32>) {
        registry().shells.remove(&self.id);
        if let Some(f) = self.cbs.on_closed {
            unsafe {
                f(
                    self.cbs.user,
                    self.id,
                    exit_code.is_some(),
                    exit_code.unwrap_or(0),
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Library version, static string.
#[unsafe(no_mangle)]
pub extern "C" fn rnssh_version() -> *const c_char {
    static V: OnceLock<CString> = OnceLock::new();
    V.get_or_init(|| cstring(rnssh_core::VERSION)).as_ptr()
}

/// Start connecting. Returns the connection handle immediately; the outcome
/// arrives via `on_connected` / `on_error`. Returns 0 only if `options` or
/// `callbacks` is NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rnssh_connect(
    options: *const RnsshConnectOptions,
    callbacks: *const RnsshConnectionCallbacks,
) -> u64 {
    init_logging();
    if options.is_null() || callbacks.is_null() {
        return 0;
    }
    let o = unsafe { &*options };
    let cbs = unsafe { std::ptr::read(callbacks) };
    let id = next_id();

    let auth = match o.auth_method {
        x if x == RnsshAuthMethod::None as u32 => Auth::None,
        x if x == RnsshAuthMethod::Password as u32 => {
            Auth::Password(Zeroizing::new(unsafe { cstr_or_empty(o.password) }))
        }
        x if x == RnsshAuthMethod::PublicKey as u32 => Auth::PrivateKey {
            pem: Zeroizing::new(unsafe { cstr_or_empty(o.private_key) }),
            passphrase: unsafe { cstr_opt(o.passphrase) }.map(Zeroizing::new),
        },
        x if x == RnsshAuthMethod::KeyboardInteractive as u32 => Auth::KeyboardInteractive,
        _ => return 0,
    };
    let opts = ConnectOptions {
        host: unsafe { cstr_or_empty(o.host) },
        port: o.port,
        username: unsafe { cstr_or_empty(o.username) },
        auth,
        connect_timeout: Duration::from_millis(if o.connect_timeout_ms == 0 {
            30_000
        } else {
            o.connect_timeout_ms as u64
        }),
        keepalive_interval: (o.keepalive_interval_ms > 0)
            .then(|| Duration::from_millis(o.keepalive_interval_ms as u64)),
        keepalive_max: o.keepalive_max.max(1) as usize,
        host_key_algorithms: if o.host_key_algorithms.is_null() || o.host_key_algorithm_count == 0 {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(o.host_key_algorithms, o.host_key_algorithm_count) }
                .iter()
                .map(|p| unsafe { cstr_or_empty(*p) })
                .filter(|s| !s.is_empty())
                .collect()
        },
        ..ConnectOptions::default()
    };

    let pending = Arc::new(PendingConn {
        host_key: Mutex::new(None),
        kbi: Mutex::new(None),
        task: Mutex::new(None),
    });
    registry().pending.insert(id, pending.clone());
    let events = Arc::new(ConnEvents {
        id,
        pending: pending.clone(),
        _user: UserPtr {
            ptr: cbs.user,
            release: cbs.release,
        },
        cbs,
    });

    registry().connecting.insert(id, events.clone());
    let task_pending = pending;
    let task = runtime::spawn(async move {
        let result = Connection::connect(opts, events.clone()).await;
        registry().pending.remove(&id);
        let still_wanted = registry().connecting.remove(&id).is_some();
        let cancel_raced = registry().cancelled.remove(&id).is_some();
        if !still_wanted {
            // rnssh_connection_cancel already reported CANCELLED and will
            // release the context; just make sure nothing stays open.
            if let Ok(conn) = result {
                conn.disconnect().await;
            }
            return;
        }
        match result {
            Ok(conn) if cancel_raced => {
                conn.disconnect().await;
                events.error(ErrorCode::Cancelled, "connection cancelled by the app");
            }
            Ok(conn) => {
                let key = CHostKey::new(conn.host_key());
                registry().connections.insert(
                    id,
                    ConnEntry {
                        conn,
                        _events: events.clone(),
                    },
                );
                if let Some(f) = events.cbs.on_connected {
                    unsafe { f(events.cbs.user, id, &key.raw) }
                }
            }
            Err(e) => events.error(e.code, &e.message),
        }
        // On failure `events` drops here → release(user).
    });
    *lock(&task_pending.task) = Some(task);
    id
}

#[unsafe(no_mangle)]
pub extern "C" fn rnssh_connection_respond_host_key(conn: u64, accept: bool) {
    if let Some(p) = registry().pending.get(&conn)
        && let Some(tx) = lock(&p.host_key).take()
    {
        let _ = tx.send(accept);
    }
}

/// `responses == NULL` cancels the authentication.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rnssh_connection_respond_kbi(
    conn: u64,
    responses: *const *const c_char,
    count: usize,
) {
    let answers = if responses.is_null() {
        None
    } else {
        let slice = unsafe { std::slice::from_raw_parts(responses, count) };
        Some(
            slice
                .iter()
                .map(|p| unsafe { cstr_or_empty(*p) })
                .collect::<Vec<_>>(),
        )
    };
    if let Some(p) = registry().pending.get(&conn)
        && let Some(tx) = lock(&p.kbi).take()
    {
        let _ = tx.send(answers);
    }
}

/// Abort a connection attempt. If it is still connecting, the attempt ends with
/// `on_error(CANCELLED)` followed by `release`; if it already connected, this
/// behaves like `rnssh_connection_disconnect` (no completion). Stale handles
/// are ignored.
#[unsafe(no_mangle)]
pub extern "C" fn rnssh_connection_cancel(conn: u64) {
    let reg = registry();
    // Flag first so a task finishing right now sees it.
    reg.cancelled.insert(conn);
    if let Some((_, events)) = reg.connecting.remove(&conn) {
        reg.cancelled.remove(&conn);
        if let Some(p) = reg.pending.remove(&conn).map(|(_, p)| p) {
            // Unblock any parked prompt, then stop the task.
            drop(lock(&p.host_key).take());
            drop(lock(&p.kbi).take());
            if let Some(task) = lock(&p.task).take() {
                task.abort();
            }
        }
        events.error(ErrorCode::Cancelled, "connection cancelled by the app");
        // `events` drops here (the aborted task drops its clone shortly after)
        // → release(user).
        return;
    }
    if let Some((_, e)) = reg.connections.remove(&conn) {
        reg.cancelled.remove(&conn);
        runtime::spawn(async move {
            e.conn.disconnect().await;
        });
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rnssh_connection_is_connected(conn: u64) -> bool {
    registry()
        .connections
        .get(&conn)
        .map(|e| e.conn.is_connected())
        .unwrap_or(false)
}

/// Close the transport. Always completes successfully, even for stale handles.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rnssh_connection_disconnect(conn: u64, completion: RnsshCompletion) {
    let completion = SendCompletion(completion);
    let entry = registry().connections.remove(&conn);
    registry().pending.remove(&conn);
    runtime::spawn(async move {
        if let Some((_, e)) = entry {
            e.conn.disconnect().await;
            // `e._events` drops here → release(user).
        }
        completion.done(Ok(()));
    });
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rnssh_connection_exec(
    conn: u64,
    command: *const c_char,
    callback: RnsshExecCallback,
) {
    let callback = SendExecCallback(callback);
    let command = unsafe { cstr_or_empty(command) };
    let connection = registry().connections.get(&conn).map(|e| e.conn.clone());
    runtime::spawn(async move {
        let result = match connection {
            None => Err(rnssh_core::SshError::not_found("connection")),
            Some(c) => c.exec(&command).await,
        };
        match result {
            Ok(r) => {
                let raw = RnsshExecResult {
                    code: RNSSH_OK,
                    message: std::ptr::null(),
                    stdout: r.stdout.as_ptr(),
                    stdout_len: r.stdout.len(),
                    stderr: r.stderr.as_ptr(),
                    stderr_len: r.stderr.len(),
                    has_exit_code: r.exit_code.is_some(),
                    exit_code: r.exit_code.unwrap_or(0),
                };
                callback.call(&raw);
            }
            Err(e) => {
                let msg = cstring(&e.message);
                let raw = RnsshExecResult {
                    code: e.code as u32,
                    message: msg.as_ptr(),
                    stdout: std::ptr::null(),
                    stdout_len: 0,
                    stderr: std::ptr::null(),
                    stderr_len: 0,
                    has_exit_code: false,
                    exit_code: 0,
                };
                callback.call(&raw);
            }
        }
    });
}

/// Open a PTY + shell. Returns the shell handle immediately; `on_opened`
/// fires once the server accepted the shell (or with an error, after which
/// `release` fires and the handle is dead). Returns 0 only for NULL arguments.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rnssh_shell_open(
    conn: u64,
    options: *const RnsshShellOptions,
    callbacks: *const RnsshShellCallbacks,
) -> u64 {
    if options.is_null() || callbacks.is_null() {
        return 0;
    }
    let o = unsafe { &*options };
    let cbs = unsafe { std::ptr::read(callbacks) };
    let id = next_id();

    let mut env = HashMap::new();
    if o.env_count > 0 && !o.env_keys.is_null() && !o.env_values.is_null() {
        let keys = unsafe { std::slice::from_raw_parts(o.env_keys, o.env_count) };
        let vals = unsafe { std::slice::from_raw_parts(o.env_values, o.env_count) };
        for (k, v) in keys.iter().zip(vals) {
            env.insert(unsafe { cstr_or_empty(*k) }, unsafe { cstr_or_empty(*v) });
        }
    }
    let opts = ShellOptions {
        term: unsafe { cstr_or_empty(o.term) },
        cols: o.cols.max(1),
        rows: o.rows.max(1),
        width_px: o.width_px,
        height_px: o.height_px,
        env,
        command: unsafe { cstr_opt(o.command) }.filter(|c| !c.is_empty()),
        ..ShellOptions::default()
    };
    let sink = Arc::new(ShellSink {
        id,
        _user: UserPtr {
            ptr: cbs.user,
            release: cbs.release,
        },
        cbs,
    });
    let connection = registry().connections.get(&conn).map(|e| e.conn.clone());

    runtime::spawn(async move {
        let result = match connection {
            None => Err(rnssh_core::SshError::not_found("connection")),
            Some(c) => c.open_shell(opts, sink.clone()).await,
        };
        match result {
            Ok(shell) => {
                registry().shells.insert(id, shell);
                sink.opened(Ok(()));
            }
            Err(e) => sink.opened(Err(e)),
        }
        // On error `sink` drops here → release(user).
    });
    id
}

#[unsafe(no_mangle)]
pub extern "C" fn rnssh_shell_is_open(shell: u64) -> bool {
    registry()
        .shells
        .get(&shell)
        .map(|s| s.is_open())
        .unwrap_or(false)
}

/// Queue bytes for the remote side. Copies `data`; never blocks.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rnssh_shell_write(shell: u64, data: *const u8, len: usize) -> RnsshCode {
    let Some(s) = registry().shells.get(&shell) else {
        return ErrorCode::NotFound as u32;
    };
    if data.is_null() || len == 0 {
        return RNSSH_OK;
    }
    let bytes = unsafe { std::slice::from_raw_parts(data, len) }.to_vec();
    match s.write(bytes) {
        Ok(()) => RNSSH_OK,
        Err(e) => e.code as u32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rnssh_shell_resize(
    shell: u64,
    cols: u32,
    rows: u32,
    width_px: u32,
    height_px: u32,
) -> RnsshCode {
    let Some(s) = registry().shells.get(&shell) else {
        return ErrorCode::NotFound as u32;
    };
    match s.resize(cols.max(1), rows.max(1), width_px, height_px) {
        Ok(()) => RNSSH_OK,
        Err(e) => e.code as u32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rnssh_shell_send_eof(shell: u64) -> RnsshCode {
    let Some(s) = registry().shells.get(&shell) else {
        return ErrorCode::NotFound as u32;
    };
    match s.eof() {
        Ok(()) => RNSSH_OK,
        Err(e) => e.code as u32,
    }
}

/// Close the shell. Always completes successfully; `on_closed` fires before.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rnssh_shell_close(shell: u64, completion: RnsshCompletion) {
    let completion = SendCompletion(completion);
    let s = registry().shells.get(&shell).map(|s| s.clone());
    runtime::spawn(async move {
        if let Some(s) = s {
            s.close().await;
        }
        completion.done(Ok(()));
    });
}

/// Free a buffer handed out by `on_data`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rnssh_bytes_free(ptr: *mut u8, len: usize, cap: usize) {
    if !ptr.is_null() {
        drop(unsafe { Vec::from_raw_parts(ptr, len, cap) });
    }
}

// ---------------------------------------------------------------------------
// Local port forwarding
// ---------------------------------------------------------------------------

struct ForwardSink {
    id: u64,
    cbs: RnsshForwardCallbacks,
    _user: UserPtr,
}
unsafe impl Send for ForwardSink {}
unsafe impl Sync for ForwardSink {}

impl ForwardSink {
    fn opened(&self, result: Result<u16, rnssh_core::SshError>) {
        let Some(f) = self.cbs.on_opened else { return };
        match result {
            Ok(port) => unsafe { f(self.cbs.user, self.id, RNSSH_OK, std::ptr::null(), port) },
            Err(e) => {
                let msg = cstring(&e.message);
                unsafe { f(self.cbs.user, self.id, e.code as u32, msg.as_ptr(), 0) }
            }
        }
    }
}

impl ForwardEvents for ForwardSink {
    fn on_closed(&self, reason: Option<String>) {
        registry().forwards.remove(&self.id);
        if let Some(f) = self.cbs.on_closed {
            match reason {
                Some(r) => {
                    let msg = cstring(&r);
                    unsafe { f(self.cbs.user, self.id, msg.as_ptr()) }
                }
                None => unsafe { f(self.cbs.user, self.id, std::ptr::null()) },
            }
        }
    }
}

unsafe fn forward_options(o: &RnsshForwardOptions) -> ForwardOptions {
    ForwardOptions {
        bind: unsafe { cstr_opt(o.bind) }
            .filter(|b| !b.is_empty())
            .unwrap_or_else(|| "127.0.0.1".into()),
        local_port: o.local_port,
        remote_host: unsafe { cstr_or_empty(o.remote_host) },
        remote_port: o.remote_port,
        max_connections: if o.max_connections == 0 {
            rnssh_core::forward::DEFAULT_MAX_FORWARD_CONNECTIONS
        } else {
            o.max_connections as usize
        },
    }
}

/// Start a local port forward on `conn`. Returns the forward handle
/// immediately; `on_opened` reports the bound port or the error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rnssh_forward_local(
    conn: u64,
    options: *const RnsshForwardOptions,
    callbacks: *const RnsshForwardCallbacks,
) -> u64 {
    if options.is_null() || callbacks.is_null() {
        return 0;
    }
    let o = unsafe { &*options };
    let cbs = unsafe { std::ptr::read(callbacks) };
    let id = next_id();
    let opts = unsafe { forward_options(o) };
    let sink = Arc::new(ForwardSink {
        id,
        _user: UserPtr {
            ptr: cbs.user,
            release: cbs.release,
        },
        cbs,
    });
    let connection = registry().connections.get(&conn).map(|e| e.conn.clone());
    runtime::spawn(async move {
        let result = match connection {
            None => Err(rnssh_core::SshError::not_found("connection")),
            Some(c) => c.forward_local(opts, sink.clone()).await,
        };
        match result {
            Ok(fwd) => {
                let port = fwd.local_port();
                registry().forwards.insert(id, fwd);
                sink.opened(Ok(port));
            }
            Err(e) => sink.opened(Err(e)),
        }
        // On error `sink` drops here → release(user).
    });
    id
}

/// Start a loopback listener piped to `remote_host:remote_port` over plain
/// TCP — no SSH connection involved. Same options, callbacks and handle
/// functions as [`rnssh_forward_local`]; the destination is resolved by this
/// device. Returns the forward handle immediately; `on_opened` reports the
/// bound port or the error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rnssh_forward_tcp(
    options: *const RnsshForwardOptions,
    callbacks: *const RnsshForwardCallbacks,
) -> u64 {
    if options.is_null() || callbacks.is_null() {
        return 0;
    }
    let o = unsafe { &*options };
    let cbs = unsafe { std::ptr::read(callbacks) };
    let id = next_id();
    let opts = unsafe { forward_options(o) };
    let sink = Arc::new(ForwardSink {
        id,
        _user: UserPtr {
            ptr: cbs.user,
            release: cbs.release,
        },
        cbs,
    });
    runtime::spawn(async move {
        match rnssh_core::forward::forward_tcp(opts, sink.clone()).await {
            Ok(fwd) => {
                let port = fwd.local_port();
                registry().forwards.insert(id, fwd);
                sink.opened(Ok(port));
            }
            Err(e) => sink.opened(Err(e)),
        }
        // On error `sink` drops here → release(user).
    });
    id
}

#[unsafe(no_mangle)]
pub extern "C" fn rnssh_forward_is_open(forward: u64) -> bool {
    registry()
        .forwards
        .get(&forward)
        .map(|f| f.is_open())
        .unwrap_or(false)
}

#[unsafe(no_mangle)]
pub extern "C" fn rnssh_forward_active_connections(forward: u64) -> u32 {
    registry()
        .forwards
        .get(&forward)
        .map(|f| u32::try_from(f.active_connections()).unwrap_or(u32::MAX))
        .unwrap_or(0)
}

/// Close the forward. Always completes successfully; `on_closed` fires before.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rnssh_forward_close(forward: u64, completion: RnsshCompletion) {
    let completion = SendCompletion(completion);
    let f = registry().forwards.get(&forward).map(|f| f.clone());
    runtime::spawn(async move {
        if let Some(f) = f {
            f.close().await;
        }
        completion.done(Ok(()));
    });
}

// ---------------------------------------------------------------------------
// Keys (synchronous; RSA generation is slow, callers should run it off the JS thread)
// ---------------------------------------------------------------------------

fn key_error(e: rnssh_core::SshError) -> RnsshKeyResult {
    RnsshKeyResult {
        code: e.code as u32,
        message: into_raw(&e.message),
        private_key: std::ptr::null_mut(),
        public_key: std::ptr::null_mut(),
        fingerprint: std::ptr::null_mut(),
        algorithm: std::ptr::null_mut(),
        comment: std::ptr::null_mut(),
        encrypted: false,
    }
}

/// `key_type`: 0 ed25519, 1 ecdsa-p256, 2 ecdsa-p384, 3 rsa-3072, 4 rsa-4096.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rnssh_generate_key_pair(
    key_type: u32,
    comment: *const c_char,
    passphrase: *const c_char,
) -> RnsshKeyResult {
    let Some(kt) = KeyType::from_u32(key_type) else {
        return key_error(rnssh_core::SshError::invalid(format!(
            "unknown key type {key_type}"
        )));
    };
    let comment = unsafe { cstr_opt(comment) };
    let passphrase = unsafe { cstr_opt(passphrase) };
    match rnssh_core::keys::generate_key_pair(kt, comment.as_deref(), passphrase.as_deref()) {
        Ok(kp) => RnsshKeyResult {
            code: RNSSH_OK,
            message: std::ptr::null_mut(),
            private_key: into_raw(&kp.private_key),
            public_key: into_raw(&kp.public_key),
            fingerprint: into_raw(&kp.fingerprint),
            algorithm: std::ptr::null_mut(),
            comment: into_raw(comment.as_deref().unwrap_or("")),
            encrypted: passphrase.map(|p| !p.is_empty()).unwrap_or(false),
        },
        Err(e) => key_error(e),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rnssh_inspect_private_key(
    pem: *const c_char,
    passphrase: *const c_char,
) -> RnsshKeyResult {
    let pem = unsafe { cstr_or_empty(pem) };
    let passphrase = unsafe { cstr_opt(passphrase) };
    match rnssh_core::keys::inspect_private_key(&pem, passphrase.as_deref()) {
        Ok(info) => RnsshKeyResult {
            code: RNSSH_OK,
            message: std::ptr::null_mut(),
            private_key: std::ptr::null_mut(),
            public_key: into_raw(&info.public_key),
            fingerprint: into_raw(&info.fingerprint),
            algorithm: into_raw(&info.algorithm),
            comment: into_raw(&info.comment),
            encrypted: info.encrypted,
        },
        Err(e) => key_error(e),
    }
}

/// Zeroizes and frees every string inside `result`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rnssh_key_result_free(result: *mut RnsshKeyResult) {
    if result.is_null() {
        return;
    }
    let r = unsafe { &mut *result };
    if !r.private_key.is_null() {
        // Secret: wipe before freeing.
        let s = unsafe { CString::from_raw(r.private_key) };
        drop(Zeroizing::new(s.into_bytes()));
        r.private_key = std::ptr::null_mut();
    }
    for p in [
        &mut r.message,
        &mut r.public_key,
        &mut r.fingerprint,
        &mut r.algorithm,
        &mut r.comment,
    ] {
        unsafe { free_raw(*p) };
        *p = std::ptr::null_mut();
    }
}
