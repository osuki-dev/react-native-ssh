//! Exercises the C ABI exactly the way the C++ layer does: raw callbacks,
//! `void* user` contexts, ownership transfer of output buffers, and the
//! "release exactly once" contract.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::ffi::{CStr, CString, c_char, c_void};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::*;
use tokio::sync::mpsc;

// ---------- server ----------

fn start_server() -> (u16, String) {
    let (config, fp) = rnssh_testserver::config();
    let rt = rnssh_core::runtime::handle();
    let listener = rt
        .block_on(tokio::net::TcpListener::bind(("127.0.0.1", 0)))
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    rt.spawn(async move {
        let _ = rnssh_testserver::serve(listener, config).await;
    });
    (port, fp)
}

// ---------- connection context ----------

#[derive(Debug, Clone, PartialEq)]
enum Ev {
    HostKey(String),
    Connected(String),
    Error(u32, String),
    Disconnected(String),
    Released,
    ShellData(u32, Vec<u8>),
    ShellClosed(Option<u32>),
    ShellReleased,
    Complete(u32, Option<String>),
}

struct Ctx {
    tx: mpsc::UnboundedSender<Ev>,
    accept_host_key: bool,
    /// `None` = never answer the host key prompt (simulates a stuck app dialog).
    answer_host_key: bool,
    released: AtomicUsize,
}

unsafe fn cstr(p: *const c_char) -> String {
    if p.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
    }
}

unsafe extern "C" fn on_host_key(user: *mut c_void, conn: u64, key: *const RnsshHostKey) {
    let ctx = unsafe { &*(user as *const Ctx) };
    let fp = unsafe { cstr((*key).fingerprint) };
    let _ = ctx.tx.send(Ev::HostKey(fp));
    if !ctx.answer_host_key {
        return;
    }
    // Answer from another thread, like the JS thread would.
    let accept = ctx.accept_host_key;
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(20));
        rnssh_connection_respond_host_key(conn, accept);
    });
}

unsafe extern "C" fn on_connected(user: *mut c_void, _conn: u64, key: *const RnsshHostKey) {
    let ctx = unsafe { &*(user as *const Ctx) };
    let _ = ctx
        .tx
        .send(Ev::Connected(unsafe { cstr((*key).fingerprint) }));
}

unsafe extern "C" fn on_error(user: *mut c_void, _conn: u64, code: RnsshCode, msg: *const c_char) {
    let ctx = unsafe { &*(user as *const Ctx) };
    let _ = ctx.tx.send(Ev::Error(code, unsafe { cstr(msg) }));
}

unsafe extern "C" fn on_disconnected(user: *mut c_void, _conn: u64, reason: *const c_char) {
    let ctx = unsafe { &*(user as *const Ctx) };
    let _ = ctx.tx.send(Ev::Disconnected(unsafe { cstr(reason) }));
}

unsafe extern "C" fn release(user: *mut c_void) {
    let ctx = unsafe { Box::from_raw(user as *mut Ctx) };
    ctx.released.fetch_add(1, Ordering::SeqCst);
    let _ = ctx.tx.send(Ev::Released);
    // Box drops here: a second release would be a double free, which the
    // sanitizer/allocator would catch under `cargo test`.
}

fn connect(
    port: u16,
    user: &str,
    password: &str,
    accept: bool,
) -> (u64, mpsc::UnboundedReceiver<Ev>) {
    connect_with(port, user, password, accept, true)
}

fn connect_with(
    port: u16,
    user: &str,
    password: &str,
    accept: bool,
    answer_host_key: bool,
) -> (u64, mpsc::UnboundedReceiver<Ev>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let ctx = Box::into_raw(Box::new(Ctx {
        tx,
        accept_host_key: accept,
        answer_host_key,
        released: AtomicUsize::new(0),
    }));
    let host = CString::new("127.0.0.1").unwrap();
    let user_c = CString::new(user).unwrap();
    let pass = CString::new(password).unwrap();
    let opts = RnsshConnectOptions {
        host: host.as_ptr(),
        port,
        username: user_c.as_ptr(),
        auth_method: RnsshAuthMethod::Password as u32,
        password: pass.as_ptr(),
        private_key: std::ptr::null(),
        passphrase: std::ptr::null(),
        connect_timeout_ms: 10_000,
        keepalive_interval_ms: 1_000,
        keepalive_max: 2,
        host_key_algorithms: std::ptr::null(),
        host_key_algorithm_count: 0,
    };
    let cbs = RnsshConnectionCallbacks {
        user: ctx as *mut c_void,
        on_host_key: Some(on_host_key),
        on_keyboard_interactive: None,
        on_connected: Some(on_connected),
        on_error: Some(on_error),
        on_disconnected: Some(on_disconnected),
        release: Some(release),
    };
    let id = unsafe { rnssh_connect(&opts, &cbs) };
    assert_ne!(id, 0);
    (id, rx)
}

fn next(rx: &mut mpsc::UnboundedReceiver<Ev>) -> Ev {
    rnssh_core::runtime::handle()
        .block_on(async { tokio::time::timeout(Duration::from_secs(10), rx.recv()).await })
        .expect("timed out waiting for event")
        .expect("channel closed")
}

// ---------- shell context ----------

struct ShellCtx {
    tx: mpsc::UnboundedSender<Ev>,
}

unsafe extern "C" fn shell_on_data(
    user: *mut c_void,
    _shell: u64,
    stream: u32,
    data: *mut u8,
    len: usize,
    cap: usize,
) {
    let ctx = unsafe { &*(user as *const ShellCtx) };
    let bytes = unsafe { std::slice::from_raw_parts(data, len) }.to_vec();
    // Ownership was transferred to us; give it back exactly once.
    unsafe { rnssh_bytes_free(data, len, cap) };
    let _ = ctx.tx.send(Ev::ShellData(stream, bytes));
}

unsafe extern "C" fn shell_on_closed(user: *mut c_void, _shell: u64, has: bool, code: u32) {
    let ctx = unsafe { &*(user as *const ShellCtx) };
    let _ = ctx.tx.send(Ev::ShellClosed(has.then_some(code)));
}

unsafe extern "C" fn shell_on_opened(
    user: *mut c_void,
    _shell: u64,
    code: RnsshCode,
    msg: *const c_char,
) {
    let ctx = unsafe { &*(user as *const ShellCtx) };
    let m = if msg.is_null() {
        None
    } else {
        Some(unsafe { cstr(msg) })
    };
    let _ = ctx.tx.send(Ev::Complete(code, m));
}

unsafe extern "C" fn shell_release(user: *mut c_void) {
    let ctx = unsafe { Box::from_raw(user as *mut ShellCtx) };
    let _ = ctx.tx.send(Ev::ShellReleased);
}

unsafe extern "C" fn on_complete(user: *mut c_void, code: RnsshCode, msg: *const c_char) {
    let tx = unsafe { Box::from_raw(user as *mut mpsc::UnboundedSender<Ev>) };
    let m = if msg.is_null() {
        None
    } else {
        Some(unsafe { cstr(msg) })
    };
    let _ = tx.send(Ev::Complete(code, m));
}

fn completion(tx: &mpsc::UnboundedSender<Ev>) -> RnsshCompletion {
    RnsshCompletion {
        user: Box::into_raw(Box::new(tx.clone())) as *mut c_void,
        on_complete: Some(on_complete),
    }
}

fn open_shell(conn: u64) -> (u64, mpsc::UnboundedReceiver<Ev>, mpsc::UnboundedSender<Ev>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let ctx = Box::into_raw(Box::new(ShellCtx { tx: tx.clone() }));
    let term = CString::new("xterm-256color").unwrap();
    let opts = RnsshShellOptions {
        term: term.as_ptr(),
        cols: 80,
        rows: 24,
        width_px: 0,
        height_px: 0,
        env_keys: std::ptr::null(),
        env_values: std::ptr::null(),
        env_count: 0,
        command: std::ptr::null(),
    };
    let cbs = RnsshShellCallbacks {
        user: ctx as *mut c_void,
        on_opened: Some(shell_on_opened),
        on_data: Some(shell_on_data),
        on_closed: Some(shell_on_closed),
        release: Some(shell_release),
    };
    let id = unsafe { rnssh_shell_open(conn, &opts, &cbs) };
    assert_ne!(id, 0);
    (id, rx, tx)
}

fn collect_until(rx: &mut mpsc::UnboundedReceiver<Ev>, needle: &str) -> String {
    let mut all = Vec::new();
    loop {
        match next(rx) {
            Ev::ShellData(_, d) => {
                all.extend_from_slice(&d);
                let s = String::from_utf8_lossy(&all).to_string();
                if s.contains(needle) {
                    return s;
                }
            }
            other => panic!("unexpected {other:?} while waiting for {needle:?}"),
        }
    }
}

// ---------- exec ----------

struct ExecOut {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    code: u32,
    exit: Option<u32>,
}

unsafe extern "C" fn on_exec(user: *mut c_void, r: *const RnsshExecResult) {
    let slot = unsafe { Box::from_raw(user as *mut Arc<Mutex<Option<ExecOut>>>) };
    let r = unsafe { &*r };
    let bytes = |p: *const u8, n: usize| {
        if p.is_null() {
            vec![]
        } else {
            unsafe { std::slice::from_raw_parts(p, n) }.to_vec()
        }
    };
    *slot.lock().unwrap() = Some(ExecOut {
        stdout: bytes(r.stdout, r.stdout_len),
        stderr: bytes(r.stderr, r.stderr_len),
        code: r.code,
        exit: r.has_exit_code.then_some(r.exit_code),
    });
}

fn exec(conn: u64, cmd: &str) -> ExecOut {
    let slot: Arc<Mutex<Option<ExecOut>>> = Arc::new(Mutex::new(None));
    let c = CString::new(cmd).unwrap();
    let cb = RnsshExecCallback {
        user: Box::into_raw(Box::new(slot.clone())) as *mut c_void,
        on_result: Some(on_exec),
    };
    unsafe { rnssh_connection_exec(conn, c.as_ptr(), cb) };
    for _ in 0..500 {
        if let Some(r) = slot.lock().unwrap().take() {
            return r;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("exec did not complete");
}

// ---------- tests ----------

#[test]
fn full_lifecycle_over_c_abi() {
    let (port, fp) = start_server();
    let (conn, mut rx) = connect(port, "test", "test", true);

    assert_eq!(next(&mut rx), Ev::HostKey(fp.clone()));
    assert_eq!(next(&mut rx), Ev::Connected(fp));
    assert!(rnssh_connection_is_connected(conn));

    // exec: stdout, stderr, exit codes, lossy bytes
    let r = exec(conn, "echo hi");
    assert_eq!(r.code, RNSSH_OK);
    assert_eq!(r.stdout, b"hi\n");
    assert_eq!(r.exit, Some(0));
    let r = exec(conn, "fail");
    assert_eq!(r.stderr, b"nope\n");
    assert_eq!(r.exit, Some(7));
    let r = exec(conn, "bytes");
    assert_eq!(r.stdout, vec![b'o', b'k', 0xff, 0xfe, b'\n']);

    // shell
    let (shell, mut srx, stx) = open_shell(conn);
    assert_eq!(next(&mut srx), Ev::Complete(RNSSH_OK, None));
    assert!(rnssh_shell_is_open(shell));
    collect_until(&mut srx, "$ ");
    let line = b"hello\n";
    assert_eq!(
        unsafe { rnssh_shell_write(shell, line.as_ptr(), line.len()) },
        RNSSH_OK
    );
    collect_until(&mut srx, "you said: hello");
    assert_eq!(rnssh_shell_resize(shell, 120, 40, 0, 0), RNSSH_OK);
    collect_until(&mut srx, "[resized to 120x40]");

    // close from our side: on_closed → completion → release
    unsafe { rnssh_shell_close(shell, completion(&stx)) };
    let mut seen = Vec::new();
    for _ in 0..3 {
        seen.push(next(&mut srx));
    }
    assert!(seen.contains(&Ev::ShellClosed(None)), "{seen:?}");
    assert!(seen.contains(&Ev::ShellReleased), "{seen:?}");
    assert!(
        seen.iter().any(|e| matches!(e, Ev::Complete(0, None))),
        "{seen:?}"
    );
    assert!(!rnssh_shell_is_open(shell));
    // stale handle → NOT_FOUND, never a crash
    assert_eq!(
        unsafe { rnssh_shell_write(shell, line.as_ptr(), line.len()) },
        2
    );

    // disconnect: release exactly once, no on_disconnected
    let (ctx_tx, mut crx) = mpsc::unbounded_channel();
    unsafe { rnssh_connection_disconnect(conn, completion(&ctx_tx)) };
    assert_eq!(next(&mut crx), Ev::Complete(RNSSH_OK, None));
    assert_eq!(next(&mut rx), Ev::Released);
    assert!(!rnssh_connection_is_connected(conn));
    std::thread::sleep(Duration::from_millis(200));
    assert!(rx.try_recv().is_err(), "no events after release");

    // disconnecting a stale handle is harmless
    let (t2, mut r2) = mpsc::unbounded_channel();
    unsafe { rnssh_connection_disconnect(conn, completion(&t2)) };
    assert_eq!(next(&mut r2), Ev::Complete(RNSSH_OK, None));
}

#[test]
fn rejected_host_key_releases_context() {
    let (port, fp) = start_server();
    let (conn, mut rx) = connect(port, "test", "test", false);
    assert_eq!(next(&mut rx), Ev::HostKey(fp));
    match next(&mut rx) {
        Ev::Error(5, msg) => assert!(msg.contains("rejected"), "{msg}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(next(&mut rx), Ev::Released);
    assert!(!rnssh_connection_is_connected(conn));
}

#[test]
fn wrong_password_reports_auth_failed() {
    let (port, _) = start_server();
    let (_conn, mut rx) = connect(port, "test", "wrong", true);
    let _ = next(&mut rx); // host key
    match next(&mut rx) {
        Ev::Error(6, _) => {}
        other => panic!("{other:?}"),
    }
    assert_eq!(next(&mut rx), Ev::Released);
}

#[test]
fn server_drop_reports_disconnected_then_releases() {
    let (config, _) = rnssh_testserver::config();
    let rt = rnssh_core::runtime::handle();
    let listener = rt
        .block_on(tokio::net::TcpListener::bind(("127.0.0.1", 0)))
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = rt.spawn(async move {
        let _ = rnssh_testserver::serve(listener, config).await;
    });
    let (conn, mut rx) = connect(port, "test", "test", true);
    let _ = next(&mut rx);
    assert!(matches!(next(&mut rx), Ev::Connected(_)));
    task.abort();
    match next(&mut rx) {
        Ev::Disconnected(reason) => assert!(!reason.is_empty()),
        other => panic!("{other:?}"),
    }
    assert!(!rnssh_connection_is_connected(conn));
    // The registry dropped the entry, so the context is released.
    assert_eq!(next(&mut rx), Ev::Released);
}

#[test]
fn key_results_round_trip_and_free() {
    let comment = CString::new("ffi@test").unwrap();
    let pass = CString::new("pw").unwrap();
    let mut r = unsafe { rnssh_generate_key_pair(0, comment.as_ptr(), pass.as_ptr()) };
    assert_eq!(r.code, RNSSH_OK);
    let pem = unsafe { cstr(r.private_key) };
    let fp = unsafe { cstr(r.fingerprint) };
    assert!(pem.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
    assert!(r.encrypted);
    unsafe { rnssh_key_result_free(&mut r) };
    assert!(r.private_key.is_null() && r.message.is_null());
    // freeing twice is safe
    unsafe { rnssh_key_result_free(&mut r) };

    let pem_c = CString::new(pem).unwrap();
    let mut info = unsafe { rnssh_inspect_private_key(pem_c.as_ptr(), pass.as_ptr()) };
    assert_eq!(info.code, RNSSH_OK);
    assert_eq!(unsafe { cstr(info.fingerprint) }, fp);
    assert_eq!(unsafe { cstr(info.comment) }, "ffi@test");
    unsafe { rnssh_key_result_free(&mut info) };

    let mut bad = unsafe { rnssh_inspect_private_key(pem_c.as_ptr(), std::ptr::null()) };
    assert_eq!(bad.code, 7);
    assert!(unsafe { cstr(bad.message) }.contains("passphrase"));
    unsafe { rnssh_key_result_free(&mut bad) };

    let mut unknown = unsafe { rnssh_generate_key_pair(99, std::ptr::null(), std::ptr::null()) };
    assert_eq!(unknown.code, 1);
    unsafe { rnssh_key_result_free(&mut unknown) };

    assert!(!rnssh_version().is_null());
}

#[test]
fn cancel_while_waiting_for_host_key() {
    let (port, _) = start_server();
    let (conn, mut rx) = connect_with(port, "test", "test", true, false);
    assert!(matches!(next(&mut rx), Ev::HostKey(_)));
    // The app never answers the prompt; the user gives up.
    rnssh_connection_cancel(conn);
    match next(&mut rx) {
        Ev::Error(11, msg) => assert!(msg.contains("cancel"), "{msg}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(next(&mut rx), Ev::Released);
    assert!(!rnssh_connection_is_connected(conn));
    std::thread::sleep(Duration::from_millis(200));
    assert!(rx.try_recv().is_err(), "nothing after release");
    // Cancelling again (stale) is harmless.
    rnssh_connection_cancel(conn);
}

#[test]
fn cancel_after_connected_acts_as_disconnect() {
    let (port, _) = start_server();
    let (conn, mut rx) = connect(port, "test", "test", true);
    let _ = next(&mut rx);
    assert!(matches!(next(&mut rx), Ev::Connected(_)));
    rnssh_connection_cancel(conn);
    assert_eq!(next(&mut rx), Ev::Released);
    assert!(!rnssh_connection_is_connected(conn));
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        rx.try_recv().is_err(),
        "no disconnect event for an app-initiated cancel"
    );
}

// ---------- local port forwarding over the C ABI ----------

struct FwdCtx {
    tx: mpsc::UnboundedSender<Ev>,
}

unsafe extern "C" fn fwd_on_opened(
    user: *mut c_void,
    _f: u64,
    code: RnsshCode,
    msg: *const c_char,
    port: u16,
) {
    let ctx = unsafe { &*(user as *const FwdCtx) };
    let m = if msg.is_null() {
        Some(port.to_string())
    } else {
        Some(unsafe { cstr(msg) })
    };
    let _ = ctx.tx.send(Ev::Complete(code, m));
}

unsafe extern "C" fn fwd_on_closed(user: *mut c_void, _f: u64, reason: *const c_char) {
    let ctx = unsafe { &*(user as *const FwdCtx) };
    let r = if reason.is_null() {
        String::new()
    } else {
        unsafe { cstr(reason) }
    };
    let _ = ctx.tx.send(Ev::Disconnected(r));
}

unsafe extern "C" fn fwd_release(user: *mut c_void) {
    let ctx = unsafe { Box::from_raw(user as *mut FwdCtx) };
    let _ = ctx.tx.send(Ev::Released);
}

#[test]
fn local_forward_over_c_abi() {
    use std::io::{Read, Write};
    let (port, _) = start_server();
    let http_port = {
        let rt = rnssh_core::runtime::handle();
        let listener = rt
            .block_on(tokio::net::TcpListener::bind(("127.0.0.1", 0)))
            .unwrap();
        let p = listener.local_addr().unwrap().port();
        rt.spawn(rnssh_testserver::serve_http(listener));
        p
    };
    let (conn, mut rx) = connect(port, "test", "test", true);
    let _ = next(&mut rx);
    assert!(matches!(next(&mut rx), Ev::Connected(_)));

    let (ftx, mut frx) = mpsc::unbounded_channel();
    let ctx = Box::into_raw(Box::new(FwdCtx { tx: ftx.clone() }));
    let remote = CString::new("127.0.0.1").unwrap();
    let opts = RnsshForwardOptions {
        bind: std::ptr::null(),
        local_port: 0,
        remote_host: remote.as_ptr(),
        remote_port: http_port,
        max_connections: 0,
    };
    let cbs = RnsshForwardCallbacks {
        user: ctx as *mut c_void,
        on_opened: Some(fwd_on_opened),
        on_closed: Some(fwd_on_closed),
        release: Some(fwd_release),
    };
    let fwd = unsafe { rnssh_forward_local(conn, &opts, &cbs) };
    assert_ne!(fwd, 0);
    let local_port: u16 = match next(&mut frx) {
        Ev::Complete(0, Some(p)) => p.parse().unwrap(),
        other => panic!("{other:?}"),
    };
    assert!(rnssh_forward_is_open(fwd));

    // Plain HTTP through the tunnel, from a blocking std socket like an app's fetch would.
    let mut s = std::net::TcpStream::connect(("127.0.0.1", local_port)).unwrap();
    s.write_all(b"GET /hello HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).unwrap();
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
    assert!(resp.contains("\"path\":\"/hello\""), "{resp}");
    assert!(resp.contains("rnssh-testserver"), "{resp}");

    unsafe { rnssh_forward_close(fwd, completion(&ftx)) };
    let mut seen = Vec::new();
    for _ in 0..3 {
        seen.push(next(&mut frx));
    }
    assert!(seen.contains(&Ev::Disconnected(String::new())), "{seen:?}");
    assert!(seen.contains(&Ev::Released), "{seen:?}");
    assert!(
        seen.iter().any(|e| matches!(e, Ev::Complete(0, None))),
        "{seen:?}"
    );
    assert!(!rnssh_forward_is_open(fwd));
    assert_eq!(rnssh_forward_active_connections(fwd), 0);

    // Stale connection handle → on_opened with NOT_FOUND, then release.
    let (ftx2, mut frx2) = mpsc::unbounded_channel();
    let ctx2 = Box::into_raw(Box::new(FwdCtx { tx: ftx2 }));
    let cbs2 = RnsshForwardCallbacks {
        user: ctx2 as *mut c_void,
        on_opened: Some(fwd_on_opened),
        on_closed: Some(fwd_on_closed),
        release: Some(fwd_release),
    };
    let _ = unsafe { rnssh_forward_local(999_999, &opts, &cbs2) };
    assert!(matches!(next(&mut frx2), Ev::Complete(2, _)));
    assert_eq!(next(&mut frx2), Ev::Released);

    let (t, mut r) = mpsc::unbounded_channel();
    unsafe { rnssh_connection_disconnect(conn, completion(&t)) };
    let _ = next(&mut r);
}
