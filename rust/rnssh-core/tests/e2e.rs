//! End-to-end tests against an in-process russh server. No network, no sshd.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rnssh_core::{
    Auth, ConnectOptions, Connection, ConnectionEvents, ForwardEvents, ForwardOptions, HostKey,
    KeyType, KeyboardInteractiveChallenge, Shell, ShellEvents, ShellOptions, StreamKind,
};
use russh::keys::{Algorithm, PrivateKey, PublicKey};
use russh::server::{self, Auth as ServerAuth, Msg, Server as _, Session};
use russh::{Channel, ChannelId, MethodKind, MethodSet};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use zeroize::Zeroizing;

// ---------- test server ----------

#[derive(Clone)]
struct TestServer {
    password_ok: bool,
    kbi_only: bool,
    authorized: Option<PublicKey>,
}

struct TestHandler {
    cfg: TestServer,
}

impl server::Server for TestServer {
    type Handler = TestHandler;
    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> TestHandler {
        TestHandler { cfg: self.clone() }
    }
}

impl server::Handler for TestHandler {
    type Error = russh::Error;

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> Result<ServerAuth, Self::Error> {
        if self.cfg.kbi_only {
            return Ok(ServerAuth::Reject {
                proceed_with_methods: Some(MethodSet::from(&[MethodKind::KeyboardInteractive][..])),
                partial_success: false,
            });
        }
        Ok(
            if self.cfg.password_ok && user == "alice" && password == "s3cret" {
                ServerAuth::Accept
            } else {
                ServerAuth::reject()
            },
        )
    }

    async fn auth_keyboard_interactive(
        &mut self,
        _user: &str,
        _submethods: &str,
        response: Option<server::Response<'_>>,
    ) -> Result<ServerAuth, Self::Error> {
        match response {
            None => Ok(ServerAuth::Partial {
                name: "test".into(),
                instructions: "answer me".into(),
                // An echoed prompt first: a client must not leak the password into it.
                prompts: vec![("Username: ".into(), true), ("Password: ".into(), false)].into(),
            }),
            Some(mut r) => {
                let answers: Vec<Vec<u8>> = r.by_ref().map(|s| s.to_vec()).collect();
                Ok(if answers == vec![Vec::new(), b"s3cret".to_vec()] {
                    ServerAuth::Accept
                } else {
                    ServerAuth::reject()
                })
            }
        }
    }

    async fn auth_publickey(
        &mut self,
        _user: &str,
        key: &PublicKey,
    ) -> Result<ServerAuth, Self::Error> {
        Ok(match &self.cfg.authorized {
            Some(k) if k.key_data() == key.key_data() => ServerAuth::Accept,
            _ => ServerAuth::reject(),
        })
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _c: u32,
        _r: u32,
        _w: u32,
        _h: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        session.data(channel, b"welcome\r\n".to_vec())?;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        let cmd = String::from_utf8_lossy(data).to_string();
        if cmd == "fail" {
            session.extended_data(channel, 1, b"nope\n".to_vec())?;
            session.exit_status_request(channel, 7)?;
        } else {
            session.data(channel, format!("ran: {cmd}\n").into_bytes())?;
            session.exit_status_request(channel, 0)?;
        }
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.data(
            channel,
            format!("resize {col_width}x{row_height}\r\n").into_bytes(),
        )?;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if data == b"exit\n" {
            session.exit_status_request(channel, 3)?;
            session.close(channel)?;
            return Ok(());
        }
        let mut echo = b"echo: ".to_vec();
        echo.extend_from_slice(data);
        session.data(channel, echo)?;
        Ok(())
    }
}

async fn start_server(cfg: TestServer) -> (u16, HostKey) {
    let host_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let expected = HostKey::from_public_key(host_key.public_key());
    let config = Arc::new(server::Config {
        inactivity_timeout: Some(Duration::from_secs(30)),
        auth_rejection_time: Duration::from_millis(10),
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        keys: vec![host_key],
        ..Default::default()
    });
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut srv = cfg;
    tokio::spawn(async move {
        let _ = srv.run_on_socket(config, &listener).await;
    });
    (port, expected)
}

// ---------- client-side event sinks ----------

struct Events {
    accept_host_key: bool,
    seen_host_key: Mutex<Option<HostKey>>,
    kbi_answers: Option<Vec<String>>,
    disconnected: Mutex<Option<String>>,
    disconnect_tx: Mutex<Option<oneshot::Sender<String>>>,
}

impl Events {
    fn accepting() -> Arc<Self> {
        Arc::new(Self {
            accept_host_key: true,
            seen_host_key: Mutex::new(None),
            kbi_answers: None,
            disconnected: Mutex::new(None),
            disconnect_tx: Mutex::new(None),
        })
    }
}

impl ConnectionEvents for Events {
    fn verify_host_key(&self, key: HostKey, respond: oneshot::Sender<bool>) {
        *self.seen_host_key.lock().unwrap() = Some(key);
        let _ = respond.send(self.accept_host_key);
    }
    fn supports_keyboard_interactive(&self) -> bool {
        self.kbi_answers.is_some()
    }
    fn keyboard_interactive(
        &self,
        challenge: KeyboardInteractiveChallenge,
        respond: oneshot::Sender<Option<Vec<String>>>,
    ) {
        if challenge.prompts.len() == 2 {
            assert!(challenge.prompts[0].echo);
            assert_eq!(challenge.prompts[1].prompt, "Password: ");
            assert!(!challenge.prompts[1].echo);
        }
        // Answer with whatever the test configured, sized to the prompts.
        let answers = self.kbi_answers.clone().map(|a| {
            if a.len() == challenge.prompts.len() {
                a
            } else {
                challenge
                    .prompts
                    .iter()
                    .map(|_| a.last().cloned().unwrap_or_default())
                    .collect()
            }
        });
        let _ = respond.send(answers);
    }
    fn disconnected(&self, reason: String) {
        *self.disconnected.lock().unwrap() = Some(reason.clone());
        if let Some(tx) = self.disconnect_tx.lock().unwrap().take() {
            let _ = tx.send(reason);
        }
    }
}

struct Sink {
    data: Mutex<Vec<(StreamKind, Vec<u8>)>>,
    closed: Mutex<Option<Option<u32>>>,
    closed_tx: Mutex<Option<oneshot::Sender<Option<u32>>>>,
    data_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
}

impl ShellEvents for Sink {
    fn on_data(&self, stream: StreamKind, data: Vec<u8>) {
        let _ = self.data_tx.send(data.clone());
        self.data.lock().unwrap().push((stream, data));
    }
    fn on_closed(&self, exit_code: Option<u32>) {
        *self.closed.lock().unwrap() = Some(exit_code);
        if let Some(tx) = self.closed_tx.lock().unwrap().take() {
            let _ = tx.send(exit_code);
        }
    }
}

fn sink() -> (
    Arc<Sink>,
    tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    oneshot::Receiver<Option<u32>>,
) {
    let (data_tx, data_rx) = tokio::sync::mpsc::unbounded_channel();
    let (closed_tx, closed_rx) = oneshot::channel();
    let s = Arc::new(Sink {
        data: Mutex::new(Vec::new()),
        closed: Mutex::new(None),
        closed_tx: Mutex::new(Some(closed_tx)),
        data_tx,
    });
    (s, data_rx, closed_rx)
}

fn options(port: u16, auth: Auth) -> ConnectOptions {
    ConnectOptions {
        host: "127.0.0.1".into(),
        port,
        username: "alice".into(),
        auth,
        connect_timeout: Duration::from_secs(10),
        ..Default::default()
    }
}

async fn recv_until(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    needle: &[u8],
) -> Vec<u8> {
    let mut all = Vec::new();
    let deadline = tokio::time::sleep(Duration::from_secs(5));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            Some(chunk) = rx.recv() => {
                all.extend_from_slice(&chunk);
                if all.windows(needle.len()).any(|w| w == needle) { return all; }
            }
            _ = &mut deadline => panic!("timed out waiting for {:?}; got {:?}", String::from_utf8_lossy(needle), String::from_utf8_lossy(&all)),
        }
    }
}

// ---------- tests ----------

#[tokio::test(flavor = "multi_thread")]
async fn password_auth_shell_and_exec() {
    let (port, expected_key) = start_server(TestServer {
        password_ok: true,
        kbi_only: false,
        authorized: None,
    })
    .await;
    let events = Events::accepting();
    let conn = Connection::connect(
        options(port, Auth::Password(Zeroizing::new("s3cret".into()))),
        events.clone(),
    )
    .await
    .expect("connect");

    assert!(conn.is_connected());
    assert_eq!(conn.host_key(), &expected_key);
    assert_eq!(
        events.seen_host_key.lock().unwrap().as_ref(),
        Some(&expected_key)
    );
    assert!(expected_key.fingerprint.starts_with("SHA256:"));

    // exec
    let r = conn.exec("uname").await.unwrap();
    assert_eq!(r.stdout, b"ran: uname\n");
    assert_eq!(r.exit_code, Some(0));
    let r = conn.exec("fail").await.unwrap();
    assert_eq!(r.stderr, b"nope\n");
    assert_eq!(r.exit_code, Some(7));

    // shell
    let (s, mut data_rx, closed_rx) = sink();
    let shell: Shell = conn
        .open_shell(
            ShellOptions {
                cols: 100,
                rows: 30,
                ..Default::default()
            },
            s.clone(),
        )
        .await
        .unwrap();
    assert!(shell.is_open());
    recv_until(&mut data_rx, b"welcome\r\n").await;
    shell.write(b"ls\n".to_vec()).unwrap();
    recv_until(&mut data_rx, b"echo: ls\n").await;
    shell.resize(120, 40, 0, 0).unwrap();
    recv_until(&mut data_rx, b"resize 120x40\r\n").await;
    shell.write(b"exit\n".to_vec()).unwrap();
    let code = tokio::time::timeout(Duration::from_secs(5), closed_rx)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(code, Some(3));
    assert!(!shell.is_open());
    assert!(shell.write(b"x".to_vec()).is_err());

    // disconnect
    let (dtx, mut drx) = oneshot::channel();
    *events.disconnect_tx.lock().unwrap() = Some(dtx);
    conn.disconnect().await;
    assert!(!conn.is_connected());
    // A client-initiated disconnect must not be reported as an unexpected drop.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(drx.try_recv().is_err() || events.disconnected.lock().unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn shell_close_from_client() {
    let (port, _) = start_server(TestServer {
        password_ok: true,
        kbi_only: false,
        authorized: None,
    })
    .await;
    let conn = Connection::connect(
        options(port, Auth::Password(Zeroizing::new("s3cret".into()))),
        Events::accepting(),
    )
    .await
    .unwrap();
    let (s, mut data_rx, closed_rx) = sink();
    let shell = conn
        .open_shell(ShellOptions::default(), s.clone())
        .await
        .unwrap();
    recv_until(&mut data_rx, b"welcome").await;
    shell.close().await;
    assert!(!shell.is_open());
    let code = tokio::time::timeout(Duration::from_secs(5), closed_rx)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(code, None);
    conn.disconnect().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn rejected_host_key_fails_connect() {
    let (port, _) = start_server(TestServer {
        password_ok: true,
        kbi_only: false,
        authorized: None,
    })
    .await;
    let events = Arc::new(Events {
        accept_host_key: false,
        seen_host_key: Mutex::new(None),
        kbi_answers: None,
        disconnected: Mutex::new(None),
        disconnect_tx: Mutex::new(None),
    });
    let err = Connection::connect(
        options(port, Auth::Password(Zeroizing::new("s3cret".into()))),
        events.clone(),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code, rnssh_core::ErrorCode::HostKeyRejected, "{err}");
    assert!(events.seen_host_key.lock().unwrap().is_some());
    assert!(
        events.disconnected.lock().unwrap().is_none(),
        "no disconnect event before connected"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_password_is_auth_failed() {
    let (port, _) = start_server(TestServer {
        password_ok: true,
        kbi_only: false,
        authorized: None,
    })
    .await;
    let err = Connection::connect(
        options(port, Auth::Password(Zeroizing::new("wrong".into()))),
        Events::accepting(),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code, rnssh_core::ErrorCode::AuthFailed, "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn password_falls_back_to_keyboard_interactive() {
    let (port, _) = start_server(TestServer {
        password_ok: false,
        kbi_only: true,
        authorized: None,
    })
    .await;
    let conn = Connection::connect(
        options(port, Auth::Password(Zeroizing::new("s3cret".into()))),
        Events::accepting(),
    )
    .await
    .expect("kbi fallback");
    assert!(conn.is_connected());
    conn.disconnect().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn explicit_keyboard_interactive() {
    let (port, _) = start_server(TestServer {
        password_ok: false,
        kbi_only: true,
        authorized: None,
    })
    .await;
    let events = Arc::new(Events {
        accept_host_key: true,
        seen_host_key: Mutex::new(None),
        kbi_answers: Some(vec![String::new(), "s3cret".into()]),
        disconnected: Mutex::new(None),
        disconnect_tx: Mutex::new(None),
    });
    let conn = Connection::connect(options(port, Auth::KeyboardInteractive), events)
        .await
        .expect("kbi");
    conn.disconnect().await;

    // Without a handler, explicit kbi must be refused up front.
    let err = Connection::connect(
        options(port, Auth::KeyboardInteractive),
        Events::accepting(),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code, rnssh_core::ErrorCode::InvalidArgument);
}

#[tokio::test(flavor = "multi_thread")]
async fn public_key_auth() {
    let kp =
        rnssh_core::keys::generate_key_pair(KeyType::Ed25519, Some("e2e"), Some("pw")).unwrap();
    let authorized = PublicKey::from_openssh(&kp.public_key).unwrap();
    let (port, _) = start_server(TestServer {
        password_ok: false,
        kbi_only: false,
        authorized: Some(authorized),
    })
    .await;

    let auth = Auth::PrivateKey {
        pem: kp.private_key.clone(),
        passphrase: Some(Zeroizing::new("pw".into())),
    };
    let conn = Connection::connect(options(port, auth), Events::accepting())
        .await
        .expect("pubkey");
    assert!(conn.is_connected());
    conn.disconnect().await;

    // Wrong passphrase → Key error, before touching the network.
    let auth = Auth::PrivateKey {
        pem: kp.private_key.clone(),
        passphrase: Some(Zeroizing::new("nope".into())),
    };
    let err = Connection::connect(options(port, auth), Events::accepting())
        .await
        .unwrap_err();
    assert_eq!(err.code, rnssh_core::ErrorCode::Key, "{err}");

    // Unauthorized key → AuthFailed.
    let other = rnssh_core::keys::generate_key_pair(KeyType::EcdsaP256, None, None).unwrap();
    let auth = Auth::PrivateKey {
        pem: other.private_key.clone(),
        passphrase: None,
    };
    let err = Connection::connect(options(port, auth), Events::accepting())
        .await
        .unwrap_err();
    assert_eq!(err.code, rnssh_core::ErrorCode::AuthFailed, "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_refused_and_timeout() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let err = Connection::connect(options(port, Auth::None), Events::accepting())
        .await
        .unwrap_err();
    assert_eq!(err.code, rnssh_core::ErrorCode::Connect, "{err}");

    // A listener that never speaks SSH → handshake never completes → timeout.
    let silent = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = silent.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _keep = silent.accept().await;
        tokio::time::sleep(Duration::from_secs(60)).await;
    });
    let mut o = options(port, Auth::None);
    o.connect_timeout = Duration::from_millis(500);
    let err = Connection::connect(o, Events::accepting())
        .await
        .unwrap_err();
    assert_eq!(err.code, rnssh_core::ErrorCode::Timeout, "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn server_drop_reports_disconnected() {
    let host_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let config = Arc::new(server::Config {
        auth_rejection_time: Duration::from_millis(10),
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        keys: vec![host_key],
        ..Default::default()
    });
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut srv = TestServer {
        password_ok: true,
        kbi_only: false,
        authorized: None,
    };
    let server_task = tokio::spawn(async move {
        let _ = srv.run_on_socket(config, &listener).await;
    });

    let events = Events::accepting();
    let (dtx, drx) = oneshot::channel();
    *events.disconnect_tx.lock().unwrap() = Some(dtx);
    let conn = Connection::connect(
        options(port, Auth::Password(Zeroizing::new("s3cret".into()))),
        events.clone(),
    )
    .await
    .unwrap();
    assert!(conn.is_connected());

    // Kill the server: its sessions are dropped, the socket closes.
    server_task.abort();
    let reason = tokio::time::timeout(Duration::from_secs(5), drx)
        .await
        .expect("disconnect event")
        .unwrap();
    assert!(!reason.is_empty());
    assert!(!conn.is_connected());
    let _ = HashMap::<String, String>::new();
}

// ---------- hardening ----------

struct SlowAccept {
    delay: Duration,
    inner: Arc<Events>,
}

impl ConnectionEvents for SlowAccept {
    fn verify_host_key(&self, key: HostKey, respond: oneshot::Sender<bool>) {
        let delay = self.delay;
        let inner = self.inner.clone();
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            inner.verify_host_key(key, respond);
        });
    }
    fn disconnected(&self, reason: String) {
        self.inner.disconnected(reason)
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn host_key_decision_time_does_not_count_toward_connect_timeout() {
    let (port, _) = start_server(TestServer {
        password_ok: true,
        kbi_only: false,
        authorized: None,
    })
    .await;
    let mut o = options(port, Auth::Password(Zeroizing::new("s3cret".into())));
    o.connect_timeout = Duration::from_millis(400);
    let events = Arc::new(SlowAccept {
        delay: Duration::from_millis(1200),
        inner: Events::accepting(),
    });
    let conn = Connection::connect(o, events)
        .await
        .expect("a slow but positive host key decision must not time out");
    assert!(conn.is_connected());
    conn.disconnect().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn exec_output_cap_is_enforced() {
    let (port, _) = start_server(TestServer {
        password_ok: true,
        kbi_only: false,
        authorized: None,
    })
    .await;
    let mut o = options(port, Auth::Password(Zeroizing::new("s3cret".into())));
    o.max_exec_output = 8;
    let conn = Connection::connect(o, Events::accepting()).await.unwrap();
    let err = conn
        .exec("this output is longer than eight bytes")
        .await
        .unwrap_err();
    assert_eq!(err.code, rnssh_core::ErrorCode::TooLarge, "{err}");
    // The connection itself survives.
    let ok = conn.exec("hi").await.unwrap();
    assert_eq!(ok.stdout, b"ran: hi\n");
    conn.disconnect().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn shell_write_queue_is_bounded() {
    let (port, _) = start_server(TestServer {
        password_ok: true,
        kbi_only: false,
        authorized: None,
    })
    .await;
    let conn = Connection::connect(
        options(port, Auth::Password(Zeroizing::new("s3cret".into()))),
        Events::accepting(),
    )
    .await
    .unwrap();
    let (s, mut data_rx, _closed) = sink();
    let shell = conn.open_shell(ShellOptions::default(), s).await.unwrap();
    recv_until(&mut data_rx, b"welcome").await;
    // One oversize write is refused outright; pending bytes stay accounted.
    let too_big = vec![b'x'; rnssh_core::shell::MAX_PENDING_WRITE_BYTES + 1];
    let err = shell.write(too_big).unwrap_err();
    assert_eq!(err.code, rnssh_core::ErrorCode::QueueFull);
    assert_eq!(shell.pending_bytes(), 0);
    shell.write(b"ok\n".to_vec()).unwrap();
    recv_until(&mut data_rx, b"echo: ok").await;
    shell.close().await;
    conn.disconnect().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn shell_setup_times_out_when_server_ignores_requests() {
    // A server whose shell_request never replies: the default russh handler
    // returns Ok(()) without channel_success, so the client waits forever.
    struct Mute;
    struct MuteHandler;
    impl server::Server for Mute {
        type Handler = MuteHandler;
        fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> MuteHandler {
            MuteHandler
        }
    }
    impl server::Handler for MuteHandler {
        type Error = russh::Error;
        async fn channel_open_session(
            &mut self,
            _c: Channel<Msg>,
            reply: server::ChannelOpenHandle,
            _s: &mut Session,
        ) -> Result<(), Self::Error> {
            reply.accept().await;
            Ok(())
        }
        async fn auth_password(&mut self, _u: &str, _p: &str) -> Result<ServerAuth, Self::Error> {
            Ok(ServerAuth::Accept)
        }
        // Never answers the PTY request: the client must give up on its own.
        async fn pty_request(
            &mut self,
            _c: ChannelId,
            _t: &str,
            _w: u32,
            _h: u32,
            _pw: u32,
            _ph: u32,
            _m: &[(russh::Pty, u32)],
            _s: &mut Session,
        ) -> Result<(), Self::Error> {
            std::future::pending::<()>().await;
            Ok(())
        }
    }
    let host_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let config = Arc::new(server::Config {
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        keys: vec![host_key],
        ..Default::default()
    });
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = Mute.run_on_socket(config, &listener).await;
    });

    let conn = Connection::connect(
        options(port, Auth::Password(Zeroizing::new("x".into()))),
        Events::accepting(),
    )
    .await
    .unwrap();
    let (s, _rx, _closed) = sink();
    let err = conn
        .open_shell(
            ShellOptions {
                setup_timeout: Duration::from_millis(500),
                ..Default::default()
            },
            s,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, rnssh_core::ErrorCode::Timeout, "{err}");
    assert!(conn.is_connected());
    conn.disconnect().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn server_drop_with_open_shell_reports_both_events() {
    let host_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let config = Arc::new(server::Config {
        auth_rejection_time: Duration::from_millis(10),
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        keys: vec![host_key],
        ..Default::default()
    });
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut srv = TestServer {
        password_ok: true,
        kbi_only: false,
        authorized: None,
    };
    let server_task = tokio::spawn(async move {
        let _ = srv.run_on_socket(config, &listener).await;
    });

    let events = Events::accepting();
    let (dtx, drx) = oneshot::channel();
    *events.disconnect_tx.lock().unwrap() = Some(dtx);
    let conn = Connection::connect(
        options(port, Auth::Password(Zeroizing::new("s3cret".into()))),
        events.clone(),
    )
    .await
    .unwrap();
    let (s, mut data_rx, closed_rx) = sink();
    let shell = conn.open_shell(ShellOptions::default(), s).await.unwrap();
    recv_until(&mut data_rx, b"welcome").await;

    server_task.abort();
    let reason = tokio::time::timeout(Duration::from_secs(5), drx)
        .await
        .expect("disconnect event")
        .unwrap();
    assert!(!reason.is_empty());
    let code = tokio::time::timeout(Duration::from_secs(5), closed_rx)
        .await
        .expect("shell closed event")
        .unwrap();
    assert_eq!(code, None);
    assert!(!shell.is_open());
    assert!(!conn.is_connected());
}

#[tokio::test(flavor = "multi_thread")]
async fn refused_shell_request_is_an_error() {
    struct Refusing;
    struct RefusingHandler;
    impl server::Server for Refusing {
        type Handler = RefusingHandler;
        fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> RefusingHandler {
            RefusingHandler
        }
    }
    impl server::Handler for RefusingHandler {
        type Error = russh::Error;
        async fn channel_open_session(
            &mut self,
            _c: Channel<Msg>,
            reply: server::ChannelOpenHandle,
            _s: &mut Session,
        ) -> Result<(), Self::Error> {
            reply.accept().await;
            Ok(())
        }
        async fn auth_password(&mut self, _u: &str, _p: &str) -> Result<ServerAuth, Self::Error> {
            Ok(ServerAuth::Accept)
        }
        async fn pty_request(
            &mut self,
            channel: ChannelId,
            _t: &str,
            _w: u32,
            _h: u32,
            _pw: u32,
            _ph: u32,
            _m: &[(russh::Pty, u32)],
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            session.channel_success(channel)?;
            Ok(())
        }
        async fn shell_request(
            &mut self,
            channel: ChannelId,
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            session.channel_failure(channel)?;
            Ok(())
        }
        async fn exec_request(
            &mut self,
            channel: ChannelId,
            _d: &[u8],
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            session.channel_failure(channel)?;
            Ok(())
        }
    }
    let host_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let config = Arc::new(server::Config {
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        keys: vec![host_key],
        ..Default::default()
    });
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = Refusing.run_on_socket(config, &listener).await;
    });

    let conn = Connection::connect(
        options(port, Auth::Password(Zeroizing::new("x".into()))),
        Events::accepting(),
    )
    .await
    .unwrap();
    let (s, _rx, _closed) = sink();
    let err = conn
        .open_shell(ShellOptions::default(), s)
        .await
        .unwrap_err();
    assert_eq!(err.code, rnssh_core::ErrorCode::Protocol, "{err}");
    assert!(err.message.contains("refused"), "{err}");
    let err = conn.exec("ls").await.unwrap_err();
    assert_eq!(err.code, rnssh_core::ErrorCode::Protocol, "{err}");
    assert!(conn.is_connected());
    conn.disconnect().await;
}

/// Interop with a real OpenSSH server on this machine (Remote Login). Runs
/// only with `--ignored`; needs no credentials: a successful key exchange,
/// host key delivery and algorithm negotiation end in AUTH_FAILED.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn openssh_interop_handshake() {
    let events = Events::accepting();
    let mut o = options(22, Auth::None);
    o.username = "rnssh-interop".into();
    let err = Connection::connect(o, events.clone()).await.unwrap_err();
    let key = events
        .seen_host_key
        .lock()
        .unwrap()
        .clone()
        .expect("host key delivered");
    assert!(key.fingerprint.starts_with("SHA256:"), "{key:?}");
    assert!(
        !key.algorithm.contains("ssh-rsa"),
        "negotiated a SHA-1 host key alg: {}",
        key.algorithm
    );
    assert_eq!(err.code, rnssh_core::ErrorCode::AuthFailed, "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn pinned_host_key_algorithm_is_offered_first() {
    // Server with both an Ed25519 and an RSA host key.
    let ed = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let rsa_pair =
        russh::keys::ssh_key::private::RsaKeypair::random(&mut rand::rng(), 2048).unwrap();
    let rsa = PrivateKey::new(rsa_pair.into(), "").unwrap();
    let ed_fp = HostKey::from_public_key(ed.public_key());
    let rsa_fp = HostKey::from_public_key(rsa.public_key());
    let config = Arc::new(server::Config {
        auth_rejection_time: Duration::from_millis(10),
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        keys: vec![ed, rsa],
        ..Default::default()
    });
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut srv = TestServer {
        password_ok: true,
        kbi_only: false,
        authorized: None,
    };
    tokio::spawn(async move {
        let _ = srv.run_on_socket(config, &listener).await;
    });

    // Default policy prefers Ed25519.
    let conn = Connection::connect(
        options(port, Auth::Password(Zeroizing::new("s3cret".into()))),
        Events::accepting(),
    )
    .await
    .unwrap();
    assert_eq!(conn.host_key(), &ed_fp);
    conn.disconnect().await;

    // An app that pinned the RSA key asks for it first and gets the same key back.
    let mut o = options(port, Auth::Password(Zeroizing::new("s3cret".into())));
    o.host_key_algorithms = vec!["ssh-rsa".into()];
    let conn = Connection::connect(o, Events::accepting()).await.unwrap();
    assert_eq!(conn.host_key(), &rsa_fp);
    assert_eq!(conn.host_key().algorithm, "ssh-rsa");
    conn.disconnect().await;

    // Unknown names are ignored, not fatal.
    let mut o = options(port, Auth::Password(Zeroizing::new("s3cret".into())));
    o.host_key_algorithms = vec!["ssh-dss".into(), "nonsense".into()];
    let conn = Connection::connect(o, Events::accepting()).await.unwrap();
    assert_eq!(conn.host_key(), &ed_fp);
    conn.disconnect().await;
}

/// Throughput of the shell output path (server → core → sink), plus the
/// number of sink callbacks, with and without coalescing. Prints numbers;
/// only asserts that coalescing reduces callbacks. Run with `--ignored`.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn perf_shell_throughput() {
    struct Blaster;
    struct BlasterHandler;
    const TOTAL: usize = 64 * 1024 * 1024;
    impl server::Server for Blaster {
        type Handler = BlasterHandler;
        fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> BlasterHandler {
            BlasterHandler
        }
    }
    impl server::Handler for BlasterHandler {
        type Error = russh::Error;
        async fn channel_open_session(
            &mut self,
            _c: Channel<Msg>,
            reply: server::ChannelOpenHandle,
            _s: &mut Session,
        ) -> Result<(), Self::Error> {
            reply.accept().await;
            Ok(())
        }
        async fn auth_password(&mut self, _u: &str, _p: &str) -> Result<ServerAuth, Self::Error> {
            Ok(ServerAuth::Accept)
        }
        async fn pty_request(
            &mut self,
            channel: ChannelId,
            _t: &str,
            _w: u32,
            _h: u32,
            _pw: u32,
            _ph: u32,
            _m: &[(russh::Pty, u32)],
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            session.channel_success(channel)?;
            Ok(())
        }
        async fn shell_request(
            &mut self,
            channel: ChannelId,
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            session.channel_success(channel)?;
            let handle = session.handle();
            tokio::spawn(async move {
                let chunk = vec![b'x'; 32 * 1024];
                let mut sent = 0;
                while sent < TOTAL {
                    if handle.data(channel, chunk.clone()).await.is_err() {
                        return;
                    }
                    sent += chunk.len();
                }
                let _ = handle.exit_status_request(channel, 0).await;
                let _ = handle.eof(channel).await;
                let _ = handle.close(channel).await;
            });
            Ok(())
        }
    }

    struct Counter {
        bytes: std::sync::atomic::AtomicUsize,
        calls: std::sync::atomic::AtomicUsize,
        done: Mutex<Option<oneshot::Sender<()>>>,
    }
    impl ShellEvents for Counter {
        fn on_data(&self, _s: StreamKind, d: Vec<u8>) {
            self.bytes
                .fetch_add(d.len(), std::sync::atomic::Ordering::Relaxed);
            self.calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        fn on_closed(&self, _c: Option<u32>) {
            if let Some(tx) = self.done.lock().unwrap().take() {
                let _ = tx.send(());
            }
        }
    }

    let host_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let config = Arc::new(server::Config {
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        keys: vec![host_key],
        ..Default::default()
    });
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = Blaster.run_on_socket(config, &listener).await;
    });

    let mut results = Vec::new();
    for coalesce_ms in [0u64, 4] {
        let conn = Connection::connect(
            options(port, Auth::Password(Zeroizing::new("x".into()))),
            Events::accepting(),
        )
        .await
        .unwrap();
        let (tx, rx) = oneshot::channel();
        let counter = Arc::new(Counter {
            bytes: Default::default(),
            calls: Default::default(),
            done: Mutex::new(Some(tx)),
        });
        let started = std::time::Instant::now();
        let _shell = conn
            .open_shell(
                ShellOptions {
                    coalesce: Duration::from_millis(coalesce_ms),
                    ..Default::default()
                },
                counter.clone(),
            )
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(120), rx)
            .await
            .expect("blast finished")
            .unwrap();
        let secs = started.elapsed().as_secs_f64();
        let bytes = counter.bytes.load(std::sync::atomic::Ordering::Relaxed);
        let calls = counter.calls.load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(bytes, TOTAL);
        println!(
            "coalesce={coalesce_ms}ms: {:.1} MB/s, {calls} callbacks ({} bytes avg)",
            bytes as f64 / secs / 1e6,
            bytes / calls.max(1)
        );
        results.push(calls);
        conn.disconnect().await;
    }
    assert!(
        results[1] < results[0] / 4,
        "coalescing must cut callbacks: {results:?}"
    );
}

/// Connect latency, interactive round-trip latency and per-cipher throughput.
/// Prints numbers only. Run with `--ignored --nocapture`.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn perf_latency_and_ciphers() {
    use russh::cipher;

    // --- connect latency (default server) ---
    let (port, _) = start_server(TestServer {
        password_ok: true,
        kbi_only: false,
        authorized: None,
    })
    .await;
    let mut samples = Vec::new();
    for _ in 0..20 {
        let t = std::time::Instant::now();
        let conn = Connection::connect(
            options(port, Auth::Password(Zeroizing::new("s3cret".into()))),
            Events::accepting(),
        )
        .await
        .unwrap();
        samples.push(t.elapsed());
        conn.disconnect().await;
    }
    samples.sort();
    println!(
        "connect latency: median {:.2} ms, p90 {:.2} ms, min {:.2} ms",
        samples[samples.len() / 2].as_secs_f64() * 1e3,
        samples[samples.len() * 9 / 10].as_secs_f64() * 1e3,
        samples[0].as_secs_f64() * 1e3
    );

    // --- interactive round trip: write one byte, wait for the echo ---
    let conn = Connection::connect(
        options(port, Auth::Password(Zeroizing::new("s3cret".into()))),
        Events::accepting(),
    )
    .await
    .unwrap();
    let (s, mut data_rx, _closed) = sink();
    let shell = conn.open_shell(ShellOptions::default(), s).await.unwrap();
    recv_until(&mut data_rx, b"welcome").await;
    let mut rtts = Vec::new();
    for _ in 0..200 {
        let t = std::time::Instant::now();
        shell.write(b"a".to_vec()).unwrap();
        recv_until(&mut data_rx, b"echo: a").await;
        rtts.push(t.elapsed());
    }
    rtts.sort();
    println!(
        "echo round trip: median {:.3} ms, p90 {:.3} ms",
        rtts[rtts.len() / 2].as_secs_f64() * 1e3,
        rtts[rtts.len() * 9 / 10].as_secs_f64() * 1e3
    );
    shell.close().await;
    conn.disconnect().await;

    // --- throughput per cipher (server pinned to one cipher) ---
    struct Blaster;
    struct BlasterHandler;
    const TOTAL: usize = 64 * 1024 * 1024;
    impl server::Server for Blaster {
        type Handler = BlasterHandler;
        fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> BlasterHandler {
            BlasterHandler
        }
    }
    impl server::Handler for BlasterHandler {
        type Error = russh::Error;
        async fn channel_open_session(
            &mut self,
            _c: Channel<Msg>,
            reply: server::ChannelOpenHandle,
            _s: &mut Session,
        ) -> Result<(), Self::Error> {
            reply.accept().await;
            Ok(())
        }
        async fn auth_password(&mut self, _u: &str, _p: &str) -> Result<ServerAuth, Self::Error> {
            Ok(ServerAuth::Accept)
        }
        async fn pty_request(
            &mut self,
            channel: ChannelId,
            _t: &str,
            _w: u32,
            _h: u32,
            _pw: u32,
            _ph: u32,
            _m: &[(russh::Pty, u32)],
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            session.channel_success(channel)?;
            Ok(())
        }
        async fn shell_request(
            &mut self,
            channel: ChannelId,
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            session.channel_success(channel)?;
            let handle = session.handle();
            tokio::spawn(async move {
                let chunk = vec![b'x'; 32 * 1024];
                let mut sent = 0;
                while sent < TOTAL {
                    if handle.data(channel, chunk.clone()).await.is_err() {
                        return;
                    }
                    sent += chunk.len();
                }
                let _ = handle.exit_status_request(channel, 0).await;
                let _ = handle.eof(channel).await;
                let _ = handle.close(channel).await;
            });
            Ok(())
        }
    }
    struct Counter {
        bytes: std::sync::atomic::AtomicUsize,
        done: Mutex<Option<oneshot::Sender<()>>>,
    }
    impl ShellEvents for Counter {
        fn on_data(&self, _s: StreamKind, d: Vec<u8>) {
            self.bytes
                .fetch_add(d.len(), std::sync::atomic::Ordering::Relaxed);
        }
        fn on_closed(&self, _c: Option<u32>) {
            if let Some(tx) = self.done.lock().unwrap().take() {
                let _ = tx.send(());
            }
        }
    }

    for name in [
        cipher::CHACHA20_POLY1305,
        cipher::AES_256_GCM,
        cipher::AES_128_GCM,
        cipher::AES_256_CTR,
        cipher::AES_128_CTR,
    ] {
        let host_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let preferred = russh::Preferred {
            cipher: std::borrow::Cow::Owned(vec![name]),
            ..Default::default()
        };
        let config = Arc::new(server::Config {
            auth_rejection_time_initial: Some(Duration::from_millis(0)),
            keys: vec![host_key],
            preferred,
            ..Default::default()
        });
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = Blaster.run_on_socket(config, &listener).await;
        });
        let conn = Connection::connect(
            options(port, Auth::Password(Zeroizing::new("x".into()))),
            Events::accepting(),
        )
        .await
        .unwrap();
        let (tx, rx) = oneshot::channel();
        let counter = Arc::new(Counter {
            bytes: Default::default(),
            done: Mutex::new(Some(tx)),
        });
        let started = std::time::Instant::now();
        let _shell = conn
            .open_shell(ShellOptions::default(), counter.clone())
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(120), rx)
            .await
            .expect("blast finished")
            .unwrap();
        let secs = started.elapsed().as_secs_f64();
        println!(
            "cipher {:<28} {:>7.1} MB/s",
            name.as_ref(),
            TOTAL as f64 / secs / 1e6
        );
        conn.disconnect().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn weak_rsa_keys_are_refused() {
    // 1024-bit RSA host key only → refused by policy, app never asked.
    let rsa_pair =
        russh::keys::ssh_key::private::RsaKeypair::random(&mut rand::rng(), 1024).unwrap();
    let weak = PrivateKey::new(rsa_pair.into(), "").unwrap();
    let config = Arc::new(server::Config {
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        keys: vec![weak.clone()],
        ..Default::default()
    });
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut srv = TestServer {
        password_ok: true,
        kbi_only: false,
        authorized: None,
    };
    tokio::spawn(async move {
        let _ = srv.run_on_socket(config, &listener).await;
    });
    let events = Events::accepting();
    let err = Connection::connect(
        options(port, Auth::Password(Zeroizing::new("s3cret".into()))),
        events.clone(),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code, rnssh_core::ErrorCode::Protocol, "{err}");
    assert!(err.message.contains("1024-bit"), "{err}");
    assert!(
        events.seen_host_key.lock().unwrap().is_none(),
        "the app must not be asked to trust a weak key"
    );

    // 1024-bit RSA user key → refused before any network traffic.
    let pem = weak
        .to_openssh(russh::keys::ssh_key::LineEnding::LF)
        .unwrap();
    let err = rnssh_core::keys::inspect_private_key(&pem, None).unwrap_err();
    assert_eq!(err.code, rnssh_core::ErrorCode::Key, "{err}");
    assert!(err.message.contains("1024-bit"), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn second_factor_after_password_and_after_key() {
    // Server: password (or key) is accepted with partial_success, then a
    // keyboard-interactive round must be answered with "otp".
    //
    // Upstream limitation: russh's *server* (0.63.1, server/encrypted.rs)
    // unconditionally resets `partial_success` to false on both the password
    // and the publickey path, so on the wire this server always reports a
    // plain failure with `[keyboard-interactive]` remaining. The client's
    // dedicated `second_factor` branch therefore cannot be exercised here; the
    // password case below goes through the "server refuses passwords →
    // app handler" fallback, which yields the same user-visible flow. Real
    // OpenSSH signals partial success and takes the `second_factor` branch.
    #[derive(Clone)]
    struct TwoFactor {
        authorized: PublicKey,
    }
    struct TwoFactorHandler {
        authorized: PublicKey,
        first_ok: bool,
    }
    impl server::Server for TwoFactor {
        type Handler = TwoFactorHandler;
        fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> TwoFactorHandler {
            TwoFactorHandler {
                authorized: self.authorized.clone(),
                first_ok: false,
            }
        }
    }
    impl server::Handler for TwoFactorHandler {
        type Error = russh::Error;
        async fn channel_open_session(
            &mut self,
            _c: Channel<Msg>,
            reply: server::ChannelOpenHandle,
            _s: &mut Session,
        ) -> Result<(), Self::Error> {
            reply.accept().await;
            Ok(())
        }
        async fn auth_password(&mut self, _u: &str, p: &str) -> Result<ServerAuth, Self::Error> {
            if p == "s3cret" {
                self.first_ok = true;
                Ok(ServerAuth::Reject {
                    proceed_with_methods: Some(MethodSet::from(
                        &[MethodKind::KeyboardInteractive][..],
                    )),
                    partial_success: true,
                })
            } else {
                Ok(ServerAuth::reject())
            }
        }
        async fn auth_publickey(
            &mut self,
            _u: &str,
            key: &PublicKey,
        ) -> Result<ServerAuth, Self::Error> {
            if key.key_data() == self.authorized.key_data() {
                self.first_ok = true;
                Ok(ServerAuth::Reject {
                    proceed_with_methods: Some(MethodSet::from(
                        &[MethodKind::KeyboardInteractive][..],
                    )),
                    partial_success: true,
                })
            } else {
                Ok(ServerAuth::reject())
            }
        }
        async fn auth_keyboard_interactive(
            &mut self,
            _user: &str,
            _sub: &str,
            response: Option<server::Response<'_>>,
        ) -> Result<ServerAuth, Self::Error> {
            if !self.first_ok {
                return Ok(ServerAuth::reject());
            }
            match response {
                None => Ok(ServerAuth::Partial {
                    name: "2fa".into(),
                    instructions: "".into(),
                    prompts: vec![("OTP: ".into(), false)].into(),
                }),
                Some(mut r) => {
                    let ok = r.next().map(|b| b.as_ref() == b"otp").unwrap_or(false);
                    Ok(if ok {
                        ServerAuth::Accept
                    } else {
                        ServerAuth::reject()
                    })
                }
            }
        }
    }
    let kp = rnssh_core::keys::generate_key_pair(KeyType::Ed25519, None, None).unwrap();
    let authorized = PublicKey::from_openssh(&kp.public_key).unwrap();
    let host_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let config = Arc::new(server::Config {
        auth_rejection_time: Duration::from_millis(10),
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        keys: vec![host_key],
        ..Default::default()
    });
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut srv = TwoFactor { authorized };
    tokio::spawn(async move {
        let _ = srv.run_on_socket(config, &listener).await;
    });

    let otp_events = || {
        Arc::new(Events {
            accept_host_key: true,
            seen_host_key: Mutex::new(None),
            kbi_answers: Some(vec!["otp".into()]),
            disconnected: Mutex::new(None),
            disconnect_tx: Mutex::new(None),
        })
    };

    // password + OTP via the app's handler
    let conn = Connection::connect(
        options(port, Auth::Password(Zeroizing::new("s3cret".into()))),
        otp_events(),
    )
    .await
    .expect("password then otp");
    conn.disconnect().await;

    // key + OTP: russh's *server* (0.63.1) cannot signal partial success on
    // the publickey path (server/encrypted.rs resets `partial_success` to
    // false right after setting it), so against this test server the key
    // attempt reads as a plain rejection. Real OpenSSH does signal it and the
    // client branch is identical to the password one (`second_factor`), so
    // only assert that the key path still fails cleanly here.
    let auth = Auth::PrivateKey {
        pem: kp.private_key.clone(),
        passphrase: None,
    };
    let err = Connection::connect(options(port, auth), otp_events())
        .await
        .unwrap_err();
    assert_eq!(err.code, rnssh_core::ErrorCode::AuthFailed, "{err}");

    // No handler → clear failure, not a hang (the auto-answer uses the
    // password, which is not a valid OTP).
    let err = Connection::connect(
        options(port, Auth::Password(Zeroizing::new("s3cret".into()))),
        Events::accepting(),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code, rnssh_core::ErrorCode::AuthFailed, "{err}");
}

// ---------- local port forwarding ----------

/// Server that honours direct-tcpip by connecting to the requested target
/// (loopback only) and piping bytes, like sshd with AllowTcpForwarding.
struct Forwarding;
struct ForwardingHandler;
impl server::Server for Forwarding {
    type Handler = ForwardingHandler;
    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> ForwardingHandler {
        ForwardingHandler
    }
}
impl server::Handler for ForwardingHandler {
    type Error = russh::Error;
    async fn auth_password(&mut self, _u: &str, _p: &str) -> Result<ServerAuth, Self::Error> {
        Ok(ServerAuth::Accept)
    }
    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host: &str,
        port: u32,
        _oa: &str,
        _op: u32,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if host != "127.0.0.1" && host != "localhost" {
            reply
                .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        }
        match TcpStream::connect(("127.0.0.1", port as u16)).await {
            Ok(mut target) => {
                reply.accept().await;
                tokio::spawn(async move {
                    let mut stream = channel.into_stream();
                    let _ = tokio::io::copy_bidirectional(&mut target, &mut stream).await;
                });
            }
            Err(_) => {
                reply.reject(russh::ChannelOpenFailure::ConnectFailed).await;
            }
        }
        Ok(())
    }
}

async fn start_echo_target() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let (mut r, mut w) = sock.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    port
}

async fn start_forwarding_server() -> (u16, tokio::task::JoinHandle<()>) {
    let host_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let config = Arc::new(server::Config {
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        keys: vec![host_key],
        ..Default::default()
    });
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let _ = Forwarding.run_on_socket(config, &listener).await;
    });
    (port, task)
}

struct ForwardSink {
    closed: Mutex<Option<oneshot::Sender<Option<String>>>>,
}
impl ForwardEvents for ForwardSink {
    fn on_closed(&self, reason: Option<String>) {
        if let Some(tx) = self.closed.lock().unwrap().take() {
            let _ = tx.send(reason);
        }
    }
}
fn forward_sink() -> (Arc<ForwardSink>, oneshot::Receiver<Option<String>>) {
    let (tx, rx) = oneshot::channel();
    (
        Arc::new(ForwardSink {
            closed: Mutex::new(Some(tx)),
        }),
        rx,
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn local_forward_tunnels_tcp() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let echo_port = start_echo_target().await;
    let (port, _server) = start_forwarding_server().await;
    let conn = Connection::connect(
        options(port, Auth::Password(Zeroizing::new("x".into()))),
        Events::accepting(),
    )
    .await
    .unwrap();

    let (sink, closed_rx) = forward_sink();
    let fwd = conn
        .forward_local(
            ForwardOptions {
                remote_port: echo_port,
                ..Default::default()
            },
            sink,
        )
        .await
        .unwrap();
    assert!(fwd.is_open());
    assert_ne!(fwd.local_port(), 0);

    // Ten concurrent clients, each echoing 200 KiB through the tunnel.
    let mut tasks = Vec::new();
    for i in 0..10u8 {
        let local_port = fwd.local_port();
        tasks.push(tokio::spawn(async move {
            let mut s = TcpStream::connect(("127.0.0.1", local_port)).await.unwrap();
            let payload = vec![i; 200 * 1024];
            s.write_all(&payload).await.unwrap();
            let mut back = vec![0u8; payload.len()];
            s.read_exact(&mut back).await.unwrap();
            assert_eq!(back, payload);
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(fwd.active_connections(), 0);

    // Close: listener gone, on_closed(None) delivered.
    fwd.close().await;
    assert!(!fwd.is_open());
    assert_eq!(closed_rx.await.unwrap(), None);
    assert!(
        TcpStream::connect(("127.0.0.1", fwd.local_port()))
            .await
            .is_err()
    );
    fwd.close().await; // idempotent
    conn.disconnect().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn local_forward_rejects_bad_options_and_refused_targets() {
    use tokio::io::AsyncReadExt;
    let (port, _server) = start_forwarding_server().await;
    let conn = Connection::connect(
        options(port, Auth::Password(Zeroizing::new("x".into()))),
        Events::accepting(),
    )
    .await
    .unwrap();

    // Non-loopback bind is refused up front.
    let (sink, _) = forward_sink();
    let err = conn
        .forward_local(
            ForwardOptions {
                bind: "0.0.0.0".into(),
                remote_port: 22,
                ..Default::default()
            },
            sink,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, rnssh_core::ErrorCode::InvalidArgument);

    // Target the server cannot reach: the local client gets EOF, the forward stays up.
    let (sink, _) = forward_sink();
    let fwd = conn
        .forward_local(
            ForwardOptions {
                remote_port: 1, // nothing listens there
                ..Default::default()
            },
            sink,
        )
        .await
        .unwrap();
    let mut s = TcpStream::connect(("127.0.0.1", fwd.local_port()))
        .await
        .unwrap();
    let mut buf = [0u8; 1];
    let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf))
        .await
        .expect("EOF in time")
        .unwrap_or(0);
    assert_eq!(n, 0);
    assert!(fwd.is_open());
    fwd.close().await;
    conn.disconnect().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn local_forward_closes_when_connection_drops() {
    let echo_port = start_echo_target().await;
    let (port, server) = start_forwarding_server().await;
    let conn = Connection::connect(
        options(port, Auth::Password(Zeroizing::new("x".into()))),
        Events::accepting(),
    )
    .await
    .unwrap();
    let (sink, closed_rx) = forward_sink();
    let fwd = conn
        .forward_local(
            ForwardOptions {
                remote_port: echo_port,
                ..Default::default()
            },
            sink,
        )
        .await
        .unwrap();
    server.abort();
    let reason = tokio::time::timeout(Duration::from_secs(5), closed_rx)
        .await
        .expect("forward closed after the connection dropped")
        .unwrap();
    assert!(reason.is_some(), "a dropped connection is not an app close");
    assert!(!fwd.is_open());
}

// ---------- plain TCP forwarding (no SSH) ----------

use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

/// Counts `on_closed` deliveries and remembers the last reason.
struct CountingSink {
    closed: AtomicUsize,
    reason: Mutex<Option<Option<String>>>,
}
impl ForwardEvents for CountingSink {
    fn on_closed(&self, reason: Option<String>) {
        self.closed.fetch_add(1, AtomicOrdering::SeqCst);
        *self.reason.lock().unwrap() = Some(reason);
    }
}
fn counting_sink() -> Arc<CountingSink> {
    Arc::new(CountingSink {
        closed: AtomicUsize::new(0),
        reason: Mutex::new(None),
    })
}

fn tcp_options(port: u16) -> ForwardOptions {
    ForwardOptions {
        remote_host: "127.0.0.1".into(),
        remote_port: port,
        ..Default::default()
    }
}

/// Deterministic, non-repeating-ish byte pattern so a corrupted or reordered
/// chunk cannot compare equal by accident.
fn pattern_byte(i: usize) -> u8 {
    ((i as u32).wrapping_mul(2_654_435_761) >> 24) as u8 ^ (i as u8)
}

async fn until<F: Fn() -> bool>(what: &str, cond: F) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !cond() {
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_forward_round_trips_small_and_large_payloads() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let echo_port = start_echo_target().await;
    let sink = counting_sink();
    let fwd = rnssh_core::forward::forward_tcp(tcp_options(echo_port), sink.clone())
        .await
        .unwrap();
    assert!(fwd.is_open());
    assert_ne!(fwd.local_port(), 0);

    // Small: a handful of bytes, one round trip.
    let mut s = TcpStream::connect(("127.0.0.1", fwd.local_port()))
        .await
        .unwrap();
    s.write_all(b"ping").await.unwrap();
    let mut back = [0u8; 4];
    s.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"ping");
    drop(s);

    // Large: 64 MiB streamed and compared byte for byte, writer and reader
    // concurrent so neither side's buffer is the limit.
    const TOTAL: usize = 64 * 1024 * 1024;
    let mut s = TcpStream::connect(("127.0.0.1", fwd.local_port()))
        .await
        .unwrap();
    let (mut r, mut w) = s.split();
    let writer = async {
        let mut chunk = vec![0u8; 256 * 1024];
        let mut sent = 0usize;
        while sent < TOTAL {
            let n = chunk.len().min(TOTAL - sent);
            for (k, b) in chunk.iter_mut().take(n).enumerate() {
                *b = pattern_byte(sent + k);
            }
            w.write_all(&chunk[..n]).await.unwrap();
            sent += n;
        }
        w.shutdown().await.unwrap();
    };
    let reader = async {
        let mut buf = vec![0u8; 256 * 1024];
        let mut got = 0usize;
        while got < TOTAL {
            let n = r.read(&mut buf).await.unwrap();
            assert_ne!(n, 0, "EOF after {got} bytes");
            for (k, b) in buf[..n].iter().enumerate() {
                assert_eq!(*b, pattern_byte(got + k), "byte {} differs", got + k);
            }
            got += n;
        }
        assert_eq!(got, TOTAL);
        // The writer's shutdown reached the echo server, which answered with EOF.
        assert_eq!(r.read(&mut buf).await.unwrap(), 0);
    };
    let started = std::time::Instant::now();
    tokio::join!(writer, reader);
    eprintln!(
        "tcp forward: 64 MiB round trip in {:?} ({:.0} MB/s)",
        started.elapsed(),
        (2 * TOTAL) as f64 / 1e6 / started.elapsed().as_secs_f64()
    );
    drop(s);

    until("active == 0", || fwd.active_connections() == 0).await;
    assert_eq!(sink.closed.load(AtomicOrdering::SeqCst), 0);
    fwd.close().await;
    assert_eq!(sink.closed.load(AtomicOrdering::SeqCst), 1);
    assert_eq!(*sink.reason.lock().unwrap(), Some(None));
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_forward_serves_fifty_concurrent_connections() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let echo_port = start_echo_target().await;
    let sink = counting_sink();
    let fwd = rnssh_core::forward::forward_tcp(tcp_options(echo_port), sink.clone())
        .await
        .unwrap();

    let mut tasks = Vec::new();
    for i in 0..50u8 {
        let local_port = fwd.local_port();
        tasks.push(tokio::spawn(async move {
            let mut s = TcpStream::connect(("127.0.0.1", local_port)).await.unwrap();
            let payload: Vec<u8> = (0..100 * 1024)
                .map(|k| pattern_byte(k ^ usize::from(i)))
                .collect();
            let (mut r, mut w) = s.split();
            let (_, back) = tokio::join!(
                async {
                    w.write_all(&payload).await.unwrap();
                    w.shutdown().await.unwrap();
                },
                async {
                    let mut back = Vec::with_capacity(payload.len());
                    r.read_to_end(&mut back).await.unwrap();
                    back
                }
            );
            assert_eq!(back, payload);
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    until("active == 0", || fwd.active_connections() == 0).await;
    fwd.close().await;
    assert_eq!(sink.closed.load(AtomicOrdering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_forward_half_close_reaches_upstream_and_reverse_still_drains() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // Upstream that reads everything until EOF, then answers with the byte
    // count, then closes. It can only answer after the client's half-close
    // arrived, so the reply proves the half-close was forwarded and that the
    // reverse direction is still open after it.
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut sink = Vec::new();
                let n = sock.read_to_end(&mut sink).await.unwrap();
                sock.write_all(format!("got {n} bytes").as_bytes())
                    .await
                    .unwrap();
                sock.shutdown().await.unwrap();
            });
        }
    });
    let sink = counting_sink();
    let fwd = rnssh_core::forward::forward_tcp(tcp_options(port), sink.clone())
        .await
        .unwrap();

    let mut s = TcpStream::connect(("127.0.0.1", fwd.local_port()))
        .await
        .unwrap();
    s.write_all(&vec![7u8; 1_000_000]).await.unwrap();
    s.shutdown().await.unwrap();
    let mut reply = String::new();
    s.read_to_string(&mut reply).await.unwrap();
    assert_eq!(reply, "got 1000000 bytes");

    until("active == 0", || fwd.active_connections() == 0).await;
    fwd.close().await;
    assert_eq!(sink.closed.load(AtomicOrdering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_forward_survives_refused_and_early_closing_peers() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let sink = counting_sink();

    // Upstream refuses: nothing listens on that port. The accepted client
    // simply sees EOF; the forward stays open and counts back down.
    let dead = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let dead_port = dead.local_addr().unwrap().port();
    drop(dead);
    let fwd = rnssh_core::forward::forward_tcp(tcp_options(dead_port), sink.clone())
        .await
        .unwrap();
    let mut s = TcpStream::connect(("127.0.0.1", fwd.local_port()))
        .await
        .unwrap();
    let mut buf = [0u8; 8];
    assert_eq!(
        s.read(&mut buf).await.unwrap(),
        0,
        "refused upstream must read as EOF"
    );
    until("refused: active == 0", || fwd.active_connections() == 0).await;
    assert!(fwd.is_open());
    fwd.close().await;
    assert_eq!(sink.closed.load(AtomicOrdering::SeqCst), 1);

    // Upstream closes first: it sends a banner and hangs up. The client gets
    // the banner, then EOF.
    let banner = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let banner_port = banner.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = banner.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let _ = sock.write_all(b"bye").await;
                drop(sock);
            });
        }
    });
    let sink = counting_sink();
    let fwd = rnssh_core::forward::forward_tcp(tcp_options(banner_port), sink.clone())
        .await
        .unwrap();
    let mut s = TcpStream::connect(("127.0.0.1", fwd.local_port()))
        .await
        .unwrap();
    let mut got = Vec::new();
    s.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"bye");
    // Still counted: a TCP forward cannot tell a peer's half-close from a
    // full close, so the tunnel lives until the client side is gone as well.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(fwd.active_connections(), 1);
    drop(s);
    until("banner: active == 0", || fwd.active_connections() == 0).await;

    // Client closes first, mid-stream: the upstream's echo copy ends, the
    // tunnel task finishes, nothing is left counted.
    let echo_port = start_echo_target().await;
    let sink2 = counting_sink();
    let fwd2 = rnssh_core::forward::forward_tcp(tcp_options(echo_port), sink2.clone())
        .await
        .unwrap();
    let mut s = TcpStream::connect(("127.0.0.1", fwd2.local_port()))
        .await
        .unwrap();
    s.write_all(&vec![1u8; 64 * 1024]).await.unwrap();
    until("active == 1", || fwd2.active_connections() == 1).await;
    drop(s);
    until("client-close: active == 0", || {
        fwd2.active_connections() == 0
    })
    .await;
    assert!(fwd2.is_open());

    fwd.close().await;
    fwd2.close().await;
    fwd2.close().await; // idempotent: the handler must not fire twice
    assert_eq!(sink.closed.load(AtomicOrdering::SeqCst), 1);
    assert_eq!(sink2.closed.load(AtomicOrdering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_forward_close_with_live_connections_frees_everything() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let echo_port = start_echo_target().await;
    let sink = counting_sink();
    let weak = Arc::downgrade(&sink);
    let fwd = rnssh_core::forward::forward_tcp(tcp_options(echo_port), sink)
        .await
        .unwrap();
    let local_port = fwd.local_port();

    // Three live tunnels, each mid-conversation.
    let mut clients = Vec::new();
    for _ in 0..3 {
        let mut s = TcpStream::connect(("127.0.0.1", local_port)).await.unwrap();
        s.write_all(b"hold").await.unwrap();
        let mut back = [0u8; 4];
        s.read_exact(&mut back).await.unwrap();
        clients.push(s);
    }
    assert_eq!(fwd.active_connections(), 3);

    let started = std::time::Instant::now();
    fwd.close().await;
    let close_took = started.elapsed();
    assert!(!fwd.is_open());
    assert!(
        close_took < Duration::from_secs(2),
        "close took {close_took:?}"
    );

    // The port refuses new connections immediately after close resolved.
    let refused = tokio::time::timeout(
        Duration::from_secs(2),
        TcpStream::connect(("127.0.0.1", local_port)),
    )
    .await
    .expect("connect must not hang");
    assert!(refused.is_err(), "listener still accepting after close");

    // Every live tunnel was torn down: the clients read EOF (or a reset)
    // instead of hanging, which is what proves the tunnel tasks are gone.
    for mut s in clients {
        let mut buf = [0u8; 16];
        let r = tokio::time::timeout(Duration::from_secs(2), s.read(&mut buf))
            .await
            .expect("tunnel not torn down within 2 s");
        assert!(matches!(r, Ok(0) | Err(_)), "{r:?}");
    }
    assert_eq!(fwd.active_connections(), 0);

    // The accept loop dropped its handler: the only strong reference was the
    // loop's, so the weak one no longer upgrades once the task has finished.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while weak.upgrade().is_some() {
        assert!(
            std::time::Instant::now() < deadline,
            "accept loop leaked its events sink"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_forward_refuses_bad_options() {
    let sink = counting_sink();
    let err = rnssh_core::forward::forward_tcp(
        ForwardOptions {
            bind: "0.0.0.0".into(),
            ..tcp_options(80)
        },
        sink.clone(),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code, rnssh_core::ErrorCode::InvalidArgument);

    let err = rnssh_core::forward::forward_tcp(
        ForwardOptions {
            bind: "not an ip".into(),
            ..tcp_options(80)
        },
        sink.clone(),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code, rnssh_core::ErrorCode::InvalidArgument);

    let err = rnssh_core::forward::forward_tcp(
        ForwardOptions {
            remote_host: "  ".into(),
            ..tcp_options(80)
        },
        sink.clone(),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code, rnssh_core::ErrorCode::InvalidArgument);

    let err = rnssh_core::forward::forward_tcp(tcp_options(0), sink.clone())
        .await
        .unwrap_err();
    assert_eq!(err.code, rnssh_core::ErrorCode::InvalidArgument);

    // A busy local port is an IO error, not a panic.
    let taken = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let err = rnssh_core::forward::forward_tcp(
        ForwardOptions {
            local_port: taken.local_addr().unwrap().port(),
            ..tcp_options(80)
        },
        sink.clone(),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code, rnssh_core::ErrorCode::Io);

    // None of the failed starts may have fired the handler.
    assert_eq!(sink.closed.load(AtomicOrdering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_forward_caps_concurrent_connections() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let echo_port = start_echo_target().await;
    let sink = counting_sink();
    let fwd = rnssh_core::forward::forward_tcp(
        ForwardOptions {
            max_connections: 2,
            ..tcp_options(echo_port)
        },
        sink,
    )
    .await
    .unwrap();
    let mut a = TcpStream::connect(("127.0.0.1", fwd.local_port()))
        .await
        .unwrap();
    let mut b = TcpStream::connect(("127.0.0.1", fwd.local_port()))
        .await
        .unwrap();
    for s in [&mut a, &mut b] {
        s.write_all(b"x").await.unwrap();
        let mut back = [0u8; 1];
        s.read_exact(&mut back).await.unwrap();
    }
    assert_eq!(fwd.active_connections(), 2);
    // The third is accepted and dropped: EOF, and the count does not move.
    let mut c = TcpStream::connect(("127.0.0.1", fwd.local_port()))
        .await
        .unwrap();
    let mut buf = [0u8; 1];
    assert_eq!(c.read(&mut buf).await.unwrap(), 0);
    assert_eq!(fwd.active_connections(), 2);
    drop(a);
    until("active == 1", || fwd.active_connections() == 1).await;
    fwd.close().await;
}
