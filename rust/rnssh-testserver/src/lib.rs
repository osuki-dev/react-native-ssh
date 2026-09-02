//! Dev-only SSH server for manual / automated testing of the module.
//!
//! ```sh
//! cargo run -p rnssh-testserver            # listens on 0.0.0.0:2222
//! RNSSH_TEST_PORT=2200 cargo run -p rnssh-testserver
//! ```
//!
//! Credentials: user `test`, password `test`. Any public key is accepted for
//! user `key`. A fixed Ed25519 host key is generated per process; its
//! fingerprint is printed on start.
//!
//! Behaviour:
//! * shell: prints a banner, then echoes each line back as `you said: <line>`;
//!   `exit` closes the channel with status 0. Window changes are reported.
//! * exec: `echo <x>` → `<x>\n` (status 0), `fail` → stderr + status 7,
//!   `env` → the requested env vars, `sleep <n>` → waits n seconds, anything
//!   else → `ran: <cmd>\n`.
//! * `kbi` user: keyboard-interactive only, single prompt, answer `test`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use russh::keys::{Algorithm, HashAlg, PrivateKey, PublicKey};
use russh::server::{self, Auth, Msg, Server as _, Session};
use russh::{Channel, ChannelId, MethodKind, MethodSet, Pty};
use tokio::net::TcpListener;

#[derive(Clone, Default)]
pub struct TestServer;

pub struct Handler {
    env: HashMap<String, String>,
    line: Vec<u8>,
}

impl server::Server for TestServer {
    type Handler = Handler;
    fn new_client(&mut self, addr: Option<std::net::SocketAddr>) -> Handler {
        log::info!("client connected: {addr:?}");
        Handler {
            env: HashMap::new(),
            line: Vec::new(),
        }
    }
    fn handle_session_error(&mut self, error: russh::Error) {
        log::info!("session ended: {error}");
    }
}

impl server::Handler for Handler {
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

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        log::info!("password auth for {user}");
        if user == "kbi" {
            return Ok(Auth::Reject {
                proceed_with_methods: Some(MethodSet::from(&[MethodKind::KeyboardInteractive][..])),
                partial_success: false,
            });
        }
        if user == "2fa" {
            // Password first, then a keyboard-interactive second factor ("test").
            return Ok(if password == "test" {
                Auth::Reject {
                    proceed_with_methods: Some(MethodSet::from(
                        &[MethodKind::KeyboardInteractive][..],
                    )),
                    partial_success: true,
                }
            } else {
                Auth::reject()
            });
        }
        Ok(if user == "test" && password == "test" {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn auth_keyboard_interactive(
        &mut self,
        user: &str,
        _submethods: &str,
        response: Option<server::Response<'_>>,
    ) -> Result<Auth, Self::Error> {
        log::info!("keyboard-interactive auth for {user}");
        match response {
            None => Ok(Auth::Partial {
                name: "rnssh test".into(),
                instructions: "Type the word 'test'".into(),
                prompts: vec![("Secret word: ".into(), false)].into(),
            }),
            Some(mut r) => {
                let ok = r.next().map(|b| b.as_ref() == b"test").unwrap_or(false);
                Ok(if ok { Auth::Accept } else { Auth::reject() })
            }
        }
    }

    async fn auth_publickey(&mut self, user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        log::info!(
            "publickey auth for {user}: {}",
            key.fingerprint(HashAlg::Sha256)
        );
        Ok(if user == "key" {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn env_request(
        &mut self,
        _channel: ChannelId,
        name: &str,
        value: &str,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.env.insert(name.to_string(), value.to_string());
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        cols: u32,
        rows: u32,
        _w: u32,
        _h: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        log::info!("pty {term} {cols}x{rows}");
        session.channel_success(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        session.data(
            channel,
            b"\x1b[1;32mrnssh test server\x1b[0m\r\nType something and press enter; 'exit' to close.\r\n$ ".to_vec(),
        )?;
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
        log::info!("exec: {cmd}");
        let mut status = 0;
        if let Some(rest) = cmd.strip_prefix("echo ") {
            session.data(channel, format!("{rest}\n").into_bytes())?;
        } else if cmd == "fail" {
            session.extended_data(channel, 1, b"nope\n".to_vec())?;
            status = 7;
        } else if cmd == "env" {
            let mut keys: Vec<_> = self.env.iter().collect();
            keys.sort();
            for (k, v) in keys {
                session.data(channel, format!("{k}={v}\n").into_bytes())?;
            }
        } else if let Some(secs) = cmd.strip_prefix("sleep ") {
            let secs: u64 = secs.trim().parse().unwrap_or(1);
            tokio::time::sleep(Duration::from_secs(secs)).await;
            session.data(channel, b"done\n".to_vec())?;
        } else if cmd == "bytes" {
            // Exercise the lossy UTF-8 path.
            session.data(channel, vec![b'o', b'k', 0xff, 0xfe, b'\n'])?;
        } else {
            session.data(channel, format!("ran: {cmd}\n").into_bytes())?;
        }
        session.exit_status_request(channel, status)?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        cols: u32,
        rows: u32,
        _w: u32,
        _h: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.data(
            channel,
            format!("\r\n[resized to {cols}x{rows}]\r\n$ ").into_bytes(),
        )?;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        for &b in data {
            match b {
                b'\r' | b'\n' => {
                    let line = String::from_utf8_lossy(&self.line).trim().to_string();
                    self.line.clear();
                    if line == "exit" {
                        session.data(channel, b"\r\nbye\r\n".to_vec())?;
                        session.exit_status_request(channel, 0)?;
                        session.eof(channel)?;
                        session.close(channel)?;
                        return Ok(());
                    }
                    session.data(channel, format!("\r\nyou said: {line}\r\n$ ").into_bytes())?;
                }
                0x03 => {
                    // Ctrl-C
                    self.line.clear();
                    session.data(channel, b"^C\r\n$ ".to_vec())?;
                }
                0x7f | 0x08 => {
                    if self.line.pop().is_some() {
                        session.data(channel, b"\x08 \x08".to_vec())?;
                    }
                }
                _ => {
                    self.line.push(b);
                    session.data(channel, vec![b])?; // echo
                }
            }
        }
        Ok(())
    }
}

/// Bind on `addr` and serve forever. Returns the bound port and the host key
/// fingerprint before serving starts, via `on_ready`.
pub async fn serve(listener: TcpListener, config: Arc<server::Config>) -> std::io::Result<()> {
    let mut srv = TestServer;
    srv.run_on_socket(config, &listener).await
}

/// Default config. The Ed25519 host key is fresh per process unless
/// `RNSSH_TEST_KEY_FILE` points at a file: then it is loaded from there, or
/// generated and written on first use, so fingerprints stay stable across
/// restarts. Returns (config, fingerprint).
pub fn config() -> (Arc<server::Config>, String) {
    let host_key = match std::env::var("RNSSH_TEST_KEY_FILE") {
        Ok(path) if !path.is_empty() => match std::fs::read_to_string(&path) {
            Ok(pem) => {
                PrivateKey::from_openssh(&pem).expect("RNSSH_TEST_KEY_FILE is not an OpenSSH key")
            }
            Err(_) => {
                let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
                let pem = key
                    .to_openssh(russh::keys::ssh_key::LineEnding::LF)
                    .unwrap();
                std::fs::write(&path, pem.as_bytes()).expect("cannot write RNSSH_TEST_KEY_FILE");
                key
            }
        },
        _ => PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap(),
    };
    let fp = host_key.fingerprint(HashAlg::Sha256).to_string();
    let config = Arc::new(server::Config {
        inactivity_timeout: Some(Duration::from_secs(3600)),
        auth_rejection_time: Duration::from_millis(200),
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        keys: vec![host_key],
        ..Default::default()
    });
    (config, fp)
}
