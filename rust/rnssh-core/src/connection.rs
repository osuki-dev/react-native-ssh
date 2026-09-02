//! Connection lifecycle: TCP → handshake → host key decision → auth → channels.

use std::borrow::Cow;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use russh::client::{self, AuthResult, DisconnectReason, Handle, KeyboardInteractiveAuthResponse};
use russh::keys::ssh_key::{Algorithm, EcdsaCurve, HashAlg};
use russh::keys::{PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::{ChannelMsg, Disconnect, MethodKind, Preferred, SshId, cipher, kex, mac};
use tokio::sync::{Mutex, oneshot};
use zeroize::Zeroizing;

use crate::error::{ErrorCode, Result, SshError};
use crate::hostkey::HostKey;
use crate::keys::parse_private_key;
use crate::runtime;
use crate::shell::{Shell, ShellEvents, ShellOptions};

/// Hard ceiling on how long a connection attempt may sit waiting for the user
/// (host key decision, keyboard-interactive prompts) regardless of
/// `connect_timeout`. User wait time is otherwise *excluded* from the timeout,
/// so nobody is rushed into trusting a fingerprint.
pub const MAX_USER_DECISION_WAIT: Duration = Duration::from_secs(10 * 60);

/// Default cap on bytes collected by [`Connection::exec`].
pub const DEFAULT_MAX_EXEC_OUTPUT: usize = 16 * 1024 * 1024;

/// Algorithms we are willing to negotiate. Modern only: no SHA-1 anywhere
/// (no `ssh-rsa` signatures, no `*-sha1` kex or MACs), no CBC, no 3DES, no
/// compression. Servers that offer nothing on these lists are refused.
pub fn preferred_algorithms() -> Preferred {
    Preferred {
        kex: Cow::Borrowed(&[
            kex::MLKEM768X25519_SHA256,
            kex::CURVE25519,
            kex::CURVE25519_PRE_RFC_8731,
            kex::DH_GEX_SHA256,
            kex::DH_G18_SHA512,
            kex::DH_G16_SHA512,
            kex::ECDH_SHA2_NISTP256,
            kex::ECDH_SHA2_NISTP384,
            kex::ECDH_SHA2_NISTP521,
            // 2048-bit DH: still acceptable, but only if nothing above is offered.
            kex::DH_G14_SHA256,
            kex::EXTENSION_SUPPORT_AS_CLIENT,
            kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
        ]),
        host_key_certificates: Cow::Borrowed(&[]),
        key: Cow::Borrowed(&[
            Algorithm::Ed25519,
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP384,
            },
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP521,
            },
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            },
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha256),
            },
        ]),
        // AES-GCM first: on every arm64 phone (and Apple silicon) hardware AES
        // makes it ~3x faster than ChaCha20 (measured in tests/e2e.rs
        // perf_latency_and_ciphers: 1.9 GB/s vs 0.65 GB/s), i.e. less CPU and
        // battery per byte at equal security.
        cipher: Cow::Borrowed(&[
            cipher::AES_256_GCM,
            cipher::AES_128_GCM,
            cipher::CHACHA20_POLY1305,
            cipher::AES_256_CTR,
            cipher::AES_192_CTR,
            cipher::AES_128_CTR,
        ]),
        mac: Cow::Borrowed(&[
            mac::HMAC_SHA512_ETM,
            mac::HMAC_SHA256_ETM,
            mac::HMAC_SHA512,
            mac::HMAC_SHA256,
        ]),
        compression: Cow::Borrowed(&[russh::compression::NONE]),
    }
}

/// Same policy as [`preferred_algorithms`], with the host key algorithms named
/// in `first` moved to the front (in that order). Names may be the plain
/// algorithm (`ssh-rsa`, `ssh-ed25519`, `ecdsa-sha2-nistp256`), an RSA
/// signature variant (`rsa-sha2-512`), or a certificate variant
/// (`*-cert-v01@openssh.com`).
pub fn preferred_algorithms_with_host_keys(first: &[String]) -> Preferred {
    let mut pref = preferred_algorithms();
    if first.is_empty() {
        return pref;
    }
    let matches = |alg: &Algorithm, name: &str| -> bool {
        let name = name.strip_suffix("-cert-v01@openssh.com").unwrap_or(name);
        match alg {
            Algorithm::Rsa { .. } => name == "ssh-rsa" || name.starts_with("rsa-sha2-"),
            other => other.as_str() == name,
        }
    };
    let mut ordered: Vec<Algorithm> = Vec::with_capacity(pref.key.len());
    for name in first {
        for alg in pref.key.iter() {
            if matches(alg, name) && !ordered.contains(alg) {
                ordered.push(alg.clone());
            }
        }
    }
    for alg in pref.key.iter() {
        if !ordered.contains(alg) {
            ordered.push(alg.clone());
        }
    }
    pref.key = Cow::Owned(ordered);
    pref
}

/// How to authenticate. Secrets are zeroized on drop.
#[derive(Clone)]
pub enum Auth {
    /// `none` method — only useful against servers that allow it.
    None,
    /// Password. If the server only offers keyboard-interactive, the password
    /// is used to answer its non-echo prompts (what OpenSSH users expect to
    /// "just work").
    Password(Zeroizing<String>),
    /// Private key in OpenSSH / PKCS#8 / PKCS#1 / PPK format.
    PrivateKey {
        pem: Zeroizing<String>,
        passphrase: Option<Zeroizing<String>>,
    },
    /// Drive keyboard-interactive entirely through
    /// [`ConnectionEvents::keyboard_interactive`].
    KeyboardInteractive,
}

impl std::fmt::Debug for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Auth::None => write!(f, "None"),
            Auth::Password(_) => write!(f, "Password(***)"),
            Auth::PrivateKey { .. } => write!(f, "PrivateKey(***)"),
            Auth::KeyboardInteractive => write!(f, "KeyboardInteractive"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConnectOptions {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth: Auth,
    /// Covers TCP connect + handshake + auth, *excluding* time spent waiting
    /// for the user (see [`MAX_USER_DECISION_WAIT`]).
    pub connect_timeout: Duration,
    /// `None` disables keepalives. Mobile links drop silently; enable it.
    pub keepalive_interval: Option<Duration>,
    /// Unanswered keepalives before the connection is declared dead.
    pub keepalive_max: usize,
    /// Cap for [`Connection::exec`] output (stdout + stderr).
    pub max_exec_output: usize,
    /// Host key algorithms to offer first, most preferred first, e.g. the
    /// algorithm of a key the app already pinned (`"ssh-rsa"`,
    /// `"ssh-ed25519"`, `"ecdsa-sha2-nistp256"`). Unknown names are ignored;
    /// everything else keeps its default order. Empty = default order.
    pub host_key_algorithms: Vec<String>,
}

impl Default for ConnectOptions {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 22,
            username: String::new(),
            auth: Auth::None,
            connect_timeout: Duration::from_secs(30),
            keepalive_interval: Some(Duration::from_secs(15)),
            keepalive_max: 3,
            max_exec_output: DEFAULT_MAX_EXEC_OUTPUT,
            host_key_algorithms: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyboardInteractivePrompt {
    pub prompt: String,
    pub echo: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyboardInteractiveChallenge {
    pub name: String,
    pub instruction: String,
    pub prompts: Vec<KeyboardInteractivePrompt>,
}

/// Interactive hooks for one connection. Implemented by the FFI layer.
///
/// All methods may be called from a tokio worker thread and must not block.
/// Decisions are delivered through the provided one-shot sender; dropping the
/// sender without answering is treated as "reject" / "cancel".
pub trait ConnectionEvents: Send + Sync + 'static {
    fn verify_host_key(&self, key: HostKey, respond: oneshot::Sender<bool>);

    /// Return `false` if the app did not provide a prompt handler. In that case
    /// password auth falls back to answering prompts with the password itself,
    /// and `Auth::KeyboardInteractive` fails with `InvalidArgument`.
    fn supports_keyboard_interactive(&self) -> bool {
        false
    }

    fn keyboard_interactive(
        &self,
        challenge: KeyboardInteractiveChallenge,
        respond: oneshot::Sender<Option<Vec<String>>>,
    ) {
        let _ = (challenge, respond);
    }

    /// Called once when the transport goes away for any reason after the
    /// connection was established.
    fn disconnected(&self, reason: String);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecResult {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// `None` if the server closed the channel without reporting a status.
    pub exit_code: Option<u32>,
}

/// Tracks how long the connect attempt has been parked on a user decision so
/// that time can be subtracted from the connect timeout.
#[derive(Default)]
struct UserWait {
    /// Milliseconds spent waiting on decisions that already completed.
    completed_ms: AtomicU64,
    /// Whether a decision is pending right now.
    pending: AtomicBool,
    pending_since: std::sync::Mutex<Option<Instant>>,
}

impl UserWait {
    fn begin(&self) {
        if let Ok(mut g) = self.pending_since.lock() {
            *g = Some(Instant::now());
        }
        self.pending.store(true, Ordering::Release);
    }

    fn end(&self) {
        self.pending.store(false, Ordering::Release);
        if let Ok(mut g) = self.pending_since.lock()
            && let Some(since) = g.take()
        {
            let ms = u64::try_from(since.elapsed().as_millis()).unwrap_or(u64::MAX);
            self.completed_ms.fetch_add(ms, Ordering::AcqRel);
        }
    }

    fn total(&self) -> Duration {
        let mut d = Duration::from_millis(self.completed_ms.load(Ordering::Acquire));
        if self.pending.load(Ordering::Acquire)
            && let Ok(g) = self.pending_since.lock()
            && let Some(since) = *g
        {
            d += since.elapsed();
        }
        d
    }

    fn is_pending(&self) -> bool {
        self.pending.load(Ordering::Acquire)
    }
}

struct Handler {
    events: Arc<dyn ConnectionEvents>,
    host_key: Arc<Mutex<Option<HostKey>>>,
    /// Set when the server key was refused by policy (never shown to the app).
    weak_host_key: Arc<Mutex<Option<String>>>,
    connected: Arc<AtomicBool>,
    user_wait: Arc<UserWait>,
}

impl client::Handler for Handler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_key: &PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Self::Error> {
        let raw_key = match server_key {
            PublicKeyOrCertificate::PublicKey { key, .. } => key.clone(),
            PublicKeyOrCertificate::Certificate(cert) => {
                russh::keys::PublicKey::from(cert.public_key().clone())
            }
        };
        if let Some(bits) = crate::hostkey::weak_rsa_bits(&raw_key) {
            // Policy decision, not the user's: a key this small must not even
            // be offered for trust.
            *self.weak_host_key.lock().await = Some(format!(
                "server host key is RSA {bits}-bit; at least {} bits are required",
                crate::hostkey::MIN_RSA_BITS
            ));
            return Ok(false);
        }
        let key = HostKey::from_server_key(server_key);
        let (tx, rx) = oneshot::channel();
        self.user_wait.begin();
        self.events.verify_host_key(key.clone(), tx);
        // A dropped sender (JS threw, app went away) is a rejection.
        let accepted = rx.await.unwrap_or(false);
        self.user_wait.end();
        if accepted {
            *self.host_key.lock().await = Some(key);
        }
        Ok(accepted)
    }

    async fn disconnected(
        &mut self,
        reason: DisconnectReason<Self::Error>,
    ) -> std::result::Result<(), Self::Error> {
        let text = match &reason {
            DisconnectReason::ReceivedDisconnect(info) => {
                if info.message.is_empty() {
                    format!("server disconnected ({:?})", info.reason_code)
                } else {
                    format!("server disconnected: {}", info.message)
                }
            }
            DisconnectReason::Error(e) => e.to_string(),
        };
        // Only report if we were actually connected; connect() reports its own errors.
        if self.connected.swap(false, Ordering::AcqRel) {
            self.events.disconnected(text);
        }
        match reason {
            DisconnectReason::ReceivedDisconnect(_) => Ok(()),
            DisconnectReason::Error(e) => Err(e),
        }
    }
}

/// An authenticated SSH session. Cheap to clone; all clones refer to the same
/// transport.
#[derive(Clone)]
pub struct Connection {
    handle: Arc<Handle<Handler>>,
    host_key: HostKey,
    connected: Arc<AtomicBool>,
    max_exec_output: usize,
    pub host: String,
    pub port: u16,
    pub username: String,
}

impl Connection {
    pub async fn connect(
        options: ConnectOptions,
        events: Arc<dyn ConnectionEvents>,
    ) -> Result<Connection> {
        if options.host.trim().is_empty() {
            return Err(SshError::invalid("host must not be empty"));
        }
        if options.username.is_empty() {
            return Err(SshError::invalid("username must not be empty"));
        }
        if matches!(options.auth, Auth::KeyboardInteractive)
            && !events.supports_keyboard_interactive()
        {
            return Err(SshError::invalid(
                "auth.type is 'keyboardInteractive' but no onKeyboardInteractive handler was given",
            ));
        }

        let timeout = options.connect_timeout;
        let user_wait = Arc::new(UserWait::default());
        let started = Instant::now();
        let fut = Self::connect_inner(options, events, user_wait.clone());
        tokio::pin!(fut);

        // The deadline moves forward by however long the user has been asked
        // to decide something, up to MAX_USER_DECISION_WAIT in total.
        loop {
            let waited = user_wait.total().min(MAX_USER_DECISION_WAIT);
            let deadline = started + timeout + waited;
            tokio::select! {
                r = &mut fut => return r,
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {
                    let waited_now = user_wait.total();
                    if user_wait.is_pending() && waited_now < MAX_USER_DECISION_WAIT {
                        continue; // still parked on the user; keep waiting
                    }
                    if Instant::now() < started + timeout + waited_now.min(MAX_USER_DECISION_WAIT) {
                        continue; // deadline moved while we slept
                    }
                    let what = if user_wait.is_pending() {
                        "waiting for a host key / prompt decision"
                    } else {
                        "connection attempt"
                    };
                    return Err(SshError::new(
                        ErrorCode::Timeout,
                        format!("{what} exceeded {} ms", timeout.as_millis()),
                    ));
                }
            }
        }
    }

    async fn connect_inner(
        options: ConnectOptions,
        events: Arc<dyn ConnectionEvents>,
        user_wait: Arc<UserWait>,
    ) -> Result<Connection> {
        let config = Arc::new(client::Config {
            client_id: SshId::Standard(Cow::Owned(format!("SSH-2.0-rnssh_{}", crate::VERSION))),
            preferred: preferred_algorithms_with_host_keys(&options.host_key_algorithms),
            keepalive_interval: options.keepalive_interval,
            keepalive_max: options.keepalive_max,
            nodelay: true,
            ..Default::default()
        });

        let host_key_slot = Arc::new(Mutex::new(None));
        let weak_host_key = Arc::new(Mutex::new(None));
        let connected = Arc::new(AtomicBool::new(false));
        let handler = Handler {
            events: events.clone(),
            host_key: host_key_slot.clone(),
            weak_host_key: weak_host_key.clone(),
            connected: connected.clone(),
            user_wait: user_wait.clone(),
        };

        let connect_result =
            client::connect(config, (options.host.as_str(), options.port), handler).await;
        if let Some(reason) = weak_host_key.lock().await.take() {
            return Err(SshError::new(ErrorCode::Protocol, reason));
        }
        let mut handle = connect_result.map_err(|e| match e {
            russh::Error::UnknownKey => {
                SshError::new(ErrorCode::HostKeyRejected, "host key was rejected")
            }
            russh::Error::IO(io) => SshError::new(ErrorCode::Connect, io.to_string()),
            russh::Error::NoCommonAlgo { .. } => SshError::new(
                ErrorCode::Protocol,
                format!("server offers no modern algorithm we accept ({e})"),
            ),
            other => {
                let mapped: SshError = other.into();
                if mapped.code == ErrorCode::Protocol || mapped.code == ErrorCode::Io {
                    SshError::new(ErrorCode::Connect, mapped.message)
                } else {
                    mapped
                }
            }
        })?;

        let host_key = host_key_slot
            .lock()
            .await
            .clone()
            .ok_or_else(|| SshError::internal("handshake finished without a host key"))?;

        authenticate(&mut handle, &options, events.as_ref(), &user_wait).await?;
        connected.store(true, Ordering::Release);

        Ok(Connection {
            handle: Arc::new(handle),
            host_key,
            connected,
            max_exec_output: options.max_exec_output,
            host: options.host,
            port: options.port,
            username: options.username,
        })
    }

    pub fn host_key(&self) -> &HostKey {
        &self.host_key
    }

    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Acquire) && !self.handle.is_closed()
    }

    pub async fn open_shell(
        &self,
        options: ShellOptions,
        events: Arc<dyn ShellEvents>,
    ) -> Result<Shell> {
        self.ensure_connected()?;
        let channel =
            tokio::time::timeout(options.setup_timeout, self.handle.channel_open_session())
                .await
                .map_err(|_| {
                    SshError::new(ErrorCode::Timeout, "server did not open a channel in time")
                })??;
        Shell::start(channel, options, events).await
    }

    /// Run a command without a PTY and collect its output. Output beyond
    /// `max_exec_output` bytes fails with [`ErrorCode::TooLarge`].
    pub async fn exec(&self, command: &str) -> Result<ExecResult> {
        self.ensure_connected()?;
        let mut channel =
            tokio::time::timeout(Duration::from_secs(30), self.handle.channel_open_session())
                .await
                .map_err(|_| {
                    SshError::new(ErrorCode::Timeout, "server did not open a channel in time")
                })??;
        channel.exec(true, command).await?;

        let limit = self.max_exec_output;
        let mut result = ExecResult {
            stdout: Vec::new(),
            stderr: Vec::new(),
            exit_code: None,
        };
        let mut total = 0usize;
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, ext: 0 } => {
                    total = total.saturating_add(data.len());
                    if total > limit {
                        let _ = channel.close().await;
                        return Err(SshError::new(
                            ErrorCode::TooLarge,
                            format!("command output exceeded {limit} bytes"),
                        ));
                    }
                    result.stdout.extend_from_slice(&data);
                }
                ChannelMsg::ExtendedData { data, .. } => {
                    total = total.saturating_add(data.len());
                    if total > limit {
                        let _ = channel.close().await;
                        return Err(SshError::new(
                            ErrorCode::TooLarge,
                            format!("command output exceeded {limit} bytes"),
                        ));
                    }
                    result.stderr.extend_from_slice(&data);
                }
                ChannelMsg::ExitStatus { exit_status } => result.exit_code = Some(exit_status),
                ChannelMsg::ExitSignal { .. } => {
                    result.exit_code.get_or_insert(128);
                }
                ChannelMsg::Failure => {
                    let _ = channel.close().await;
                    return Err(SshError::new(
                        ErrorCode::Protocol,
                        "server refused to run the command",
                    ));
                }
                ChannelMsg::Close => break,
                _ => {}
            }
        }
        Ok(result)
    }

    /// Politely close the transport. Idempotent.
    pub async fn disconnect(&self) {
        if self.connected.swap(false, Ordering::AcqRel) {
            let _ = self
                .handle
                .disconnect(Disconnect::ByApplication, "", "en")
                .await;
        }
    }

    fn ensure_connected(&self) -> Result<()> {
        if self.is_connected() {
            Ok(())
        } else {
            Err(SshError::closed("connection"))
        }
    }
}

async fn authenticate(
    handle: &mut Handle<Handler>,
    options: &ConnectOptions,
    events: &dyn ConnectionEvents,
    user_wait: &UserWait,
) -> Result<()> {
    let user = options.username.clone();
    match &options.auth {
        Auth::None => {
            let r = handle.authenticate_none(user).await?;
            finish(r, "none")
        }
        Auth::PrivateKey { pem, passphrase } => {
            let key = parse_private_key(pem, passphrase.as_deref().map(|s| s.as_str()))?;
            let hash = handle.best_supported_rsa_hash().await?.flatten();
            if matches!(key.algorithm(), Algorithm::Rsa { .. }) && hash.is_none() {
                return Err(SshError::new(
                    ErrorCode::AuthFailed,
                    "server only accepts SHA-1 signatures for RSA keys (ssh-rsa); use an Ed25519 or ECDSA key",
                ));
            }
            let r = handle
                .authenticate_publickey(
                    user.clone(),
                    PrivateKeyWithHashAlg::new(Arc::new(key), hash),
                )
                .await?;
            match r {
                AuthResult::Success => Ok(()),
                // Key accepted, server wants a second factor (OTP etc).
                AuthResult::Failure {
                    remaining_methods,
                    partial_success: true,
                } if remaining_methods.contains(&MethodKind::KeyboardInteractive) => {
                    second_factor(handle, user, events, user_wait, "publickey").await
                }
                other => finish(other, "publickey"),
            }
        }
        Auth::Password(password) => {
            let r = handle
                .authenticate_password(user.clone(), password.to_string())
                .await?;
            match r {
                AuthResult::Success => Ok(()),
                // Password accepted, server wants a second factor (OTP etc).
                AuthResult::Failure {
                    remaining_methods,
                    partial_success: true,
                } if remaining_methods.contains(&MethodKind::KeyboardInteractive) => {
                    second_factor(handle, user, events, user_wait, "password").await
                }
                AuthResult::Failure {
                    remaining_methods,
                    partial_success: false,
                } if remaining_methods.contains(&MethodKind::KeyboardInteractive)
                    && !remaining_methods.contains(&MethodKind::Password) =>
                {
                    // Common sshd setup: PasswordAuthentication no,
                    // KbdInteractiveAuthentication yes. Only fall back when the
                    // server does not take passwords at all — if it does and
                    // rejected ours, the password is simply wrong (and some
                    // PAM stacks stall on a keyboard-interactive retry).
                    if events.supports_keyboard_interactive() {
                        // The app can show the prompts (and prefill the password if it likes).
                        return keyboard_interactive_via_events(handle, user, events, user_wait)
                            .await;
                    }
                    // Only secret (non-echo) prompts get the password; anything
                    // echoed back is not a password prompt.
                    let password = password.clone();
                    keyboard_interactive(handle, user, |challenge| {
                        Some(
                            challenge
                                .prompts
                                .iter()
                                .map(|p| {
                                    if p.echo {
                                        String::new()
                                    } else {
                                        password.to_string()
                                    }
                                })
                                .collect(),
                        )
                    })
                    .await
                }
                other => finish(other, "password"),
            }
        }
        Auth::KeyboardInteractive => {
            keyboard_interactive_via_events(handle, user, events, user_wait).await
        }
    }
}

/// The first method was accepted but the server wants more (2FA). Only the
/// app can answer that; without a handler it is a clear, actionable failure.
async fn second_factor(
    handle: &mut Handle<Handler>,
    user: String,
    events: &dyn ConnectionEvents,
    user_wait: &UserWait,
    first: &str,
) -> Result<()> {
    if !events.supports_keyboard_interactive() {
        return Err(SshError::new(
            ErrorCode::AuthFailed,
            format!(
                "{first} accepted but the server requires a second factor (keyboard-interactive); provide an onKeyboardInteractive handler"
            ),
        ));
    }
    keyboard_interactive_via_events(handle, user, events, user_wait).await
}

fn finish(result: AuthResult, method: &str) -> Result<()> {
    match result {
        AuthResult::Success => Ok(()),
        AuthResult::Failure {
            remaining_methods,
            partial_success,
        } => {
            let remaining: Vec<String> = remaining_methods
                .iter()
                .map(|m| format!("{m:?}").to_lowercase())
                .collect();
            let detail = if partial_success {
                format!(
                    "server requires further authentication after {method}; remaining: {remaining:?}"
                )
            } else {
                format!("{method} authentication rejected; server accepts: {remaining:?}")
            };
            Err(SshError::new(ErrorCode::AuthFailed, detail))
        }
    }
}

fn challenge_from(
    name: String,
    instructions: String,
    prompts: Vec<client::Prompt>,
) -> KeyboardInteractiveChallenge {
    KeyboardInteractiveChallenge {
        name,
        instruction: instructions,
        prompts: prompts
            .into_iter()
            .map(|p| KeyboardInteractivePrompt {
                prompt: p.prompt,
                echo: p.echo,
            })
            .collect(),
    }
}

async fn keyboard_interactive_via_events(
    handle: &mut Handle<Handler>,
    user: String,
    events: &dyn ConnectionEvents,
    user_wait: &UserWait,
) -> Result<()> {
    let mut response = handle
        .authenticate_keyboard_interactive_start(user, None)
        .await?;
    // Servers may send several rounds; cap them so a hostile server cannot
    // keep the app in a prompt loop forever.
    for _ in 0..16 {
        match response {
            KeyboardInteractiveAuthResponse::Success => return Ok(()),
            KeyboardInteractiveAuthResponse::Failure {
                remaining_methods,
                partial_success,
            } => {
                return finish(
                    AuthResult::Failure {
                        remaining_methods,
                        partial_success,
                    },
                    "keyboard-interactive",
                );
            }
            KeyboardInteractiveAuthResponse::InfoRequest {
                name,
                instructions,
                prompts,
            } => {
                let challenge = challenge_from(name, instructions, prompts);
                let expected = challenge.prompts.len();
                let (tx, rx) = oneshot::channel();
                user_wait.begin();
                events.keyboard_interactive(challenge, tx);
                let answer = rx.await;
                user_wait.end();
                let answers = match answer {
                    Ok(Some(a)) => a,
                    _ => {
                        return Err(SshError::new(
                            ErrorCode::Cancelled,
                            "keyboard-interactive cancelled",
                        ));
                    }
                };
                if answers.len() != expected {
                    return Err(SshError::invalid(format!(
                        "keyboard-interactive handler returned {} answers for {expected} prompts",
                        answers.len()
                    )));
                }
                response = handle
                    .authenticate_keyboard_interactive_respond(answers)
                    .await?;
            }
        }
    }
    Err(SshError::new(
        ErrorCode::AuthFailed,
        "keyboard-interactive did not complete after 16 rounds",
    ))
}

async fn keyboard_interactive<F>(
    handle: &mut Handle<Handler>,
    user: String,
    mut answer: F,
) -> Result<()>
where
    F: FnMut(&KeyboardInteractiveChallenge) -> Option<Vec<String>>,
{
    let mut response = handle
        .authenticate_keyboard_interactive_start(user, None)
        .await?;
    for _ in 0..16 {
        match response {
            KeyboardInteractiveAuthResponse::Success => return Ok(()),
            KeyboardInteractiveAuthResponse::Failure {
                remaining_methods,
                partial_success,
            } => {
                return finish(
                    AuthResult::Failure {
                        remaining_methods,
                        partial_success,
                    },
                    "password",
                );
            }
            KeyboardInteractiveAuthResponse::InfoRequest {
                name,
                instructions,
                prompts,
            } => {
                let challenge = challenge_from(name, instructions, prompts);
                let Some(answers) = answer(&challenge) else {
                    return Err(SshError::new(
                        ErrorCode::Cancelled,
                        "keyboard-interactive cancelled",
                    ));
                };
                response = handle
                    .authenticate_keyboard_interactive_respond(answers)
                    .await?;
            }
        }
    }
    Err(SshError::new(
        ErrorCode::AuthFailed,
        "keyboard-interactive did not complete after 16 rounds",
    ))
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("connected", &self.is_connected())
            .finish()
    }
}

/// Convenience for callers that are not already inside the runtime.
pub fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    runtime::handle().block_on(fut)
}
