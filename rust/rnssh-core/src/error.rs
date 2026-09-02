use std::fmt;

/// Stable, numeric error codes. These cross the C ABI unchanged and are
/// surfaced to JavaScript as `SshError.code`, so their values are part of the
/// public contract: append, never renumber.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum ErrorCode {
    Ok = 0,
    /// Caller passed something we cannot use (bad UTF-8, empty host, ...).
    InvalidArgument = 1,
    /// Handle does not refer to a live connection / shell.
    NotFound = 2,
    /// TCP connect / DNS / SSH handshake failed.
    Connect = 3,
    /// The operation exceeded its deadline.
    Timeout = 4,
    /// The `verifyHostKey` callback rejected the server key.
    HostKeyRejected = 5,
    /// Server refused every authentication attempt we made.
    AuthFailed = 6,
    /// Private key could not be parsed / decrypted.
    Key = 7,
    /// Connection or channel is already closed.
    Closed = 8,
    /// Server violated the protocol or sent something we do not support.
    Protocol = 9,
    /// Socket-level I/O failure after the connection was established.
    Io = 10,
    /// Caller cancelled (e.g. answered a keyboard-interactive prompt with cancel).
    Cancelled = 11,
    /// Should not happen; a bug in this library.
    Internal = 12,
    /// The shell write queue is full (the server is not draining input).
    QueueFull = 13,
    /// An exec produced more output than the configured limit.
    TooLarge = 14,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::Ok => "OK",
            ErrorCode::InvalidArgument => "INVALID_ARGUMENT",
            ErrorCode::NotFound => "NOT_FOUND",
            ErrorCode::Connect => "CONNECT",
            ErrorCode::Timeout => "TIMEOUT",
            ErrorCode::HostKeyRejected => "HOST_KEY_REJECTED",
            ErrorCode::AuthFailed => "AUTH_FAILED",
            ErrorCode::Key => "KEY",
            ErrorCode::Closed => "CLOSED",
            ErrorCode::Protocol => "PROTOCOL",
            ErrorCode::Io => "IO",
            ErrorCode::Cancelled => "CANCELLED",
            ErrorCode::Internal => "INTERNAL",
            ErrorCode::QueueFull => "QUEUE_FULL",
            ErrorCode::TooLarge => "TOO_LARGE",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SshError {
    pub code: ErrorCode,
    pub message: String,
}

impl SshError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidArgument, message)
    }
    pub fn not_found(what: &str) -> Self {
        Self::new(
            ErrorCode::NotFound,
            format!("{what} not found or already released"),
        )
    }
    pub fn closed(what: &str) -> Self {
        Self::new(ErrorCode::Closed, format!("{what} is closed"))
    }
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Internal, message)
    }
}

impl fmt::Display for SshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for SshError {}

impl From<russh::Error> for SshError {
    fn from(e: russh::Error) -> Self {
        use russh::Error as E;
        let code = match &e {
            E::IO(_) => ErrorCode::Io,
            E::ConnectionTimeout | E::KeepaliveTimeout | E::InactivityTimeout => ErrorCode::Timeout,
            E::UnknownKey | E::WrongServerSig => ErrorCode::HostKeyRejected,
            E::NotAuthenticated | E::NoAuthMethod => ErrorCode::AuthFailed,
            E::CouldNotReadKey => ErrorCode::Key,
            E::Disconnect | E::SendError | E::RecvError | E::HUP => ErrorCode::Closed,
            _ => ErrorCode::Protocol,
        };
        SshError::new(code, e.to_string())
    }
}

impl From<russh::keys::Error> for SshError {
    fn from(e: russh::keys::Error) -> Self {
        SshError::new(ErrorCode::Key, e.to_string())
    }
}

impl From<russh::keys::ssh_key::Error> for SshError {
    fn from(e: russh::keys::ssh_key::Error) -> Self {
        SshError::new(ErrorCode::Key, e.to_string())
    }
}

impl From<std::io::Error> for SshError {
    fn from(e: std::io::Error) -> Self {
        SshError::new(ErrorCode::Io, e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, SshError>;
