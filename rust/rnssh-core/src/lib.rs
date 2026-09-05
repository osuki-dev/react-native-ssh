//! `rnssh-core` — the binding-agnostic SSH client core behind
//! `@osuki-dev/react-native-ssh`.
//!
//! Design rules (see ARCHITECTURE.md at the repo root):
//!
//! * This crate knows nothing about JavaScript, Nitro, or C. It exposes plain
//!   Rust types plus two small event traits ([`ConnectionEvents`],
//!   [`ShellEvents`]) that the FFI layer implements.
//! * Every operation runs on one process-wide tokio runtime ([`runtime`]).
//!   Connections are never tied to the caller's thread.
//! * Bytes flowing out of a shell are handed to the event sink as owned
//!   `Vec<u8>` so the binding layer can transfer ownership to JS without a copy.
//! * Interactive decisions (host key trust, keyboard-interactive prompts) are
//!   modelled as a request plus a one-shot responder, so the UI can take as
//!   long as it needs without blocking any thread.

#![forbid(unsafe_code)]

pub mod connection;
pub mod error;
pub mod forward;
pub mod hostkey;
pub mod keys;
pub mod runtime;
pub mod shell;

pub use connection::{
    Auth, ConnectOptions, Connection, ConnectionEvents, ExecResult, KeyboardInteractiveChallenge,
    KeyboardInteractivePrompt,
};
pub use error::{ErrorCode, SshError};
pub use forward::{ForwardEvents, ForwardOptions, LocalForward, forward_tcp};
pub use hostkey::HostKey;
pub use keys::{KeyInfo, KeyPair, KeyType};
pub use shell::{Shell, ShellEvents, ShellOptions, StreamKind};

/// Version of the core crate, surfaced to JS as `SSH.version`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
