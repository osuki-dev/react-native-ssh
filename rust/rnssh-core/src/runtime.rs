//! One process-wide tokio runtime shared by every connection.
//!
//! A mobile app never needs more than a couple of worker threads for SSH; the
//! runtime is created lazily on first use and lives for the process lifetime.
//! Nothing here is tied to the JS thread.

use std::sync::OnceLock;

use tokio::runtime::{Builder, Runtime};

static RUNTIME: OnceLock<Runtime> = OnceLock::new();

/// Returns the shared runtime, creating it on first call.
pub fn handle() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        // Building a runtime only fails when the OS refuses to create threads;
        // nothing useful can happen after that, so aborting is the honest choice.
        #[allow(clippy::expect_used)]
        Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("rnssh")
            .enable_io()
            .enable_time()
            .build()
            .expect("failed to build the rnssh tokio runtime")
    })
}

/// Spawn a future on the shared runtime and forget about it.
pub fn spawn<F>(fut: F) -> tokio::task::JoinHandle<F::Output>
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    handle().spawn(fut)
}
