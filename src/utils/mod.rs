use prover::CharmsSP1Prover;
use std::{
    fmt::Debug,
    sync::OnceLock,
    time::{Duration, Instant},
};
use tokio::{sync::OnceCell, task::block_in_place};

pub(crate) mod logger;
pub mod pool;
pub mod prover;

pub const TRANSIENT_PROVER_FAILURE: &str = " transient prover failure:";

pub type BoxedSP1Prover = Box<dyn CharmsSP1Prover>;

/// Create a string representation of the index `i` in the format `$xxxx`.
pub fn str_index(i: &u32) -> String {
    format!("${:04}", i)
}

pub struct AsyncShared<T> {
    pub create: fn() -> T,
    pub instance: OnceCell<T>,
}

impl<T> AsyncShared<T> {
    pub fn new(create: fn() -> T) -> Self {
        Self {
            create,
            instance: OnceCell::new(),
        }
    }

    pub async fn get(&self) -> &T {
        let create = self.create;
        self.instance.get_or_init(|| async { create() }).await
    }
}

pub struct Shared<T> {
    pub create: fn() -> T,
    pub instance: OnceLock<T>,
}

impl<T> Shared<T> {
    pub fn new(create: fn() -> T) -> Self {
        Self {
            create,
            instance: OnceLock::new(),
        }
    }

    pub fn get(&self) -> &T {
        self.instance.get_or_init(|| (self.create)())
    }
}

pub async fn retry<Fut, F, T, E>(secs: u64, f: F) -> Result<T, E>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: Debug,
{
    let timeout = Duration::from_secs(secs);
    let start_time = Instant::now();

    let mut r = f().await;
    while r.is_err() {
        if !timeout.is_zero() && start_time.elapsed() > timeout {
            return r;
        }
        tracing::warn!("{:?}", r.err().expect("it must be an error at this point"));
        tracing::info!("retrying...");
        tokio::time::sleep(Duration::from_secs(1)).await;
        r = f().await;
    }

    r
}

/// Utility method for blocking on an async function.
///
/// If we're already in a tokio runtime, we'll block in place. Otherwise, we'll create a new
/// runtime.
///
/// (borrowed from Succinct's SP1)
pub fn block_on<T>(fut: impl Future<Output = T>) -> T {
    // Handle case if we're already in an tokio runtime.
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        block_in_place(|| handle.block_on(fut))
    } else {
        // Otherwise create a new runtime.
        let rt = tokio::runtime::Runtime::new().expect("Failed to create a new runtime");
        rt.block_on(fut)
    }
}
