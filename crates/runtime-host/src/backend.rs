//! Backend-specific program setup. CUDA session keys stay in memory; CPU ROM
//! preprocessing and the expected program identity share the disk VK cache.

use sp1_sdk::{
    Elf,
    blocking::{CpuProver, LightProver, MockProver, Prover},
};

use crate::Sp1HostError;

use std::{
    cell::{Cell, RefCell},
    sync::Arc,
    time::{Duration, Instant},
};

mod cuda;
mod gate;

#[cfg(feature = "cuda")]
pub use cuda::{MAX_CUDA_SETUP_ATTEMPTS, cuda_prover};
pub use cuda::{cuda_submission_gate, ensure_cuda_available};
pub use gate::{SubmissionGate, SubmissionGuard, SubmissionRequest};

use cuda::submit_serial;

/// Priority of a native proving or setup submission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubmissionPriority {
    /// Block and Chunk work needed for current finality.
    Critical,
    /// Cryptographic facts, evidence and program setup.
    Normal,
}

impl SubmissionPriority {
    const fn index(self) -> usize {
        match self {
            Self::Critical => 0,
            Self::Normal => 1,
        }
    }
}

thread_local! {
    static PRIORITY: Cell<SubmissionPriority> = const { Cell::new(SubmissionPriority::Critical) };
    static RESERVED: Cell<Option<usize>> = const { Cell::new(None) };
    static OBSERVER: RefCell<Option<Arc<dyn SubmissionObserver>>> = const { RefCell::new(None) };
    static LOCAL_ADMISSION: RefCell<Option<Arc<dyn NativeAdmission>>> = const { RefCell::new(None) };
}

/// Opaque owned resource lease, released when its native call returns.
pub trait NativeLease: Send {}
impl<T: Send> NativeLease for T {}

/// Host-provided capacity for one native CPU call inside a composite operation.
pub trait NativeAdmission: Send + Sync {
    /// Wait for and return one owned lease, outside all backend gate locks.
    fn acquire(&self) -> Box<dyn NativeLease>;
}

/// Scope CPU admission around a composite operation. Its individual native
/// calls acquire separate leases; an existing outer permit should not install
/// this hook again. CUDA uses its device gate instead.
pub fn with_native_admission<T>(
    admission: Arc<dyn NativeAdmission>,
    work: impl FnOnce() -> T,
) -> T {
    struct Restore(Option<Arc<dyn NativeAdmission>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            LOCAL_ADMISSION.with(|value| drop(value.replace(self.0.take())));
        }
    }
    let _restore = Restore(LOCAL_ADMISSION.with(|value| value.replace(Some(admission))));
    work()
}

fn submit_local<T>(priority: SubmissionPriority, work: impl FnOnce() -> T) -> T {
    // A nested wrapper belongs to this already admitted synchronous call.
    // Reacquiring the same CPU budget would deadlock at capacity one.
    struct Restore(Option<Arc<dyn NativeAdmission>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            LOCAL_ADMISSION.with(|value| drop(value.replace(self.0.take())));
        }
    }
    let admission = LOCAL_ADMISSION.with(|value| value.borrow().clone());
    let _lease = admission.map(|admission| admission.acquire());
    let _restore = Restore(LOCAL_ADMISSION.with(|value| value.replace(None)));
    with_submission_priority(priority, work)
}

/// Optional metrics hook for individual native submissions. Callbacks execute
/// without the gate mutex and do not change scheduling or proof authority.
pub trait SubmissionObserver: Send + Sync {
    /// One call entered the native resource queue.
    fn queued(&self);
    /// A call acquired its resource after this wait.
    fn admitted(&self, wait: Duration);
    /// An admitted call returned or unwound.
    fn released(&self);
    /// A queued call unwound before admission.
    fn cancelled(&self, wait: Duration);
}

/// Observe synchronous native calls inside a composite operation, restoring
/// the previous observer after return or panic. Existing reservations are not
/// observed again by nested wrappers.
pub fn with_submission_observer<T>(
    observer: Arc<dyn SubmissionObserver>,
    work: impl FnOnce() -> T,
) -> T {
    struct Restore(Option<Arc<dyn SubmissionObserver>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            OBSERVER.with(|value| {
                drop(value.replace(self.0.take()));
            });
        }
    }
    let _restore = Restore(OBSERVER.with(|value| value.replace(Some(observer))));
    work()
}

struct ObservedSubmission {
    observer: Option<Arc<dyn SubmissionObserver>>,
    started: Instant,
    admitted: bool,
}

impl Drop for ObservedSubmission {
    fn drop(&mut self) {
        if let Some(observer) = &self.observer {
            if self.admitted {
                observer.released();
            } else {
                observer.cancelled(self.started.elapsed());
            }
        }
    }
}

/// Priority inherited by synchronous backend calls on this worker.
#[must_use]
pub fn submission_priority() -> SubmissionPriority {
    PRIORITY.with(Cell::get)
}

/// Scope a priority around synchronous work, restoring it even on panic.
pub fn with_submission_priority<T>(priority: SubmissionPriority, work: impl FnOnce() -> T) -> T {
    struct Restore(SubmissionPriority);
    impl Drop for Restore {
        fn drop(&mut self) {
            PRIORITY.with(|value| value.set(self.0));
        }
    }
    let _restore = Restore(PRIORITY.with(|value| value.replace(priority)));
    work()
}

/// An SP1 prover with reusable, program-bound key setup.
///
/// The returned key must remain valid for this prover's lifetime and bind the
/// supplied ELF. Callers retain it for all subsequent proofs of that program.
pub trait ProgramProver: Prover<ProvingKey: 'static> + 'static {
    /// Prepare a program, reusing cached preprocessing where supported.
    ///
    /// # Errors
    /// Returns an SDK error when setup fails or the backend changes program identity.
    fn setup_program(&self, elf: Elf) -> Result<Self::ProvingKey, Sp1HostError>;

    /// Whether native setup and proving share a serialized device connection.
    fn serial_submission(&self) -> bool {
        false
    }

    /// CUDA device whose native resource this prover uses, when applicable.
    fn submission_device(&self) -> Option<u32> {
        None
    }

    /// Whether `submit` honors scoped native CPU admission or its device gate.
    /// Custom overrides that bypass both must return `false`.
    fn native_submission_admission(&self) -> bool {
        true
    }

    /// Submit synchronous work under this backend's native resource policy.
    fn submit<T>(&self, priority: SubmissionPriority, work: impl FnOnce() -> T) -> T {
        submit_local(priority, work)
    }
}

impl ProgramProver for CpuProver {
    fn setup_program(&self, elf: Elf) -> Result<Self::ProvingKey, Sp1HostError> {
        crate::cached_proving_key(self, elf)
    }
}

impl ProgramProver for MockProver {
    fn setup_program(&self, elf: Elf) -> Result<Self::ProvingKey, Sp1HostError> {
        crate::cached_proving_key(self, elf)
    }
}

impl ProgramProver for LightProver {
    fn setup_program(&self, elf: Elf) -> Result<Self::ProvingKey, Sp1HostError> {
        crate::cached_proving_key(self, elf)
    }
}

impl ProgramProver for sp1_sdk::blocking::EnvProver {
    fn setup_program(&self, elf: Elf) -> Result<Self::ProvingKey, Sp1HostError> {
        // The SDK seals EnvProvingKey construction. Route its own setup call
        // through the same native gate; explicit CPU/CUDA factories additionally
        // reuse their backend-specific preprocessing caches.
        let expected = if self.submission_device().is_some() {
            use sp1_sdk::{ProvingKey, blocking::ProverClient};
            Some(match crate::load_cached_vk_for(&elf) {
                Some(vk) => vk,
                None => crate::cached_proving_key(
                    &ProverClient::builder().light().build(),
                    elf.clone(),
                )?
                .verifying_key()
                .clone(),
            })
        } else {
            None
        };
        let key = self.submit(SubmissionPriority::Normal, || {
            #[cfg(feature = "cuda")]
            if let Some(device) = self.submission_device() {
                cuda::reserve_cuda_setup(device)?;
            }
            self.setup(elf).map_err(crate::sdk_err)
        })?;
        if let Some(expected) = expected {
            use sp1_sdk::{HashableKey, ProvingKey};
            if key.verifying_key().hash_u32() != expected.hash_u32() {
                return Err(Sp1HostError::Sdk(
                    "CUDA program verifying key mismatch".into(),
                ));
            }
        }
        Ok(key)
    }
    fn serial_submission(&self) -> bool {
        #[cfg(feature = "cuda")]
        if matches!(self, Self::Cuda(_)) {
            return true;
        }
        false
    }
    fn submission_device(&self) -> Option<u32> {
        #[cfg(feature = "cuda")]
        if let Self::Cuda(prover) = self {
            return prover.submission_device();
        }
        None
    }
    fn submit<T>(&self, priority: SubmissionPriority, work: impl FnOnce() -> T) -> T {
        if let Some(device) = self.submission_device() {
            submit_serial(device, priority, work)
        } else {
            submit_local(priority, work)
        }
    }
}

#[cfg(test)]
mod tests;
