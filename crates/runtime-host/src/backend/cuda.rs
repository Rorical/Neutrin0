//! CUDA device gates, serialized device submission and the CUDA prover
//! factory. Session keys stay in memory and are authenticated against the
//! locally derived program identity.

use std::{
    cell::Cell,
    collections::BTreeMap,
    sync::{Arc, Mutex, OnceLock},
    time::Instant,
};

use super::{OBSERVER, ObservedSubmission, RESERVED, SubmissionGate, SubmissionPriority};
use crate::Sp1HostError;
#[cfg(feature = "cuda")]
use sp1_sdk::blocking::Prover;

#[derive(Default)]
pub(super) struct CudaGates {
    devices: BTreeMap<u32, Arc<SubmissionGate>>,
    #[cfg(feature = "cuda")]
    handles: BTreeMap<usize, u32>,
    #[cfg(feature = "cuda")]
    pub(super) setup_attempts: BTreeMap<u32, usize>,
}

/// Local per-device setup-attempt budget per process. SDK session destruction is
/// asynchronous; this does not establish reclamation or a global VRAM bound.
#[cfg(feature = "cuda")]
pub const MAX_CUDA_SETUP_ATTEMPTS: usize = 64;

#[cfg(feature = "cuda")]
pub(super) fn reserve_cuda_setup(device: u32) -> Result<(), Sp1HostError> {
    let mut gates = cuda_gates()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    gates.reserve_setup(device)
}

#[cfg(feature = "cuda")]
impl CudaGates {
    pub(super) fn reserve_setup(&mut self, device: u32) -> Result<(), Sp1HostError> {
        let attempts = self.setup_attempts.entry(device).or_default();
        if *attempts >= MAX_CUDA_SETUP_ATTEMPTS {
            return Err(Sp1HostError::Sdk("per-process CUDA setup-attempt budget exhausted; operator-confirmed server cleanup/fresh server is required before restarting".into()));
        }
        *attempts += 1;
        Ok(())
    }
}

fn cuda_gates() -> &'static Mutex<CudaGates> {
    static GATES: OnceLock<Mutex<CudaGates>> = OnceLock::new();
    GATES.get_or_init(|| {
        let mut gates = CudaGates::default();
        gates.devices.insert(0, Arc::new(SubmissionGate::default()));
        Mutex::new(gates)
    })
}

/// Shared native submission gate for a CUDA device.
/// # Errors
/// Refuses more than 64 distinct device schedulers in one host process.
/// # Panics
/// Panics if the device registry is poisoned.
pub fn cuda_submission_gate(device: u32) -> Result<Arc<SubmissionGate>, Sp1HostError> {
    let mut gates = cuda_gates().lock().expect("CUDA gates");
    if !gates.devices.contains_key(&device) && gates.devices.len() >= 64 {
        return Err(Sp1HostError::Sdk(
            "CUDA scheduler device budget exceeded".into(),
        ));
    }
    Ok(Arc::clone(gates.devices.entry(device).or_default()))
}

#[cfg(feature = "cuda")]
fn cuda_device(prover: &sp1_sdk::blocking::CudaProver) -> u32 {
    let identity = std::ptr::from_ref(prover.inner()).cast::<()>() as usize;
    cuda_gates()
        .lock()
        .expect("CUDA gates")
        .handles
        .get(&identity)
        .copied()
        .unwrap_or(0)
}

pub(super) fn submit_serial<T>(
    device: u32,
    priority: SubmissionPriority,
    work: impl FnOnce() -> T,
) -> T {
    let gate = cuda_submission_gate(device).expect("registered CUDA scheduler");
    if RESERVED.with(Cell::get) == Some(Arc::as_ptr(&gate) as usize) {
        work()
    } else {
        let observer = OBSERVER.with(|value| value.borrow().clone());
        let mut submission = ObservedSubmission {
            observer,
            started: Instant::now(),
            admitted: false,
        };
        if let Some(observer) = &submission.observer {
            observer.queued();
        }
        gate.acquire(priority).run(move || {
            submission.admitted = true;
            if let Some(observer) = &submission.observer {
                observer.admitted(submission.started.elapsed());
            }
            let result = work();
            drop(submission);
            result
        })
    }
}

/// Check build and platform support without initializing a GPU or downloading
/// the SDK's GPU server. Hardware/driver availability is checked by SDK startup.
///
/// # Errors
/// CUDA requires the `cuda` Cargo feature and Linux x86-64.
pub const fn ensure_cuda_available() -> Result<(), &'static str> {
    if !cfg!(feature = "cuda") {
        return Err("CUDA requires building neutrin0-node with --features cuda");
    }
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return Err("SP1 CUDA requires Linux x86-64 and an NVIDIA GPU; macOS/Metal is unsupported");
    }
    Ok(())
}

/// Start the local SP1 GPU server on one CUDA device. Never falls back to CPU.
///
/// Call inside a multithreaded Tokio runtime, keeping the runtime alive until
/// the prover and its session keys are dropped (the SDK schedules their cleanup).
///
/// # Errors
/// Returns a platform, runtime or SDK startup error, including SDK builder panics.
/// # Panics
/// Panics if the device registry is poisoned.
#[cfg(feature = "cuda")]
pub fn cuda_prover(device_id: u32) -> Result<sp1_sdk::blocking::CudaProver, Sp1HostError> {
    ensure_cuda_available().map_err(|error| Sp1HostError::Sdk(error.into()))?;
    let _ = cuda_submission_gate(device_id)?;
    let runtime = tokio::runtime::Handle::try_current()
        .map_err(|_| Sp1HostError::Sdk("CUDA requires a multithreaded Tokio runtime".into()))?;
    if runtime.runtime_flavor() != tokio::runtime::RuntimeFlavor::MultiThread {
        return Err(Sp1HostError::Sdk(
            "CUDA requires a multithreaded Tokio runtime".into(),
        ));
    }
    let prover = std::panic::catch_unwind(|| {
        sp1_sdk::blocking::ProverClient::builder()
            .cuda()
            .with_device_id(device_id)
            .build()
    })
    .map_err(|payload| {
        let reason = payload
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| payload.downcast_ref::<&str>().copied())
            .unwrap_or("unknown SDK panic");
        Sp1HostError::Sdk(format!("CUDA initialization failed: {reason}"))
    })?;
    let identity = std::ptr::from_ref(prover.inner()).cast::<()>() as usize;
    let mut gates = cuda_gates().lock().expect("CUDA gates");
    if !gates.handles.contains_key(&identity) && gates.handles.len() >= 256 {
        return Err(Sp1HostError::Sdk(
            "CUDA scheduler handle budget exceeded".into(),
        ));
    }
    gates.handles.insert(identity, device_id);
    drop(gates);
    Ok(prover)
}

#[cfg(feature = "cuda")]
impl super::ProgramProver for sp1_sdk::blocking::CudaProver {
    fn setup_program(&self, elf: sp1_sdk::Elf) -> Result<Self::ProvingKey, Sp1HostError> {
        use sp1_sdk::{HashableKey, ProvingKey, blocking::ProverClient};

        // The server returns its VK during setup. Authenticate it against the
        // same locally derived program identity used by CPU verification.
        let expected = match crate::load_cached_vk_for(&elf) {
            Some(vk) => vk,
            None => {
                crate::cached_proving_key(&ProverClient::builder().light().build(), elf.clone())?
                    .verifying_key()
                    .clone()
            }
        };
        let device = cuda_device(self);
        let key = submit_serial(device, SubmissionPriority::Normal, || {
            // Reserve only after native admission, immediately before the SDK
            // call. Failed attempts also consume budget: their remote cleanup
            // cannot be inferred from a missing local key.
            reserve_cuda_setup(device)?;
            self.setup(elf).map_err(crate::sdk_err)
        })?;
        if key.verifying_key().hash_u32() != expected.hash_u32() {
            return Err(Sp1HostError::Sdk(
                "CUDA program verifying key mismatch".into(),
            ));
        }
        // A CUDA key owns a server session. It cannot be reconstructed from a
        // disk VK, and must be retained until the last proof request completes.
        Ok(key)
    }

    fn serial_submission(&self) -> bool {
        true
    }

    fn submission_device(&self) -> Option<u32> {
        Some(cuda_device(self))
    }

    fn submit<T>(&self, priority: SubmissionPriority, work: impl FnOnce() -> T) -> T {
        submit_serial(cuda_device(self), priority, work)
    }
}
