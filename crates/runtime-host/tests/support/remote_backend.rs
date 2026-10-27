//! Explicit CPU/CUDA selection for the ignored real-proof tests.
//! SP1 executes Guest instructions on the CPU with either prover; CUDA selects
//! the compressed-proof backend and never silently falls back to CPU proving.
#![allow(
    clippy::redundant_pub_crate,
    reason = "Shared fixtures of a private test support module; `pub` would be unreachable."
)]

pub(crate) fn name() -> String {
    std::env::var("NEUTRIN0_PROVING_BACKEND").unwrap_or_else(|_| "cpu".into())
}

macro_rules! with_prover {
    ($run:path) => {{
        match $crate::remote_backend::name().as_str() {
            "cpu" => {
                eprintln!("prover backend=cpu execution_backend=cpu");
                $run(sp1_sdk::blocking::ProverClient::builder().cpu().build());
            }
            "cuda" => {
                #[cfg(feature = "cuda")]
                {
                    let device = std::env::var("NEUTRIN0_CUDA_DEVICE")
                        .map_or(Ok(0), |value| value.parse::<u32>())
                        .expect("CUDA device must be an unsigned integer");
                    let runtime = tokio::runtime::Builder::new_multi_thread()
                        .enable_all()
                        .build()
                        .expect("multithreaded CUDA acceptance runtime");
                    let entered = runtime.enter();
                    eprintln!("prover backend=cuda device={device} execution_backend=cpu");
                    $run(
                        neutrin0_runtime_host::backend::cuda_prover(device)
                            .expect("requested CUDA prover must initialize without CPU fallback"),
                    );
                    drop(entered);
                    runtime.shutdown_timeout(std::time::Duration::from_secs(2));
                }
                #[cfg(not(feature = "cuda"))]
                panic!("CUDA acceptance requires the runtime-host cuda Cargo feature");
            }
            other => panic!("unsupported acceptance backend {other:?}; select cpu or cuda"),
        }
    }};
}

pub(crate) use with_prover;
