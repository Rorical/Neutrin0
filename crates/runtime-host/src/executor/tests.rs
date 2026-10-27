use super::*;
use neutrin0_proof_system::artifacts::ProgramRetention;
use neutrin0_proof_system::executor::BlockExecutor;
use neutrin0_trie::Trie;

#[test]
fn proving_writer_refuses_growth_before_crossing_the_limit() {
    use borsh::io::Write as _;
    let mut writer = ProvingInputWriter::new(8).unwrap();
    writer.write_all(&[1; 8]).unwrap();
    assert!(writer.write_all(&[2]).is_err());
    assert_eq!(writer.into_bytes(), vec![1; 8]);
    assert!(ProvingInputWriter::new(0).is_err());
    assert!(
        ProvingInputWriter::new(neutrin0_primitives::MAX_BLOCK_PROVING_INPUT_BYTES + 1).is_err()
    );
}

#[test]
fn abandoned_runtime_eviction_preserves_the_inflight_arc() {
    let executor = WasmExecutor::embedded().unwrap();
    let hash = crate::embedded_runtime_code_hash();
    let lease = executor.runtime(&hash).unwrap();
    BlockExecutor::retain_programs(&executor, &ProgramRetention::default());
    assert_eq!(executor.runtime_hashes(), Vec::<[u8; 32]>::new());
    assert!(executor.has_runtime(&hash));
    assert_eq!(lease.code_hash(), hash);
    assert_eq!(executor.runtimes.lock().unwrap().retired.len(), 1);
    drop(lease);
    BlockExecutor::retain_programs(&executor, &ProgramRetention::default());
    assert!(executor.runtimes.lock().unwrap().retired.is_empty());
}

#[test]
fn executor_indexes_only_the_compiled_artifact_identity() {
    let wasm = WasmRuntime::embedded().unwrap();
    let code_hash = crate::embedded_runtime_code_hash();
    assert_eq!(wasm.code_hash(), code_hash);
    let executor = WasmExecutor::new(wasm);
    assert_eq!(executor.runtime_hashes(), vec![code_hash]);

    let mut unknown = code_hash;
    unknown[0] ^= 1;
    let result =
        BlockExecutor::validate_tx(&executor, &[], 7, 30_000_000, unknown, &Trie::default());
    assert!(matches!(result, Err(ExecutorError::UnknownRuntime(hash)) if hash == unknown));
    assert_eq!(executor.runtime_hashes(), vec![code_hash]);

    assert_eq!(
        executor
            .install_runtime(crate::wasm::EVM_MASTER_WASM)
            .unwrap(),
        code_hash
    );
    assert_eq!(executor.runtime_hashes(), vec![code_hash]);
}
