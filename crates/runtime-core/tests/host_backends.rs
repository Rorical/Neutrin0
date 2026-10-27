//! Host-side `TracingState`/`LiveTrie` coverage. Gated by the `host`
//! feature so the default `no_std` test surface stays untouched.

#![cfg(feature = "host")]

use neutrin0_runtime_core::{
    StateBackend, WitnessState,
    host::{LiveTrie, TracingState},
};

#[test]
fn dry_run_records_read_set_and_replays_under_witness() {
    let mut live = LiveTrie::default();
    live.insert(b"counter", 5u32.to_le_bytes().to_vec());
    let pre_root = live.state_root();

    let mut tracer = TracingState::new(&live);
    let read = tracer.read(b"counter").unwrap();
    assert_eq!(u32::from_le_bytes(read.as_slice().try_into().unwrap()), 5);
    tracer.write(b"counter", 8u32.to_le_bytes().to_vec());
    let post_root_dry = tracer.post_state_root();
    assert_ne!(post_root_dry, pre_root);

    let witness = tracer.into_witness().unwrap();
    assert_eq!(witness.pre_state_root, pre_root);

    // Replay against the witness as the SP1 Guest would.
    let mut wstate = WitnessState::new(&witness).unwrap();
    let read = wstate.read(b"counter").unwrap();
    assert_eq!(u32::from_le_bytes(read.as_slice().try_into().unwrap()), 5);
    wstate.write(b"counter", 8u32.to_le_bytes().to_vec());

    // Both backends must agree on the post-state root for the same
    // sequence of operations.
    assert_eq!(wstate.post_state_root(), post_root_dry);
}

#[test]
fn tracing_state_post_root_reflects_overlay_writes_and_deletes() {
    let mut live = LiveTrie::default();
    live.insert(b"a", b"1".to_vec());
    live.insert(b"b", b"2".to_vec());
    let pre = live.state_root();

    let mut tracer = TracingState::new(&live);
    tracer.write(b"c", b"3".to_vec());
    tracer.delete(b"a");
    assert_eq!(tracer.pre_state_root(), pre);
    let post = tracer.post_state_root();

    let mut expected = LiveTrie::default();
    expected.insert(b"b", b"2".to_vec());
    expected.insert(b"c", b"3".to_vec());
    assert_eq!(post, expected.state_root());
}
