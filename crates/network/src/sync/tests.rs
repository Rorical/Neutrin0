use super::*;
use libp2p::identity;

fn pid() -> PeerId {
    PeerId::from(identity::Keypair::generate_ed25519().public())
}

fn fresh_progress(chain_id: u64) -> LocalProgress {
    LocalProgress {
        chain_id,
        ..LocalProgress::default()
    }
}

/// A light client that accepts any single advertisement, for tests of
/// provider mechanics rather than sampling.
fn single_sample(progress: LocalProgress) -> SyncMachine {
    SyncMachine::new(SyncMode::LightClient, progress).with_light_sampling(SamplingPolicy {
        peers: 1,
        quorum: 1,
    })
}

fn peer_status(chain_id: u64, finalized: CheckpointIndex, head: Height) -> rpc::Status {
    rpc::Status {
        chain_id,
        chain_spec_hash: [0; 32],
        finalized_chunk_id: finalized.checked_sub(1),
        finalized_chunk_hash: [0; 32],
        checkpoint_hash: if finalized == 0 { [0; 32] } else { [0xAA; 32] },
        head_block_hash: [0xBB; 32],
        head_slot: head,
        head_height: head,
    }
}

#[test]
fn init_handshakes_new_peers() {
    let mut fsm = SyncMachine::new(SyncMode::Snap, fresh_progress(7));
    let peer = pid();
    let cmds = fsm.on_event(SyncEvent::PeerConnected(peer));
    assert_eq!(cmds, vec![SyncCommand::RequestStatus(peer)]);
    assert!(matches!(fsm.state(), SyncState::Init));
}

#[test]
fn init_ignores_peer_with_wrong_chain_id() {
    let mut fsm = SyncMachine::new(SyncMode::Snap, fresh_progress(7));
    let peer = pid();
    let cmds = fsm.on_event(SyncEvent::PeerStatus {
        peer,
        status: peer_status(99, 5, 100),
    });
    assert!(cmds.is_empty(), "wrong chain id must not advance");
    assert!(matches!(fsm.state(), SyncState::Init));
    assert_eq!(fsm.sync_peer(), None);
}

#[test]
fn init_ignores_peer_with_wrong_chain_spec_hash() {
    let mut progress = fresh_progress(7);
    progress.chain_spec_hash = [1; 32];
    let mut fsm = SyncMachine::new(SyncMode::Snap, progress);
    let peer = pid();
    let mut status = peer_status(7, 5, 100);
    status.chain_spec_hash = [2; 32];
    let cmds = fsm.on_event(SyncEvent::PeerStatus { peer, status });
    assert!(cmds.is_empty(), "wrong chain spec must not advance");
    assert!(matches!(fsm.state(), SyncState::Init));
    assert_eq!(fsm.sync_peer(), None);
}

#[test]
fn init_ignores_status_when_peer_is_not_ahead() {
    let mut fsm = SyncMachine::new(SyncMode::Snap, fresh_progress(7));
    let peer = pid();
    let cmds = fsm.on_event(SyncEvent::PeerStatus {
        peer,
        status: peer_status(7, 0, 0),
    });
    assert_eq!(cmds, [] as [SyncCommand; 0]);
    assert!(matches!(fsm.state(), SyncState::Init));
}

#[test]
fn light_client_at_equal_finalized_enters_following() {
    let mut fsm = SyncMachine::new(SyncMode::LightClient, fresh_progress(7));
    let peer = pid();
    let cmds = fsm.on_event(SyncEvent::PeerStatus {
        peer,
        status: peer_status(7, 0, 0),
    });
    // Expect Following + topic subscribes.
    assert!(matches!(fsm.state(), SyncState::Following));
    assert!(cmds.contains(&SyncCommand::EnterFollowing));
    assert!(
        cmds.iter()
            .any(|c| matches!(c, SyncCommand::Subscribe(Topic::Checkpoints)))
    );
}

#[test]
fn init_to_history_fetch_when_peer_is_ahead() {
    let mut fsm = single_sample(fresh_progress(7));
    let peer = pid();
    let cmds = fsm.on_event(SyncEvent::PeerStatus {
        peer,
        status: peer_status(7, 10, 1280),
    });
    match fsm.state() {
        SyncState::HistoryFetch {
            local_finalized_index,
            target_index,
            in_flight,
        } => {
            assert_eq!(*local_finalized_index, 0);
            assert_eq!(*target_index, 10);
            assert!(*in_flight);
        }
        other => panic!("expected HistoryFetch, got {other:?}"),
    }
    assert_eq!(
        cmds,
        vec![SyncCommand::RequestHistoryProof {
            peer,
            anchor_chunks: 0,
            end_chunks: 10,
            checkpoint_hash: [0xAA; 32],
        }]
    );
}

#[test]
fn history_fetch_completes_for_light_client() {
    let mut fsm = single_sample(fresh_progress(7));
    let peer = pid();
    fsm.on_event(SyncEvent::PeerStatus {
        peer,
        status: peer_status(7, 4, 512),
    });
    // Apply 4 checkpoint advances (the driver verified each batch); the
    // last one is the advertised endpoint.
    for i in 1_u8..=4 {
        let cmds = fsm.on_event(SyncEvent::CheckpointsAdvanced {
            new_finalized_index: u64::from(i),
            new_finalized_hash: if i == 4 { [0xAA; 32] } else { [i; 32] },
            new_finalized_state_root: [i; 32],
            new_finalized_height: u64::from(i) * 128,
            new_finalized_block_hash: [i; 32],
        });
        if i < 4 {
            // Should request next batch.
            assert!(
                cmds.iter()
                    .any(|c| matches!(c, SyncCommand::RequestHistoryProof { .. }))
            );
            assert!(matches!(fsm.state(), SyncState::HistoryFetch { .. }));
        } else {
            // Final batch — LightClient goes straight to Following.
            assert!(matches!(fsm.state(), SyncState::Following));
            assert!(cmds.contains(&SyncCommand::EnterFollowing));
            assert!(!cmds.contains(&SyncCommand::Subscribe(Topic::Blocks)));
        }
    }
}

#[test]
fn lost_sync_peer_resets_to_init() {
    let mut fsm = SyncMachine::new(SyncMode::Snap, fresh_progress(7));
    let peer = pid();
    fsm.on_event(SyncEvent::PeerStatus {
        peer,
        status: peer_status(7, 5, 640),
    });
    assert!(matches!(fsm.state(), SyncState::Following));

    fsm.on_event(SyncEvent::PeerDisconnected(peer));
    assert!(matches!(fsm.state(), SyncState::Init));
    assert_eq!(fsm.sync_peer(), None);
}

#[test]
fn history_unavailable_waits_for_notification() {
    let mut fsm = single_sample(fresh_progress(7));
    let peer = pid();
    fsm.on_event(SyncEvent::PeerStatus {
        peer,
        status: peer_status(7, 5, 640),
    });
    let cmds = fsm.on_event(SyncEvent::RpcFailed {
        protocol: RpcProtocol::HistoryProof,
        peer,
    });
    assert_eq!(cmds, [] as [SyncCommand; 0]);
    match fsm.state() {
        SyncState::HistoryFetch { in_flight, .. } => assert!(!in_flight),
        other => panic!("expected HistoryFetch, got {other:?}"),
    }
    let resumed = fsm.on_event(SyncEvent::PeerStatus {
        peer,
        status: peer_status(7, 5, 640),
    });
    assert!(
        resumed
            .iter()
            .any(|cmd| matches!(cmd, SyncCommand::RequestHistoryProof { .. }))
    );
}

#[test]
fn history_provider_failover_preserves_anchors_and_single_in_flight_request() {
    let mut local = fresh_progress(7);
    local.finalized_chunk_id = Some(1);
    local.checkpoint_hash = [2; 32];
    let mut fsm = single_sample(local);
    let original = pid();
    let replacement = pid();
    let status = peer_status(7, 5, 640);
    fsm.on_event(SyncEvent::PeerStatus {
        peer: original,
        status,
    });
    assert_eq!(fsm.retry_history_from(replacement), [] as [SyncCommand; 0]);
    fsm.on_event(SyncEvent::PeerDisconnected(original));
    assert_eq!(
        fsm.retry_history_from(replacement),
        vec![SyncCommand::RequestHistoryProof {
            peer: replacement,
            anchor_chunks: local.finalized_chunks(),
            end_chunks: status.finalized_chunks(),
            checkpoint_hash: status.checkpoint_hash,
        }]
    );
    assert_eq!(fsm.retry_history_from(original), [] as [SyncCommand; 0]);
    assert_eq!(fsm.progress(), &local);
    let mut full = SyncMachine::new(SyncMode::Snap, local);
    assert_eq!(full.retry_history_from(original), [] as [SyncCommand; 0]);
}

#[test]
fn light_client_ignores_larger_header_heads_with_an_older_endpoint() {
    let mut local = fresh_progress(7);
    local.finalized_chunk_id = Some(9);
    local.checkpoint_hash = [10; 32];
    local.head_height = 1_280;
    let mut fsm = single_sample(local);
    fsm.state = SyncState::Following;
    let peer = pid();
    assert_eq!(
        fsm.on_event(SyncEvent::PeerStatus {
            peer,
            status: peer_status(7, 9, 5_000),
        }),
        [] as [SyncCommand; 0]
    );
    assert_eq!(fsm.state(), &SyncState::Following);
    let commands = fsm.on_event(SyncEvent::PeerStatus {
        peer,
        status: peer_status(7, 20, 2_560),
    });
    assert!(matches!(
        commands.as_slice(),
        [SyncCommand::RequestHistoryProof { .. }]
    ));
}

#[test]
fn in_flight_history_keeps_its_provider_target_and_ignores_foreign_failures() {
    let mut fsm = single_sample(fresh_progress(7));
    let original = pid();
    let other = pid();
    fsm.on_event(SyncEvent::PeerStatus {
        peer: original,
        status: peer_status(7, 5, 640),
    });
    let state = fsm.state().clone();
    assert_eq!(
        fsm.on_event(SyncEvent::PeerStatus {
            peer: other,
            status: peer_status(7, 20, 2_560),
        }),
        [] as [SyncCommand; 0]
    );
    fsm.on_event(SyncEvent::PeerDisconnected(other));
    fsm.on_event(SyncEvent::RpcFailed {
        protocol: RpcProtocol::HistoryProof,
        peer: other,
    });
    assert_eq!(fsm.state(), &state);
    assert_eq!(fsm.sync_peer(), Some(original));
    assert_eq!(fsm.retry_history_from(other), [] as [SyncCommand; 0]);
}

#[test]
fn full_modes_follow_once_a_peer_is_useful() {
    // Complete-chunk sync and snapshot bootstrap run in the driver; the
    // machine only decides when a full node subscribes.
    for mode in [SyncMode::Snap, SyncMode::Archive] {
        let mut fsm = SyncMachine::new(mode, fresh_progress(7));
        let commands = fsm.on_event(SyncEvent::PeerStatus {
            peer: pid(),
            status: peer_status(7, 5, 640),
        });
        assert!(matches!(fsm.state(), SyncState::Following));
        assert!(commands.contains(&SyncCommand::EnterFollowing));
        assert_eq!(
            fsm.on_event(SyncEvent::RpcFailed {
                protocol: RpcProtocol::BlocksByRange,
                peer: pid(),
            }),
            [] as [SyncCommand; 0]
        );
    }
}

#[test]
fn reset_clears_state() {
    let mut fsm = SyncMachine::new(SyncMode::Snap, fresh_progress(7));
    let peer = pid();
    fsm.on_event(SyncEvent::PeerStatus {
        peer,
        status: peer_status(7, 5, 640),
    });
    assert!(matches!(fsm.state(), SyncState::Following));
    fsm.on_event(SyncEvent::Reset);
    assert!(matches!(fsm.state(), SyncState::Init));
    assert_eq!(fsm.sync_peer(), None);
}
#[test]
fn light_client_requires_endpoint_identity_and_resumes_on_new_status() {
    let mut fsm = single_sample(fresh_progress(7));
    let peer = pid();
    let mut conflict = peer_status(7, 0, 0);
    conflict.checkpoint_hash = [99; 32];
    assert_eq!(
        fsm.on_event(SyncEvent::PeerStatus {
            peer,
            status: conflict
        }),
        [] as [SyncCommand; 0]
    );
    assert_eq!(fsm.state(), &SyncState::Init);
    fsm.on_event(SyncEvent::PeerStatus {
        peer,
        status: peer_status(7, 0, 0),
    });
    assert_eq!(fsm.state(), &SyncState::Following);
    let commands = fsm.on_event(SyncEvent::PeerStatus {
        peer,
        status: peer_status(7, 1, 128),
    });
    assert!(
        commands
            .iter()
            .any(|cmd| matches!(cmd, SyncCommand::RequestHistoryProof { .. }))
    );
}

fn advertising(finalized: CheckpointIndex, hash: u8) -> rpc::Status {
    rpc::Status {
        checkpoint_hash: [hash; 32],
        ..peer_status(7, finalized, finalized * 128)
    }
}

#[test]
fn light_client_advances_only_when_a_quorum_of_samples_agree() {
    let mut fsm = SyncMachine::new(SyncMode::LightClient, fresh_progress(7));
    let peers = [pid(), pid(), pid(), pid()];
    // Two agreeing peers and one ahead are not a quorum of three.
    for (peer, status) in [
        (peers[0], advertising(5, 5)),
        (peers[1], advertising(5, 5)),
        (peers[2], advertising(6, 6)),
    ] {
        assert_eq!(
            fsm.on_event(SyncEvent::PeerStatus { peer, status }),
            [] as [SyncCommand; 0]
        );
    }
    assert_eq!(fsm.state(), &SyncState::Init);
    // The third agreeing peer completes the quorum; the proof is fetched
    // from it with the opening of the client's own endpoint.
    assert_eq!(
        fsm.on_event(SyncEvent::PeerStatus {
            peer: peers[3],
            status: advertising(5, 5),
        }),
        vec![SyncCommand::RequestHistoryProof {
            peer: peers[3],
            anchor_chunks: 0,
            end_chunks: 5,
            checkpoint_hash: [5; 32],
        }]
    );
    let mut providers = fsm.history_providers();
    providers.sort();
    let mut agreeing = vec![peers[0], peers[1], peers[3]];
    agreeing.sort();
    assert_eq!(providers, agreeing);
    // Only the last five distinct peers count.
    let mut window = SyncMachine::new(SyncMode::LightClient, fresh_progress(7));
    for status in [advertising(5, 5), advertising(5, 5)] {
        window.on_event(SyncEvent::PeerStatus {
            peer: pid(),
            status,
        });
    }
    for count in [3, 4, 6] {
        window.on_event(SyncEvent::PeerStatus {
            peer: pid(),
            status: advertising(count, u8::try_from(count).unwrap()),
        });
    }
    // The sixth peer pushes the first out of the window: still two.
    assert_eq!(
        window.on_event(SyncEvent::PeerStatus {
            peer: pid(),
            status: advertising(5, 5),
        }),
        [] as [SyncCommand; 0]
    );
    assert_eq!(window.state(), &SyncState::Init);
}

#[test]
fn identities_on_one_host_count_as_one_sample() {
    let mut fsm = SyncMachine::new(SyncMode::LightClient, fresh_progress(7));
    let shared = [pid(), pid(), pid()];
    for peer in shared {
        fsm.on_event(SyncEvent::PeerHost {
            peer,
            host: [0, 0, 0, 10, 0, 0],
        });
        assert_eq!(
            fsm.on_event(SyncEvent::PeerStatus {
                peer,
                status: advertising(5, 5),
            }),
            [] as [SyncCommand; 0]
        );
    }
    assert_eq!(fsm.history_providers(), Vec::<PeerId>::new());
    assert_eq!(fsm.state(), &SyncState::Init);
    // Two more hosts agreeing complete the quorum of three.
    for (byte, peer) in [(11, pid()), (12, pid())] {
        fsm.on_event(SyncEvent::PeerHost {
            peer,
            host: [0, 0, 0, byte, 0, 0],
        });
        fsm.on_event(SyncEvent::PeerStatus {
            peer,
            status: advertising(5, 5),
        });
    }
    assert!(matches!(fsm.state(), SyncState::HistoryFetch { .. }));
}

#[test]
fn conflicting_samples_are_checked_and_a_verified_conflict_stalls() {
    let mut local = fresh_progress(7);
    local.finalized_chunk_id = Some(1);
    local.checkpoint_hash = [2; 32];
    let mut fsm = SyncMachine::new(SyncMode::LightClient, local);
    let (a, b, c) = (pid(), pid(), pid());
    fsm.on_event(SyncEvent::PeerStatus {
        peer: a,
        status: advertising(5, 5),
    });
    // Two endpoints at one count: both sides are fetched, neither accepted.
    let commands = fsm.on_event(SyncEvent::PeerStatus {
        peer: b,
        status: advertising(5, 9),
    });
    assert_eq!(
        commands,
        vec![
            SyncCommand::CheckHistoryConflict {
                peer: a,
                end_chunks: 5,
                checkpoint_hash: [5; 32],
            },
            SyncCommand::CheckHistoryConflict {
                peer: b,
                end_chunks: 5,
                checkpoint_hash: [9; 32],
            },
        ]
    );
    // A side that cannot back its advertisement stops counting.
    assert_eq!(
        fsm.on_event(SyncEvent::SampleRejected(b)),
        [] as [SyncCommand; 0]
    );
    // A peer contradicting the current endpoint is checked alone.
    assert_eq!(
        fsm.on_event(SyncEvent::PeerStatus {
            peer: c,
            status: advertising(2, 7),
        }),
        vec![SyncCommand::CheckHistoryConflict {
            peer: c,
            end_chunks: 2,
            checkpoint_hash: [7; 32],
        }]
    );
    // Once the backend has verified both sides, nothing moves the client.
    fsm.on_event(SyncEvent::HistoryConflict);
    assert_eq!(
        fsm.state(),
        &SyncState::Stalled {
            reason: SyncStallReason::HistoryConflict
        }
    );
    for status in [advertising(6, 6), advertising(6, 6), advertising(6, 6)] {
        assert_eq!(
            fsm.on_event(SyncEvent::PeerStatus {
                peer: pid(),
                status
            }),
            [] as [SyncCommand; 0]
        );
    }
}
