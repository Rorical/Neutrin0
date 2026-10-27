//! Cryptographic requests extracted from observed consensus artifacts.
//!
//! Extraction asserts neither membership, quorum, validity nor guilt.

use alloc::vec::Vec;
use neutrin0_primitives::{BitVec, BlsPublicKey, Hash, Validator};

use super::request::FactRequest;

/// Cryptographic requests available as soon as a BFT vote is observed.
/// This extraction does not assert membership, quorum, validity or guilt.
pub fn vote_requests(
    domain: neutrin0_primitives::ConsensusDomain,
    validators: &[Validator],
    vote: &neutrin0_consensus_types::FinalityVote,
) -> Vec<FactRequest> {
    let mut requests = Vec::new();
    let message = vote.data.signing_message(domain);
    let keys = marked_keys(validators, &vote.aggregation_bits);
    if keys.len() == 1 {
        requests.push(FactRequest::Signature {
            key: keys[0],
            message: message.clone(),
            signature: vote.signature,
            possession: false,
        });
    }
    requests.push(FactRequest::Aggregate {
        keys,
        message,
        signature: vote.signature,
    });
    for claim in &vote.attestations {
        let Some(validator) = validators.get(claim.validator_index as usize) else {
            continue;
        };
        requests.push(FactRequest::Signature {
            key: validator.pubkey,
            message: claim.vote.signing_message(domain),
            signature: claim.vote_signature,
            possession: false,
        });
        requests.push(FactRequest::Signature {
            key: validator.pubkey,
            message: claim.signing_message(domain),
            signature: claim.signature,
            possession: false,
        });
        if let Some(quorum) = &claim.unlock_quorum {
            requests.push(quorum_request(domain, validators, quorum));
        }
    }
    requests
}

/// Keys of every validator marked in `bits`, in set order. Extraction only:
/// membership and activity are checked by the consuming verifier.
fn marked_keys(validators: &[Validator], bits: &BitVec) -> Vec<BlsPublicKey> {
    validators
        .iter()
        .enumerate()
        .filter_map(|(index, validator)| {
            (bits.get(u32::try_from(index).ok()?) == Some(true)).then_some(validator.pubkey)
        })
        .collect()
}

/// Aggregate check for a quorum certificate over `validators`.
fn quorum_request(
    domain: neutrin0_primitives::ConsensusDomain,
    validators: &[Validator],
    quorum: &neutrin0_consensus_types::QuorumCertificate,
) -> FactRequest {
    FactRequest::Aggregate {
        keys: marked_keys(validators, &quorum.aggregate.aggregation_bits),
        message: quorum.data.signing_message(domain),
        signature: quorum.aggregate.signature,
    }
}

/// Leader proposal signature plus every signature inside its round-change
/// certificate, so a chunk's proposal checks can be answered from facts.
pub fn proposal_requests(
    domain: neutrin0_primitives::ConsensusDomain,
    validators: &[Validator],
    proposal: &neutrin0_consensus_types::BftProposal,
) -> Vec<FactRequest> {
    let mut requests = Vec::new();
    if let Some(validator) = validators.get(proposal.proposer_index as usize) {
        requests.push(FactRequest::Signature {
            key: validator.pubkey,
            message: proposal.signing_message(domain),
            signature: proposal.signature,
            possession: false,
        });
    }
    if let Some(certificate) = &proposal.round_change_certificate {
        requests.extend(round_change_certificate_requests(
            domain,
            validators,
            certificate,
        ));
    }
    requests
}

/// Round-change report signature and its carried highest quorum, if any.
pub fn round_change_requests(
    domain: neutrin0_primitives::ConsensusDomain,
    validators: &[Validator],
    report: &neutrin0_consensus_types::RoundChange,
) -> Vec<FactRequest> {
    let mut requests = Vec::new();
    if let Some(validator) = validators.get(report.validator_index as usize) {
        requests.push(FactRequest::Signature {
            key: validator.pubkey,
            message: report.signing_message(domain),
            signature: report.signature,
            possession: false,
        });
    }
    if let Some(quorum) = &report.highest_quorum {
        requests.push(quorum_request(domain, validators, quorum));
    }
    requests
}

/// Every signature a round-change certificate carries.
pub fn round_change_certificate_requests(
    domain: neutrin0_primitives::ConsensusDomain,
    validators: &[Validator],
    certificate: &neutrin0_consensus_types::RoundChangeCertificate,
) -> Vec<FactRequest> {
    certificate
        .reports
        .iter()
        .flat_map(|report| round_change_requests(domain, validators, report))
        .collect()
}

/// Exact nil signatures available for early cryptographic fact compression.
pub fn nil_vote_requests(
    domain: neutrin0_primitives::ConsensusDomain,
    validators: &[Validator],
    vote: &neutrin0_consensus_types::NilVote,
) -> Vec<FactRequest> {
    let mut requests = Vec::new();
    let message = vote.data.signing_message(domain);
    requests.push(FactRequest::Aggregate {
        keys: marked_keys(validators, &vote.aggregation_bits),
        message: message.clone(),
        signature: vote.signature,
    });
    for claim in &vote.attestations {
        let Some(validator) = validators.get(claim.validator_index as usize) else {
            continue;
        };
        requests.push(FactRequest::Signature {
            key: validator.pubkey,
            message: message.clone(),
            signature: claim.vote_signature,
            possession: false,
        });
        requests.push(FactRequest::Signature {
            key: validator.pubkey,
            message: claim.signing_message(domain),
            signature: claim.signature,
            possession: false,
        });
    }
    requests
}

/// Header authentication and VRF facts can be compressed before finality.
pub fn header_requests(
    domain: neutrin0_primitives::ConsensusDomain,
    validators: &[Validator],
    seed: &Hash,
    header: &neutrin0_consensus_types::Header,
) -> Vec<FactRequest> {
    let Some(validator) = validators.get(header.proposer_index as usize) else {
        return Vec::new();
    };
    let domain = domain.at_height(header.height);
    let message = domain.signing_message(neutrin0_primitives::DOMAIN_PROPOSER_SIG, &header.hash());
    alloc::vec![
        FactRequest::Signature {
            key: validator.pubkey,
            message,
            signature: header.signature,
            possession: false
        },
        FactRequest::Signature {
            key: validator.pubkey,
            message: neutrin0_vrf::vrf_message(domain, seed, header.slot),
            signature: header.vrf_proof,
            possession: false
        },
    ]
}
