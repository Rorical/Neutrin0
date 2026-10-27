//! Poseidon2-backed trie hasher.
//!
//! This is the SP1-precompile-aligned trie hash. Inside the SP1 Guest
//! (`target_os = "zkvm"`) each permutation maps to a single
//! `syscall_poseidon2` precompile call (~100 prover cycles); outside
//! the guest we run a software implementation built on SP1's `slop-koala-bear` that produces byte-identical digests.
//!
//! # Parameters
//!
//! Matches SP1's canonical KoalaBear Poseidon2 instance
//! (`slop-koala-bear::my_kb_16_perm`):
//!
//! - Field: `KoalaBear`, modulus `p = 2^31 - 2^24 + 1 = 0x7F000001`
//! - Width 16, S-box `x^3` (`D = 3`)
//! - 8 external full rounds + 20 internal partial rounds
//! - Round constants and diffusion matrix supplied by the pinned SP1 library
//!
//! # Byte hashing convention
//!
//! Matches `sp1-lib::poseidon2::Poseidon2ByteHash::hash`:
//!
//! 1. Absorb a length-prefix block first (`u64_le(input.len()` packed
//!    into the first 24-byte block, zero-padded). The explicit `u64`
//!    keeps the digest target-independent and matches SP1's 64-bit Guest.
//! 2. Absorb every full 24-byte block (3 bytes per field element,
//!    little-endian into the low 24 bits, 8 field elements per
//!    block = the sponge rate).
//! 3. Absorb the final partial block with zero padding (no length
//!    delimiter — the leading length-prefix is sufficient).
//! 4. Output the first 8 state elements (the rate portion), packed
//!    as 4 little-endian bytes per element = 32-byte digest.
//!
//! Each KoalaBear element fits in 31 bits, so the top bit of every
//! 4th output byte is always zero.  Effective digest entropy is
//! `8 * 31 = 248 bits`, well above the 128-bit safety floor for
//! collision resistance.
//!
//! # Domain separation
//!
//! `Hasher::hash_node` prepends [`TRIE_NODE_DOMAIN_POSEIDON2`] (16
//! bytes, disjoint from the BLAKE3 variant's `TRIE_NODE_DOMAIN`) so a
//! chain that ran on the BLAKE3 trie and a chain that ran on the
//! Poseidon2 trie cannot share a node digest by accident, even if
//! they happened to share initial state.
//! `Hasher::hash_value` hashes value bytes directly without a domain
//! tag — values are content-addressed and the column they live in is
//! disjoint from the node column.

extern crate alloc;

use neutrin0_primitives::Hash;

use crate::hasher::Hasher;

// Software-impl imports.  The SP1 Guest (`target_os = "zkvm"`) calls
// the precompile via `sp1-lib`; the master cdylib's `wasm32-unknown-
// unknown` build never executes the hash function at runtime (state
// roots are supplied by host imports), so we link a panic-stub there
// to avoid pulling the `getrandom`-bearing `slop-koala-bear` dep into the
// wasm cdylib build.
#[cfg(not(any(target_os = "zkvm", target_arch = "wasm32")))]
use alloc::boxed::Box;
#[cfg(not(any(target_os = "zkvm", target_arch = "wasm32")))]
use once_cell::race::OnceBox;
#[cfg(not(any(target_os = "zkvm", target_arch = "wasm32")))]
use slop_algebra::{AbstractField, PrimeField32};
#[cfg(not(any(target_os = "zkvm", target_arch = "wasm32")))]
use slop_koala_bear::{KoalaBear, KoalaPerm, my_kb_16_perm};
#[cfg(not(any(target_os = "zkvm", target_arch = "wasm32")))]
use slop_symmetric::Permutation;

/// 16-byte domain tag prepended to every Poseidon2 trie-node hash.
/// Disjoint from the BLAKE3 variant's
/// [`crate::TRIE_NODE_DOMAIN`] so the two hash families cannot
/// alias on the same input.
pub const TRIE_NODE_DOMAIN_POSEIDON2: [u8; 16] = *b"NTRO_TR_NODE_P2_";

/// Sponge rate — 8 elements per absorb (`24` bytes of byte-input
/// per absorb).  Matches `sp1-lib::poseidon2::RATE`.  Used by every
/// code path that produces a digest (host software, zkvm precompile)
/// to drive the output-packing loop; only the wasm32 panic-stub
/// doesn't reference it.
#[cfg(not(target_arch = "wasm32"))]
const RATE: usize = 8;

/// Sponge width and byte-block size —
/// software-impl only.  The SP1 Guest reaches the precompile via
/// `sp1-lib` (which carries its own copies of these constants
/// internally), and the master `wasm32-unknown-unknown` cdylib
/// never executes the trie's hash function at runtime, so neither
/// target needs these baked in.
#[cfg(not(any(target_os = "zkvm", target_arch = "wasm32")))]
const WIDTH: usize = 16;
#[cfg(not(any(target_os = "zkvm", target_arch = "wasm32")))]
const BYTE_BLOCK_SIZE: usize = RATE * 3;

/// SP1's canonical software permutation, initialized once on first use.
/// Host hashing and the Guest precompile share its parameters and constants.
#[cfg(not(any(target_os = "zkvm", target_arch = "wasm32")))]
fn perm_instance() -> &'static KoalaPerm {
    static INSTANCE: OnceBox<KoalaPerm> = OnceBox::new();
    INSTANCE.get_or_init(|| Box::new(my_kb_16_perm()))
}

/// Inside the SP1 Guest, dispatch straight to the precompile-backed
/// [`sp1_lib::poseidon2::Poseidon2ByteHash::hash`].  Each absorbed
/// block costs ~100 prover cycles instead of the ~1.5 M cycles a
/// software BLAKE3 invocation would take in emulated RISC-V.
#[cfg(target_os = "zkvm")]
fn poseidon2_byte_hash(bytes: &[u8]) -> Hash {
    let output: [u32; RATE] = sp1_lib::poseidon2::Poseidon2ByteHash::hash(bytes);
    let mut digest = [0u8; 32];
    for i in 0..RATE {
        digest[i * 4..(i + 1) * 4].copy_from_slice(&output[i].to_le_bytes());
    }
    digest
}

/// `wasm32-unknown-unknown` panic-stub.  The master cdylib delegates
/// every state-root computation to host imports
/// (`pre_state_root` / `post_state_root`) and never instantiates the
/// trie's hash function at runtime — so the only purpose of this
/// stub is to keep the crate's dead code linking cleanly without
/// pulling the `slop-koala-bear` → `rand` → `getrandom` chain into the
/// wasm cdylib's dep graph.  A live call here indicates a regression
/// in the WASM ABI surface; failing loudly is the right behaviour.
#[cfg(target_arch = "wasm32")]
fn poseidon2_byte_hash(_bytes: &[u8]) -> Hash {
    panic!(
        "neutrin0-trie's Poseidon2 software impl is not compiled into \
         the wasm32-unknown-unknown cdylib build; host imports own \
         state-root computation"
    )
}

/// Absorb a single 24-byte block into the sponge state, using SP1's
/// 3-bytes-per-element little-endian packing.  Software-impl only —
/// the guest path is `sp1-lib::poseidon2::Poseidon2ByteHash::hash`
/// (which uses the same convention internally) and the wasm32 cdylib
/// path is a panic-stub.
#[cfg(not(any(target_os = "zkvm", target_arch = "wasm32")))]
fn absorb_byte_block(state: &mut [u32; WIDTH], block: &[u8; BYTE_BLOCK_SIZE]) {
    for (i, slot) in state.iter_mut().take(RATE).enumerate() {
        let start = 3 * i;
        *slot = u32::from(block[start])
            | (u32::from(block[start + 1]) << 8)
            | (u32::from(block[start + 2]) << 16);
    }
    // Convert sponge state to field elements, permute, convert back.
    let mut field_state: [KoalaBear; WIDTH] = [KoalaBear::zero(); WIDTH];
    for (i, &v) in state.iter().enumerate() {
        field_state[i] = KoalaBear::from_canonical_u32(v);
    }
    perm_instance().permute_mut(&mut field_state);
    for (i, slot) in state.iter_mut().enumerate() {
        *slot = field_state[i].as_canonical_u32();
    }
}

/// Length-prefixed sponge hash, matching
/// `sp1-lib::poseidon2::Poseidon2ByteHash::hash` byte-for-byte.  Returns a 32-byte digest formed by packing
/// the first [`RATE`] state elements as 4 little-endian bytes each.
///
/// Software-impl path; the SP1 Guest goes through the
/// precompile-backed `poseidon2_byte_hash` defined above and the
/// master `wasm32-unknown-unknown` cdylib uses a panic-stub since
/// it never executes the trie's hash function at runtime.
#[cfg(not(any(target_os = "zkvm", target_arch = "wasm32")))]
fn poseidon2_byte_hash(bytes: &[u8]) -> Hash {
    let mut state = [0u32; WIDTH];

    // Block 0: length prefix.  Using u64 explicitly keeps the digest
    // identical between 32-bit and 64-bit hosts and SP1's 64-bit Guest.
    let len_bytes = (bytes.len() as u64).to_le_bytes();
    let mut len_block = [0u8; BYTE_BLOCK_SIZE];
    len_block[..len_bytes.len()].copy_from_slice(&len_bytes);
    absorb_byte_block(&mut state, &len_block);

    // Full input blocks.
    let (blocks, remainder) = bytes.as_chunks::<BYTE_BLOCK_SIZE>();
    for block in blocks {
        absorb_byte_block(&mut state, block);
    }

    // Final partial block, zero-padded.
    if !remainder.is_empty() {
        let mut last_block = [0u8; BYTE_BLOCK_SIZE];
        last_block[..remainder.len()].copy_from_slice(remainder);
        absorb_byte_block(&mut state, &last_block);
    }

    // Output: first RATE elements, packed as 4 LE bytes each.
    let mut digest = [0u8; 32];
    for i in 0..RATE {
        digest[i * 4..(i + 1) * 4].copy_from_slice(&state[i].to_le_bytes());
    }
    digest
}

/// Poseidon2-backed [`Hasher`].
///
/// Inside the SP1 Guest this maps to a `POSEIDON2` precompile call
/// per absorbed block — ~100 prover cycles vs ~1.5M for BLAKE3 in
/// software-emulated RISC-V.  Outside the guest the software fallback
/// produces byte-identical digests.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Poseidon2Hasher;

impl Hasher for Poseidon2Hasher {
    fn hash_node(encoded_node: &[u8]) -> Hash {
        let mut buf =
            alloc::vec::Vec::with_capacity(TRIE_NODE_DOMAIN_POSEIDON2.len() + encoded_node.len());
        buf.extend_from_slice(&TRIE_NODE_DOMAIN_POSEIDON2);
        buf.extend_from_slice(encoded_node);
        poseidon2_byte_hash(&buf)
    }

    fn hash_value(value: &[u8]) -> Hash {
        poseidon2_byte_hash(value)
    }
}

// Tests run on the host toolchain (which is neither the SP1 Guest
// `target_os = "zkvm"` nor a wasm32 target).  Gating to "software
// impl available" keeps the `perm_instance` test reachable while
// avoiding `unused`-warnings under the gated-out targets.
#[cfg(all(test, not(any(target_os = "zkvm", target_arch = "wasm32"))))]
mod tests;
