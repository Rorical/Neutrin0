//! Counted, append-only historical commitments in a fixed 64-level tree.

mod frontier;
mod path;
#[cfg(test)]
mod tests;

pub use frontier::HistoryFrontier;
pub use path::HistoryPath;

use neutrin0_primitives::{
    DOMAIN_HISTORY_LEAF, DOMAIN_HISTORY_NODE, DOMAIN_HISTORY_ROOT, Hash, blake3_256,
};

/// Number of address bits in a historical chunk index.
pub const HISTORY_DEPTH: usize = 64;

/// Number of preceding finalized chunks available to current consensus inputs.
/// Archive nodes retain more data but enforce this same protocol window.
pub const HISTORY_RETENTION_CHUNKS: u64 = 8;

/// Whether an index belongs to the eight finalized chunks before `count`.
/// Current and future chunks are excluded; genesis has no historical records.
#[must_use]
pub const fn is_recent_history_index(index: u64, count: u64) -> bool {
    is_history_index_within(index, count, HISTORY_RETENTION_CHUNKS)
}

/// Whether an index belongs to the `window` finalized chunks before `count`.
#[must_use]
pub const fn is_history_index_within(index: u64, count: u64, window: u64) -> bool {
    index < count && index >= count.saturating_sub(window)
}

/// Default number of preceding finalized chunks whose complete historical
/// records (validator vector, seed, certificate) a full node keeps so safety
/// evidence can still be constructed locally.
///
/// Safety claims have no age window, so this is a local service horizon, not
/// an admissibility bound. A still-bonded validator may have signed outside
/// this window. Older records and their openings require a retaining reporter
/// or archive node; ordinary nodes keep bounded cached openings. The
/// eight-chunk liveness window is never shrunk.
#[must_use]
pub const fn history_record_window_chunks(unbonding_delay_blocks: u64, chunk_size: u64) -> u64 {
    if chunk_size == 0 {
        return HISTORY_RETENTION_CHUNKS;
    }
    let chunks = unbonding_delay_blocks.div_ceil(chunk_size);
    if chunks > HISTORY_RETENTION_CHUNKS {
        chunks
    } else {
        HISTORY_RETENTION_CHUNKS
    }
}

/// Distinguish an empty slot from an occupied context commitment.
#[must_use]
pub fn history_leaf_hash(value: Option<Hash>) -> Hash {
    let mut bytes = [0; 49];
    bytes[..16].copy_from_slice(&DOMAIN_HISTORY_LEAF);
    let Some(value) = value else {
        return blake3_256(&bytes[..17]);
    };
    bytes[16] = 1;
    bytes[17..].copy_from_slice(&value);
    blake3_256(&bytes)
}

/// Hash children of height `level`; level zero combines historical leaves.
#[must_use]
pub fn history_node_hash(level: usize, left: Hash, right: Hash) -> Hash {
    assert!(level < HISTORY_DEPTH, "historical node level");
    let mut bytes = [0; 81];
    bytes[..16].copy_from_slice(&DOMAIN_HISTORY_NODE);
    bytes[16] = u8::try_from(level).expect("bounded history depth");
    bytes[17..49].copy_from_slice(&left);
    bytes[49..].copy_from_slice(&right);
    blake3_256(&bytes)
}

/// Empty subtree hashes, indexed by height (zero is an empty leaf).
///
/// Generated from `history_leaf_hash(None)` and
/// `history_node_hash(level, empty[level], empty[level])`; a unit test checks
/// every entry against that recursive definition.
pub const EMPTY_HISTORY_HASHES: [Hash; HISTORY_DEPTH + 1] = [
    hex32(b"c9e44a37177632df9377c62678301de17d290653ca2fd5e34c2962bb97f219ca"),
    hex32(b"7974304fbab5d11f60b5f11ec9d0be50acbd7eecb26c2fecb3cf91fd163a7268"),
    hex32(b"147ae9ff8be01dce9fd219f5da0b7ade1f441024f5b1274a9b36dde34941464e"),
    hex32(b"2b8aefee97edea19c37b79883a800d302cedc1967669e5adee53e05628cf0a3c"),
    hex32(b"bda726d617e74543d422d693fa6dd8db1de6c4e1553d159fcb6d9ba54316b889"),
    hex32(b"4a4a5a565001f75dfcc8e79bbac99751a33f63319796b0d46544fe89fe82ed3a"),
    hex32(b"255a2a87542293746b32ce1350ce046569f7849c12ef26be34282e6248daccb7"),
    hex32(b"363e495b97bab065e0c4c0404696ec929eeda54cddcc9e391441e91691770f8f"),
    hex32(b"2727aeee2f4e8715eddfd9d011723519b8aee9035aa09a86462915a7c0d697f5"),
    hex32(b"3a06e1ed5901edf28116fb76603277a8f7d254d45f69de6106540f25f9fce94e"),
    hex32(b"489eea0a637845903add164d9fe2982085b3c84121613aee49b475f34bd3991f"),
    hex32(b"13afb30166ea09418ba7762d0f921fcfeba7c8effb81364cd4510b81633db3aa"),
    hex32(b"081e23617f949d25854fe604efbd1615beb7fc4562ccaa6bf5e5aae6622a6bff"),
    hex32(b"9cfb52d9a7e0a0099cb21e76d729bcbeee9177dc47e7a56b35e7c7654481ff34"),
    hex32(b"041838ca3f8f29973cdc15aeeaaa6731e79fc4c69da68fa565a447b72eeae171"),
    hex32(b"825e593ca627ec96fe1bc998d84a5eda6a3eaf4970ab78fc5c317cb10705002a"),
    hex32(b"98719e8c2f6a480c56ac3b9f3e9fd3197a5469b7516a55fe591eacd9fb8d7950"),
    hex32(b"9f814cdad8974365da65dc2d89e0752fe5a64c1eeb44be3e16e51600f9c09416"),
    hex32(b"1ed110d31194cfaa012cdeba9a9d87f1e20958a78eb30fdcc0fdcb9828baed3e"),
    hex32(b"3148ab597b917b59fb114d0433b69bd08bb8dcec45dcf215b288245175e5d94a"),
    hex32(b"8fce5e4db50a08c8b2b5f6888275510c105a79f69520ead6769d1611dff57e81"),
    hex32(b"c6bbf4d722ef408662308150d8041a62a11e19ea141e0560085383709a0ab0a2"),
    hex32(b"17539fb86a661a7cf88b8267f87ed683a9e7255477e58a57549b509cb00c11b6"),
    hex32(b"1fc268ea28bbf25cccb5788421f1122f38802b0a1c01594ff75db2a6937b04ed"),
    hex32(b"e571f87eebf95fedcc6cf315e1a96d8cb11b1bcb8838ad9f2a35037438c578ca"),
    hex32(b"a5837b5da2ab336eb85159226199c24629c67a54c5ff9d5842db19c861658687"),
    hex32(b"f9237677daf3e1022193d41453719fef6b7ff3045f6519740ba037763236b8f5"),
    hex32(b"119abb8c7a1aaf2ec94f732b140701098d26d3349bb2e2ab5b023fe99210beb1"),
    hex32(b"3a6fd63bebd76c0c0b8d60f7be4f5c6788982d6ba691ec133654ab0b3ddc9feb"),
    hex32(b"f0340db146305008ef8a5348df90637e707622330293f8d6aa558b57e6239f3d"),
    hex32(b"6bdf2a7d508b9fa7f345b76ad9e5f63c608cf1811348be0736bda0992594b9c4"),
    hex32(b"275a5421a1a8c70d7189f8274faa6679f747530006356fb93617e5245009cfcc"),
    hex32(b"9f56109fb603f0eaa904b3c9eb2e5373ee6e8c346caa7bfee18ae4554f19c5af"),
    hex32(b"17190ec3e3c731090c556d265ce22f5ba0ca0991a8d8627892384ca8b72399ae"),
    hex32(b"d80c2de2eb4275a638492ce820282c549b26504b3342ff1be15179da621ef90d"),
    hex32(b"b909304a100a339c39ef6f4369f35df8ef93ee0a91201b7c3de94aeca076df1c"),
    hex32(b"313160f80e4aabf4bcad0f9b4ead651c1a9577b564971a9b53ee28d1cf047c58"),
    hex32(b"e8ae14d7cce179b3efbf0f8974055f5285cb043165ebcbbdcd7de2a2e1a8e00a"),
    hex32(b"f4ae4ae98e5bc36a713c3c32e6b6e9f010549c284da9ee2211caecbde9c55d1f"),
    hex32(b"f491d9504e9cea219b3e7ffedf6872e399c2cbde420ccea1690509923efbde2b"),
    hex32(b"f01e115424eb963df06533386b7d7ef84c6f3def2c344f2a08e43966cf9665ff"),
    hex32(b"23f9d29d4518c60cf1db627e660a1a4f7a9995ddd3ca38fe1dfad156c3f8a745"),
    hex32(b"355da7b3bf9a9e635b08bda659117d77b5d592bd1f0abf764f7d3874fc428b01"),
    hex32(b"03014d41e1a8fe2c095ac5cb469dda06cc7c9c0e8954d84ae10b9f067a41e98f"),
    hex32(b"eb989b1ac1f703c36544bdff7b85d03c46e38c013b6b47018d4f1df08c70a131"),
    hex32(b"a250a0922bea56e27da9c5b1f816aa7c5f3e5c6605aaca20725a2ecbda8ed055"),
    hex32(b"ed4912fba282d9c8ab1ece8d1016f9d6ef35b29a65258a1cdaf29e68bcdf5dd0"),
    hex32(b"b1ee33f07ed510f81af21db36d8b6f2f89eae746aa29ffb16efd711788589716"),
    hex32(b"a8d52fbfee48b3b3b657f4be02caaf59ae75d5f2b56d799bca36b9b9b1044c09"),
    hex32(b"1ff647fe77292b59d784cde1664b093483be43abb4f347c1f715fd7fc1826d7a"),
    hex32(b"0e668a3b41ffe368015c49833bd07399c05074816b9dc42c83deaf7f3ff94768"),
    hex32(b"a64a1196fe1a3533237ec94a8bd7a1a4c38f09ac2b7d71155526ce3218d57674"),
    hex32(b"0a721527c24a1e680d59e7ebeab0b40986a4f1684349d8c4e1f59bfff0c7263d"),
    hex32(b"66cfaabec3f77fc2cacda30f49d6ab0c56ec975db174da8245aede8885323410"),
    hex32(b"0fd2aaa6e903cc5accb2f3494a3c3fd20bd7f6f07d89c5a0766502b9782f6d50"),
    hex32(b"4c4e28827db78b2815395d8f9e0ea959de8d6a1fbc7ea81d6f7046cf6c658675"),
    hex32(b"94729756aa905b6effcf13dfa5c15a53721ab882cb5387b191149d7bf59d06b4"),
    hex32(b"03bc6f50543a2f3d534b846b5ab7525f5a1e8e8343892e32542ae53a0c99969f"),
    hex32(b"023cd9f9d932fab1b66c9e193cafe872337afac8c8a76b0d0715d2636325ded7"),
    hex32(b"a8dac7d39524c4f27a238422624b593a705de2ef0daec429ded04efc1bdcf31d"),
    hex32(b"9f13265ca38f209ff7393265f11cc63080b07246858f80e7a157284ce1fe97ed"),
    hex32(b"924d6a5d90015405286d7f64202dd163447d0fe56667c3cd6025577f2fc67f27"),
    hex32(b"cbd8f02918d889cc41ac2f6f133294c9d7b654211df32538a9adc03153730899"),
    hex32(b"7acb34cb3439b7677b7f38aa846c075f6ad81e2932e9342c682c84f0c39f121e"),
    hex32(b"00857cbc2424f5c9f704c26aa264829b4cb4bf6d6af761f58b132fe3764e7d7a"),
];

/// Canonical genesis historical commitment,
/// `counted_history_root(0, EMPTY_HISTORY_HASHES[HISTORY_DEPTH])`.
pub const EMPTY_HISTORY_ROOT: Hash = neutrin0_primitives::EMPTY_HISTORY_ROOT;

/// Decode 64 lowercase hexadecimal digits at compile time.
const fn hex32(digits: &[u8; 64]) -> Hash {
    const fn nibble(digit: u8) -> u8 {
        match digit {
            b'0'..=b'9' => digit - b'0',
            b'a'..=b'f' => digit - b'a' + 10,
            _ => panic!("lowercase hexadecimal digit"),
        }
    }
    let mut bytes = [0; 32];
    let mut index = 0;
    while index < 32 {
        bytes[index] = (nibble(digits[2 * index]) << 4) | nibble(digits[2 * index + 1]);
        index += 1;
    }
    bytes
}

/// Empty subtree hashes, indexed by height (zero is an empty leaf).
#[must_use]
pub const fn empty_history_hashes() -> [Hash; HISTORY_DEPTH + 1] {
    EMPTY_HISTORY_HASHES
}

/// Bind the append position to the tree commitment.
#[must_use]
pub fn counted_history_root(count: u64, root: Hash) -> Hash {
    let mut bytes = [0; 56];
    bytes[..16].copy_from_slice(&DOMAIN_HISTORY_ROOT);
    bytes[16..24].copy_from_slice(&count.to_le_bytes());
    bytes[24..].copy_from_slice(&root);
    blake3_256(&bytes)
}

/// Canonical genesis historical commitment.
#[must_use]
pub const fn empty_history_root() -> Hash {
    EMPTY_HISTORY_ROOT
}

/// Root of a complete aligned subtree of the History tree: all `2^level`
/// positions from `start` are occupied, so its root never changes again.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistorySubtree {
    /// Height above the leaves; 0 is a single leaf.
    pub level: u8,
    /// First position, a multiple of `2^level`.
    pub start: u64,
    /// Subtree root.
    pub root: Hash,
}

/// Whether the aligned subtree at `level` from `start` is fully occupied.
fn subtree_complete(level: usize, start: u64, count: u64) -> bool {
    u128::from(start) + (1_u128 << level) <= u128::from(count)
}

/// A tree level below [`HISTORY_DEPTH`] as its one-byte encoding.
fn level_byte(level: usize) -> u8 {
    u8::try_from(level).expect("history levels fit one byte")
}

/// Build the root of archived contexts. Runtime appends use a frontier instead.
#[must_use]
pub fn history_root(leaves: &[Hash]) -> Hash {
    HistoryFrontier::from_leaves(leaves)
        .and_then(|frontier| frontier.root())
        .expect("history length fits u64")
}
