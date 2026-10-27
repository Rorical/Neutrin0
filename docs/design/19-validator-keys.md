# Validator keys

A validator's BLS key signs block headers, VRF proofs, finality votes and their
attestations, nil votes, round-leader proposals and round changes. A second
signature on a conflicting message forfeits the validator's whole slashable
balance ([evidence proofs](16-evidence-proofs.md)), so the key needs protection
at rest, protection from being used twice and a way to keep it apart from the
node. Keys are min-pk BLS12-381 keys; every seated key carries a verified
registration proof of possession ([consensus](09-consensus.md)).

## Key sources

A validator node takes its key from exactly one source and refuses to start
with more than one:

| Source | Configuration |
| --- | --- |
| remote signer | `[remote_signer]`: a `neutrin0-signer` process holds the key |
| encrypted keystore | `proposer_keystore_path`, an EIP-2335 keystore decrypted at startup with the password from `NEUTRIN0_KEYSTORE_PASSWORD` or the owner-only file `proposer_keystore_password_path` |
| IKM | exactly one of `NEUTRIN0_PROPOSER_IKM_HEX`, the owner-only file `proposer_ikm_path` or, for tests, `proposer_ikm_hex` |

A node given two IKM sources refuses to start rather than let a stale one
replace the other. Key and password files must be regular files no other user
can read; surrounding whitespace is not part of their content.

Whatever the source, the engine signs every production message through one typed
`SignRequest`:

| Request | Signs |
| --- | --- |
| `Header` | a block header, over its hash |
| `Vrf { seed, slot }` | the proposer VRF of a slot under the finalized seed |
| `Vote` | a value vote, then the attestation that carries its signature |
| `NilVote` | a nil vote, then its attestation |
| `Proposal` | a round leader's proposal |
| `RoundChange` | a round change |

`SignRequest::sign_with` fixes the messages and their order. The engine's
signing journal (`crates/consensus-engine/src/signing.rs`) reserves each request
durably before asking for the signature, whichever source holds the key.

## Encrypted keystores

`neutrin0-keystore` reads and writes EIP-2335 version 4 keystores: the 32-byte
big-endian secret key encrypted with AES-128-CTR under a scrypt-derived key
(`n = 2^18`, `r = 8`, `p = 1` when written), with a SHA-256 checksum over the
second half of the derived key and the ciphertext that refuses a wrong password
before anything is decrypted. Passwords are NFKD-normalised and stripped of C0,
C1 and delete control codes as EIP-2335 requires, so keystores move freely
between this and other EIP-2335 tools. Opening refuses another version or
function, scrypt parameters that would need more than 1 GiB or `p > 16`, and a
secret that does not match the public key the file names.

`neutrin0-cli keygen --keystore-password-file <file>` writes
`<name>.keystore.json` instead of `<name>.ikm`; `neutrin0-cli keys encrypt`
converts an existing IKM file; `neutrin0-cli keys inspect --keystore <file>`
prints a keystore's public key without its password.

## Remote signer

`neutrin0-signer --config <file>` holds one chain's keys, decrypted from
keystores at startup, and its own slashing-protection journal in a RocksDB
directory. Nodes reach it over a Unix socket or over TCP with mutually
authenticated TLS (rustls with the ring provider, TLS 1.2 and 1.3).

The socket's directory must belong to the signer's user and be closed to everyone
else (mode 700), so no other user can reach the socket even before its own mode
is narrowed to 600; a connection on the socket may use every key the signer
holds. Over TLS the signer accepts only client certificates its configured
authority issued and that `[[tcp.clients]]` lists by the SHA-256 of their DER,
each with the keys it may use. A listed node sees and signs with only its own
keys, so one compromised node cannot sign, even conflict-free, for another
validator served by the same signer. The node accepts only a signer certificate
from its configured authority under the configured `server_name`.

| Bound | Value |
| --- | --- |
| concurrent TLS handshakes | 16, each with a 10-second deadline |
| served connections per listener | 64 |
| idle connection | closed after five minutes |
| frame | little-endian `u32` length, at most 16 MiB |
| node request deadline | 5 seconds, connection included |
| node backoff after a failure | 10 seconds without contacting the signer |

A frame carries a borsh `Request` (`Identities`, or `Sign { identity, request }`)
and the answer is `Identities`, `Signatures` (in `sign_with` order) or
`Refused(reason)`. The node sends one request at a time per connection,
reconnects once when a connection broke, and the signer signs an exactly repeated
request again. Signing runs under the engine lock, so the backoff costs that lock
one timed-out attempt per period instead of one per signature.

The signer is configured with the chain ID and specification hash and builds
every message under that domain, so it never signs for another chain. The node
verifies each returned signature against its own domain and the key's public key
before using it, so a signer configured for another chain, or one answering
wrongly, gets nothing published.

### Signer journal

Before signing, the signer reserves the request durably and refuses one that
could form an offence with a message it already signed for that key:

- a header at a slot below the last signed one, or another header at that slot;
- a vote (value or nil) at a chunk, round and step that already holds another;
- a proposal or round change at a chunk and round that already holds another;
- anything at a round below the highest round signed in that chunk;
- a prevote for another value than the one last precommitted in the chunk,
  unless its attestation carries a quorum for the new value from a round strictly
  between the lock's round and its own;
- a precommit whose attestation does not carry a quorum of its own round for its
  own value.

Quorums are checked by shape only, since the signer holds no validator sets; the
node verifies their signatures before asking. VRF requests are signed freely: a
second evaluation yields the same proof and no offence exists. The journal keeps
positions for the 64 chunks below the highest chunk the key signed in and refuses
anything older. Slots and chunks advance at most one a second, so it also refuses
a header slot more than 600 slots, or a chunk more than 64 chunks, beyond the
highest one signed plus the seconds elapsed since; one far-future request cannot
move the window past every real chunk. This journal is independent of the node's
journal and also stops two nodes that mistakenly share one signer key from both
signing.

## Doppelganger protection

Another process signing with the same key would sooner or later sign a message
that conflicts with one this node signed. Both see each other's messages on
gossip, so a validator defends in two ways (`[doppelganger]`):

- After it starts it signs nothing (no vote, nil vote, proposal, round change,
  header or VRF) for `quiet_chunks` chunks of slots, default 2; 0 disables the
  wait, as a single-validator devnet needs. A running twin shows itself in that
  time, before this node can conflict with it.
- At all times each authenticated message signed by a local key (individual
  votes, nil votes, round-leader proposals, round changes and headers, as the
  slashing monitor observes them) is compared with the signing journal. The
  journal reserves everything this node signs before signing it, so a message at
  a position the journal holds with other content, or at a round or slot beyond
  anything it signed, came from another signer. Positions the journal no longer
  holds (compacted earlier rounds, finalized chunks, slots before its last
  header) tell nothing and are skipped.

A foreign message pauses signing and production durably, exactly as
`neutrin0-cli validator pause-signing` and `pause-production` would, so the pause
survives restarts until the operator has stopped the other instance and resumes
both. Resuming clears the detection, so a later foreign message pauses the node
again. The node logs the message once, `neutrin0-cli node control-status`
reports it with the end of the quiet period, and `neutrin0_doppelganger_detected`
drives the critical `Neutrin0Doppelganger` alert.

## Key rotation

A validator replaces its consensus key without exiting. The account that owns
the seat calls `rotateKey(bytes blsPublicKey, bytes proofOfPossession)` on the
staking interface (`SystemAction::RotateKey`; `neutrin0-cli validator
rotate-key`). The runtime refuses:

- an account without stake, or whose seat is exiting;
- an account whose registered key carries a safety tombstone;
- a key with a safety tombstone, a key seated or carried by any candidate;
- a proof of possession not bound to the account's address;
- a second rotation while the account's seat still holds another key than its
  registration (the previous rotation is not seated yet).

It then stores the new key in the registration, keeping the registration's
height (a genesis validator, which has none, gets one dated at genesis), and in
the candidate entry.

At the next chunk boundary the validator-set transition, natively and in the
Chunk Guest, gives each seat whose candidate entry carries a different key that
key, when its registration proof binds the seat's address and no seat holds the
key already; stake, weight, activation and position stay. A leaving seat keeps
its key. Chunks up to the boundary are signed with the old key and later ones
with the new key, each under that chunk's validator list, so historical records,
evidence and reporter retention attribute every signature to the key that made
it.

The old key stays accountable: an offence names the address it was seated under,
and the sanction deducts from that address's slashable balance whatever key is
registered there now. Rotation cannot shelter a seat from a safety offence
either. The admission returns the address's registration to the offending, now
tombstoned key (keeping the rotated key's unused proof), so the address can
neither bond, rotate nor be projected again, exactly as if it had never rotated,
and drops its candidate entry. The identity-sanction transition, natively and in
the Chunk Guest, removes every seat and candidate at the offender's address along
with the banned key, so the seat leaves at the next boundary whatever key it then
holds. The tombstone itself bans only the offending key.

The node holds the next key beside the current one:
`proposer_next_keystore_path` (same password as `proposer_keystore_path`, which
it requires) or `[remote_signer] next_public_key_hex` (a key the signer must hold
too). When a validator-set transition seats it in place of the current key, the
two swap: votes, proposals and blocks follow the seat's key, each key under its
own signing journal, and doppelganger detection watches both. A validator with an
IKM key restarts with the new key after the boundary.
