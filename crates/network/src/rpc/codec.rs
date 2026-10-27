//! Length-framed Borsh codec and the per-protocol codec/behaviour aliases.

use super::{
    BftRoundByChunkRequest, BftRoundByChunkResponse, BlocksByRangeRequest, BlocksByRangeResponse,
    CandidateByChunkRequest, CandidateByChunkResponse, ChunkProofByIdRequest,
    ChunkProofByIdResponse, DEFAULT_MAX_REQUEST_SIZE, DEFAULT_MAX_RESPONSE_SIZE,
    FinalityCertByChunkRequest, FinalityCertByChunkResponse, HistoryProofRequest,
    HistoryProofResponse, Metadata, MetadataRequest, PingPayload, ReceiptsByHashRequest,
    ReceiptsByHashResponse, RpcResult, SignedArtifactByIdRequest, SignedArtifactByIdResponse,
    SignedArtifactInventoryByChunkRequest, SignedArtifactInventoryByChunkResponse,
    StateByRootRequest, StateByRootResponse, Status, WitnessByBlockRequest, WitnessByBlockResponse,
};
use borsh::{BorshDeserialize, BorshSerialize};
use core::marker::PhantomData;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{StreamProtocol, request_response};
use std::{io, time::Duration};

/// Generic borsh request/response codec.
///
/// One instance is parameterized per protocol via the (`Req`, `Resp`) type pair.
/// The implementation mirrors the canonical libp2p `cbor::codec::Codec`: it
/// reads up to `request_size_maximum` (or `response_size_maximum`) bytes,
/// then borsh-deserializes. Encoding writes the full borsh payload in one
/// `write_all` call.
pub struct BorshCodec<Req, Resp> {
    request_size_maximum: u64,
    response_size_maximum: u64,
    phantom: PhantomData<(Req, Resp)>,
    request_read_budget: std::sync::Arc<tokio::sync::Semaphore>,
    response_read_budget: std::sync::Arc<tokio::sync::Semaphore>,
}

impl<Req, Resp> Default for BorshCodec<Req, Resp> {
    fn default() -> Self {
        Self {
            request_size_maximum: DEFAULT_MAX_REQUEST_SIZE,
            response_size_maximum: DEFAULT_MAX_RESPONSE_SIZE,
            phantom: PhantomData,
            request_read_budget: std::sync::Arc::new(tokio::sync::Semaphore::new(4)),
            response_read_budget: std::sync::Arc::new(tokio::sync::Semaphore::new(4)),
        }
    }
}

impl<Req, Resp> Clone for BorshCodec<Req, Resp> {
    fn clone(&self) -> Self {
        Self {
            request_size_maximum: self.request_size_maximum,
            response_size_maximum: self.response_size_maximum,
            phantom: PhantomData,
            request_read_budget: std::sync::Arc::clone(&self.request_read_budget),
            response_read_budget: std::sync::Arc::clone(&self.response_read_budget),
        }
    }
}

impl<Req, Resp> BorshCodec<Req, Resp> {
    pub(crate) fn with_read_budgets(
        mut self,
        requests: std::sync::Arc<tokio::sync::Semaphore>,
        responses: std::sync::Arc<tokio::sync::Semaphore>,
    ) -> Self {
        self.request_read_budget = requests;
        self.response_read_budget = responses;
        self
    }

    /// Override the maximum request payload size in bytes.
    #[must_use]
    pub const fn with_request_size_maximum(mut self, max: u64) -> Self {
        self.request_size_maximum = max;
        self
    }

    /// Override the maximum response payload size in bytes.
    #[must_use]
    pub const fn with_response_size_maximum(mut self, max: u64) -> Self {
        self.response_size_maximum = max;
        self
    }
}

/// Longest an inbound request may take to arrive, reader wait included.
///
/// Requests are small; an idle or trickling stream is dropped long before
/// the response timeout instead of holding a reader that whole time.
pub const REQUEST_READ_DEADLINE: Duration = Duration::from_secs(5);

/// Frames up to this size are read without the shared reader budget. Every
/// honest request and most responses are this small, so a peer trickling
/// bytes into many streams holds nothing they need.
pub const UNBUDGETED_FRAME_BYTES: u32 = 64 * 1024;

/// Longest a larger frame waits for the shared reader budget. Running out of
/// it is local overload (`WouldBlock`), never the peer's fault.
pub const BUDGET_WAIT: Duration = Duration::from_secs(2);

/// Read one frame: a little-endian `u32` length, then exactly that many
/// Borsh bytes, at most `maximum`. Only a frame above
/// [`UNBUDGETED_FRAME_BYTES`] takes the reader budget, once its length has
/// arrived. A stream that ends before the length is no frame
/// (`UnexpectedEof`), never invalid data: a provider that refused or failed
/// sends nothing.
async fn read_frame<T, Payload>(
    io: &mut T,
    maximum: u64,
    budget: &tokio::sync::Semaphore,
) -> io::Result<Payload>
where
    T: AsyncRead + Unpin + Send,
    Payload: BorshDeserialize,
{
    let mut prefix = [0_u8; 4];
    io.read_exact(&mut prefix).await?;
    let length = u32::from_le_bytes(prefix);
    if u64::from(length) > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "RPC payload exceeds byte limit",
        ));
    }
    let _permit = if length > UNBUDGETED_FRAME_BYTES {
        Some(
            tokio::time::timeout(BUDGET_WAIT, budget.acquire())
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "RPC reader budget busy"))?
                .map_err(|_| io::Error::other("RPC reader budget closed"))?,
        )
    } else {
        None
    };
    // Grow with the bytes that actually arrive, never from the declared length.
    let mut bytes = Vec::new();
    io.take(u64::from(length)).read_to_end(&mut bytes).await?;
    if bytes.len() != usize::try_from(length).map_err(io::Error::other)? {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    Payload::try_from_slice(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))
}

/// Write one frame (length, then payload) without closing the stream.
async fn write_frame<T, Payload>(io: &mut T, payload: Payload, maximum: u64) -> io::Result<()>
where
    T: AsyncWrite + Unpin + Send,
    Payload: BorshSerialize + Send,
{
    let length = borsh::object_length(&payload)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
    let length = u32::try_from(length)
        .ok()
        .filter(|length| u64::from(*length) <= maximum)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "RPC payload exceeds byte limit")
        })?;
    let bytes = borsh::to_vec(&payload)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
    io.write_all(&length.to_le_bytes()).await?;
    io.write_all(&bytes).await?;
    Ok(())
}

impl<Req, Resp> request_response::Codec for BorshCodec<Req, Resp>
where
    Req: BorshSerialize + BorshDeserialize + Send + 'static,
    Resp: BorshSerialize + BorshDeserialize + Send + 'static,
{
    type Protocol = StreamProtocol;
    type Request = Req;
    type Response = Resp;

    async fn read_request<T>(&mut self, _: &StreamProtocol, io: &mut T) -> io::Result<Req>
    where
        T: AsyncRead + Unpin + Send,
    {
        tokio::time::timeout(
            REQUEST_READ_DEADLINE,
            read_frame(io, self.request_size_maximum, &self.request_read_budget),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "RPC request read deadline"))?
    }

    async fn read_response<T>(&mut self, _: &StreamProtocol, io: &mut T) -> io::Result<Resp>
    where
        T: AsyncRead + Unpin + Send,
    {
        // The protocol's request timeout bounds the whole exchange.
        read_frame(io, self.response_size_maximum, &self.response_read_budget).await
    }

    async fn write_request<T>(&mut self, _: &StreamProtocol, io: &mut T, req: Req) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_frame(io, req, self.request_size_maximum).await
    }

    async fn write_response<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        resp: Resp,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_frame(io, resp, self.response_size_maximum).await
    }
}

// --- Per-protocol type aliases ------------------------------------------------

/// Codec for the Status RPC.
pub type StatusCodec = BorshCodec<Status, RpcResult<Status>>;
/// Codec for the Metadata RPC.
pub type MetadataCodec = BorshCodec<MetadataRequest, RpcResult<Metadata>>;
/// Codec for the Ping RPC.
pub type PingCodec = BorshCodec<PingPayload, RpcResult<PingPayload>>;
/// Codec for the `BlocksByRange` RPC.
pub type BlocksByRangeCodec = BorshCodec<BlocksByRangeRequest, RpcResult<BlocksByRangeResponse>>;
/// Codec for the `StateByRoot` RPC.
pub type StateByRootCodec = BorshCodec<StateByRootRequest, RpcResult<StateByRootResponse>>;
/// Codec for the `ChunkProofById` RPC.
pub type ChunkProofByIdCodec = BorshCodec<ChunkProofByIdRequest, RpcResult<ChunkProofByIdResponse>>;
/// Codec for the `HistoryProof` RPC.
pub type HistoryProofCodec = BorshCodec<HistoryProofRequest, RpcResult<HistoryProofResponse>>;
/// Codec for the `FinalityCertByChunk` RPC.
pub type FinalityCertByChunkCodec =
    BorshCodec<FinalityCertByChunkRequest, RpcResult<FinalityCertByChunkResponse>>;
/// Codec for the `WitnessByBlock` RPC.
pub type WitnessByBlockCodec = BorshCodec<WitnessByBlockRequest, RpcResult<WitnessByBlockResponse>>;
/// Codec for the `ReceiptsByHash` RPC.
pub type ReceiptsByHashCodec = BorshCodec<ReceiptsByHashRequest, RpcResult<ReceiptsByHashResponse>>;

/// Behaviour type for the Status RPC.
pub type StatusBehaviour = request_response::Behaviour<StatusCodec>;
/// Behaviour type for the Metadata RPC.
pub type MetadataBehaviour = request_response::Behaviour<MetadataCodec>;
/// Behaviour type for the Ping RPC.
pub type PingBehaviour = request_response::Behaviour<PingCodec>;
/// Behaviour type for the `BlocksByRange` RPC.
pub type BlocksByRangeBehaviour = request_response::Behaviour<BlocksByRangeCodec>;
/// Behaviour type for the `StateByRoot` RPC.
pub type StateByRootBehaviour = request_response::Behaviour<StateByRootCodec>;
/// Behaviour type for the `ChunkProofById` RPC.
pub type ChunkProofByIdBehaviour = request_response::Behaviour<ChunkProofByIdCodec>;
/// Behaviour type for the `HistoryProof` RPC.
pub type HistoryProofBehaviour = request_response::Behaviour<HistoryProofCodec>;
/// Behaviour type for the `FinalityCertByChunk` RPC.
pub type FinalityCertByChunkBehaviour = request_response::Behaviour<FinalityCertByChunkCodec>;
/// Behaviour type for the `WitnessByBlock` RPC.
pub type WitnessByBlockBehaviour = request_response::Behaviour<WitnessByBlockCodec>;
/// Behaviour type for the `ReceiptsByHash` RPC.
pub type ReceiptsByHashBehaviour = request_response::Behaviour<ReceiptsByHashCodec>;

/// Codec for bounded candidate discovery.
pub type CandidateByChunkCodec =
    BorshCodec<CandidateByChunkRequest, RpcResult<CandidateByChunkResponse>>;
/// SignedArtifactById bounded codec.
pub type SignedArtifactByIdCodec =
    BorshCodec<SignedArtifactByIdRequest, RpcResult<SignedArtifactByIdResponse>>;
/// SignedArtifactById request/response behaviour.
pub type SignedArtifactByIdBehaviour = request_response::Behaviour<SignedArtifactByIdCodec>;
/// SignedArtifactInventoryByChunk bounded codec.
pub type SignedArtifactInventoryByChunkCodec = BorshCodec<
    SignedArtifactInventoryByChunkRequest,
    RpcResult<SignedArtifactInventoryByChunkResponse>,
>;
/// SignedArtifactInventoryByChunk request/response behaviour.
pub type SignedArtifactInventoryByChunkBehaviour =
    request_response::Behaviour<SignedArtifactInventoryByChunkCodec>;
/// BftRoundByChunk bounded codec.
pub type BftRoundByChunkCodec =
    BorshCodec<BftRoundByChunkRequest, RpcResult<BftRoundByChunkResponse>>;
/// BftRoundByChunk request/response behaviour.
pub type BftRoundByChunkBehaviour = request_response::Behaviour<BftRoundByChunkCodec>;

/// Candidate request/response behaviour.
pub type CandidateByChunkBehaviour = request_response::Behaviour<CandidateByChunkCodec>;
