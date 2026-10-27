//! Behavioral contracts for the Borsh request/response transport.

use super::*;
use borsh::{BorshDeserialize, BorshSerialize};
use futures::{AsyncRead, AsyncWrite, AsyncWriteExt};
use libp2p::request_response::Codec;
use std::io;
use tokio::io::DuplexStream;
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};

/// An in-memory stream pair buffering at most `capacity` bytes per direction.
fn pipe(capacity: usize) -> (Compat<DuplexStream>, Compat<DuplexStream>) {
    let (a, b) = tokio::io::duplex(capacity);
    (a.compat(), b.compat())
}

/// A length prefix then `payload`, as `write_frame` sends it.
fn frame(payload: &[u8]) -> Vec<u8> {
    let mut bytes = u32::try_from(payload.len()).unwrap().to_le_bytes().to_vec();
    bytes.extend_from_slice(payload);
    bytes
}

#[tokio::test]
async fn oversized_frames_fail_before_allocation_in_either_direction() {
    let protocol = RpcProtocol::Ping.stream_protocol();
    let mut codec = BorshCodec::<u16, u16>::default().with_request_size_maximum(1);
    let mut writer = RecordingWriter::default();
    assert!(
        codec
            .write_request(&protocol, &mut writer, 123)
            .await
            .is_err()
    );
    assert_eq!(writer.bytes, Vec::<u8>::new());
    // A declared length above the cap is refused after only the prefix.
    let mut reader = futures::io::Cursor::new(frame(&[1, 0]));
    assert_eq!(
        codec
            .read_request(&protocol, &mut reader)
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(reader.position(), 4);
    codec = codec.with_request_size_maximum(2);
    let mut reader = futures::io::Cursor::new(frame(&[1, 0]));
    assert_eq!(codec.read_request(&protocol, &mut reader).await.unwrap(), 1);
}

#[tokio::test(start_paused = true)]
async fn idle_and_trickling_request_streams_cannot_hold_readers() {
    let protocol = RpcProtocol::Ping.stream_protocol();
    let budget = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
    let codec = BorshCodec::<u16, u16>::default().with_read_budgets(budget.clone(), budget.clone());
    // A stream that never sends its length takes no reader while it waits.
    let (_idle_peer, mut idle) = pipe(64);
    let mut stalled = codec.clone();
    let stalled_protocol = protocol.clone();
    let idle_read =
        tokio::spawn(async move { stalled.read_request(&stalled_protocol, &mut idle).await });
    tokio::task::yield_now().await;
    assert_eq!(budget.available_permits(), 1);
    let mut ready = futures::io::Cursor::new(frame(&[7, 0]));
    assert_eq!(
        codec
            .clone()
            .read_request(&protocol, &mut ready)
            .await
            .unwrap(),
        7
    );
    // A small frame that trickles holds no reader at all.
    let (mut small_peer, mut small) = pipe(64);
    small_peer.write_all(&2_u32.to_le_bytes()).await.unwrap();
    let mut small_codec = codec.clone();
    let small_protocol = protocol.clone();
    let small_read =
        tokio::spawn(async move { small_codec.read_request(&small_protocol, &mut small).await });
    tokio::task::yield_now().await;
    assert_eq!(budget.available_permits(), 1);
    // A large one holds a reader only until the deadline, which also ends
    // the others.
    let (mut trickling_peer, mut trickling) = pipe(64);
    trickling_peer
        .write_all(&(UNBUDGETED_FRAME_BYTES + 1).to_le_bytes())
        .await
        .unwrap();
    let mut slow = codec.clone();
    let slow_protocol = protocol.clone();
    let slow_read =
        tokio::spawn(async move { slow.read_request(&slow_protocol, &mut trickling).await });
    tokio::task::yield_now().await;
    assert_eq!(budget.available_permits(), 0);
    tokio::time::advance(REQUEST_READ_DEADLINE).await;
    for read in [idle_read, small_read, slow_read] {
        assert_eq!(
            read.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }
    assert_eq!(budget.available_permits(), 1);
}

#[tokio::test]
async fn request_reader_exhaustion_never_blocks_response_decoding() {
    let requests = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
    let responses = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
    let _held = requests.try_acquire().unwrap();
    let protocol = RpcProtocol::Ping.stream_protocol();
    let mut codec =
        BorshCodec::<u16, u16>::default().with_read_budgets(requests.clone(), responses);
    let mut reply = futures::io::Cursor::new(frame(&[2, 0]));
    assert_eq!(codec.read_response(&protocol, &mut reply).await.unwrap(), 2);
}

#[tokio::test]
async fn a_stream_closed_without_a_frame_is_no_response_rather_than_invalid_data() {
    // A provider that refused or failed sends nothing; scoring must not count
    // that as malformed input from an honest peer.
    let protocol = RpcProtocol::Ping.stream_protocol();
    let mut codec = BorshCodec::<u16, u16>::default();
    let mut empty = futures::io::Cursor::new(Vec::new());
    assert_eq!(
        codec
            .read_response(&protocol, &mut empty)
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::UnexpectedEof
    );
}

#[tokio::test]
async fn borsh_codec_round_trips_status() {
    let req = Status {
        chain_id: 9,
        chain_spec_hash: [8; 32],
        finalized_chunk_id: None,
        finalized_chunk_hash: [0; 32],
        checkpoint_hash: [3; 32],
        head_block_hash: [4; 32],
        head_slot: 1,
        head_height: 1,
    };
    let mut codec = StatusCodec::default();
    let protocol = RpcProtocol::Status.stream_protocol();

    let (mut a, mut b) = pipe(1024);
    codec
        .write_request(&protocol, &mut a, req)
        .await
        .expect("write request");
    a.close().await.unwrap();
    let decoded = codec
        .read_request(&protocol, &mut b)
        .await
        .expect("read request");
    assert_eq!(decoded, req);
}

#[tokio::test]
async fn borsh_codec_rejects_request_above_size_limit() {
    // Build a State request whose borsh size exceeds 100 bytes.
    let req = StateByRootRequest {
        state_root: [0; 32],
        items: neutrin0_consensus_types::bootstrap::StateItems::new(
            (0..16)
                .map(|_| neutrin0_consensus_types::bootstrap::StateItem::node([0; 32]))
                .collect(),
        )
        .unwrap(),
    };
    let mut codec = StateByRootCodec::default().with_request_size_maximum(100);
    let protocol = RpcProtocol::StateByRoot.stream_protocol();

    let (mut a, mut b) = pipe(2048);
    let mut writer = StateByRootCodec::default();
    writer.write_request(&protocol, &mut a, req).await.unwrap();
    a.close().await.unwrap();
    let result = codec.read_request(&protocol, &mut b).await;
    assert!(result.is_err(), "oversized request must fail to decode");
}

#[derive(Default)]
struct RecordingWriter {
    bytes: Vec<u8>,
    closed: bool,
    fail: bool,
}

impl AsyncWrite for RecordingWriter {
    fn poll_write(
        mut self: core::pin::Pin<&mut Self>,
        _: &mut core::task::Context<'_>,
        bytes: &[u8],
    ) -> core::task::Poll<io::Result<usize>> {
        if self.fail {
            return core::task::Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "write failed",
            )));
        }
        self.bytes.extend_from_slice(bytes);
        core::task::Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(
        self: core::pin::Pin<&mut Self>,
        _: &mut core::task::Context<'_>,
    ) -> core::task::Poll<io::Result<()>> {
        core::task::Poll::Ready(Ok(()))
    }

    fn poll_close(
        mut self: core::pin::Pin<&mut Self>,
        _: &mut core::task::Context<'_>,
    ) -> core::task::Poll<io::Result<()>> {
        self.closed = true;
        core::task::Poll::Ready(Ok(()))
    }
}

struct FailingReader;

impl AsyncRead for FailingReader {
    fn poll_read(
        self: core::pin::Pin<&mut Self>,
        _: &mut core::task::Context<'_>,
        _: &mut [u8],
    ) -> core::task::Poll<io::Result<usize>> {
        core::task::Poll::Ready(Err(io::Error::new(
            io::ErrorKind::ConnectionReset,
            "read failed",
        )))
    }
}

#[derive(BorshDeserialize)]
struct FailingPayload;

impl BorshSerialize for FailingPayload {
    fn serialize<W: borsh::io::Write>(&self, _: &mut W) -> borsh::io::Result<()> {
        Err(borsh::io::Error::new(
            borsh::io::ErrorKind::PermissionDenied,
            "serialization failed",
        ))
    }
}

// Cell is Send but not Sync: the public codec supports this payload shape.
struct SendOnlyPayload(core::cell::Cell<u8>);

impl BorshSerialize for SendOnlyPayload {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        self.0.get().serialize(writer)
    }
}

impl BorshDeserialize for SendOnlyPayload {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        u8::deserialize_reader(reader).map(|value| Self(core::cell::Cell::new(value)))
    }
}

fn assert_send<T: Send>(value: T) -> T {
    value
}

#[tokio::test]
async fn borsh_codec_writes_exact_bytes_without_closing_within_caps() {
    let protocol = RpcProtocol::Ping.stream_protocol();
    let mut codec = BorshCodec::<u16, u16>::default()
        .with_request_size_maximum(2)
        .with_response_size_maximum(2);
    let mut request = RecordingWriter::default();
    codec
        .write_request(&protocol, &mut request, 0x1234)
        .await
        .unwrap();
    assert_eq!(request.bytes, frame(&[0x34, 0x12]));
    assert!(!request.closed);

    let mut response = RecordingWriter::default();
    codec
        .write_response(&protocol, &mut response, 0x5678)
        .await
        .unwrap();
    assert_eq!(response.bytes, frame(&[0x78, 0x56]));
    assert!(!response.closed);
}

#[tokio::test]
async fn borsh_codec_read_caps_are_independent_and_accept_exact_size() {
    let protocol = RpcProtocol::Ping.stream_protocol();
    for (request_cap, response_cap, request_ok, response_ok) in
        [(2, 4, true, true), (1, 4, false, true), (2, 3, true, false)]
    {
        let mut codec = BorshCodec::<u16, u32>::default()
            .with_request_size_maximum(request_cap)
            .with_response_size_maximum(response_cap);
        let mut request = futures::io::Cursor::new(frame(&[0x34, 0x12]));
        let result = codec.read_request(&protocol, &mut request).await;
        if request_ok {
            assert_eq!(result.unwrap(), 0x1234);
        } else {
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        }
        let mut response = futures::io::Cursor::new(frame(&[0x78, 0x56, 0x34, 0x12]));
        let result = codec.read_response(&protocol, &mut response).await;
        if response_ok {
            assert_eq!(result.unwrap(), 0x1234_5678);
        } else {
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        }
    }
}

#[tokio::test]
async fn borsh_codec_rejects_trailing_truncated_and_oversized_frames() {
    let protocol = RpcProtocol::Ping.stream_protocol();
    let mut truncated = frame(&[0x34, 0x12]);
    truncated.pop();
    for (bytes, cap, outcome, consumed) in [
        (frame(&[0x34, 0x12]), 2, None, 6),
        // Declared above the cap: refused after the prefix.
        (
            frame(&[0x34, 0x12, 0xff]),
            2,
            Some(io::ErrorKind::InvalidData),
            4,
        ),
        // Within the cap, but the payload has a trailing byte.
        (
            frame(&[0x34, 0x12, 0xff]),
            3,
            Some(io::ErrorKind::InvalidData),
            7,
        ),
        (truncated, 2, Some(io::ErrorKind::UnexpectedEof), 5),
        (Vec::new(), 2, Some(io::ErrorKind::UnexpectedEof), 0),
    ] {
        let mut codec = BorshCodec::<u16, u16>::default()
            .with_request_size_maximum(cap)
            .with_response_size_maximum(cap);
        let mut request = futures::io::Cursor::new(bytes.clone());
        let result = codec.read_request(&protocol, &mut request).await;
        match outcome {
            None => assert_eq!(result.unwrap(), 0x1234),
            Some(kind) => assert_eq!(result.unwrap_err().kind(), kind),
        }
        assert_eq!(request.position(), consumed);

        let mut response = futures::io::Cursor::new(bytes);
        let result = codec.read_response(&protocol, &mut response).await;
        match outcome {
            None => assert_eq!(result.unwrap(), 0x1234),
            Some(kind) => assert_eq!(result.unwrap_err().kind(), kind),
        }
        assert_eq!(response.position(), consumed);
    }
}

#[tokio::test]
async fn borsh_codec_preserves_read_and_write_io_errors() {
    let protocol = RpcProtocol::Ping.stream_protocol();
    let mut codec = BorshCodec::<u16, u16>::default();
    let error = codec
        .read_request(&protocol, &mut FailingReader)
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
    assert_eq!(error.to_string(), "read failed");
    let error = codec
        .read_response(&protocol, &mut FailingReader)
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
    assert_eq!(error.to_string(), "read failed");

    let mut writer = RecordingWriter {
        fail: true,
        ..RecordingWriter::default()
    };
    let error = codec
        .write_request(&protocol, &mut writer, 1)
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    assert_eq!(error.to_string(), "write failed");
    let error = codec
        .write_response(&protocol, &mut writer, 1)
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    assert_eq!(error.to_string(), "write failed");
    assert!(!writer.closed);
}

#[tokio::test]
async fn borsh_codec_maps_serialization_errors_to_invalid_data() {
    let protocol = RpcProtocol::Ping.stream_protocol();
    let mut codec = BorshCodec::<FailingPayload, FailingPayload>::default();
    let mut writer = RecordingWriter::default();
    let error = codec
        .write_request(&protocol, &mut writer, FailingPayload)
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(error.to_string(), "serialization failed");
    let error = codec
        .write_response(&protocol, &mut writer, FailingPayload)
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(error.to_string(), "serialization failed");
    assert_eq!(writer.bytes, Vec::<u8>::new());
    assert!(!writer.closed);
}

#[tokio::test]
async fn borsh_codec_keeps_send_only_payloads_supported() {
    let protocol = RpcProtocol::Ping.stream_protocol();
    let mut codec = BorshCodec::<SendOnlyPayload, SendOnlyPayload>::default();
    let mut writer = RecordingWriter::default();
    assert_send(codec.write_request(
        &protocol,
        &mut writer,
        SendOnlyPayload(core::cell::Cell::new(7)),
    ))
    .await
    .unwrap();
    assert_send(codec.write_response(
        &protocol,
        &mut writer,
        SendOnlyPayload(core::cell::Cell::new(9)),
    ))
    .await
    .unwrap();
    assert_eq!(writer.bytes, [frame(&[7]), frame(&[9])].concat());

    let mut request = futures::io::Cursor::new(frame(&[7]));
    let decoded = assert_send(codec.read_request(&protocol, &mut request))
        .await
        .unwrap();
    assert_eq!(decoded.0.get(), 7);
    let mut response = futures::io::Cursor::new(frame(&[9]));
    let decoded = assert_send(codec.read_response(&protocol, &mut response))
        .await
        .unwrap();
    assert_eq!(decoded.0.get(), 9);
}
