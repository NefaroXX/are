//! Length-prefixed JSON framing for the wire protocol.
//!
//! Each message is framed as:
//!
//! ```text
//! [u32 BE length][JSON payload bytes]
//! ```
//!
//! The length prefix is a big-endian 32-bit unsigned integer indicating the
//! byte length of the JSON payload that follows. Maximum payload size is
//! 16 MiB (configurable) to prevent memory exhaustion from malicious
//! payloads.
//!
//! ## Why not HTTP/2?
//!
//! HTTP/2 adds framing complexity (HPACK, stream management, SETTINGS
//! negotiation) without benefit for Gate 3's single-request-per-connection
//! model. This is a deliberate deferral to Gate 14 (protocol stabilization)
//! per PLAN.md Rule 5. The length-prefixed format is simple, debuggable,
//! and sufficient for authenticated RPC over a TLS tunnel.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Default maximum payload size: 16 MiB.
///
/// Reused as the daemon send-side response-size guard (see
/// [`write_message_sized`]): a single constant bounds both directions so
/// the client read cap and the daemon write guard can never disagree.
pub const DEFAULT_MAX_PAYLOAD: usize = 16 * 1024 * 1024;

/// Length prefix size in bytes.
const LEN_PREFIX_SIZE: usize = 4;

/// Error from [`write_message`] / [`write_message_sized`].
#[derive(Debug, thiserror::Error)]
pub enum FramingError {
    /// The serialized payload exceeds the transmit limit. Nothing was
    /// written: the caller must send a small replacement error instead.
    /// Carries the serialized `size` and the `max` it was checked against.
    #[error("response too large to transmit: {size} bytes exceeds {max} bytes")]
    ResponseTooLarge { size: usize, max: usize },

    /// JSON serialization failed.
    #[error("serialization failed: {0}")]
    Serialization(String),

    /// Underlying I/O error while writing the frame.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Write a length-prefixed JSON message to the writer.
///
/// The payload is serialized FIRST and its serialized length is checked
/// against [`DEFAULT_MAX_PAYLOAD`] before anything is written. Oversized
/// payloads return [`FramingError::ResponseTooLarge`] with nothing sent —
/// see [`write_message_sized`] for the rationale.
///
/// # Arguments
///
/// * `writer` — Async writer (e.g., TLS stream).
/// * `payload` — JSON-serializable payload.
///
/// # Errors
///
/// Returns [`FramingError::Serialization`] if serialization fails,
/// [`FramingError::ResponseTooLarge`] if the serialized form exceeds the
/// limit (nothing written), or [`FramingError::Io`] if I/O fails.
pub async fn write_message<W: AsyncWrite + Unpin, T: serde::Serialize>(
    writer: &mut W,
    payload: &T,
) -> Result<(), FramingError> {
    write_message_sized(writer, payload, DEFAULT_MAX_PAYLOAD).await
}

/// Write a length-prefixed JSON message with an explicit size limit.
///
/// This is the same as [`write_message`] but with a caller-supplied `max`.
/// The production path passes [`DEFAULT_MAX_PAYLOAD`]; tests pass a tiny
/// `max` to exercise the guard without allocating megabytes.
///
/// ## Response-size guard (FIX 11)
///
/// `Vec<u8>` fields (file bytes, captured stdout/stderr) serialize as a
/// JSON array-of-numbers, so each payload byte costs up to ~4 wire bytes
/// (`"255,"`). A `ReadFile` of a ~5 MiB file or a `WaitProcess` with two
/// full 8 MiB output streams therefore serializes to MORE than the 16 MiB
/// framing limit even though the in-memory caps (16 MiB file cap, 8 MiB per
/// stream output caps) hold. Caps alone bound daemon memory; they do NOT
/// bound the wire. Without this check the daemon would serialize and flush
/// a ~30 MB frame that the client's read cap then rejects with an obscure
/// framing error (observed live: `payload size 29950309 exceeds maximum
/// 16777216`).
///
/// The guard serializes first, compares `json.len()` against `max`, and on
/// excess returns [`FramingError::ResponseTooLarge`] WITHOUT writing a
/// single byte. The server loop maps that to a SMALL replacement
/// `RpcError::InternalError` ("response too large to transmit…"), which
/// always fits — so oversized responses surface as clean RPC errors, never
/// as doomed megabytes plus a client framing failure.
///
/// Efficient binary encoding (base64/`bytes`, streaming/chunked reads) is
/// deliberately deferred to Gate 14 protocol work; this guard is the
/// honest backstop until then. No public types change here.
///
/// # Errors
///
/// Same as [`write_message`].
pub async fn write_message_sized<W: AsyncWrite + Unpin, T: serde::Serialize>(
    writer: &mut W,
    payload: &T,
    max_payload: usize,
) -> Result<(), FramingError> {
    let json =
        serde_json::to_vec(payload).map_err(|e| FramingError::Serialization(e.to_string()))?;

    if json.len() > max_payload {
        return Err(FramingError::ResponseTooLarge {
            size: json.len(),
            max: max_payload,
        });
    }

    let len = u32::try_from(json.len()).map_err(|_| {
        FramingError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "payload exceeds 4 GiB",
        ))
    })?;

    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&json).await?;
    writer.flush().await?;
    Ok(())
}

/// Read a length-prefixed JSON message from the reader.
///
/// # Arguments
///
/// * `reader` — Async reader (e.g., TLS stream).
///
/// # Returns
///
/// The deserialized payload, or an error if the frame is invalid, too
/// large, or deserialization fails.
pub async fn read_message<R: AsyncRead + Unpin, T: serde::de::DeserializeOwned>(
    reader: &mut R,
) -> Result<T, std::io::Error> {
    read_message_sized(reader, DEFAULT_MAX_PAYLOAD).await
}

/// Read a length-prefixed JSON message with an explicit size limit.
pub async fn read_message_sized<R: AsyncRead + Unpin, T: serde::de::DeserializeOwned>(
    reader: &mut R,
    max_payload: usize,
) -> Result<T, std::io::Error> {
    let mut len_buf = [0u8; LEN_PREFIX_SIZE];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > max_payload {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("payload size {len} exceeds maximum {max_payload}"),
        ));
    }

    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;

    serde_json::from_slice(&buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq)]
    struct TestMsg {
        id: u32,
        text: String,
    }

    /// Helper: creates a connected pair of (writer, reader) halves.
    fn duplex_pair() -> (
        tokio::io::BufWriter<tokio::io::DuplexStream>,
        tokio::io::BufReader<tokio::io::DuplexStream>,
    ) {
        let (writer, reader) = tokio::io::duplex(1024);
        (
            tokio::io::BufWriter::new(writer),
            tokio::io::BufReader::new(reader),
        )
    }

    #[tokio::test]
    async fn roundtrip_valid_message() {
        let (mut client, mut server) = duplex_pair();

        let msg = TestMsg {
            id: 1,
            text: "hello".into(),
        };
        write_message(&mut client, &msg).await.unwrap();

        let got: TestMsg = read_message(&mut server).await.unwrap();
        assert_eq!(got, msg);
    }

    #[tokio::test]
    async fn roundtrip_multiple_messages() {
        let (mut client, mut server) = duplex_pair();

        for i in 0..10 {
            let msg = TestMsg {
                id: i,
                text: format!("msg-{i}"),
            };
            write_message(&mut client, &msg).await.unwrap();
        }

        for i in 0..10 {
            let got: TestMsg = read_message(&mut server).await.unwrap();
            assert_eq!(got.id, i);
            assert_eq!(got.text, format!("msg-{i}"));
        }
    }

    #[tokio::test]
    async fn rejects_payload_exceeding_max_size() {
        let (mut client, mut server) = duplex_pair();

        let msg = TestMsg {
            id: 1,
            text: "hello".into(),
        };
        write_message(&mut client, &msg).await.unwrap();

        // Try to read with a tiny max — should fail
        let result: Result<TestMsg, _> = read_message_sized(&mut server, 2).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn rejects_invalid_json() {
        let (mut client, mut server) = duplex_pair();

        let bad = b"not json";
        let len = (bad.len() as u32).to_be_bytes();
        client.write_all(&len).await.unwrap();
        client.write_all(bad).await.unwrap();
        client.flush().await.unwrap();

        let result: Result<TestMsg, _> = read_message(&mut server).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn write_sized_rejects_oversize_without_writing() {
        let (mut client, mut server) = duplex_pair();

        // Serialized form (~30+ bytes) exceeds the tiny 8-byte limit.
        let msg = TestMsg {
            id: 1,
            text: "this text is far too long for eight bytes".into(),
        };
        let err = write_message_sized(&mut client, &msg, 8).await.unwrap_err();
        let (size, max) = match err {
            FramingError::ResponseTooLarge { size, max } => (size, max),
            other => panic!("expected ResponseTooLarge, got {other:?}"),
        };
        assert!(size > 8);
        assert_eq!(max, 8);
        drop(client);

        // Nothing was written: the peer sees EOF (empty read), not a frame.
        let mut buf = [0u8; 1];
        let n = server.read(&mut buf).await.unwrap();
        assert_eq!(n, 0, "guard must write nothing on oversize");
    }

    #[tokio::test]
    async fn write_sized_accepts_payload_within_limit() {
        let (mut client, mut server) = duplex_pair();

        let msg = TestMsg {
            id: 7,
            text: "hi".into(),
        };
        let json_len = serde_json::to_vec(&msg).unwrap().len();
        write_message_sized(&mut client, &msg, json_len)
            .await
            .unwrap();

        let got: TestMsg = read_message(&mut server).await.unwrap();
        assert_eq!(got, msg);
    }
}
