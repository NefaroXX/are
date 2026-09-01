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
const DEFAULT_MAX_PAYLOAD: usize = 16 * 1024 * 1024;

/// Length prefix size in bytes.
const LEN_PREFIX_SIZE: usize = 4;

/// Write a length-prefixed JSON message to the writer.
///
/// # Arguments
///
/// * `writer` — Async writer (e.g., TLS stream).
/// * `payload` — JSON-serializable payload.
///
/// # Errors
///
/// Returns an error if serialization or I/O fails.
pub async fn write_message<W: AsyncWrite + Unpin, T: serde::Serialize>(
    writer: &mut W,
    payload: &T,
) -> Result<(), std::io::Error> {
    let json = serde_json::to_vec(payload)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let len = u32::try_from(json.len()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "payload exceeds 4 GiB")
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
}
