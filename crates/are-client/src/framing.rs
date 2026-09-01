//! Length-prefixed JSON framing for the client wire protocol.
//!
//! Mirrors `are-daemon/src/framing.rs`. Each message is framed as:
//!
//! ```text
//! [u32 BE length][JSON payload bytes]
//! ```
//!
//! This is intentionally a separate module (not shared via are-core) to
//! maintain the constraint that are-core has zero I/O dependencies. The
//! two implementations must remain wire-compatible — this is verified by
//! the integration tests in Gate 3.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Default maximum payload size: 16 MiB.
const DEFAULT_MAX_PAYLOAD: usize = 16 * 1024 * 1024;

/// Write a length-prefixed JSON message to the writer.
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
    let mut len_buf = [0u8; 4];
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
