//! Async byte-transport adapter for the shared local management protocol.

use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use pathchord_core::management::decode_length_prefix;
pub use pathchord_core::management::{
    Actor, ErrorBody, ErrorCode, GenerationExpectation, LOCAL_API_VERSION, LocalProtocolError,
    MAX_ENVELOPE_BYTES, RequestEnvelope, ResponseEnvelope, decode_object, encode_object,
};

/// Reads one framed JSON object from an async byte transport.
pub async fn read_object<R, T>(reader: &mut R) -> Result<T, LocalProtocolError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let (length, prefix) = read_prefix(reader).await?;
    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload).await?;
    let mut framed = Vec::with_capacity(prefix.len() + payload.len());
    framed.extend_from_slice(&prefix);
    framed.extend_from_slice(&payload);
    decode_object(&framed)
}

/// Writes one framed JSON object to an async byte transport.
pub async fn write_object<W, T>(writer: &mut W, value: &T) -> Result<(), LocalProtocolError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let encoded = encode_object(value)?;
    writer.write_all(&encoded).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_prefix<R>(reader: &mut R) -> Result<(usize, Vec<u8>), LocalProtocolError>
where
    R: AsyncRead + Unpin,
{
    let mut first = [0_u8; 1];
    reader
        .read_exact(&mut first)
        .await
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::UnexpectedEof => LocalProtocolError::TruncatedPrefix,
            _ => LocalProtocolError::Io(error.to_string()),
        })?;
    let width = 1_usize << (first[0] >> 6);
    let mut prefix = vec![0_u8; width];
    prefix[0] = first[0];
    if width > 1 {
        reader
            .read_exact(&mut prefix[1..])
            .await
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::UnexpectedEof => LocalProtocolError::TruncatedPrefix,
                _ => LocalProtocolError::Io(error.to_string()),
            })?;
    }
    let (length, consumed) = decode_length_prefix(&prefix)?;
    debug_assert_eq!(consumed, width);
    Ok((length, prefix))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn async_transport_round_trips_the_shared_envelope() {
        let value = RequestEnvelope {
            api_version: LOCAL_API_VERSION.to_owned(),
            operation: "status.get".to_owned(),
            request_id: "req-1".to_owned(),
            actor: Actor {
                id: "local-admin".to_owned(),
                capabilities: vec!["status:read".to_owned()],
            },
            expected_generation: None,
            body: serde_json::json!({}),
        };
        let mut output = Vec::new();
        write_object(&mut output, &value).await.unwrap();
        let mut input = Cursor::new(output);
        let decoded: RequestEnvelope = read_object(&mut input).await.unwrap();
        assert_eq!(decoded, value);
    }
}
