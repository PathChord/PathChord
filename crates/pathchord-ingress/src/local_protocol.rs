//! Length-prefixed JSON framing for the local control-plane protocol.
//!
//! The framing layer is transport-neutral: Unix sockets, named pipes, and
//! test transports all use the same canonical envelope and size checks.

use std::fmt;

use pathchord_core::{VarIntError, decode_varint, encode_varint};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum number of UTF-8 JSON bytes in one local protocol envelope.
pub const MAX_ENVELOPE_BYTES: usize = 1024 * 1024;

/// API version carried by the local management envelope.
pub const LOCAL_API_VERSION: &str = "1";

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LocalProtocolError {
    #[error("local envelope length prefix is truncated")]
    TruncatedPrefix,
    #[error("local envelope payload is truncated: expected {expected} bytes, got {actual}")]
    TruncatedPayload { expected: usize, actual: usize },
    #[error("local envelope contains trailing bytes: {remaining}")]
    TrailingBytes { remaining: usize },
    #[error("local envelope length must be non-zero")]
    ZeroLength,
    #[error("local envelope length {length} exceeds maximum {maximum}")]
    Oversized { length: usize, maximum: usize },
    #[error("invalid local envelope varint: {0}")]
    VarInt(#[source] VarIntError),
    #[error("local envelope JSON must be one object")]
    NotObject,
    #[error("local envelope JSON is invalid: {0}")]
    Json(String),
    #[error("local protocol I/O failed: {0}")]
    Io(String),
}

impl From<serde_json::Error> for LocalProtocolError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error.to_string())
    }
}

impl From<std::io::Error> for LocalProtocolError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

/// A generation precondition scoped to one owner snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerationExpectation {
    pub scope: String,
    pub value: u64,
}

/// Actor identity and capabilities attached to a command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actor {
    pub id: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

/// Typed local control-plane request envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RequestEnvelope {
    pub api_version: String,
    pub operation: String,
    pub request_id: String,
    pub actor: Actor,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_generation: Option<GenerationExpectation>,
    pub body: Value,
}

/// Stable typed error codes exposed by the local control plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    MalformedRequest,
    AuthenticationRequired,
    CapabilityDenied,
    ValidationFailed,
    NotFound,
    GenerationConflict,
    IdempotencyConflict,
    ResourceLimit,
    PersistenceUnavailable,
    UnsupportedOperation,
}

/// Safe typed error body. `details` MUST NOT contain secrets.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub code: ErrorCode,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

/// Typed local control-plane response envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResponseEnvelope {
    pub api_version: String,
    pub request_id: String,
    pub ok: bool,
    pub observed_generation: GenerationExpectation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorBody>,
}

impl ResponseEnvelope {
    #[must_use]
    pub fn success(
        request_id: impl Into<String>,
        observed_generation: GenerationExpectation,
        result: Value,
    ) -> Self {
        Self {
            api_version: LOCAL_API_VERSION.to_owned(),
            request_id: request_id.into(),
            ok: true,
            observed_generation,
            result: Some(result),
            error: None,
        }
    }

    #[must_use]
    pub fn failure(
        request_id: impl Into<String>,
        observed_generation: GenerationExpectation,
        error: ErrorBody,
    ) -> Self {
        Self {
            api_version: LOCAL_API_VERSION.to_owned(),
            request_id: request_id.into(),
            ok: false,
            observed_generation,
            result: None,
            error: Some(error),
        }
    }
}

/// Encodes one JSON object with a canonical QUIC-style varint length prefix.
pub fn encode_object<T: Serialize>(value: &T) -> Result<Vec<u8>, LocalProtocolError> {
    let json = serde_json::to_vec(value)?;
    validate_json_object(&json)?;
    if json.len() > MAX_ENVELOPE_BYTES {
        return Err(LocalProtocolError::Oversized {
            length: json.len(),
            maximum: MAX_ENVELOPE_BYTES,
        });
    }
    let mut output = Vec::with_capacity(json.len() + 8);
    encode_varint(json.len() as u64, &mut output).map_err(LocalProtocolError::VarInt)?;
    output.extend_from_slice(&json);
    Ok(output)
}

/// Decodes exactly one framed JSON object from a complete byte slice.
pub fn decode_object<T: DeserializeOwned>(input: &[u8]) -> Result<T, LocalProtocolError> {
    let (length, prefix_len) = decode_prefix(input)?;
    let payload_start = prefix_len;
    let payload_end = payload_start
        .checked_add(length)
        .ok_or(LocalProtocolError::Oversized {
            length,
            maximum: MAX_ENVELOPE_BYTES,
        })?;
    if input.len() < payload_end {
        return Err(LocalProtocolError::TruncatedPayload {
            expected: length,
            actual: input.len().saturating_sub(payload_start),
        });
    }
    if input.len() > payload_end {
        return Err(LocalProtocolError::TrailingBytes {
            remaining: input.len() - payload_end,
        });
    }
    let payload = &input[payload_start..payload_end];
    validate_json_object(payload)?;
    Ok(serde_json::from_slice(payload)?)
}

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

fn validate_json_object(payload: &[u8]) -> Result<(), LocalProtocolError> {
    let value: Value = serde_json::from_slice(payload)?;
    if !value.is_object() {
        return Err(LocalProtocolError::NotObject);
    }
    Ok(())
}

fn decode_prefix(input: &[u8]) -> Result<(usize, usize), LocalProtocolError> {
    let (length, consumed) = decode_varint(input).map_err(|error| match error {
        VarIntError::Truncated { .. } => LocalProtocolError::TruncatedPrefix,
        other => LocalProtocolError::VarInt(other),
    })?;
    if length == 0 {
        return Err(LocalProtocolError::ZeroLength);
    }
    if length > MAX_ENVELOPE_BYTES as u64 {
        return Err(LocalProtocolError::Oversized {
            length: length as usize,
            maximum: MAX_ENVELOPE_BYTES,
        });
    }
    Ok((length as usize, consumed))
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
    let (length, consumed) = decode_prefix(&prefix)?;
    debug_assert_eq!(consumed, width);
    Ok((length, prefix))
}

impl fmt::Display for Actor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tokio::runtime::Builder;

    fn request() -> RequestEnvelope {
        RequestEnvelope {
            api_version: LOCAL_API_VERSION.to_owned(),
            operation: "status.get".to_owned(),
            request_id: "req-1".to_owned(),
            actor: Actor {
                id: "local-admin".to_owned(),
                capabilities: vec!["status:read".to_owned()],
            },
            expected_generation: None,
            body: Value::Object(serde_json::Map::new()),
        }
    }

    #[test]
    fn round_trips_typed_request_and_response() {
        let encoded = encode_object(&request()).expect("encode");
        let decoded: RequestEnvelope = decode_object(&encoded).expect("decode");
        assert_eq!(decoded, request());

        let response = ResponseEnvelope::failure(
            "req-1",
            GenerationExpectation {
                scope: "observation".to_owned(),
                value: 3,
            },
            ErrorBody {
                code: ErrorCode::ValidationFailed,
                message: "invalid request".to_owned(),
                details: Some(serde_json::json!({"field": "body"})),
            },
        );
        let decoded: ResponseEnvelope = decode_object(&encode_object(&response).unwrap()).unwrap();
        assert_eq!(decoded, response);
    }

    #[test]
    fn rejects_zero_noncanonical_truncated_trailing_and_oversized_frames() {
        assert_eq!(
            decode_object::<Value>(&[0]),
            Err(LocalProtocolError::ZeroLength)
        );
        assert!(matches!(
            decode_object::<Value>(&[0x40]),
            Err(LocalProtocolError::TruncatedPrefix)
        ));
        assert!(matches!(
            decode_object::<Value>(&[0x40, 0x01]),
            Err(LocalProtocolError::VarInt(VarIntError::NonCanonical { .. }))
        ));
        let mut truncated = encode_object(&request()).unwrap();
        truncated.pop();
        assert!(matches!(
            decode_object::<RequestEnvelope>(&truncated),
            Err(LocalProtocolError::TruncatedPayload { .. })
        ));
        let mut trailing = encode_object(&request()).unwrap();
        trailing.push(0);
        assert!(matches!(
            decode_object::<RequestEnvelope>(&trailing),
            Err(LocalProtocolError::TrailingBytes { remaining: 1 })
        ));
        let mut oversized = Vec::new();
        encode_varint((MAX_ENVELOPE_BYTES + 1) as u64, &mut oversized).unwrap();
        assert!(matches!(
            decode_object::<Value>(&oversized),
            Err(LocalProtocolError::Oversized { .. })
        ));
    }

    #[test]
    fn rejects_non_object_json_and_async_round_trip() {
        let mut framed = Vec::new();
        encode_varint(1, &mut framed).unwrap();
        framed.push(b'1');
        assert_eq!(
            decode_object::<Value>(&framed),
            Err(LocalProtocolError::NotObject)
        );

        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let value = request();
            let mut output = Vec::new();
            write_object(&mut output, &value).await.unwrap();
            let mut input = Cursor::new(output);
            let decoded: RequestEnvelope = read_object(&mut input).await.unwrap();
            assert_eq!(decoded, value);
        });
    }
}
