//! Transport-independent local management envelopes and framing.

use std::fmt;

use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{VarIntError, decode_varint, encode_varint};

/// Maximum number of UTF-8 JSON bytes in one management envelope.
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

impl fmt::Display for Actor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.id)
    }
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

/// Stable typed error codes exposed by local control planes.
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

/// Trusted transport that accepted a management request. This value is supplied
/// by the adapter, never by the serialized request envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagementSource {
    Local,
    Web,
}

impl ManagementSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Web => "web",
        }
    }
}

/// Synchronous request handler used behind local transport adapters.
///
/// Dispatchers own validation, authorization, and response shaping. Transport
/// adapters may serialize calls through a short-lived lock while serving client
/// byte streams concurrently.
#[async_trait]
pub trait ManagementDispatcher: Send + 'static {
    async fn dispatch(&mut self, request: RequestEnvelope) -> ResponseEnvelope;

    async fn dispatch_from(
        &mut self,
        request: RequestEnvelope,
        _source: ManagementSource,
    ) -> ResponseEnvelope {
        self.dispatch(request).await
    }

    async fn record_authentication_failure(&mut self, _source: &str) {}
}

#[async_trait]
impl<F> ManagementDispatcher for F
where
    F: FnMut(RequestEnvelope) -> ResponseEnvelope + Send + 'static,
{
    async fn dispatch(&mut self, request: RequestEnvelope) -> ResponseEnvelope {
        self(request)
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
    let (length, prefix_len) = decode_length_prefix(input)?;
    let payload_end = prefix_len
        .checked_add(length)
        .ok_or(LocalProtocolError::Oversized {
            length,
            maximum: MAX_ENVELOPE_BYTES,
        })?;
    if input.len() < payload_end {
        return Err(LocalProtocolError::TruncatedPayload {
            expected: length,
            actual: input.len().saturating_sub(prefix_len),
        });
    }
    if input.len() > payload_end {
        return Err(LocalProtocolError::TrailingBytes {
            remaining: input.len() - payload_end,
        });
    }
    let payload = &input[prefix_len..payload_end];
    validate_json_object(payload)?;
    Ok(serde_json::from_slice(payload)?)
}

/// Decodes and validates one complete management-envelope length prefix.
pub fn decode_length_prefix(input: &[u8]) -> Result<(usize, usize), LocalProtocolError> {
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

fn validate_json_object(payload: &[u8]) -> Result<(), LocalProtocolError> {
    let value: Value = serde_json::from_slice(payload)?;
    if !value.is_object() {
        return Err(LocalProtocolError::NotObject);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn rejects_invalid_frame_shapes() {
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

        let mut scalar = Vec::new();
        encode_varint(1, &mut scalar).unwrap();
        scalar.push(b'1');
        assert_eq!(
            decode_object::<Value>(&scalar),
            Err(LocalProtocolError::NotObject)
        );
    }
}
