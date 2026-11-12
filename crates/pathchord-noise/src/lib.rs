//! Noise IK handshakes and encrypted records for a single Path.
//!
//! Every [`InitiatorHandshake`] or [`ResponderHandshake`] owns fresh Noise
//! state and must be used for exactly one Path. A successful handshake
//! authenticates the peer's static key, but it does **not** authorize that key.
//! The Egress must compare [`NoiseTransport::authenticated_remote_static`] with
//! its enabled authorization snapshot before allowing the Path to become
//! `PATH_READY`.
//!
//! `snow` 0.10 does not zeroize all private/DH and traffic-key storage held in
//! its handshake and transport states. The wrapper zeroizes generated static
//! key material, but this limitation remains a Phase-0 non-production concern;
//! see the technology-selection document before using this crate for deployed
//! long-lived secrets.

use std::fmt;

use pathchord_core::{FrameCodecError, MAX_VARINT, PathFrame, ProtocolLimits};
use snow::{Builder, HandshakeState, StatelessTransportState, params::NoiseParams};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The only Noise protocol name supported by PathChord.
pub const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_SHA256";

/// Size of Curve25519 static private and public keys.
pub const STATIC_KEY_LEN: usize = 32;

/// Maximum Noise message size mandated by the Noise specification and `snow`.
pub const MAX_NOISE_MESSAGE_LEN: usize = 65_535;

/// Authentication tag added to each ChaCha20-Poly1305 transport message.
pub const TRANSPORT_TAG_LEN: usize = 16;

/// Largest plaintext that fits into one authenticated Noise transport record.
///
/// Path framing must reject or split anything larger before calling
/// [`NoiseTransport::seal_record`].
pub const MAX_TRANSPORT_PLAINTEXT_LEN: usize = MAX_NOISE_MESSAGE_LEN - TRANSPORT_TAG_LEN;

/// Largest record nonce representable by the core's canonical 62-bit varint.
pub const MAX_RECORD_NONCE: u64 = MAX_VARINT;

/// Number of recent inbound record nonces retained for replay detection.
pub const REPLAY_WINDOW_SIZE: u64 = 64;

/// Number of bytes in the record envelope before ciphertext bytes.
pub const RECORD_ENVELOPE_HEADER_LEN: usize = 10;

/// Largest complete encoded record envelope accepted by this crate.
pub const MAX_RECORD_ENVELOPE_LEN: usize = RECORD_ENVELOPE_HEADER_LEN + MAX_NOISE_MESSAGE_LEN;

/// A Curve25519 static keypair used by an Ingress or Egress.
///
/// The custom `Debug` implementation deliberately omits the private key.
#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct StaticKeypair {
    private: [u8; STATIC_KEY_LEN],
    public: [u8; STATIC_KEY_LEN],
}

impl StaticKeypair {
    /// Reconstructs a persisted keypair.
    ///
    /// This function cannot verify that the two halves match. A mismatched pair
    /// will fail to authenticate during the Noise handshake.
    #[must_use]
    pub const fn from_parts(private: [u8; STATIC_KEY_LEN], public: [u8; STATIC_KEY_LEN]) -> Self {
        Self { private, public }
    }

    /// Returns the private key bytes for secure persistence or handshake setup.
    #[must_use]
    pub const fn private(&self) -> &[u8; STATIC_KEY_LEN] {
        &self.private
    }

    /// Returns the public key bytes used for enrollment and peer matching.
    #[must_use]
    pub const fn public(&self) -> &[u8; STATIC_KEY_LEN] {
        &self.public
    }
}

impl fmt::Debug for StaticKeypair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StaticKeypair")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

/// Failure returned by the bounded inbound replay window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ReplayError {
    /// A nonce cannot be represented by the core's canonical 62-bit sequence.
    #[error("record nonce {nonce} exceeds the core 62-bit maximum {MAX_RECORD_NONCE}")]
    NonceOutOfRange {
        /// Invalid nonce.
        nonce: u64,
    },

    /// An authenticated record repeats a nonce already accepted in the window.
    #[error("record nonce {nonce} is a duplicate")]
    Duplicate {
        /// Repeated nonce.
        nonce: u64,
    },

    /// An authenticated record is older than the retained window.
    #[error("record nonce {nonce} is stale; highest accepted nonce is {highest}")]
    Stale {
        /// Old nonce.
        nonce: u64,
        /// Highest nonce currently retained.
        highest: u64,
    },
}

/// A bounded sliding replay window for one authenticated transport direction.
///
/// Authentication must happen before [`Self::accept`] is called. This prevents
/// forged records from consuming window entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayWindow {
    highest: Option<u64>,
    seen: u64,
}

impl ReplayWindow {
    /// Creates an empty window.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            highest: None,
            seen: 0,
        }
    }

    /// Returns the greatest nonce observed so far, if any.
    #[must_use]
    pub const fn highest(&self) -> Option<u64> {
        self.highest
    }

    /// Authenticates a nonce's ordering after decryption and marks it seen.
    ///
    /// Nonces may arrive out of order within [`REPLAY_WINDOW_SIZE`]. A duplicate
    /// or stale nonce is rejected. The operation is atomic on failure.
    pub fn accept(&mut self, nonce: u64) -> Result<(), ReplayError> {
        if nonce > MAX_RECORD_NONCE {
            return Err(ReplayError::NonceOutOfRange { nonce });
        }
        match self.highest {
            None => {
                self.highest = Some(nonce);
                self.seen = 1;
                Ok(())
            }
            Some(highest) if nonce > highest => {
                let shift = nonce - highest;
                self.seen = if shift >= REPLAY_WINDOW_SIZE {
                    1
                } else {
                    (self.seen << shift) | 1
                };
                self.highest = Some(nonce);
                Ok(())
            }
            Some(highest) => {
                let distance = highest - nonce;
                if distance >= REPLAY_WINDOW_SIZE {
                    return Err(ReplayError::Stale { nonce, highest });
                }
                let bit = 1_u64 << distance;
                if self.seen & bit != 0 {
                    return Err(ReplayError::Duplicate { nonce });
                }
                self.seen |= bit;
                Ok(())
            }
        }
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors produced while constructing or using a Path Noise session.
#[derive(Debug, Error)]
pub enum NoiseError {
    /// The caller did not bind the configured EgressID into the handshake
    /// transcript.
    #[error("the Egress identity binding must not be empty")]
    EmptyEgressIdentity,

    /// A key returned by the crypto provider had an unexpected size.
    #[error("{kind} key has length {actual}, expected {STATIC_KEY_LEN}")]
    InvalidKeyLength {
        /// Whether the malformed key was private, public, or remote.
        kind: &'static str,
        /// Actual number of bytes returned.
        actual: usize,
    },

    /// A handshake message exceeded the hard Noise message limit.
    #[error("handshake message has length {actual}, maximum is {MAX_NOISE_MESSAGE_LEN}")]
    HandshakeMessageTooLarge {
        /// Actual message length.
        actual: usize,
    },

    /// A transport plaintext cannot fit in one Noise record.
    #[error("transport plaintext has length {actual}, maximum is {MAX_TRANSPORT_PLAINTEXT_LEN}")]
    PlaintextTooLarge {
        /// Actual plaintext length.
        actual: usize,
    },

    /// An encrypted record was too large to be a Noise message.
    #[error("encrypted record has length {actual}, maximum is {MAX_NOISE_MESSAGE_LEN}")]
    RecordTooLarge {
        /// Actual record length.
        actual: usize,
    },

    /// An encrypted record cannot contain a complete authentication tag.
    #[error("encrypted record has length {actual}, minimum is {TRANSPORT_TAG_LEN}")]
    RecordTooShort {
        /// Actual record length.
        actual: usize,
    },

    /// A nonce exceeds the core's canonical 62-bit sequence range.
    #[error("record nonce {nonce} exceeds the core 62-bit maximum {MAX_RECORD_NONCE}")]
    NonceOutOfRange {
        /// Invalid record nonce.
        nonce: u64,
    },

    /// The per-direction 62-bit nonce space has been exhausted.
    #[error("the per-Path outbound record nonce is exhausted")]
    NonceExhausted,

    /// A complete record envelope is shorter than its fixed header or tag.
    #[error("record envelope is truncated: got {actual} bytes")]
    RecordEnvelopeTooShort {
        /// Actual encoded envelope length.
        actual: usize,
    },

    /// A complete record envelope exceeds the encoded Noise message limit.
    #[error("record envelope is too large: got {actual} bytes")]
    RecordEnvelopeTooLarge {
        /// Actual encoded envelope length.
        actual: usize,
    },

    /// The envelope length field declares bytes not present in the input.
    #[error("record envelope ciphertext is truncated: expected {expected} bytes, got {actual}")]
    RecordEnvelopeTruncated {
        /// Declared complete envelope length.
        expected: usize,
        /// Actual input length.
        actual: usize,
    },

    /// Bytes remain after the declared complete envelope.
    #[error("record envelope has {remaining} trailing bytes")]
    RecordEnvelopeTrailing {
        /// Number of bytes after the declared envelope.
        remaining: usize,
    },

    /// The record was authenticated but rejected by the bounded replay window.
    #[error("record replay check failed: {0}")]
    Replay(#[from] ReplayError),

    /// The frame sequence does not match the record nonce.
    #[error("record nonce {nonce} does not match decoded frame sequence {frame_seq}")]
    FrameSequenceMismatch { nonce: u64, frame_seq: u64 },

    /// The authenticated plaintext is not one complete PathChord frame.
    #[error("decoded PathChord frame is invalid: {0}")]
    FrameDecode(#[from] FrameCodecError),

    /// The selected handshake pattern did not expose the authenticated static
    /// key required for explicit authorization.
    #[error("the Noise handshake did not expose a remote static key")]
    MissingRemoteStatic,

    /// The underlying Noise implementation rejected an operation.
    #[error("Noise operation failed: {0}")]
    Snow(#[from] snow::Error),
}

/// Generates a new Curve25519 static keypair using `snow`'s secure RNG.
pub fn generate_static_keypair() -> Result<StaticKeypair, NoiseError> {
    let keypair = Builder::new(noise_params()?).generate_keypair()?;
    let private = copy_private_key(keypair.private)?;
    let public =
        keypair
            .public
            .try_into()
            .map_err(|public: Vec<u8>| NoiseError::InvalidKeyLength {
                kind: "public",
                actual: public.len(),
            })?;

    Ok(StaticKeypair::from_parts(private, public))
}

fn copy_private_key(mut bytes: Vec<u8>) -> Result<[u8; STATIC_KEY_LEN], NoiseError> {
    if bytes.len() != STATIC_KEY_LEN {
        let actual = bytes.len();
        bytes.zeroize();
        return Err(NoiseError::InvalidKeyLength {
            kind: "private",
            actual,
        });
    }

    let mut private = [0_u8; STATIC_KEY_LEN];
    private.copy_from_slice(&bytes);
    bytes.zeroize();
    Ok(private)
}

/// An authenticated, complete Noise record envelope.
///
/// The envelope is encoded as `nonce:u64_be`, `ciphertext_len:u16_be`, and the
/// exact ciphertext bytes. It is deliberately owned and cloneable so a sender
/// can retransmit the same nonce/ciphertext without re-encrypting plaintext.
#[derive(Clone, Eq, PartialEq)]
pub struct SealedRecord {
    nonce: u64,
    ciphertext: Vec<u8>,
}

impl fmt::Debug for SealedRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SealedRecord")
            .field("nonce", &self.nonce)
            .field("ciphertext_len", &self.ciphertext.len())
            .finish()
    }
}

impl SealedRecord {
    /// Validates and constructs a record from its parsed fields.
    pub fn from_parts(nonce: u64, ciphertext: Vec<u8>) -> Result<Self, NoiseError> {
        require_record_nonce(nonce)?;
        validate_ciphertext_len(ciphertext.len())?;
        Ok(Self { nonce, ciphertext })
    }

    /// Returns the explicit transport nonce.
    #[must_use]
    pub const fn nonce(&self) -> u64 {
        self.nonce
    }

    /// Returns the authenticated ciphertext without copying it.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Consumes the record and returns `(nonce, ciphertext)`.
    #[must_use]
    pub fn into_parts(self) -> (u64, Vec<u8>) {
        (self.nonce, self.ciphertext)
    }

    /// Encodes the complete record envelope.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(RECORD_ENVELOPE_HEADER_LEN + self.ciphertext.len());
        output.extend_from_slice(&self.nonce.to_be_bytes());
        output.extend_from_slice(&(self.ciphertext.len() as u16).to_be_bytes());
        output.extend_from_slice(&self.ciphertext);
        output
    }

    /// Parses one complete record envelope, rejecting truncation and trailing
    /// bytes before allocating the ciphertext.
    pub fn decode(input: &[u8]) -> Result<Self, NoiseError> {
        if input.len() > MAX_RECORD_ENVELOPE_LEN {
            return Err(NoiseError::RecordEnvelopeTooLarge {
                actual: input.len(),
            });
        }
        if input.len() < RECORD_ENVELOPE_HEADER_LEN {
            return Err(NoiseError::RecordEnvelopeTooShort {
                actual: input.len(),
            });
        }

        let nonce = u64::from_be_bytes(input[..8].try_into().expect("checked nonce length"));
        require_record_nonce(nonce)?;
        let ciphertext_len = usize::from(u16::from_be_bytes(
            input[8..10].try_into().expect("checked length field"),
        ));
        validate_ciphertext_len(ciphertext_len)?;
        let expected = RECORD_ENVELOPE_HEADER_LEN + ciphertext_len;
        if input.len() < expected {
            return Err(NoiseError::RecordEnvelopeTruncated {
                expected,
                actual: input.len(),
            });
        }
        if input.len() > expected {
            return Err(NoiseError::RecordEnvelopeTrailing {
                remaining: input.len() - expected,
            });
        }

        Ok(Self {
            nonce,
            ciphertext: input[RECORD_ENVELOPE_HEADER_LEN..].to_vec(),
        })
    }
}

fn validate_ciphertext_len(length: usize) -> Result<(), NoiseError> {
    if length < TRANSPORT_TAG_LEN {
        return Err(NoiseError::RecordTooShort { actual: length });
    }
    if length > MAX_NOISE_MESSAGE_LEN {
        return Err(NoiseError::RecordTooLarge { actual: length });
    }
    Ok(())
}

/// Initiator side of one Path's Noise IK handshake.
///
/// `egress_identity` is mixed into the Noise prologue and must be the same on
/// both peers. It must contain the canonical configured EgressID bytes, which
/// are known to the responder before it can read the first IK message. The
/// authenticated initiator static key is mapped to an authorized IngressID
/// after message one; Session attachment must then match that mapping.
pub struct InitiatorHandshake {
    state: HandshakeState,
}

impl InitiatorHandshake {
    /// Creates fresh initiator handshake state for one Path.
    pub fn new(
        local_private: &[u8; STATIC_KEY_LEN],
        expected_responder_public: &[u8; STATIC_KEY_LEN],
        egress_identity: &[u8],
    ) -> Result<Self, NoiseError> {
        Self::build(
            local_private,
            expected_responder_public,
            egress_identity,
            None,
        )
    }

    fn build(
        local_private: &[u8; STATIC_KEY_LEN],
        expected_responder_public: &[u8; STATIC_KEY_LEN],
        egress_identity: &[u8],
        fixed_ephemeral: Option<&[u8; STATIC_KEY_LEN]>,
    ) -> Result<Self, NoiseError> {
        require_egress_identity(egress_identity)?;
        let builder = Builder::new(noise_params()?)
            .local_private_key(local_private)?
            .remote_public_key(expected_responder_public)?
            .prologue(egress_identity)?;
        let builder = match fixed_ephemeral {
            Some(key) => builder.fixed_ephemeral_key_for_testing_only(key),
            None => builder,
        };

        Ok(Self {
            state: builder.build_initiator()?,
        })
    }

    /// Writes the next IK handshake message with an optional protocol payload.
    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, NoiseError> {
        write_handshake_message(&mut self.state, payload)
    }

    /// Reads the next IK handshake message and returns its protocol payload.
    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>, NoiseError> {
        read_handshake_message(&mut self.state, message)
    }

    /// Returns whether the IK exchange has completed.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }

    /// Returns the static key authenticated by the handshake.
    ///
    /// Authentication does not imply authorization. The caller must still
    /// validate this key against configured identity and enrollment state.
    pub fn authenticated_remote_static(&self) -> Result<[u8; STATIC_KEY_LEN], NoiseError> {
        remote_static(&self.state)
    }

    /// Consumes a finished handshake and enters explicit-nonce transport mode.
    pub fn into_transport(self) -> Result<NoiseTransport, NoiseError> {
        into_transport(self.state)
    }

    #[cfg(test)]
    fn with_fixed_ephemeral(
        local_private: &[u8; STATIC_KEY_LEN],
        expected_responder_public: &[u8; STATIC_KEY_LEN],
        egress_identity: &[u8],
        fixed_ephemeral: &[u8; STATIC_KEY_LEN],
    ) -> Result<Self, NoiseError> {
        Self::build(
            local_private,
            expected_responder_public,
            egress_identity,
            Some(fixed_ephemeral),
        )
    }
}

impl fmt::Debug for InitiatorHandshake {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InitiatorHandshake")
            .field("finished", &self.is_finished())
            .finish_non_exhaustive()
    }
}

/// Responder side of one Path's Noise IK handshake.
///
/// The remote initiator static key becomes available after the first message.
/// The Egress must map it to an enabled authorization record and its IngressID
/// before advancing the Path to `PATH_READY`; this type intentionally performs
/// no enrollment or authorization lookup.
pub struct ResponderHandshake {
    state: HandshakeState,
}

impl ResponderHandshake {
    /// Creates fresh responder handshake state for one Path.
    pub fn new(
        local_private: &[u8; STATIC_KEY_LEN],
        egress_identity: &[u8],
    ) -> Result<Self, NoiseError> {
        Self::build(local_private, egress_identity, None)
    }

    fn build(
        local_private: &[u8; STATIC_KEY_LEN],
        egress_identity: &[u8],
        fixed_ephemeral: Option<&[u8; STATIC_KEY_LEN]>,
    ) -> Result<Self, NoiseError> {
        require_egress_identity(egress_identity)?;
        let builder = Builder::new(noise_params()?)
            .local_private_key(local_private)?
            .prologue(egress_identity)?;
        let builder = match fixed_ephemeral {
            Some(key) => builder.fixed_ephemeral_key_for_testing_only(key),
            None => builder,
        };

        Ok(Self {
            state: builder.build_responder()?,
        })
    }

    /// Reads the next IK handshake message and returns its protocol payload.
    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>, NoiseError> {
        read_handshake_message(&mut self.state, message)
    }

    /// Writes the next IK handshake message with an optional protocol payload.
    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, NoiseError> {
        write_handshake_message(&mut self.state, payload)
    }

    /// Returns whether the IK exchange has completed.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }

    /// Returns the authenticated initiator static key for explicit Egress-side
    /// authorization. A successful return value alone never authorizes a Path.
    pub fn authenticated_remote_static(&self) -> Result<[u8; STATIC_KEY_LEN], NoiseError> {
        remote_static(&self.state)
    }

    /// Consumes a finished handshake and enters explicit-nonce transport mode.
    pub fn into_transport(self) -> Result<NoiseTransport, NoiseError> {
        into_transport(self.state)
    }

    #[cfg(test)]
    fn with_fixed_ephemeral(
        local_private: &[u8; STATIC_KEY_LEN],
        egress_identity: &[u8],
        fixed_ephemeral: &[u8; STATIC_KEY_LEN],
    ) -> Result<Self, NoiseError> {
        Self::build(local_private, egress_identity, Some(fixed_ephemeral))
    }
}

impl fmt::Debug for ResponderHandshake {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResponderHandshake")
            .field("finished", &self.is_finished())
            .finish_non_exhaustive()
    }
}

/// Authenticated, explicit-nonce Noise record protection for exactly one Path.
///
/// PathChord permits whole-record loss, duplication, and reordering, so an
/// implicit counter is not usable here. The adapter must carry `nonce` in its
/// record envelope, then verify after decryption that it matches the decoded
/// frame's `frame_seq`. A nonce must never protect different plaintexts under
/// the same directional key; retransmission must reuse the original ciphertext.
pub struct NoiseTransport {
    state: StatelessTransportState,
    authenticated_remote_static: [u8; STATIC_KEY_LEN],
    next_send_nonce: u64,
    replay_window: ReplayWindow,
}

impl NoiseTransport {
    /// Returns the peer static key authenticated by this Path's handshake.
    ///
    /// Callers must still apply their independent enrollment/authorization
    /// policy before allowing business traffic.
    #[must_use]
    pub const fn authenticated_remote_static(&self) -> &[u8; STATIC_KEY_LEN] {
        &self.authenticated_remote_static
    }

    /// Encrypts one complete PathChord frame into one owned Noise record.
    ///
    /// The nonce is owned and advanced by this transport; callers cannot select
    /// or reuse it. Cache the returned [`SealedRecord`] for retransmission.
    /// The size check happens before allocating the output buffer.
    pub fn seal_record(&mut self, plaintext: &[u8]) -> Result<SealedRecord, NoiseError> {
        let nonce = self.next_send_nonce;
        require_record_nonce(nonce).map_err(|_| NoiseError::NonceExhausted)?;
        if plaintext.len() > MAX_TRANSPORT_PLAINTEXT_LEN {
            return Err(NoiseError::PlaintextTooLarge {
                actual: plaintext.len(),
            });
        }

        let mut record = vec![0_u8; plaintext.len() + TRANSPORT_TAG_LEN];
        let written = self.state.write_message(nonce, plaintext, &mut record)?;
        record.truncate(written);
        self.next_send_nonce = nonce + 1;
        SealedRecord::from_parts(nonce, record)
    }

    /// Encodes and seals one complete PathFrame whose `frame_seq` is exactly
    /// the next owned outbound nonce.
    pub fn seal_frame(
        &mut self,
        frame: &PathFrame,
        limits: ProtocolLimits,
    ) -> Result<SealedRecord, NoiseError> {
        let nonce = self.next_send_nonce().ok_or(NoiseError::NonceExhausted)?;
        let frame_seq = frame.header().frame_seq();
        if frame_seq != nonce {
            return Err(NoiseError::FrameSequenceMismatch { nonce, frame_seq });
        }
        let encoded = frame.encode(limits)?;
        self.seal_record(&encoded)
    }

    /// Authenticates and decrypts one complete Noise transport record.
    ///
    /// Both size bounds are checked before allocating the plaintext buffer;
    /// replay state is changed only after AEAD authentication succeeds.
    /// For protocol traffic, prefer [`Self::open_frame`] so the authenticated
    /// `frame_seq` is checked before the replay window is committed.
    pub fn open_record(&mut self, record: &SealedRecord) -> Result<Vec<u8>, NoiseError> {
        let plaintext = self.decrypt_record(record)?;
        self.replay_window.accept(record.nonce)?;
        Ok(plaintext)
    }

    /// Parses and opens an encoded complete record envelope.
    pub fn open_encoded_record(&mut self, encoded: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let record = SealedRecord::decode(encoded)?;
        self.open_record(&record)
    }

    /// Parses, authenticates, and decodes one complete encoded PathChord frame.
    pub fn open_encoded_frame(
        &mut self,
        encoded: &[u8],
        limits: ProtocolLimits,
    ) -> Result<PathFrame, NoiseError> {
        let record = SealedRecord::decode(encoded)?;
        self.open_frame(&record, limits)
    }

    /// Opens one record and decodes a complete PathChord frame.
    ///
    /// The nonce/header equality check is part of the authenticated record
    /// boundary: callers cannot hand a valid frame to Session logic under a
    /// different Path sequence number.
    pub fn open_frame(
        &mut self,
        record: &SealedRecord,
        limits: ProtocolLimits,
    ) -> Result<PathFrame, NoiseError> {
        let plaintext = self.decrypt_record(record)?;
        let frame = PathFrame::decode(&plaintext, limits)?;
        let frame_seq = frame.header().frame_seq();
        if frame_seq != record.nonce() {
            return Err(NoiseError::FrameSequenceMismatch {
                nonce: record.nonce(),
                frame_seq,
            });
        }
        self.replay_window.accept(record.nonce)?;
        Ok(frame)
    }

    fn decrypt_record(&self, record: &SealedRecord) -> Result<Vec<u8>, NoiseError> {
        require_record_nonce(record.nonce)?;
        validate_ciphertext_len(record.ciphertext.len())?;

        let mut plaintext = vec![0_u8; record.ciphertext.len() - TRANSPORT_TAG_LEN];
        let written = self
            .state
            .read_message(record.nonce, &record.ciphertext, &mut plaintext)?;
        plaintext.truncate(written);
        Ok(plaintext)
    }

    /// Returns the next outbound nonce, or `None` after exhaustion.
    #[must_use]
    pub const fn next_send_nonce(&self) -> Option<u64> {
        if self.next_send_nonce <= MAX_RECORD_NONCE {
            Some(self.next_send_nonce)
        } else {
            None
        }
    }

    /// Returns the highest inbound nonce retained by the replay window.
    #[must_use]
    pub const fn highest_received_nonce(&self) -> Option<u64> {
        self.replay_window.highest()
    }
}

impl fmt::Debug for NoiseTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NoiseTransport")
            .field(
                "authenticated_remote_static",
                &self.authenticated_remote_static,
            )
            .finish_non_exhaustive()
    }
}

fn noise_params() -> Result<NoiseParams, NoiseError> {
    Ok(NOISE_PATTERN.parse()?)
}

fn require_egress_identity(egress_identity: &[u8]) -> Result<(), NoiseError> {
    if egress_identity.is_empty() {
        Err(NoiseError::EmptyEgressIdentity)
    } else {
        Ok(())
    }
}

fn require_record_nonce(nonce: u64) -> Result<(), NoiseError> {
    if nonce > MAX_RECORD_NONCE {
        Err(NoiseError::NonceOutOfRange { nonce })
    } else {
        Ok(())
    }
}

fn write_handshake_message(
    state: &mut HandshakeState,
    payload: &[u8],
) -> Result<Vec<u8>, NoiseError> {
    if payload.len() > MAX_NOISE_MESSAGE_LEN {
        return Err(NoiseError::HandshakeMessageTooLarge {
            actual: payload.len(),
        });
    }

    let mut message = vec![0_u8; MAX_NOISE_MESSAGE_LEN];
    let written = state.write_message(payload, &mut message)?;
    message.truncate(written);
    Ok(message)
}

fn read_handshake_message(
    state: &mut HandshakeState,
    message: &[u8],
) -> Result<Vec<u8>, NoiseError> {
    if message.len() > MAX_NOISE_MESSAGE_LEN {
        return Err(NoiseError::HandshakeMessageTooLarge {
            actual: message.len(),
        });
    }

    let mut payload = vec![0_u8; message.len()];
    let written = state.read_message(message, &mut payload)?;
    payload.truncate(written);
    Ok(payload)
}

fn remote_static(state: &HandshakeState) -> Result<[u8; STATIC_KEY_LEN], NoiseError> {
    let key = state
        .get_remote_static()
        .ok_or(NoiseError::MissingRemoteStatic)?;
    key.try_into().map_err(|_| NoiseError::InvalidKeyLength {
        kind: "remote public",
        actual: key.len(),
    })
}

fn into_transport(state: HandshakeState) -> Result<NoiseTransport, NoiseError> {
    let authenticated_remote_static = remote_static(&state)?;
    Ok(NoiseTransport {
        state: state.into_stateless_transport_mode()?,
        authenticated_remote_static,
        next_send_nonce: 0,
        replay_window: ReplayWindow::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const EGRESS_IDENTITY: &[u8] = b"PathChord/v1/egress-id";
    const INITIATOR_PRIVATE: [u8; STATIC_KEY_LEN] = [1; STATIC_KEY_LEN];
    const INITIATOR_PUBLIC: [u8; STATIC_KEY_LEN] = [
        0xa4, 0xe0, 0x92, 0x92, 0xb6, 0x51, 0xc2, 0x78, 0xb9, 0x77, 0x2c, 0x56, 0x9f, 0x5f, 0xa9,
        0xbb, 0x13, 0xd9, 0x06, 0xb4, 0x6a, 0xb6, 0x8c, 0x9d, 0xf9, 0xdc, 0x2b, 0x44, 0x09, 0xf8,
        0xa2, 0x09,
    ];
    const RESPONDER_PRIVATE: [u8; STATIC_KEY_LEN] = [2; STATIC_KEY_LEN];
    const RESPONDER_PUBLIC: [u8; STATIC_KEY_LEN] = [
        0xce, 0x8d, 0x3a, 0xd1, 0xcc, 0xb6, 0x33, 0xec, 0x7b, 0x70, 0xc1, 0x78, 0x14, 0xa5, 0xc7,
        0x6e, 0xcd, 0x02, 0x96, 0x85, 0x05, 0x0d, 0x34, 0x47, 0x45, 0xba, 0x05, 0x87, 0x0e, 0x58,
        0x7d, 0x59,
    ];
    const WRONG_RESPONDER_PRIVATE: [u8; STATIC_KEY_LEN] = [3; STATIC_KEY_LEN];

    fn establish_path(
        initiator_ephemeral: [u8; STATIC_KEY_LEN],
        responder_ephemeral: [u8; STATIC_KEY_LEN],
    ) -> (NoiseTransport, NoiseTransport) {
        let mut initiator = InitiatorHandshake::with_fixed_ephemeral(
            &INITIATOR_PRIVATE,
            &RESPONDER_PUBLIC,
            EGRESS_IDENTITY,
            &initiator_ephemeral,
        )
        .expect("initiator state");
        let mut responder = ResponderHandshake::with_fixed_ephemeral(
            &RESPONDER_PRIVATE,
            EGRESS_IDENTITY,
            &responder_ephemeral,
        )
        .expect("responder state");

        let request = initiator
            .write_message(b"path hello")
            .expect("first IK message");
        assert_eq!(
            responder
                .read_message(&request)
                .expect("read first message"),
            b"path hello"
        );
        assert_eq!(
            responder
                .authenticated_remote_static()
                .expect("authenticated initiator"),
            INITIATOR_PUBLIC
        );

        let response = responder
            .write_message(b"path accepted")
            .expect("second IK message");
        assert_eq!(
            initiator
                .read_message(&response)
                .expect("read second message"),
            b"path accepted"
        );
        assert!(initiator.is_finished());
        assert!(responder.is_finished());

        (
            initiator.into_transport().expect("initiator transport"),
            responder.into_transport().expect("responder transport"),
        )
    }

    #[test]
    fn ik_handshake_authenticates_and_encrypts_bidirectionally() {
        let (mut initiator, mut responder) = establish_path([4; 32], [5; 32]);

        assert_eq!(initiator.authenticated_remote_static(), &RESPONDER_PUBLIC);
        assert_eq!(responder.authenticated_remote_static(), &INITIATOR_PUBLIC);

        let upstream = initiator
            .seal_record(b"complete upstream frame")
            .expect("encrypt upstream");
        assert_eq!(
            responder.open_record(&upstream).expect("decrypt upstream"),
            b"complete upstream frame"
        );

        let downstream = responder
            .seal_record(b"complete downstream frame")
            .expect("encrypt downstream");
        assert_eq!(
            initiator
                .open_record(&downstream)
                .expect("decrypt downstream"),
            b"complete downstream frame"
        );
    }

    #[test]
    fn wrong_responder_private_key_fails_the_ik_handshake() {
        let mut initiator = InitiatorHandshake::with_fixed_ephemeral(
            &INITIATOR_PRIVATE,
            &RESPONDER_PUBLIC,
            EGRESS_IDENTITY,
            &[6; 32],
        )
        .expect("initiator state");
        let mut wrong_responder = ResponderHandshake::with_fixed_ephemeral(
            &WRONG_RESPONDER_PRIVATE,
            EGRESS_IDENTITY,
            &[7; 32],
        )
        .expect("responder state");

        let request = initiator.write_message(&[]).expect("first IK message");
        assert!(wrong_responder.read_message(&request).is_err());
    }

    #[test]
    fn mismatched_egress_identity_fails_the_ik_handshake() {
        let mut initiator = InitiatorHandshake::with_fixed_ephemeral(
            &INITIATOR_PRIVATE,
            &RESPONDER_PUBLIC,
            EGRESS_IDENTITY,
            &[22; 32],
        )
        .expect("initiator state");
        let mut responder = ResponderHandshake::with_fixed_ephemeral(
            &RESPONDER_PRIVATE,
            b"PathChord/v1/other-egress",
            &[23; 32],
        )
        .expect("responder state");
        let request = initiator.write_message(&[]).expect("first IK message");
        assert!(responder.read_message(&request).is_err());
    }

    #[test]
    fn each_path_has_independent_transport_keys() {
        let (mut initiator_one, mut responder_one) = establish_path([8; 32], [9; 32]);
        let (_initiator_two, mut responder_two) = establish_path([10; 32], [11; 32]);

        let record = initiator_one
            .seal_record(b"path-one-only")
            .expect("encrypt on first path");
        assert!(responder_two.open_record(&record).is_err());
        assert_eq!(
            responder_one
                .open_record(&record)
                .expect("decrypt on matching path"),
            b"path-one-only"
        );
    }

    #[test]
    fn record_limit_accepts_the_boundary_and_rejects_one_more_byte() {
        let (mut initiator, mut responder) = establish_path([12; 32], [13; 32]);
        let largest_plaintext = vec![0xa5; MAX_TRANSPORT_PLAINTEXT_LEN];
        let largest_record = initiator
            .seal_record(&largest_plaintext)
            .expect("encrypt largest permitted record");
        assert_eq!(largest_record.ciphertext().len(), MAX_NOISE_MESSAGE_LEN);
        assert_eq!(
            responder
                .open_record(&largest_record)
                .expect("decrypt largest permitted record"),
            largest_plaintext
        );

        let oversized_plaintext = vec![0_u8; MAX_TRANSPORT_PLAINTEXT_LEN + 1];
        assert!(matches!(
            initiator.seal_record(&oversized_plaintext),
            Err(NoiseError::PlaintextTooLarge { .. })
        ));

        let oversized_record = vec![0_u8; MAX_NOISE_MESSAGE_LEN + 1];
        assert!(matches!(
            SealedRecord::from_parts(0, oversized_record),
            Err(NoiseError::RecordTooLarge { .. })
        ));
    }

    #[test]
    fn records_decrypt_after_loss_and_out_of_order_delivery() {
        let (mut initiator, mut responder) = establish_path([14; 32], [15; 32]);
        let first = initiator
            .seal_record(b"first frame")
            .expect("encrypt first frame");
        let later = initiator
            .seal_record(b"later frame")
            .expect("encrypt later frame");

        assert_eq!(
            responder
                .open_record(&later)
                .expect("decrypt later frame first"),
            b"later frame"
        );
        assert_eq!(
            responder
                .open_record(&first)
                .expect("decrypt earlier frame after gap"),
            b"first frame"
        );
    }

    #[test]
    fn open_frame_requires_record_nonce_to_match_authenticated_frame_sequence() {
        use pathchord_core::{FrameFlags, FrameType, PathFrame, PathId, ProtocolLimits, SessionId};

        let (mut initiator, mut responder) = establish_path([20; 32], [21; 32]);
        let limits = ProtocolLimits::default();
        let frame = PathFrame::new(
            FrameType::Heartbeat,
            FrameFlags::empty(),
            SessionId::new(1),
            PathId::new(2),
            0,
            Vec::new(),
            limits,
        )
        .expect("frame");
        let record = initiator.seal_frame(&frame, limits).expect("record");
        assert_eq!(
            responder
                .open_encoded_frame(&record.encode(), limits)
                .expect("open encoded frame"),
            frame
        );

        // Advance the sender nonce, then encrypt a frame whose authenticated
        // sequence deliberately does not match that record nonce.
        initiator
            .seal_record(b"nonce advance")
            .expect("advance nonce");
        let mismatched = PathFrame::new(
            FrameType::Heartbeat,
            FrameFlags::empty(),
            SessionId::new(1),
            PathId::new(2),
            0,
            Vec::new(),
            limits,
        )
        .expect("mismatched frame");
        let mismatched_record = initiator
            .seal_record(&mismatched.encode(limits).expect("encode mismatched frame"))
            .expect("mismatched record");
        assert!(matches!(
            responder.open_frame(&mismatched_record, limits),
            Err(NoiseError::FrameSequenceMismatch {
                nonce: 2,
                frame_seq: 0
            })
        ));
        assert_eq!(responder.highest_received_nonce(), Some(0));
    }

    #[test]
    fn seal_frame_requires_the_owned_next_sequence() {
        use pathchord_core::{FrameFlags, FrameType, PathFrame, PathId, ProtocolLimits, SessionId};

        let (mut initiator, _responder) = establish_path([24; 32], [25; 32]);
        let frame = PathFrame::new(
            FrameType::Heartbeat,
            FrameFlags::empty(),
            SessionId::new(1),
            PathId::new(2),
            1,
            Vec::new(),
            ProtocolLimits::default(),
        )
        .expect("frame");
        assert!(matches!(
            initiator.seal_frame(&frame, ProtocolLimits::default()),
            Err(NoiseError::FrameSequenceMismatch {
                nonce: 0,
                frame_seq: 1
            })
        ));
        assert_eq!(initiator.next_send_nonce(), Some(0));
    }

    #[test]
    fn duplicate_and_wrong_nonce_records_are_rejected() {
        let (mut initiator, mut responder) = establish_path([16; 32], [17; 32]);
        let record = initiator
            .seal_record(b"deduplicate above Noise")
            .expect("encrypt record");

        let wrong_nonce = SealedRecord::from_parts(1, record.ciphertext().to_vec())
            .expect("construct wrong nonce record");
        assert!(responder.open_record(&wrong_nonce).is_err());
        assert_eq!(
            responder
                .open_record(&record)
                .expect("decrypt original delivery"),
            b"deduplicate above Noise"
        );
        assert!(matches!(
            responder.open_record(&record),
            Err(NoiseError::Replay(ReplayError::Duplicate { nonce: 0 }))
        ));
    }

    #[test]
    fn outbound_nonce_is_monotonic_and_exhaustion_is_rejected() {
        let (mut initiator, _responder) = establish_path([18; 32], [19; 32]);
        assert_eq!(initiator.next_send_nonce(), Some(0));
        let first = initiator.seal_record(b"first").expect("first record");
        let second = initiator.seal_record(b"second").expect("second record");
        assert_eq!(first.nonce(), 0);
        assert_eq!(second.nonce(), 1);
        assert_ne!(first, second);
        initiator.next_send_nonce = MAX_RECORD_NONCE;
        let last = initiator
            .seal_record(b"last")
            .expect("last permitted record");
        assert_eq!(last.nonce(), MAX_RECORD_NONCE);
        assert_eq!(initiator.next_send_nonce(), None);
        assert!(matches!(
            initiator.seal_record(b"exhausted"),
            Err(NoiseError::NonceExhausted)
        ));
    }

    #[test]
    fn empty_egress_identity_is_rejected() {
        assert!(matches!(
            InitiatorHandshake::new(&INITIATOR_PRIVATE, &RESPONDER_PUBLIC, &[]),
            Err(NoiseError::EmptyEgressIdentity)
        ));
        assert!(matches!(
            ResponderHandshake::new(&RESPONDER_PRIVATE, &[]),
            Err(NoiseError::EmptyEgressIdentity)
        ));
    }

    #[test]
    fn replay_window_accepts_reordering_and_rejects_stale_values() {
        let mut window = ReplayWindow::new();
        window.accept(10).unwrap();
        window.accept(12).unwrap();
        window.accept(11).unwrap();
        assert!(matches!(
            window.accept(11),
            Err(ReplayError::Duplicate { nonce: 11 })
        ));
        window.accept(100).unwrap();
        assert!(matches!(
            window.accept(100 - REPLAY_WINDOW_SIZE),
            Err(ReplayError::Stale { .. })
        ));
        assert!(matches!(
            window.accept(MAX_RECORD_NONCE + 1),
            Err(ReplayError::NonceOutOfRange { .. })
        ));
    }

    #[test]
    fn record_envelope_rejects_truncation_and_trailing_bytes() {
        let (mut initiator, _responder) = establish_path([20; 32], [21; 32]);
        let record = initiator.seal_record(b"envelope").unwrap();
        let encoded = record.encode();
        assert!(matches!(
            SealedRecord::decode(&encoded[..encoded.len() - 1]),
            Err(NoiseError::RecordEnvelopeTruncated { .. })
        ));
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(matches!(
            SealedRecord::decode(&trailing),
            Err(NoiseError::RecordEnvelopeTrailing { remaining: 1 })
        ));
        let oversized = vec![0; MAX_RECORD_ENVELOPE_LEN + 1];
        assert!(matches!(
            SealedRecord::decode(&oversized),
            Err(NoiseError::RecordEnvelopeTooLarge { .. })
        ));
        assert_eq!(SealedRecord::decode(&encoded).unwrap(), record);
    }

    #[test]
    fn static_keypair_can_be_cleared_before_drop() {
        let mut keypair = StaticKeypair::from_parts([0x5a; 32], [0xa5; 32]);
        keypair.zeroize();
        assert_eq!(keypair.private(), &[0; 32]);
        assert_eq!(keypair.public(), &[0; 32]);
    }
}
