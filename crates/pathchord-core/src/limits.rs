use std::error::Error;
use std::fmt;

/// wire-profile-v1 hard caps. Negotiated limits may reduce, but never exceed,
/// these values.
///
/// The frame payload cap is 63 KiB so a complete v1 frame, including
/// its worst-case header and the Noise authentication tag, fits within Snow's
/// 65,535-byte message limit without record fragmentation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtocolLimits {
    max_frame_payload: usize,
    max_control_payload: usize,
    max_target_name: usize,
    max_stream_reordering: usize,
    max_session_buffering: usize,
}

impl ProtocolLimits {
    pub const HARD_MAX_FRAME_PAYLOAD: usize = 63 * 1024;
    pub const HARD_MAX_CONTROL_PAYLOAD: usize = 4 * 1024;
    pub const HARD_MAX_TARGET_NAME: usize = 255;
    pub const HARD_MAX_STREAM_REORDERING: usize = 4 * 1024 * 1024;
    pub const HARD_MAX_SESSION_BUFFERING: usize = 32 * 1024 * 1024;
    pub const HARD_MAX_ENDPOINT_ADDRESSES: usize = 16;
    pub const HARD_MAX_ACK_RANGES: usize = 256;

    pub fn try_new(
        max_frame_payload: usize,
        max_control_payload: usize,
        max_target_name: usize,
        max_stream_reordering: usize,
        max_session_buffering: usize,
    ) -> Result<Self, LimitsError> {
        let limits = Self {
            max_frame_payload,
            max_control_payload,
            max_target_name,
            max_stream_reordering,
            max_session_buffering,
        };
        limits.validate()?;
        Ok(limits)
    }

    pub const fn max_frame_payload(self) -> usize {
        self.max_frame_payload
    }

    pub const fn max_control_payload(self) -> usize {
        self.max_control_payload
    }

    pub const fn max_target_name(self) -> usize {
        self.max_target_name
    }

    pub const fn max_stream_reordering(self) -> usize {
        self.max_stream_reordering
    }

    pub const fn max_session_buffering(self) -> usize {
        self.max_session_buffering
    }

    fn validate(self) -> Result<(), LimitsError> {
        let fields = [
            (
                "max_frame_payload",
                self.max_frame_payload,
                Self::HARD_MAX_FRAME_PAYLOAD,
            ),
            (
                "max_control_payload",
                self.max_control_payload,
                Self::HARD_MAX_CONTROL_PAYLOAD,
            ),
            (
                "max_target_name",
                self.max_target_name,
                Self::HARD_MAX_TARGET_NAME,
            ),
            (
                "max_stream_reordering",
                self.max_stream_reordering,
                Self::HARD_MAX_STREAM_REORDERING,
            ),
            (
                "max_session_buffering",
                self.max_session_buffering,
                Self::HARD_MAX_SESSION_BUFFERING,
            ),
        ];

        for (field, value, hard_maximum) in fields {
            if value == 0 || value > hard_maximum {
                return Err(LimitsError::OutOfRange {
                    field,
                    value,
                    hard_maximum,
                });
            }
        }

        if self.max_control_payload > self.max_frame_payload {
            return Err(LimitsError::ControlExceedsFrame);
        }
        if self.max_stream_reordering > self.max_session_buffering {
            return Err(LimitsError::StreamExceedsSession);
        }
        Ok(())
    }
}

impl Default for ProtocolLimits {
    fn default() -> Self {
        Self {
            max_frame_payload: Self::HARD_MAX_FRAME_PAYLOAD,
            max_control_payload: Self::HARD_MAX_CONTROL_PAYLOAD,
            max_target_name: Self::HARD_MAX_TARGET_NAME,
            max_stream_reordering: Self::HARD_MAX_STREAM_REORDERING,
            max_session_buffering: Self::HARD_MAX_SESSION_BUFFERING,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LimitsError {
    OutOfRange {
        field: &'static str,
        value: usize,
        hard_maximum: usize,
    },
    ControlExceedsFrame,
    StreamExceedsSession,
}

impl fmt::Display for LimitsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfRange {
                field,
                value,
                hard_maximum,
            } => write!(
                formatter,
                "{field} must be in 1..={hard_maximum}, got {value}"
            ),
            Self::ControlExceedsFrame => {
                formatter.write_str("control payload limit exceeds frame payload limit")
            }
            Self::StreamExceedsSession => {
                formatter.write_str("Stream reordering limit exceeds Session buffering limit")
            }
        }
    }
}

impl Error for LimitsError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_protocol_baseline() {
        let limits = ProtocolLimits::default();
        assert_eq!(limits.max_frame_payload(), 63 * 1024);
        assert_eq!(limits.max_control_payload(), 4 * 1024);
        assert_eq!(limits.max_target_name(), 255);
        assert_eq!(limits.max_stream_reordering(), 4 * 1024 * 1024);
        assert_eq!(limits.max_session_buffering(), 32 * 1024 * 1024);
    }

    #[test]
    fn negotiated_limits_may_only_reduce_hard_caps() {
        assert!(ProtocolLimits::try_new(1024, 512, 128, 1024, 4096).is_ok());
        assert!(
            ProtocolLimits::try_new(
                ProtocolLimits::HARD_MAX_FRAME_PAYLOAD + 1,
                512,
                128,
                1024,
                4096,
            )
            .is_err()
        );
    }

    #[test]
    fn nested_limits_are_ordered() {
        assert_eq!(
            ProtocolLimits::try_new(128, 129, 1, 1, 1),
            Err(LimitsError::ControlExceedsFrame)
        );
        assert_eq!(
            ProtocolLimits::try_new(1024, 128, 1, 2, 1),
            Err(LimitsError::StreamExceedsSession)
        );
    }
}
