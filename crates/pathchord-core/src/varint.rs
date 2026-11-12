use std::error::Error;
use std::fmt;

/// Largest value representable by the QUIC-style 62-bit variable integer.
pub const MAX_VARINT: u64 = (1_u64 << 62) - 1;

/// Returns the canonical encoded length of `value`.
pub const fn encoded_varint_len(value: u64) -> Result<usize, VarIntError> {
    match value {
        0..=63 => Ok(1),
        64..=16_383 => Ok(2),
        16_384..=1_073_741_823 => Ok(4),
        1_073_741_824..=MAX_VARINT => Ok(8),
        _ => Err(VarIntError::ValueTooLarge { value }),
    }
}

/// Appends the canonical QUIC-style encoding of `value` to `output`.
pub fn encode_varint(value: u64, output: &mut Vec<u8>) -> Result<(), VarIntError> {
    match encoded_varint_len(value)? {
        1 => output.push(value as u8),
        2 => output.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes()),
        4 => output.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes()),
        8 => output.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes()),
        _ => unreachable!("encoded_varint_len only returns valid QUIC lengths"),
    }
    Ok(())
}

/// Decodes one canonical QUIC-style integer and returns its value and length.
pub fn decode_varint(input: &[u8]) -> Result<(u64, usize), VarIntError> {
    let first = *input.first().ok_or(VarIntError::Truncated {
        expected: 1,
        actual: 0,
    })?;
    let encoded_len = 1_usize << (first >> 6);
    if input.len() < encoded_len {
        return Err(VarIntError::Truncated {
            expected: encoded_len,
            actual: input.len(),
        });
    }

    let value = match encoded_len {
        1 => u64::from(first & 0x3f),
        2 => u64::from(u16::from_be_bytes([first & 0x3f, input[1]])),
        4 => u64::from(u32::from_be_bytes([
            first & 0x3f,
            input[1],
            input[2],
            input[3],
        ])),
        8 => u64::from_be_bytes([
            first & 0x3f,
            input[1],
            input[2],
            input[3],
            input[4],
            input[5],
            input[6],
            input[7],
        ]),
        _ => unreachable!("the two-bit prefix only represents 1, 2, 4, or 8"),
    };

    let canonical_len = encoded_varint_len(value)?;
    if canonical_len != encoded_len {
        return Err(VarIntError::NonCanonical {
            value,
            encoded_len,
            canonical_len,
        });
    }
    Ok((value, encoded_len))
}

/// Decodes exactly one integer, rejecting bytes after its canonical encoding.
pub fn decode_varint_exact(input: &[u8]) -> Result<u64, VarIntError> {
    let (value, consumed) = decode_varint(input)?;
    if consumed != input.len() {
        return Err(VarIntError::TrailingBytes {
            remaining: input.len() - consumed,
        });
    }
    Ok(value)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VarIntError {
    ValueTooLarge {
        value: u64,
    },
    Truncated {
        expected: usize,
        actual: usize,
    },
    NonCanonical {
        value: u64,
        encoded_len: usize,
        canonical_len: usize,
    },
    TrailingBytes {
        remaining: usize,
    },
}

impl fmt::Display for VarIntError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ValueTooLarge { value } => {
                write!(formatter, "value {value} exceeds the 62-bit varint limit")
            }
            Self::Truncated { expected, actual } => write!(
                formatter,
                "truncated varint: expected {expected} bytes, got {actual}"
            ),
            Self::NonCanonical {
                value,
                encoded_len,
                canonical_len,
            } => write!(
                formatter,
                "non-canonical varint for {value}: used {encoded_len} bytes instead of {canonical_len}"
            ),
            Self::TrailingBytes { remaining } => {
                write!(formatter, "{remaining} trailing bytes after varint")
            }
        }
    }
}

impl Error for VarIntError {}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn boundary_values_use_canonical_lengths() {
        let cases = [
            (0, 1),
            (63, 1),
            (64, 2),
            (16_383, 2),
            (16_384, 4),
            (1_073_741_823, 4),
            (1_073_741_824, 8),
            (MAX_VARINT, 8),
        ];

        for (value, expected_len) in cases {
            let mut encoded = Vec::new();
            encode_varint(value, &mut encoded).unwrap();
            assert_eq!(encoded.len(), expected_len);
            assert_eq!(decode_varint_exact(&encoded), Ok(value));
        }
    }

    #[test]
    fn value_above_62_bits_is_rejected() {
        assert_eq!(
            encode_varint(MAX_VARINT + 1, &mut Vec::new()),
            Err(VarIntError::ValueTooLarge {
                value: MAX_VARINT + 1
            })
        );
    }

    #[test]
    fn truncated_values_report_the_encoded_width() {
        assert_eq!(
            decode_varint(&[0x40]),
            Err(VarIntError::Truncated {
                expected: 2,
                actual: 1
            })
        );
        assert_eq!(
            decode_varint(&[0x80, 0, 0]),
            Err(VarIntError::Truncated {
                expected: 4,
                actual: 3
            })
        );
        assert_eq!(
            decode_varint(&[0xc0, 0, 0, 0, 0, 0, 0]),
            Err(VarIntError::Truncated {
                expected: 8,
                actual: 7
            })
        );
    }

    #[test]
    fn wider_than_needed_values_are_rejected() {
        assert!(matches!(
            decode_varint_exact(&[0x40, 0x25]),
            Err(VarIntError::NonCanonical {
                value: 37,
                encoded_len: 2,
                canonical_len: 1
            })
        ));
        assert!(matches!(
            decode_varint_exact(&[0x80, 0, 0, 64]),
            Err(VarIntError::NonCanonical { .. })
        ));
    }

    #[test]
    fn exact_decode_rejects_trailing_bytes() {
        assert_eq!(
            decode_varint_exact(&[37, 0]),
            Err(VarIntError::TrailingBytes { remaining: 1 })
        );
    }

    proptest! {
        #[test]
        fn every_62_bit_value_round_trips(value in 0_u64..=MAX_VARINT) {
            let mut encoded = Vec::new();
            encode_varint(value, &mut encoded).unwrap();
            prop_assert_eq!(encoded.len(), encoded_varint_len(value).unwrap());
            prop_assert_eq!(decode_varint_exact(&encoded), Ok(value));
        }
    }
}
