use std::error::Error;
use std::fmt;

macro_rules! u128_id {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(u128);

        impl $name {
            pub const fn new(value: u128) -> Self {
                Self(value)
            }

            pub const fn get(self) -> u128 {
                self.0
            }

            pub const fn from_be_bytes(bytes: [u8; 16]) -> Self {
                Self(u128::from_be_bytes(bytes))
            }

            pub const fn to_be_bytes(self) -> [u8; 16] {
                self.0.to_be_bytes()
            }
        }

        impl From<u128> for $name {
            fn from(value: u128) -> Self {
                Self::new(value)
            }
        }

        impl From<$name> for u128 {
            fn from(value: $name) -> Self {
                value.get()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "{}({self})", stringify!($name))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "{:032x}", self.0)
            }
        }
    };
}

u128_id!(SessionId, "A random 128-bit Session identifier.");
u128_id!(PathId, "A random 128-bit physical Path identifier.");
u128_id!(RequestId, "A random 128-bit idempotency identifier.");

/// A Session-local Stream identifier.
///
/// Stream identifiers occupy 62 bits and must never be reused within a
/// Session. Allocation policy belongs to the Session implementation.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StreamId(u64);

impl StreamId {
    pub const MAX: u64 = (1_u64 << 62) - 1;

    pub const fn new(value: u64) -> Result<Self, IdError> {
        if value <= Self::MAX {
            Ok(Self(value))
        } else {
            Err(IdError::StreamIdOutOfRange { value })
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

impl TryFrom<u64> for StreamId {
    type Error = IdError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<StreamId> for u64 {
    fn from(value: StreamId) -> Self {
        value.get()
    }
}

impl fmt::Debug for StreamId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "StreamId({})", self.0)
    }
}

impl fmt::Display for StreamId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdError {
    StreamIdOutOfRange { value: u64 },
}

impl fmt::Display for IdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StreamIdOutOfRange { value } => {
                write!(
                    formatter,
                    "Stream identifier {value} exceeds the 62-bit limit"
                )
            }
        }
    }
}

impl Error for IdError {}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn u128_ids_use_network_byte_order() {
        let value = 0x0011_2233_4455_6677_8899_aabb_ccdd_eeff;
        let id = SessionId::new(value);

        assert_eq!(SessionId::from_be_bytes(id.to_be_bytes()), id);
        assert_eq!(id.to_string(), "00112233445566778899aabbccddeeff");
    }

    #[test]
    fn stream_id_accepts_exact_upper_bound() {
        assert_eq!(StreamId::new(StreamId::MAX).unwrap().get(), StreamId::MAX);
    }

    #[test]
    fn stream_id_rejects_values_above_62_bits() {
        assert_eq!(
            StreamId::new(1_u64 << 62),
            Err(IdError::StreamIdOutOfRange { value: 1_u64 << 62 })
        );
    }

    proptest! {
        #[test]
        fn session_id_byte_round_trip(value in any::<u128>()) {
            let id = SessionId::new(value);
            prop_assert_eq!(SessionId::from_be_bytes(id.to_be_bytes()), id);
        }

        #[test]
        fn stream_id_round_trip(value in 0_u64..=StreamId::MAX) {
            let id = StreamId::try_from(value).unwrap();
            prop_assert_eq!(u64::from(id), value);
        }
    }
}
