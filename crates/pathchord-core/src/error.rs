use std::error::Error;
use std::fmt;

/// Stable error classes exposed by wire-profile-v1.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum ErrorClass {
    LocalPolicy = 1,
    PathFailure = 2,
    EgressFailure = 3,
    TargetFailure = 4,
    ResourceLimit = 5,
}

impl ErrorClass {
    pub const fn code(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for ErrorClass {
    type Error = UnknownErrorClass;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::LocalPolicy),
            2 => Ok(Self::PathFailure),
            3 => Ok(Self::EgressFailure),
            4 => Ok(Self::TargetFailure),
            5 => Ok(Self::ResourceLimit),
            code => Err(UnknownErrorClass { code }),
        }
    }
}

impl fmt::Display for ErrorClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::LocalPolicy => "LOCAL_POLICY",
            Self::PathFailure => "PATH_FAILURE",
            Self::EgressFailure => "EGRESS_FAILURE",
            Self::TargetFailure => "TARGET_FAILURE",
            Self::ResourceLimit => "RESOURCE_LIMIT",
        };
        formatter.write_str(name)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnknownErrorClass {
    pub code: u8,
}

impl fmt::Display for UnknownErrorClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "unknown error class code {}", self.code)
    }
}

impl Error for UnknownErrorClass {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v1_error_codes_round_trip() {
        for class in [
            ErrorClass::LocalPolicy,
            ErrorClass::PathFailure,
            ErrorClass::EgressFailure,
            ErrorClass::TargetFailure,
            ErrorClass::ResourceLimit,
        ] {
            assert_eq!(ErrorClass::try_from(class.code()), Ok(class));
        }
    }

    #[test]
    fn unknown_error_code_is_not_coerced() {
        assert_eq!(ErrorClass::try_from(0), Err(UnknownErrorClass { code: 0 }));
    }
}
