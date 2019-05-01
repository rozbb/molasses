/// An error type for anything that goes wrong in this crate
#[derive(Debug)]
pub enum Error {
    /// For errors that occur in AEAD algorithms
    EncryptionError(&'static str),
    /// For errors that occur in Diffie-Hellman key agreement
    DhError(&'static str),
    /// For errors that occur in signature algorithms
    SignatureError(&'static str),
    /// For errors that occur in KDF operations
    KdfError(&'static str),
    /// For errors encountered during (de)serialization
    SerdeError(std::io::Error),
    /// For errors encountered during upcasting
    UpcastError(&'static str),
    /// For errors concerning ratchet tree operations
    TreeError(&'static str),
    /// For errors concerning invalid data structures
    ValidationError(&'static str),
    /// For when we need randomness and there's none left
    OutOfEntropy,
    /// For when we've been removed from a group
    IAmRemoved,
}

// The only IO done in molasses is via serde, so this is a natural conversion
impl<'a> std::convert::From<std::io::Error> for Error {
    fn from(other: std::io::Error) -> Error {
        crate::error::Error::SerdeError(other)
    }
}

// Serde requires that any Serializer's error type implement std::error::Error
impl std::error::Error for Error {
    fn description(&self) -> &str {
        match self {
            Error::EncryptionError(e) => e,
            Error::DhError(e) => e,
            Error::TreeError(e) => e,
            Error::ValidationError(e) => e,
            Error::SignatureError(e) => e,
            Error::KdfError(e) => e,
            Error::SerdeError(e) => e.description(),
            Error::UpcastError(e) => e,
            Error::OutOfEntropy => "Out of Entropy",
            Error::IAmRemoved => "I am Removed",
        }
    }
}

// Serde also requires that any Serializer's error type implement std::fmt::Display
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        use std::error::Error;
        f.write_str(self.description())
    }
}

// serde requires that any Serializer's error type implement serde::ser::Error
impl serde::ser::Error for Error {
    fn custom<T: std::fmt::Display>(msg: T) -> Self {
        Error::SerdeError(std::io::Error::new(std::io::ErrorKind::Other, format!("{}", msg)))
    }
}

// serde requires that any Deserializer's error type implement serde::de::Error
impl serde::de::Error for Error {
    fn custom<T: std::fmt::Display>(msg: T) -> Self {
        Error::SerdeError(std::io::Error::new(std::io::ErrorKind::Other, format!("{}", msg)))
    }
}
