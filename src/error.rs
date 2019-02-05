/// An error type for anything that goes wrong in this crate
#[derive(Debug)]
pub enum Error {
    /// For errors that occur in AEAD algorithms
    EncryptionError(&'static str),
    /// For errors that occur in Diffie-Hellman key agreement
    DHError(&'static str),
    /// For errors that occur in signature algorithms
    SignatureError(&'static str),
    /// For errors encountered during (de)serialization
    SerdeError(String),
    /// For when we need randomness and there's none left
    OutOfEntropy,
}

// The only IO done in molasses is via serde, so this is a natural conversion
impl<'a> std::convert::From<std::io::Error> for Error {
    fn from(other: std::io::Error) -> Error {
        use std::error::Error;
        crate::error::Error::SerdeError(other.description().to_string())
    }
}

// Serde requires that any Serializer's error type implement std::error::Error
impl std::error::Error for Error {
    fn description(&self) -> &str {
        match self {
            Error::EncryptionError(e) => e,
            Error::DHError(e) => e,
            Error::SignatureError(e) => e,
            Error::SerdeError(e) => e.as_str(),
            Error::OutOfEntropy => "Out of Entropy",
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

// Finally, serde requires that any Serializer's error type implement serde::ser::Error
impl serde::ser::Error for Error {
    fn custom<T: std::fmt::Display>(msg: T) -> Self {
        Error::SerdeError(format!("{}", msg))
    }
}
