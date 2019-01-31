/// An error type for anything that goes wrong in this crate
#[derive(Debug)]
pub enum Error {
    /// For errors that occur in AEAD algorithms
    EncryptionError(&'static str),
    /// For errors that occur in Diffie-Hellman key agreement
    DHError(&'static str),
    /// For errors that occur in signature algorithms
    SignatureError(&'static str),
    /// For when we need randomness and there's none left
    OutOfEntropy,
}
