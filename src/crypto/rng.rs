//! Defines `CryptoRng`, which is used for secure randomness throughout this crate

/// A trait representing a cryptographically secure random number generator
pub trait CryptoRng: rand::RngCore + rand::CryptoRng {}

/// Anything with a cryptographically secure `fill_bytes` method is a `CryptoRng`
impl<T> CryptoRng for T where T: rand::RngCore + rand::CryptoRng {}
