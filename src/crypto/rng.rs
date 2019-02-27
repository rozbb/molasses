pub(crate) trait CryptoRng: rand_core::RngCore + rand::CryptoRng {}

/// Defines a cryptographically secure `fill_bytes` method
impl<T> CryptoRng for T where T: rand_core::RngCore + rand::CryptoRng {}
