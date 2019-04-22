pub(crate) trait CryptoRng: rand::RngCore + rand::CryptoRng {}

/// Defines a cryptographically secure `fill_bytes` method
impl<T> CryptoRng for T where T: rand::RngCore + rand::CryptoRng {}
