pub(crate) trait CryptoRng: rand_core::RngCore + rand::CryptoRng {}

impl<T> CryptoRng for T where T: rand_core::RngCore + rand::CryptoRng {}
