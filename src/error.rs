#[derive(Debug)]
pub enum Error {
    CryptoError(&'static str),
    OutOfEntropy,
}
