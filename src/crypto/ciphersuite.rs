use crate::crypto::{
    aead::{Aes128Gcm, AuthenticatedEncryption},
    dh::{DiffieHellman, X25519},
    sig::ED25519,
};
use crate::error::Error;

use digest::Digest;

/// A trait representing the contents of an MLS ciphersuite: a DH-like key-agreement protocol, a
/// hashing algorithm, and an authenticated encryption algorithm.
pub(crate) trait CipherSuite {
    const ID: u16;

    type DH: DiffieHellman;
    type Hash: Digest;
    type Aead: AuthenticatedEncryption;

    fn derive_key_pair(
        bytes: &[u8],
    ) -> Result<
        (
            <Self::DH as DiffieHellman>::Point,
            <Self::DH as DiffieHellman>::Scalar,
        ),
        Error,
    >;
}

/// This represents the X25519-SHA256-AES128GCM ciphersuite. Notably, it implements `CipherSuite`.
#[allow(non_camel_case_types)]
pub(crate) struct X25519_SHA256_AES128GCM;

impl CipherSuite for X25519_SHA256_AES128GCM {
    /// This is for serialization purposes. The MLS specifies that this is variant of the
    /// CipherSuite enum has value 0x0000.
    const ID: u16 = 0;

    type DH = X25519;
    type Hash = sha2::Sha256;
    type Aead = Aes128Gcm;

    /// Given an arbitrary number of bytes, derives a Diffie-Hellman keypair. For this ciphersuite,
    /// the function is simply `scalar: [0u8; 32] = SHA256(bytes)`.
    fn derive_key_pair(
        bytes: &[u8],
    ) -> Result<
        (
            <X25519 as DiffieHellman>::Point,
            <X25519 as DiffieHellman>::Scalar,
        ),
        Error,
    > {
        let mut hasher = sha2::Sha256::new();
        hasher.input(bytes);
        let scalar_bytes = hasher.result();

        let privkey = X25519::scalar_from_bytes(&scalar_bytes)?;
        let pubkey = X25519::multiply_basepoint(&privkey);

        Ok((pubkey, privkey))
    }
}
