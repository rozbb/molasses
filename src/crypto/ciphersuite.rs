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

    /// The type that implements our key exchange functionality
    type DH: DiffieHellman;
    /// The type that implements our authenticated encryption functionality
    type Aead: AuthenticatedEncryption;

    /// The `ring::digest::Algorithm` that implements our hashing functionality
    // We're gonna have to break the mold here. Originally this was Hash: digest::Digest. But to
    // define HKDF and HMAC over a generic Digest, one needs the following constraints:
    //     Hash: Input + BlockInput + FixedOutput + Reset + Default + Clone,
    //     Hash::BlockSize: ArrayLength<u8> + Clone,
    //     Hash::OutputSize: ArrayLength<u8>
    // and I'm not about to do that. Idea for the future: come back to using something like Hash,
    // but we can kill off all the ArrayLength stuff once associated constants for array lengths
    // becomes possible. Until then, we're probably just gonna use Vecs. The other downside is that
    // using a const locks us into whatever ring implements. Currently, it's just the SHA2 family.
    const HASH_ALG: &'static ring::digest::Algorithm;

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
    type Aead = Aes128Gcm;
    const HASH_ALG: &'static ring::digest::Algorithm = &ring::digest::SHA256;

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
        let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
        let scalar_bytes = digest.as_ref();

        let privkey = X25519::scalar_from_bytes(scalar_bytes)?;
        let pubkey = X25519::multiply_basepoint(&privkey);

        Ok((pubkey, privkey))
    }
}
