use crate::{
    crypto::{
        aead::{AuthenticatedEncryption, AES128GCM_IMPL},
        dh::{DhPoint, DhScalar, DiffieHellman, X25519_IMPL},
    },
    error::Error,
};

/// This represents the X25519-SHA256-AES128GCM ciphersuite. Notably, it implements `CipherSuite`.
pub(crate) const X25519_SHA256_AES128GCM: CipherSuite = CipherSuite {
    id: 0,
    name: "X25519_SHA256_AES128GCM",
    dh_impl: &X25519_IMPL,
    aead_impl: &AES128GCM_IMPL,
    hash_alg: &ring::digest::SHA256,
};

/// Represents the contents of an MLS ciphersuite: a DH-like key-agreement protocol, a
/// hashing algorithm, and an authenticated encryption algorithm.
pub(crate) struct CipherSuite {
    /// For serialization purposes
    pub(crate) id: u16,
    /// The name of this cipher suite
    pub(crate) name: &'static str,
    /// The trait object that implements our key exchange functionality
    pub(crate) dh_impl: &'static dyn DiffieHellman,
    /// The trait object that implements our authenticated encryption functionality
    pub(crate) aead_impl: &'static dyn AuthenticatedEncryption,
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
    pub(crate) hash_alg: &'static ring::digest::Algorithm,
}

impl CipherSuite {
    /// Given an arbitrary number of bytes, derives a Diffie-Hellman keypair. For this ciphersuite,
    /// the function is simply `scalar: [0u8; 32] = SHA256(bytes)`.
    fn derive_key_pair(&self, bytes: &[u8]) -> Result<(DhPoint, DhScalar), Error> {
        let digest = ring::digest::digest(self.hash_alg, bytes);
        let scalar_bytes = digest.as_ref();

        let privkey = self.dh_impl.scalar_from_bytes(scalar_bytes)?;
        let pubkey = self.dh_impl.multiply_basepoint(&privkey);

        Ok((pubkey, privkey))
    }
}
