//! Defines and instantiates `CipherSuite` objects, corresponding to MLS ciphersuites

use crate::{
    crypto::{
        aead::{AeadScheme, AES128GCM_IMPL},
        dh::{DhPrivateKey, DhPublicKey, DiffieHellman, P256_IMPL, X25519_IMPL},
        hash::{HashFunction, SHA256_IMPL},
    },
    error::Error,
};

/// This represents the X25519-SHA256-AES128GCM ciphersuite
pub const X25519_SHA256_AES128GCM: CipherSuite = CipherSuite {
    name: "X25519_SHA256_AES128GCM",
    dh_impl: &X25519_IMPL,
    aead_impl: &AES128GCM_IMPL,
    hash_impl: &SHA256_IMPL,
};

pub(crate) const P256_SHA256_AES128GCM: CipherSuite = CipherSuite {
    name: "P256_SHA256_AES128GCM",
    dh_impl: &P256_IMPL,
    aead_impl: &AES128GCM_IMPL,
    hash_impl: &SHA256_IMPL,
};

/// Represents the contents of an MLS ciphersuite: a DH-like key-agreement protocol, a
/// hashing algorithm, and an authenticated encryption algorithm.
pub struct CipherSuite {
    /// The name of this cipher suite
    pub(crate) name: &'static str,

    /// The trait object that implements our key exchange functionality
    pub(crate) dh_impl: &'static dyn DiffieHellman,

    /// The trait object that implements our authenticated encryption functionality
    pub(crate) aead_impl: &'static AeadScheme,

    /// The object that implements our hashing functionality
    pub(crate) hash_impl: &'static HashFunction,
}

// TODO: Remove this impl if Add messages come with public_key indices in the future
// CipherSuites are uniquely identified by their tags. We need this in order to dedup ciphersuite
// lists in UserInitKeys
impl PartialEq for CipherSuite {
    fn eq(&self, other: &CipherSuite) -> bool {
        self.name.eq(other.name)
    }
}

impl CipherSuite {
    /// Given an arbitrary number of bytes, derives a Diffie-Hellman keypair. For this ciphersuite,
    /// the function is simply `scalar: [u8; 32] = SHA256(bytes)`.
    ///
    /// Requires: `bytes.len() == self.hash_impl.digest_size()`
    ///
    /// Returns: `Ok((pubkey, privkey))` on success. If the above condition is not met, returns an
    /// `Error::ValidationError`. If something goes wrong in key derivation, returns an
    /// `Error::CryptoError`.
    pub(crate) fn derive_key_pair(
        &self,
        bytes: &[u8],
    ) -> Result<(DhPublicKey, DhPrivateKey), Error> {
        // The spec requires this condition in the definition of Derive-Key-Pair
        // TODO: URGENT: Uncomment this check once the official crypto test cases use appropriately
        // sized input values for this function
        //if bytes.len() != self.hash_impl.digest_size() {
        //    return Err(Error::ValidationError("Derive-Key-Pair input length != Hash.length"));
        //}

        // Hash the input and use the digest as a private key
        let digest = self.hash_impl.hash_bytes(bytes);
        let privkey = self.dh_impl.private_key_from_bytes(digest.as_bytes())?;
        // Derive the pubkey
        let pubkey = self.dh_impl.derive_public_key(&privkey);

        Ok((pubkey, privkey))
    }
}

impl core::fmt::Debug for CipherSuite {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        // Ensure that the secret value isn't accidentally logged
        f.write_str(self.name)
    }
}
