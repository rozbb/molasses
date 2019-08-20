//! This file is mostly boilerplate for converting the output keying material (OKM) from `ring`'s
//! HKDF-Expand implementation into useful types. Specifically, we need to define structs that
//! implement `ring::hkdf::KeyType` in order to tell `ring` how many OKM bytes we need, and we
//! define and implement `FromHkdfExpand` in order to be able to automatically convert OKM into
//! something we want, like a salt or an AEAD key.

use crate::{
    crypto::{
        aead::{AeadKey, AeadNonce},
        ciphersuite::CipherSuite,
        hkdf::{HkdfPrk, HkdfSalt},
        hmac::HmacKey,
    },
    error::Error,
    ratchet_tree::{NodeSecret, PathSecret},
};

/// A struct that encodes the digest length of the hash function in a given ciphersuite
pub(crate) struct HashDigestLen(&'static CipherSuite);

impl ring::hkdf::KeyType for HashDigestLen {
    fn len(&self) -> usize {
        self.0.hash_impl.digest_size()
    }
}

impl HashDigestLen {
    fn new(cs: &'static CipherSuite) -> HashDigestLen {
        HashDigestLen(cs)
    }
}

/// The length of a PRK isn't really a defined value, but it's always the digest size in MLS, so
/// that's what we return.
pub(crate) type HkdfPrkLen = HashDigestLen;

/// The length of an HKDF salt isn't really a defined value, but it's always the digest size in MLS
/// (i.e., `init_secret`), so that's what we return.
pub(crate) type HkdfSaltLen = HashDigestLen;

/// The length of `node_secret` is Hash.length
pub(crate) type NodeSecretLen = HashDigestLen;

/// The length of `path_secret` is Hash.length
pub(crate) type PathSecretLen = HashDigestLen;

/// The length of `confirmation_key` is Hash.length
pub(crate) type HmacKeyLen = HashDigestLen;

/// A struct that encodes the length of an AEAD key under a specific ciphersuite
pub(crate) struct AeadKeyLen(&'static CipherSuite);

impl ring::hkdf::KeyType for AeadKeyLen {
    fn len(&self) -> usize {
        self.0.aead_impl.key_size()
    }
}

/// A struct that encodes the length of an AEAD nonce under a specific ciphersuite
pub(crate) struct AeadNonceLen(&'static CipherSuite);

impl ring::hkdf::KeyType for AeadNonceLen {
    fn len(&self) -> usize {
        self.0.aead_impl.nonce_size()
    }
}

/// A dumb helper trait that we need in order to be able to derive things like `AeadNonce`,
/// `AeadKey`, `HkdfSalt`, etc. from ring's HKDF-Expand operation
pub(crate) trait FromHkdfExpand: Sized {
    /// A struct that encodes the length of the secret we want to HKDF-Expand to
    type SecretLen: ring::hkdf::KeyType;

    /// The length of a secret depends on what secret we want (AEAD nonce vs AEAD key vs MAC key,
    /// etc.) and what algorithm we're using. This returns something that knows both by
    /// instantiating Self::SecretLen (which knows the type of secret we want) with the ciphersuite
    /// (which knows what algirhtm we're using).
    fn get_secret_len(cs: &'static CipherSuite) -> Self::SecretLen;

    /// A defined way to make the secret from raw bytes
    fn new_from_bytes(cs: &CipherSuite, bytes: &[u8]) -> Result<Self, Error>;
}

/// Defines how to get an `AeadKey` from running HKDF-Expand on a PRK
impl FromHkdfExpand for AeadKey {
    type SecretLen = AeadKeyLen;

    /// Returns an object that encodes the length of the desired secret. I know this is
    /// complicated. It's what `ring` wants, though.
    fn get_secret_len(cs: &'static CipherSuite) -> AeadKeyLen {
        AeadKeyLen(cs)
    }

    fn new_from_bytes(cs: &CipherSuite, bytes: &[u8]) -> Result<AeadKey, Error> {
        AeadKey::new_from_bytes(cs.aead_impl, bytes)
    }
}

impl FromHkdfExpand for AeadNonce {
    type SecretLen = AeadNonceLen;

    fn get_secret_len(cs: &'static CipherSuite) -> AeadNonceLen {
        AeadNonceLen(cs)
    }

    fn new_from_bytes(cs: &CipherSuite, bytes: &[u8]) -> Result<AeadNonce, Error> {
        AeadNonce::new_from_bytes(cs.aead_impl, bytes)
    }
}

impl FromHkdfExpand for HmacKey {
    type SecretLen = HmacKeyLen;

    fn get_secret_len(cs: &'static CipherSuite) -> HmacKeyLen {
        HmacKeyLen::new(cs)
    }

    fn new_from_bytes(cs: &CipherSuite, bytes: &[u8]) -> Result<HmacKey, Error> {
        Ok(HmacKey::new_from_bytes(cs.hash_impl, bytes))
    }
}

impl FromHkdfExpand for HkdfSalt {
    type SecretLen = HkdfSaltLen;

    fn get_secret_len(cs: &'static CipherSuite) -> HkdfSaltLen {
        HkdfSaltLen::new(cs)
    }

    fn new_from_bytes(cs: &CipherSuite, bytes: &[u8]) -> Result<HkdfSalt, Error> {
        Ok(HkdfSalt::new_from_bytes(cs.hash_impl, bytes))
    }
}

impl FromHkdfExpand for HkdfPrk {
    type SecretLen = HkdfPrkLen;

    fn get_secret_len(cs: &'static CipherSuite) -> HkdfPrkLen {
        HkdfPrkLen::new(cs)
    }

    fn new_from_bytes(cs: &CipherSuite, bytes: &[u8]) -> Result<HkdfPrk, Error> {
        Ok(HkdfPrk::new_from_bytes(cs.hash_impl, bytes))
    }
}

impl FromHkdfExpand for NodeSecret {
    type SecretLen = NodeSecretLen;

    fn get_secret_len(cs: &'static CipherSuite) -> NodeSecretLen {
        NodeSecretLen::new(cs)
    }

    fn new_from_bytes(cs: &CipherSuite, bytes: &[u8]) -> Result<NodeSecret, Error> {
        Ok(NodeSecret::new_from_bytes(cs.hash_impl, bytes))
    }
}

impl FromHkdfExpand for PathSecret {
    type SecretLen = PathSecretLen;

    fn get_secret_len(cs: &'static CipherSuite) -> PathSecretLen {
        PathSecretLen::new(cs)
    }

    fn new_from_bytes(cs: &CipherSuite, bytes: &[u8]) -> Result<PathSecret, Error> {
        Ok(PathSecret::new_from_bytes(cs.hash_impl, bytes))
    }
}
