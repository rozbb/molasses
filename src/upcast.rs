//! This module defines the `CryptoUpcast` trait. This purpose of this trait is to act as a stage 2
//! to deserialization. It takes raw signatures and DH public keys and "upcasts" them into the
//! appropriate variants thereof.
//!
//! For example, we might receive some sequence of bytes over the wire, which we interpret as a
//! `DhPublicKey::Raw(DhPublicKeyRaw(v))` at first. However, we know from context that the current
//! cipher suite is `X25519_SHA256_AES128GCM`, so we can "upcast" this to a
//! `DhPublicKey::X25519PublicKey` and use it elsewhere in the library in a more typesafe way.
//!
//! The reason this has to be defined for a lot of types is because this transformation is
//! hierarchichal in nature. We sometimes have to use the ciphersuite or signature scheme from a
//! struct to properly interpret the bytes in other structs it contains. This requires at least a
//! little bit of custom logic, so we opt to implement this manually for all the types that need
//! it.

use crate::credential::Credential;
use crate::crypto::{
    ciphersuite::CipherSuite,
    dh::DhPublicKey,
    ecies::EciesCiphertext,
    sig::SignatureScheme,
};

/// The context necessary for a `CryptoUpcast`. This specifies the ambient ciphersuite and
/// signature scheme.
#[derive(Clone, Copy)]
pub(crate) struct CryptoCtx {
    cs: Option<&'static CipherSuite>,
    ss: Option<&'static dyn SignatureScheme>,
}

impl CryptoCtx {
    /// Makes a new `CryptoCtx` with the given ciphersuite and an empty signature scheme
    pub(crate) fn new_from_cipher_suite(cs: &'static CipherSuite) -> CryptoCtx {
        CryptoCtx { cs: Some(cs), ss: None }
    }

    /// Makes a new `CryptoCtx` with the given signature scheme and an empty ciphersuite
    pub(crate) fn new_from_signature_scheme(ss: &'static SignatureScheme) -> CryptoCtx {
        CryptoCtx { cs: None, ss: Some(ss) }
    }
}

/// This trait describes how an object's "raw" parts are to be interpreted given the context of the
/// ambient cipher suite and signature scheme. See module documentation for more.
pub(crate) trait CryptoUpcast {
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx);
}

impl<T: CryptoUpcast> CryptoUpcast for Option<T> {
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) {
        match self {
            Some(inner) => inner.upcast_crypto_values(ctx),
            None => (),
        }
    }
}

impl<T: CryptoUpcast> CryptoUpcast for Vec<T> {
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) {
        for item in self.iter_mut() {
            item.upcast_crypto_values(ctx);
        }
    }
}

impl CryptoUpcast for DhPublicKey {
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) {
        let raw = enum_variant!(self, DhPublicKey::Raw);
        match ctx.cs {
            Some(cs) => *self = cs.dh_impl.point_from_bytes(raw.0.as_slice()),
            None => panic!("need a CipherSuite to upcast a DhPublicKey"),
        }
    }
}

impl CryptoUpcast for crate::crypto::ecies::EciesCiphertext {
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) {
        self.ephemeral_public_key.upcast_crypto_values(ctx);
    }
}

impl CryptoUpcast for crate::credential::BasicCredential {
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) {
    }
}

impl CryptoUpcast for Credential {
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) {
        match self {
            Credential::Basic(b) => {
                let mut new_ctx = *ctx;
                new_ctx.ss = Some(b.signature_scheme);
                b.upcast_crypto_values(&new_ctx);
            },
            _ => ()
        }
    }
}
