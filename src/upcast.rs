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

use crate::{
    credential::{self, Credential},
    crypto::{
        ciphersuite::CipherSuite,
        dh::DhPublicKey,
        sig::{SigPublicKey, Signature, SignatureScheme},
    },
    error::Error,
};

/// The context necessary for a `CryptoUpcast`. This specifies the ambient ciphersuite and
/// signature scheme.
#[derive(Clone, Copy)]
pub(crate) struct CryptoCtx {
    cs: Option<&'static CipherSuite>,
    ss: Option<&'static dyn SignatureScheme>,
}

// TODO: Figure out when to check for coherence in ciphersuites

impl CryptoCtx {
    /// Returns a new `CryptoCtx` object with the specified cipher suite
    pub(crate) fn set_cipher_suite(&self, cs: &'static CipherSuite) -> CryptoCtx {
        let mut new_ctx = *self;
        new_ctx.cs = Some(cs);
        new_ctx
    }

    /// Returns a new `CryptoCtx` object with the specified signature scheme
    pub(crate) fn set_signature_scheme(&self, ss: &'static SignatureScheme) -> CryptoCtx {
        let mut new_ctx = *self;
        new_ctx.ss = Some(ss);
        new_ctx
    }
}

impl CryptoCtx {
    /// Makes a new empty `CryptoCtx`
    pub(crate) fn new() -> CryptoCtx {
        CryptoCtx {
            cs: None,
            ss: None,
        }
    }
}

/// This trait describes how an object's "raw" parts are to be interpreted given the context of the
/// ambient cipher suite and signature scheme. See module documentation for more.
pub(crate) trait CryptoUpcast {
    #[must_use]
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<(), Error>;
}

impl<T: CryptoUpcast> CryptoUpcast for Option<T> {
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<(), Error> {
        match self {
            Some(inner) => inner.upcast_crypto_values(ctx),
            None => Ok(()),
        }
    }
}

impl<T: CryptoUpcast> CryptoUpcast for Vec<T> {
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<(), Error> {
        for item in self.iter_mut() {
            item.upcast_crypto_values(ctx)?;
        }
        Ok(())
    }
}

impl CryptoUpcast for credential::Roster {
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<(), Error> {
        self.0.upcast_crypto_values(ctx)
    }
}

impl CryptoUpcast for DhPublicKey {
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<(), Error> {
        let raw = enum_variant!(self, DhPublicKey::Raw);
        match ctx.cs {
            Some(cs) => {
                *self = cs.dh_impl.public_key_from_bytes(raw.0.as_slice())?;
                Ok(())
            }
            None => Err(Error::UpcastError("Need a CipherSuite to upcast a DhPublicKey")),
        }
    }
}

impl CryptoUpcast for SigPublicKey {
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<(), Error> {
        let raw = enum_variant!(self, SigPublicKey::Raw);
        match ctx.ss {
            Some(ss) => {
                *self = ss.public_key_from_bytes(&raw.0)?;
                Ok(())
            }
            None => Err(Error::UpcastError("Need a SignatureScheme to upcast a SigPublicKey")),
        }
    }
}

impl CryptoUpcast for Signature {
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<(), Error> {
        let raw = match self {
            Signature::Raw(r) => r,
            _ => return Err(Error::UpcastError("Cannot upcast a non-raw Signature")),
        };
        match ctx.ss {
            Some(ss) => {
                *self = ss.signature_from_bytes(&raw.0)?;
                Ok(())
            }
            None => Err(Error::UpcastError("Need a SignatureScheme to upcast a Signature")),
        }
    }
}

impl CryptoUpcast for crate::crypto::ecies::EciesCiphertext {
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<(), Error> {
        self.ephemeral_public_key.upcast_crypto_values(ctx)
    }
}

impl CryptoUpcast for crate::credential::BasicCredential {
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<(), Error> {
        let mut new_ctx = *ctx;
        new_ctx.ss = Some(self.signature_scheme);
        self.public_key.upcast_crypto_values(&new_ctx)
    }
}

impl CryptoUpcast for Credential {
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<(), Error> {
        match self {
            Credential::Basic(b) => {
                let mut new_ctx = *ctx;
                new_ctx.ss = Some(b.signature_scheme);
                b.upcast_crypto_values(&new_ctx)
            }
            _ => Ok(()),
        }
    }
}

impl CryptoUpcast for crate::group_state::WelcomeInfo {
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<(), Error> {
        for cred_opt in self.roster.0.iter_mut() {
            if let Some(cred) = cred_opt.as_mut() {
                cred.upcast_crypto_values(ctx)?;
            }
        }
        Ok(())
    }
}

impl CryptoUpcast for crate::group_state::Welcome {
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<(), Error> {
        let new_ctx = ctx.set_cipher_suite(self.cipher_suite);
        self.encrypted_welcome_info.upcast_crypto_values(&new_ctx)
    }
}

// TODO: URGENT: self.signature should have the variant determined by
// self.credential.signature_scheme. This may require a large refactor.
impl CryptoUpcast for crate::handshake::UserInitKey {
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<(), Error> {
        for (cs, pk) in self.cipher_suites.iter().zip(self.init_keys.iter_mut()) {
            let new_ctx = ctx.set_cipher_suite(cs);
            pk.upcast_crypto_values(&new_ctx)?;
        }
        self.credential.upcast_crypto_values(ctx)?;
        self.signature.upcast_crypto_values(ctx)?;

        Ok(())
    }
}

impl CryptoUpcast for crate::handshake::DirectPathNodeMessage {
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<(), Error> {
        self.public_key.upcast_crypto_values(ctx)?;
        for ct in self.node_secrets.iter_mut() {
            ct.upcast_crypto_values(ctx)?;
        }
        Ok(())
    }
}

impl CryptoUpcast for crate::handshake::DirectPathMessage {
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<(), Error> {
        for node_msg in self.node_messages.iter_mut() {
            node_msg.upcast_crypto_values(ctx)?;
        }
        Ok(())
    }
}

impl CryptoUpcast for crate::handshake::GroupInit {
    // GroupInit is empty; this is a no-op
    fn upcast_crypto_values(&mut self, _ctx: &CryptoCtx) -> Result<(), Error> {
        Ok(())
    }
}

impl CryptoUpcast for crate::handshake::GroupAdd {
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<(), Error> {
        self.init_key.upcast_crypto_values(ctx)
    }
}

impl CryptoUpcast for crate::handshake::GroupUpdate {
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<(), Error> {
        self.path.upcast_crypto_values(ctx)
    }
}

impl CryptoUpcast for crate::handshake::GroupRemove {
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<(), Error> {
        self.path.upcast_crypto_values(ctx)
    }
}

impl CryptoUpcast for crate::handshake::GroupOperation {
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<(), Error> {
        use crate::handshake::GroupOperation::*;
        match self {
            Init(init) => init.upcast_crypto_values(ctx),
            Add(add) => add.upcast_crypto_values(ctx),
            Update(update) => update.upcast_crypto_values(ctx),
            Remove(remove) => remove.upcast_crypto_values(ctx),
        }
    }
}

impl CryptoUpcast for crate::handshake::Handshake {
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<(), Error> {
        self.operation.upcast_crypto_values(ctx)?;
        self.signature.upcast_crypto_values(ctx)?;
        Ok(())
    }
}
