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
        dh::{DhPrivateKey, DhPublicKey},
        sig::{SigPublicKey, Signature, SignatureScheme},
    },
    error::Error,
    ratchet_tree,
};

/// The context necessary for a `CryptoUpcast`. This specifies the ambient ciphersuite and
/// signature scheme.
#[derive(Clone, Copy)]
pub struct CryptoCtx {
    cs: Option<&'static CipherSuite>,
    ss: Option<&'static dyn SignatureScheme>,
}

// TODO: Figure out when to check for coherence in ciphersuites

impl CryptoCtx {
    /// Makes a new empty `CryptoCtx`
    pub fn new() -> CryptoCtx {
        CryptoCtx {
            cs: None,
            ss: None,
        }
    }

    /// Returns a new `CryptoCtx` object with the specified cipher suite
    pub fn set_cipher_suite(&self, cs: &'static CipherSuite) -> CryptoCtx {
        let mut new_ctx = *self;
        new_ctx.cs = Some(cs);
        new_ctx
    }

    /// Returns a new `CryptoCtx` object with the specified signature scheme
    pub fn set_signature_scheme(&self, ss: &'static SignatureScheme) -> CryptoCtx {
        let mut new_ctx = *self;
        new_ctx.ss = Some(ss);
        new_ctx
    }
}

/// This trait describes how an object's "raw" parts are to be interpreted given the context of the
/// ambient cipher suite and signature scheme. See module documentation for more.
///
/// The reason the method below returns a `CryptoCtx` is because sometimes the signature scheme of
/// one field of the struct is determined by the signature scheme of the other (namely, in the case
/// of `UserInitKey::signature` and `UserInitKey::credential::signature_scheme`). We need a way to
/// propogate that information, so we send it back up to the caller.
pub trait CryptoUpcast {
    #[must_use]
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<CryptoCtx, Error>;
}

impl CryptoUpcast for DhPublicKey {
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<CryptoCtx, Error> {
        let raw = enum_variant!(self, DhPublicKey::Raw);
        match ctx.cs {
            Some(cs) => {
                *self = cs.dh_impl.public_key_from_bytes(raw.0.as_slice())?;
                Ok(*ctx)
            }
            None => Err(Error::UpcastError("Need a CipherSuite to upcast a DhPublicKey")),
        }
    }
}

impl CryptoUpcast for DhPrivateKey {
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<CryptoCtx, Error> {
        // This is a no-op. Since private keys are never serialized, they don't have a "raw"
        // variant like public keys do.
        Ok(*ctx)
    }
}

impl CryptoUpcast for SigPublicKey {
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<CryptoCtx, Error> {
        let raw = enum_variant!(self, SigPublicKey::Raw, "can't upcast a non-raw SigPublicKey");
        match ctx.ss {
            Some(ss) => {
                *self = ss.public_key_from_bytes(&raw.0)?;
                // No change to context
                Ok(*ctx)
            }
            None => Err(Error::UpcastError("Need a SignatureScheme to upcast a SigPublicKey")),
        }
    }
}

impl CryptoUpcast for Signature {
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<CryptoCtx, Error> {
        let raw = enum_variant!(self, Signature::Raw, "can't upcast a non-raw Signature");
        match ctx.ss {
            Some(ss) => {
                *self = ss.signature_from_bytes(&raw.0)?;
                // No change to context
                Ok(*ctx)
            }
            None => Err(Error::UpcastError("Need a SignatureScheme to upcast a Signature")),
        }
    }
}

impl CryptoUpcast for crate::crypto::ecies::EciesCiphertext {
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<CryptoCtx, Error> {
        self.ephemeral_public_key.upcast_crypto_values(ctx)
    }
}

impl<T: CryptoUpcast> CryptoUpcast for Option<T> {
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<CryptoCtx, Error> {
        match self {
            Some(inner) => inner.upcast_crypto_values(ctx),
            None => Ok(*ctx),
        }
    }
}

impl<T: CryptoUpcast> CryptoUpcast for Vec<T> {
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<CryptoCtx, Error> {
        for item in self.iter_mut() {
            item.upcast_crypto_values(ctx)?;
        }
        // No change in context
        Ok(*ctx)
    }
}

impl CryptoUpcast for credential::Roster {
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<CryptoCtx, Error> {
        self.0.upcast_crypto_values(ctx)
    }
}

impl CryptoUpcast for ratchet_tree::RatchetTreeNode {
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<CryptoCtx, Error> {
        if let ratchet_tree::RatchetTreeNode::Filled {
            ref mut public_key,
            ref mut private_key,
        } = self
        {
            public_key.upcast_crypto_values(ctx)?;
            private_key.upcast_crypto_values(ctx)?;
        }
        // No change in context
        Ok(*ctx)
    }
}

impl CryptoUpcast for ratchet_tree::RatchetTree {
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<CryptoCtx, Error> {
        self.nodes.upcast_crypto_values(ctx)
    }
}

impl CryptoUpcast for crate::credential::BasicCredential {
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<CryptoCtx, Error> {
        let new_ctx = ctx.set_signature_scheme(self.signature_scheme);
        self.public_key.upcast_crypto_values(&new_ctx)
    }
}

impl CryptoUpcast for Credential {
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<CryptoCtx, Error> {
        match self {
            Credential::Basic(b) => b.upcast_crypto_values(ctx),
            _ => unimplemented!("Cannot do X.509 upcasting yet"),
        }
    }
}

impl CryptoUpcast for crate::group_state::WelcomeInfo {
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<CryptoCtx, Error> {
        self.roster.upcast_crypto_values(ctx)?;
        self.tree.upcast_crypto_values(ctx)?;
        // No change in context
        Ok(*ctx)
    }
}

impl CryptoUpcast for crate::group_state::Welcome {
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<CryptoCtx, Error> {
        let new_ctx = ctx.set_cipher_suite(self.cipher_suite);
        self.encrypted_welcome_info.upcast_crypto_values(&new_ctx)
    }
}

impl CryptoUpcast for crate::handshake::UserInitKey {
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<CryptoCtx, Error> {
        // Try to upcast the private keys if they're around
        if let Some(ref mut private_keys) = self.private_keys {
            // Each ciphersuite corresponds to a keypair. Upcast both of these with respect to that
            // ciphersuite.
            for ((cs, pubkey), privkey) in self
                .cipher_suites
                .iter()
                .zip(self.init_keys.iter_mut())
                .zip(private_keys.iter_mut())
            {
                let new_ctx = ctx.set_cipher_suite(cs);
                pubkey.upcast_crypto_values(&new_ctx)?;
                privkey.upcast_crypto_values(&new_ctx)?;
            }
        } else {
            // If there are no private keys, just upcast the pubkeys. Each ciphersuite corresponds
            // to a pubkey. Upcast both of these with respect to that ciphersuite.
            for (cs, pubkey) in self.cipher_suites.iter().zip(self.init_keys.iter_mut()) {
                let new_ctx = ctx.set_cipher_suite(cs);
                pubkey.upcast_crypto_values(&new_ctx)?;
            }
        }

        // Use the credential's signature scheme to upcast the signature
        let new_ctx = self.credential.upcast_crypto_values(ctx)?;
        self.signature.upcast_crypto_values(&new_ctx)?;

        Ok(new_ctx)
    }
}

impl CryptoUpcast for crate::handshake::DirectPathNodeMessage {
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<CryptoCtx, Error> {
        self.public_key.upcast_crypto_values(ctx)?;
        for ct in self.node_secrets.iter_mut() {
            ct.upcast_crypto_values(ctx)?;
        }
        // No change to context
        Ok(*ctx)
    }
}

impl CryptoUpcast for crate::handshake::DirectPathMessage {
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<CryptoCtx, Error> {
        for node_msg in self.node_messages.iter_mut() {
            node_msg.upcast_crypto_values(ctx)?;
        }
        // No change to context
        Ok(*ctx)
    }
}

impl CryptoUpcast for crate::handshake::GroupInit {
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<CryptoCtx, Error> {
        // GroupInit is empty; this is a no-op
        Ok(*ctx)
    }
}

impl CryptoUpcast for crate::handshake::GroupAdd {
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<CryptoCtx, Error> {
        self.init_key.upcast_crypto_values(ctx)
    }
}

impl CryptoUpcast for crate::handshake::GroupUpdate {
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<CryptoCtx, Error> {
        self.path.upcast_crypto_values(ctx)
    }
}

impl CryptoUpcast for crate::handshake::GroupRemove {
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<CryptoCtx, Error> {
        self.path.upcast_crypto_values(ctx)
    }
}

impl CryptoUpcast for crate::handshake::GroupOperation {
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<CryptoCtx, Error> {
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
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<CryptoCtx, Error> {
        self.operation.upcast_crypto_values(ctx)?;
        self.signature.upcast_crypto_values(ctx)?;
        // No change to context
        Ok(*ctx)
    }
}

impl CryptoUpcast for crate::application::ApplicationMessage {
    fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<CryptoCtx, Error> {
        // No-op
        Ok(*ctx)
    }
}
