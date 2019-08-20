//! Defines specialized serialization and deserialization routines for various types

use crate::crypto::{
    aead::{AeadNonce, AeadNonceRaw},
    ciphersuite::{CipherSuite, P256_SHA256_AES128GCM, X25519_SHA256_AES128GCM},
    dh::{DhPublicKey, DhPublicKeyRaw},
    hash::{Digest, DigestRaw},
    hkdf::{HkdfSalt, HkdfSaltRaw},
    sig::{
        SigPublicKey, SigPublicKeyRaw, Signature, SignatureRaw, SignatureScheme, ECDSA_P256_IMPL,
        ED25519_IMPL,
    },
};

use serde::{
    de::{Deserialize, Deserializer},
    ser::{Serialize, Serializer},
};

static CIPHERSUITE_NAME_IDS: &[(&CipherSuite, &str, u16)] = &[
    (&P256_SHA256_AES128GCM, "P256_SHA256_AES128GCM", 0x0000),
    (&X25519_SHA256_AES128GCM, "X25519_SHA256_AES128GCM", 0x0001),
];
static SIGSCHEME_NAME_IDS: &[(&SignatureScheme, &str, u16)] = &[
    (&ECDSA_P256_IMPL, "dummy_ecdsa_secp256r1_sha256", 0x0403),
    (&ED25519_IMPL, "ed25519", 0x0807),
];

// Implement Serialize for our CipherSuites and SignatureSchemes. This just serializes their ID

impl Serialize for CipherSuite {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let my_name = self.name;
        for (_, name, id) in CIPHERSUITE_NAME_IDS {
            if name == &my_name {
                return serializer.serialize_u16(*id);
            }
        }
        panic!("tried to serialize unknown ciphersuite: {}", self.name);
    }
}

impl<'de> Deserialize<'de> for &'static CipherSuite {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Make a visitor type that just deserializes from u8 to an enum variant
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = &'static CipherSuite;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a u16 representing a cipher suite")
            }

            fn visit_u16<E>(self, value: u16) -> Result<&'static CipherSuite, E>
            where
                E: serde::de::Error,
            {
                for (cs, _, id) in CIPHERSUITE_NAME_IDS {
                    if value == *id {
                        return Ok(cs);
                    }
                }
                Err(E::custom(format_args!(
                    "could not deserialize 0x{:04x} into cipher suite",
                    value
                )))
            }
        }

        deserializer.deserialize_u16(Visitor)
    }
}

impl Serialize for SignatureScheme {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let my_name = self.name();
        for (_, name, id) in SIGSCHEME_NAME_IDS {
            if name == &my_name {
                return serializer.serialize_u16(*id);
            }
        }
        panic!("tried to serialize unknown signature scheme: {}", my_name);
    }
}

impl<'de> Deserialize<'de> for &'static SignatureScheme {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = &'static SignatureScheme;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a u16 representing a signature scheme")
            }

            fn visit_u16<E>(self, value: u16) -> Result<&'static SignatureScheme, E>
            where
                E: serde::de::Error,
            {
                for (ss, _, id) in SIGSCHEME_NAME_IDS {
                    if value == *id {
                        return Ok(*ss);
                    }
                }
                Err(E::custom(format_args!(
                    "could not deserialize 0x{:04x} into signature scheme",
                    value
                )))
            }
        }

        deserializer.deserialize_u16(Visitor)
    }
}

impl Serialize for DhPublicKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // If it's not already, convert it to a Raw public key, then serialize that
        match self {
            DhPublicKey::Raw(p) => p.serialize(serializer),
            p => DhPublicKeyRaw(p.as_bytes().to_vec()).serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for DhPublicKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Deserialize everything as a raw vec. We deal with variants in CryptoUpcast
        DhPublicKeyRaw::deserialize(deserializer).map(DhPublicKey::Raw)
    }
}

impl Serialize for SigPublicKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // If it's not already, convert it to a Raw public key, then serialize that
        match self {
            SigPublicKey::Raw(p) => p.serialize(serializer),
            p => SigPublicKeyRaw(p.as_bytes().to_vec()).serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for SigPublicKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Deserialize everything as a raw vec. We deal with variants in CryptoUpcast
        SigPublicKeyRaw::deserialize(deserializer).map(SigPublicKey::Raw)
    }
}

impl Serialize for Signature {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // If it's not already, convert it to a Raw signature, then serialize that
        match self {
            Signature::Raw(p) => p.serialize(serializer),
            p => SignatureRaw(p.as_bytes().to_vec()).serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Deserialize everything as a raw vec. We deal with variants in CryptoUpcast
        SignatureRaw::deserialize(deserializer).map(Signature::Raw)
    }
}

impl Serialize for AeadNonce {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // If it's not already, convert it to a Raw signature, then serialize that
        match self {
            AeadNonce::Raw(p) => p.serialize(serializer),
            p => AeadNonceRaw(p.as_bytes().to_vec()).serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for AeadNonce {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Deserialize everything as a raw vec. We deal with variants in CryptoUpcast
        AeadNonceRaw::deserialize(deserializer).map(AeadNonce::Raw)
    }
}

impl Serialize for HkdfSalt {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // If it's not already, convert it to a Raw salt, then serialize that
        match self {
            HkdfSalt::Raw(p) => p.serialize(serializer),
            p => HkdfSaltRaw(p.as_bytes().to_vec()).serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for HkdfSalt {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Deserialize everything as a raw vec. We deal with variants in CryptoUpcast
        HkdfSaltRaw::deserialize(deserializer).map(HkdfSalt::Raw)
    }
}

impl Serialize for Digest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // If it's not already, convert it to a Raw digest, then serialize that
        match self {
            Digest::Raw(p) => p.serialize(serializer),
            p => DigestRaw(p.as_bytes().to_vec()).serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Deserialize everything as a raw vec. We deal with variants in CryptoUpcast
        DigestRaw::deserialize(deserializer).map(Digest::Raw)
    }
}
