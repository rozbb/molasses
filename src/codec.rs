use crate::crypto::{
    ciphersuite::{CipherSuite, X25519_SHA256_AES128GCM},
    dh::{DhPublicKey, DhPublicKeyRaw},
    sig::{SigPublicKey, SigPublicKeyRaw, Signature, SignatureRaw, SignatureScheme, ED25519_IMPL},
};

use serde::{
    de::{Deserialize, Deserializer},
    ser::{Serialize, SerializeStruct, Serializer},
};

// TODO: These always return the 25519 impl, because I don't have P-256, and I need deserialization
// to function correctly for testing. Doing what I'm doing here may significantly impact security.
// This should be made correct ASAP

const CIPHERSUITE_NAME_IDS: &'static [(&'static CipherSuite, &'static str, u16)] = &[
    (&X25519_SHA256_AES128GCM, "X25519_SHA256_AES128GCM", 0x0000), // FAKE
    (&X25519_SHA256_AES128GCM, "X25519_SHA256_AES128GCM", 0x0001),
];
const SIGSCHEME_NAME_IDS: &'static [(&'static dyn SignatureScheme, &'static str, u16)] = &[
    (&ED25519_IMPL, "ed25519", 0x0403), // FAKE
    (&ED25519_IMPL, "ed25519", 0x0807),
];

// Implement Serialize for our CipherSuites and SignatureSchemes. This just serializes their ID

impl Serialize for CipherSuite {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        for (_, name, id) in CIPHERSUITE_NAME_IDS {
            if &self.name == name {
                return serializer.serialize_u16(*id);
            }
        }
        panic!("tried to serialize unknown ciphersuite");
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
                    "could not deserialize {:x} into cipher suite",
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
        panic!("tried to serialize unknown signature scheme");
    }
}

impl<'de> Deserialize<'de> for &'static SignatureScheme {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = &'static dyn SignatureScheme;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a u16 representing a signature scheme")
            }

            fn visit_u16<E>(self, value: u16) -> Result<&'static dyn SignatureScheme, E>
            where
                E: serde::de::Error,
            {
                for (ss, _, id) in SIGSCHEME_NAME_IDS {
                    if value == *id {
                        return Ok(*ss);
                    }
                }
                Err(E::custom(format_args!(
                    "could not deserialize {:x} into signature scheme",
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
        // Deserialize everything as a raw vec. We deal with variants in CipherSuiteUpcast
        DhPublicKeyRaw::deserialize(deserializer).map(|raw| DhPublicKey::Raw(raw))
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
        // Deserialize everything as a raw vec. We deal with variants in CipherSuiteUpcast
        SigPublicKeyRaw::deserialize(deserializer).map(|raw| SigPublicKey::Raw(raw))
    }
}

impl Serialize for Signature {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // If it's not already, convert it to a Raw signature, then serialize that
        match self {
            Signature::Raw(p) => p.serialize(serializer),
            p => SignatureRaw(p.to_bytes().to_vec()).serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Deserialize everything as a raw vec. We deal with variants in CipherSuiteUpcast
        SignatureRaw::deserialize(deserializer).map(|raw| Signature::Raw(raw))
    }
}
