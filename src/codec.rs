use crate::crypto::{
    ciphersuite::{CipherSuite, X25519_SHA256_AES128GCM},
    sig::{Signature, SignatureScheme, ED25519_IMPL},
};

use serde::{
    de::{Deserialize, Deserializer},
    ser::{Serialize, SerializeStruct, Serializer},
};

const CIPHERSUITE_NAME_IDS: &'static [(&'static CipherSuite, &'static str, u16)] =
    &[(&X25519_SHA256_AES128GCM, "X25519_SHA256_AES128GCM", 0x0001)];
const SIGSCHEME_NAME_IDS: &'static [(&'static SignatureScheme, &'static str, u16)] =
    &[(&ED25519_IMPL, "ED25519", 0x0807)];

// Implement Serialize for our CipherSuites and SignatureSchemes. This just serializes their ID

impl Serialize for CipherSuite {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        for (_, name, id) in CIPHERSUITE_NAME_IDS {
            if &self.name == name {
                return serializer.serialize_u16(*id);
            }
        }
        panic!("tried to serialize unknown ciphersuite");
    }
}

impl<'de> Deserialize<'de> for &'static CipherSuite {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
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
                Err(E::custom(format!(
                    "could not deserialize {:x} into cipher suite",
                    value
                )))
            }
        }

        deserializer.deserialize_u16(Visitor)
    }
}

impl Serialize for SignatureScheme {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        for (_, name, id) in SIGSCHEME_NAME_IDS {
            if &self.name == name {
                return serializer.serialize_u16(*id);
            }
        }
        panic!("tried to serialize unknown signature scheme");
    }
}

impl<'de> Deserialize<'de> for &'static SignatureScheme {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
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
                        return Ok(ss);
                    }
                }
                Err(E::custom(format!(
                    "could not deserialize {:x} into signature scheme",
                    value
                )))
            }
        }

        deserializer.deserialize_u16(Visitor)
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Signature::Ed25519Signature(sig) => {
                let bytes = sig.to_bytes();
                (&bytes).serialize(serializer)
            }
        }
    }
}
