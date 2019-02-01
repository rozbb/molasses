use crate::crypto::{
    ciphersuite::{CipherSuite, X25519_SHA256_AES128GCM},
    sig::{SignatureScheme, ED25519},
};

use serde::ser::{Serialize, Serializer};

// Implement Serialize for our CipherSuites and SignatureSchemes. This just serializes their ID

impl Serialize for X25519_SHA256_AES128GCM {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u16(<X25519_SHA256_AES128GCM as CipherSuite>::ID)
    }
}

impl Serialize for ED25519 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u16(<ED25519 as SignatureScheme>::ID)
    }
}
