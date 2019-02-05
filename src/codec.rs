use crate::{
    credential::{BasicCredential, Identity},
    crypto::{
        ciphersuite::{CipherSuite, X25519_SHA256_AES128GCM},
        sig::{SignatureScheme, ED25519},
    },
    error::Error,
};

use serde::ser::{Serialize, SerializeStruct, Serializer};

impl<SS: SignatureScheme> Serialize for BasicCredential<SS> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut struct_serializer = serializer.serialize_struct("BasicCredential", 3)?;
        struct_serializer.serialize_field("identity", &self.identity)?;
        // TODO: FINISH
        struct_serializer.end()
    }
}

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
