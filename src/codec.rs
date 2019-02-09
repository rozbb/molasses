use crate::{
    credential::{BasicCredential, Identity},
    crypto::{ciphersuite::CipherSuite, sig::SignatureScheme},
    error::Error,
};

use serde::ser::{Serialize, SerializeStruct, Serializer};

impl Serialize for BasicCredential {
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

impl Serialize for CipherSuite {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u16(self.id)
    }
}

impl Serialize for SignatureScheme {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u16(self.id)
    }
}
