//! Defines the data structures that relate to user identity and long-term keys

use crate::crypto::sig::{SigPublicKey, SignatureScheme};

// opaque cert_data<1..2^24-1>;
/// A bunch of bytes representing an X.509 certificate.
///
/// NOTE: This currently doesn't do anything.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename = "X509CertData__bound_u24")]
pub struct X509CertData(Vec<u8>);

// opaque identity<0..2^16-1>;
/// A bytestring that should uniquely identify the user in the Group
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename = "Identity__bound_u16")]
pub struct Identity(pub(crate) Vec<u8>);

impl Identity {
    /// Makes an `Identity` from the given bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Identity {
        Identity(bytes)
    }

    /// Returns a reference to the identity information
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

/// A user credential without respect to any standard credential format
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BasicCredential {
    /// This is a user ID
    pub(crate) identity: Identity,

    /// The member's preferred signature scheme
    pub(crate) signature_scheme: &'static SignatureScheme,

    /// The member's public key under said signature scheme
    pub(crate) public_key: SigPublicKey,
}

impl BasicCredential {
    /// Makes a new credential with the given information
    pub fn new(
        identity: Identity,
        ss: &'static SignatureScheme,
        public_key: SigPublicKey,
    ) -> BasicCredential {
        BasicCredential {
            identity,
            signature_scheme: ss,
            public_key,
        }
    }
}

/// A user credential specifies the member's identity, public signing key, and signature scheme the
/// member will use to sign messages
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename = "Credential__enum_u8")]
pub enum Credential {
    Basic(BasicCredential),
    X509(X509CertData),
}

impl Credential {
    pub(crate) fn get_public_key(&self) -> &SigPublicKey {
        match self {
            Credential::Basic(ref basic) => &basic.public_key,
            Credential::X509(_) => unimplemented!(),
        }
    }

    pub(crate) fn get_signature_scheme(&self) -> &'static SignatureScheme {
        match self {
            Credential::Basic(ref basic) => basic.signature_scheme,
            Credential::X509(_) => unimplemented!(),
        }
    }

    pub fn get_identity(&self) -> &Identity {
        match self {
            Credential::Basic(ref basic) => &basic.identity,
            Credential::X509(_) => unimplemented!(),
        }
    }
}
