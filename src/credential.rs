use crate::crypto::sig::{SigPublicKey, SignatureScheme};

// TODO: Decide whether we check the size on the lower end while (de)serializing

// opaque cert_data<1..2^24-1>;
/// A bunch of bytes representing an X.509 certificate. This currently doesn't do anything.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename = "X509CertData__bound_u24")]
pub(crate) struct X509CertData(Vec<u8>);

// opaque identity<0..2^16-1>;
/// A bytestring that should uniquely identify the user in the Group
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename = "Identity__bound_u16")]
pub(crate) struct Identity(pub(crate) Vec<u8>);

/// Defines a simple user credential consisting of a user ID, the user's preferred signature
/// scheme, and the user's public key under said signature scheme.
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct BasicCredential {
    pub(crate) identity: Identity,
    pub(crate) signature_scheme: &'static dyn SignatureScheme,
    pub(crate) public_key: SigPublicKey,
}

/// A user credential, as defined in section 5.6 of the MLS spec
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename = "Credential__enum_u8")]
pub(crate) enum Credential {
    Basic(BasicCredential),
    X509(X509CertData),
}

impl Credential {
    pub(crate) fn get_public_key(&self) -> &SigPublicKey {
        match &self {
            Credential::Basic(basic) => &basic.public_key,
            Credential::X509(_) => unimplemented!(),
        }
    }
}
