use crate::crypto::sig::{SigPublicKey, SigSecretKey, SignatureScheme};

// TODO: Decide whether we check the size on the lower end while (de)serializing

/// A `Roster`, as it appears in a `GroupState`, is a list of optional `Credential`s
pub(crate) type Roster = Vec<Option<Credential>>;

// opaque cert_data<1..2^24-1>;
/// A bunch of bytes representing an X.509 certificate. This currently doesn't do anything.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename = "X509CertData__bound_u24")]
pub(crate) struct X509CertData(Vec<u8>);

// opaque identity<0..2^16-1>;
/// A bytestring that should uniquely identify the user in the Group
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename = "Identity__bound_u16")]
pub(crate) struct Identity(pub(crate) Vec<u8>);

/// Defines a simple user credential
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct BasicCredential {
    /// This is a user ID
    pub(crate) identity: Identity,

    /// The member's preferred signature scheme
    pub(crate) signature_scheme: &'static dyn SignatureScheme,

    /// The member's public key under said signature scheme
    pub(crate) public_key: SigPublicKey,
}

/// A user credential, as defined in section 5.6 of the MLS spec
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename = "Credential__enum_u8")]
pub(crate) enum Credential {
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

    pub(crate) fn get_signature_scheme(&self) -> &'static dyn SignatureScheme {
        match self {
            Credential::Basic(ref basic) => basic.signature_scheme,
            Credential::X509(_) => unimplemented!(),
        }
    }

    pub(crate) fn get_identity(&self) -> &Identity {
        match self {
            Credential::Basic(ref basic) => &basic.identity,
            Credential::X509(_) => unimplemented!(),
        }
    }
}
