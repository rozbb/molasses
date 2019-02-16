use crate::crypto::sig::{SigPublicKey, SignatureScheme};

// TODO: Decide whether we check the size on the lower end while (de)serializing

// opaque cert_data<1..2^24-1>;
#[derive(Deserialize, Serialize)]
#[serde(rename = "X509CertData__bound_u24")]
pub(crate) struct X509CertData(Vec<u8>);

// opaque identity<0..2^16-1>;
#[derive(Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename = "Identity__bound_u16")]
pub(crate) struct Identity(pub(crate) Vec<u8>);

pub(crate) struct BasicCredential {
    pub(crate) identity: Identity,
    pub(crate) signature_scheme: &'static SignatureScheme,
    pub(crate) public_key: SigPublicKey,
}

#[derive(Serialize)]
pub(crate) enum Credential {
    Basic(BasicCredential),
    X509(X509CertData),
}
