use crate::crypto::SignatureScheme;

// opaque cert_data<1..2^24-1>;
struct X509CertData(Vec<u8>);

// opaque identity<0..2^16-1>;
struct Identity(Vec<u8>);

struct BasicCredential<SS: SignatureScheme> {
    identity: Identity,
    signature_scheme: SS,
    public_key: SS::PublicKey,
}

enum Credential<SS: SignatureScheme> {
    Basic(BasicCredential<SS>),
    X509(X509CertData),
}
