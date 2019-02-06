use crate::crypto::{aead::AuthenticatedEncryption, ciphersuite::CipherSuite, dh::DiffieHellman};
use crate::error::Error;

use hmac::Hmac;

/// A label struct used for ECIES key/nonce derivation
#[derive(Serialize, Deserialize)]
struct EciesLabel {
    length: u16,
    // opaque label<12..255> = "mls10 ecies " + Label;
    #[serde(rename = "label__bound_u8")]
    label: Vec<u8>,
}

impl EciesLabel {
    fn new(label: &[u8], length: u16) -> EciesLabel {
        EciesLabel {
            length: length,
            label: [b"mls10 ecies ", label].concat(),
        }
    }
}

/// A short ciphertext encrypted with the enclosed ephemeral DH key
struct EciesCiphertext<CS: CipherSuite> {
    /// Pubkey the ciphertext is encrypted under
    ephemeral_public_key: <CS::DH as DiffieHellman>::Point,
    /// The payload
    // opaque ciphertext<0..255>;
    ciphertext: Vec<u8>,
}

/// Performs an ECIES encryption of a given plaintext under a given DH public key
fn ecies_encrypt<CS, R>(
    others_public_key: &<CS::DH as DiffieHellman>::Point,
    plaintext: Vec<u8>,
    csprng: &mut R,
) -> Result<EciesCiphertext<CS>, Error>
where
    CS: CipherSuite,
    R: rand::Rng + rand::CryptoRng,
{
    // Denote this by `a`
    let my_ephemeral_secret = <CS::DH as DiffieHellman>::scalar_from_random(csprng)?;
    // Denote this by `aP`
    let my_ephemeral_public_key =
        <CS::DH as DiffieHellman>::multiply_basepoint(&my_ephemeral_secret);

    // This is `abP` where `bP` is the other person's public key is `bP`
    let shared_secret =
        <CS::DH as DiffieHellman>::diffie_hellman(&my_ephemeral_secret, &others_public_key);
    let shared_secret_bytes = <CS::DH as DiffieHellman>::point_as_bytes(&shared_secret);

    let (key, nonce) = derive_ecies_key_nonce::<CS>(&shared_secret_bytes);

    let ciphertext = <CS::Aead as AuthenticatedEncryption>::seal(&key, nonce, plaintext)?;

    let ret = EciesCiphertext {
        ephemeral_public_key: my_ephemeral_public_key,
        ciphertext: ciphertext,
    };
    Ok(ret)
}

fn ecies_decrypt<CS>(
    my_secret_key: &<CS::DH as DiffieHellman>::Scalar,
    EciesCiphertext {
        ephemeral_public_key,
        mut ciphertext,
    }: EciesCiphertext<CS>,
) -> Result<Vec<u8>, Error>
where
    CS: CipherSuite,
{
    // This is `abP` where `bP` is the other person's public key is `bP` and my secret key is `a`
    let shared_secret =
        <CS::DH as DiffieHellman>::diffie_hellman(&my_secret_key, &ephemeral_public_key);
    let shared_secret_bytes = <CS::DH as DiffieHellman>::point_as_bytes(&shared_secret);

    let (key, nonce) = derive_ecies_key_nonce::<CS>(&shared_secret_bytes);
    let out_len =
        <CS::Aead as AuthenticatedEncryption>::open(&key, nonce, ciphertext.as_mut_slice())?.len();
    // Decryption was done in-place
    let mut plaintext = ciphertext;
    // However, it still has the tag on the end. Remove everything after the end of the plaintext
    plaintext.truncate(out_len);

    Ok(plaintext)
}

// From the spec:
//     key = HKDF-Expand(Secret, ECIESLabel("key"), Length)
//     nonce = HKDF-Expand(Secret, ECIESLabel("nonce"), Length)
//
//     Where ECIESLabel is specified as:
//
//     struct {
//       uint16 length = Length;
//       opaque label<12..255> = "mls10 ecies " + Label;
//     } ECIESLabel;
// I think that the Length specified above is supposed to be different for keys and nonces, since
// it wouldn't make sense otherwise, so I've done that and hope I'm right.
fn derive_ecies_key_nonce<CS: CipherSuite>(
    shared_secret_bytes: &[u8],
) -> (
    <CS::Aead as AuthenticatedEncryption>::Key,
    <CS::Aead as AuthenticatedEncryption>::Nonce,
) {
    let key_label = EciesLabel::new(
        b"key",
        <CS::Aead as AuthenticatedEncryption>::KEY_SIZE as u16,
    );
    let nonce_label = EciesLabel::new(
        b"nonce",
        <CS::Aead as AuthenticatedEncryption>::NONCE_SIZE as u16,
    );
    // We're gonna used the serialized labels as the `info` parameter to HKDF-Expand
    let serialized_key_label = crate::tls_ser::serialize_to_bytes(&key_label);
    let serialized_nonce_label = crate::tls_ser::serialize_to_bytes(&nonce_label);

    // This is the keying information that we will expand
    let prk = ring::hmac::SigningKey::new(CS::HASH_ALG, &shared_secret_bytes);

    // TODO: Once it's possible to do so, I want
    // key_buf: [u8; <CS::Aead as AuthenticatedEncryption>::KEY_SIZE]. And ditto for
    // nonce_buf. This is blocked on https://github.com/rust-lang/rust/issues/39211
    let mut key_buf = vec![0u8; <CS::Aead as AuthenticatedEncryption>::KEY_SIZE];
    let mut nonce_buf = vec![0u8; <CS::Aead as AuthenticatedEncryption>::NONCE_SIZE];

    ring::hkdf::expand(&prk, &serialized_key_label, &mut key_buf[..]);
    ring::hkdf::expand(&prk, &serialized_nonce_label, &mut nonce_buf[..]);

    let key = <CS::Aead as AuthenticatedEncryption>::key_from_bytes(&key_buf)
        .expect("couldn't derive AEAD key from HKDF");
    let nonce = <CS::Aead as AuthenticatedEncryption>::nonce_from_bytes(&nonce_buf)
        .expect("couldn't derive AEAD nonce from HKDF");
    (key, nonce)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::crypto::{ciphersuite::X25519_SHA256_AES128GCM, dh::X25519};

    use quickcheck_macros::quickcheck;
    use rand::SeedableRng;

    // TODO: Test over all ciphersuites. I think this is gonna require a big refactor. If x: X you
    // can't say x::foo() if foo() is an associated function to X. You have to do X::foo(). So I
    // think I'm going to turn all the Struct::method things into object.method and instead of
    // associated types I'll do consts that are static refs to empty objects that implement all
    // these methods.

    #[quickcheck]
    fn ecies_correctness(plaintext: Vec<u8>, rng_seed: u64) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(rng_seed);
        // First make an identity we'll encrypt to
        let alice_scalar = X25519::scalar_from_random(&mut rng).unwrap();
        let alice_point = X25519::multiply_basepoint(&alice_scalar);

        // Now encrypt to Alice
        let ecies_ciphertext: EciesCiphertext<X25519_SHA256_AES128GCM> =
            ecies_encrypt(&alice_point, plaintext.clone(), &mut rng)
                .expect("failed to encrypt under ECIES");
        // Now let Alice decrypt it
        let recovered_plaintext = ecies_decrypt(&alice_scalar, ecies_ciphertext)
            .expect("failed to decrypt ECIES ciphertext");

        assert_eq!(recovered_plaintext, plaintext);
    }
}
