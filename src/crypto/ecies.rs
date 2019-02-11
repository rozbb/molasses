use crate::crypto::{
    aead::{AeadKey, AeadNonce},
    ciphersuite::CipherSuite,
    dh::{DhPoint, DhScalar},
    rng::CryptoRng,
};
use crate::error::Error;

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
struct EciesCiphertext {
    /// Pubkey the ciphertext is encrypted under
    ephemeral_public_key: DhPoint,
    /// The payload
    // opaque ciphertext<0..255>;
    ciphertext: Vec<u8>,
}

/// Performs an ECIES encryption of a given plaintext under a given DH public key
fn ecies_encrypt(
    cs: &CipherSuite,
    others_public_key: &DhPoint,
    plaintext: Vec<u8>,
    csprng: &mut dyn CryptoRng,
) -> Result<EciesCiphertext, Error> {
    // Denote this by `a`
    let my_ephemeral_secret = cs.dh_impl.scalar_from_random(csprng)?;
    // Denote this by `aP`
    let my_ephemeral_public_key = cs.dh_impl.multiply_basepoint(&my_ephemeral_secret);

    // This is `abP` where `bP` is the other person's public key is `bP`
    let shared_secret = cs
        .dh_impl
        .diffie_hellman(&my_ephemeral_secret, &others_public_key);
    let shared_secret_bytes = cs.dh_impl.point_as_bytes(&shared_secret);

    let (key, nonce) = derive_ecies_key_nonce(cs, &shared_secret_bytes);

    let ciphertext = cs.aead_impl.seal(&key, nonce, plaintext)?;

    let ret = EciesCiphertext {
        ephemeral_public_key: my_ephemeral_public_key,
        ciphertext: ciphertext,
    };
    Ok(ret)
}

fn ecies_decrypt(
    cs: &CipherSuite,
    my_secret_key: &DhScalar,
    EciesCiphertext {
        ephemeral_public_key,
        mut ciphertext,
    }: EciesCiphertext,
) -> Result<Vec<u8>, Error> {
    // This is `abP` where `bP` is the other person's public key is `bP` and my secret key is `a`
    let shared_secret = cs
        .dh_impl
        .diffie_hellman(&my_secret_key, &ephemeral_public_key);
    let shared_secret_bytes = cs.dh_impl.point_as_bytes(&shared_secret);

    let (key, nonce) = derive_ecies_key_nonce(cs, &shared_secret_bytes);
    let out_len = cs
        .aead_impl
        .open(&key, nonce, ciphertext.as_mut_slice())?
        .len();
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
fn derive_ecies_key_nonce(cs: &CipherSuite, shared_secret_bytes: &[u8]) -> (AeadKey, AeadNonce) {
    let key_label = EciesLabel::new(b"key", cs.aead_impl.key_size() as u16);
    let nonce_label = EciesLabel::new(b"nonce", cs.aead_impl.nonce_size() as u16);

    // We're gonna used the serialized labels as the `info` parameter to HKDF-Expand
    let serialized_key_label = crate::tls_ser::serialize_to_bytes(&key_label)
        .expect("couldn't serialize ECIES key label");
    let serialized_nonce_label = crate::tls_ser::serialize_to_bytes(&nonce_label)
        .expect("couldn't serialize ECIES nonce label");

    // This is the keying information that we will expand
    let prk = ring::hmac::SigningKey::new(cs.hash_alg, &shared_secret_bytes);

    // TODO: Once it's possible to do so, I want
    // key_buf: [u8; <CS::Aead as AuthenticatedEncryption>::KEY_SIZE]. And ditto for
    // nonce_buf. This is blocked on https://github.com/rust-lang/rust/issues/39211
    let mut key_buf = vec![0u8; cs.aead_impl.key_size()];
    let mut nonce_buf = vec![0u8; cs.aead_impl.nonce_size()];

    ring::hkdf::expand(&prk, &serialized_key_label, &mut key_buf[..]);
    ring::hkdf::expand(&prk, &serialized_nonce_label, &mut nonce_buf[..]);

    let key = cs
        .aead_impl
        .key_from_bytes(&key_buf)
        .expect("couldn't derive AEAD key from HKDF");
    let nonce = cs
        .aead_impl
        .nonce_from_bytes(&nonce_buf)
        .expect("couldn't derive AEAD nonce from HKDF");

    (key, nonce)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::crypto::ciphersuite::X25519_SHA256_AES128GCM;

    use quickcheck_macros::quickcheck;
    use rand::SeedableRng;

    // TODO: Test over all ciphersuites. I think this is gonna require a big refactor. If x: X you
    // can't say x::foo() if foo() is an associated function to X. You have to do X::foo(). So I
    // think I'm going to turn all the Struct::method things into object.method and instead of
    // associated types I'll do consts that are static refs to empty objects that implement all
    // these methods.

    const CIPHERSUITES: &[CipherSuite] = &[X25519_SHA256_AES128GCM];

    #[quickcheck]
    fn ecies_correctness(plaintext: Vec<u8>, rng_seed: u64) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(rng_seed);

        for cs in CIPHERSUITES {
            println!("Current ciphersuite: {}", cs.name);

            // First make an identity we'll encrypt to
            let alice_scalar = cs.dh_impl.scalar_from_random(&mut rng).unwrap();
            let alice_point = cs.dh_impl.multiply_basepoint(&alice_scalar);

            // Now encrypt to Alice
            let ecies_ciphertext: EciesCiphertext =
                ecies_encrypt(cs, &alice_point, plaintext.clone(), &mut rng)
                    .expect("failed to encrypt with ECIES");
            // Now let Alice decrypt it
            let recovered_plaintext: Vec<u8> = ecies_decrypt(cs, &alice_scalar, ecies_ciphertext)
                .expect("failed to decrypt ECIES ciphertext");

            assert_eq!(recovered_plaintext, plaintext);
        }
    }
}
