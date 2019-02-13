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
struct EciesCiphertext<'a> {
    /// Pubkey the ciphertext is encrypted under
    ephemeral_public_key: DhPoint,
    /// The payload
    // opaque ciphertext<0..255>;
    ciphertext: &'a mut [u8],
}

/// Performs an ECIES encryption of a given plaintext under a given DH public key.
///
/// Requires: `plaintext` must have the form `message || extra` where `extra` is the tag length of
/// the underlying authenticated encryption algorithm
fn ecies_encrypt<'a>(
    cs: &CipherSuite,
    others_public_key: &DhPoint,
    plaintext: &'a mut [u8],
    csprng: &mut dyn CryptoRng,
) -> Result<EciesCiphertext<'a>, Error> {
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

    cs.aead_impl.seal(&key, nonce, plaintext)?;
    // Rename for clarity
    let ciphertext = plaintext;

    let ret = EciesCiphertext {
        ephemeral_public_key: my_ephemeral_public_key,
        ciphertext: ciphertext,
    };
    Ok(ret)
}

/// Performs an ECIES decryption of a given ciphertext under a given DH ephemeral public key and
/// known secret
///
/// Returns: `Ok(plaintext)` on success, where `plaintext` is a `&mut [u8]` to the decrypted
/// plaintext corresponding to the ciphertext. Returns some sort of `Error` otherwise.
fn ecies_decrypt<'a>(
    cs: &CipherSuite,
    my_secret_key: &DhScalar,
    EciesCiphertext {
        ephemeral_public_key,
        ciphertext,
    }: EciesCiphertext<'a>,
) -> Result<&'a mut [u8], Error> {
    // This is `abP` where `bP` is the other person's public key is `bP` and my secret key is `a`
    let shared_secret = cs
        .dh_impl
        .diffie_hellman(&my_secret_key, &ephemeral_public_key);
    let shared_secret_bytes = cs.dh_impl.point_as_bytes(&shared_secret);

    let (key, nonce) = derive_ecies_key_nonce(cs, &shared_secret_bytes);
    cs.aead_impl.open(&key, nonce, ciphertext)
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
    let serialized_key_label =
        crate::tls_ser::serialize_to_bytes(&key_label).expect("couldn't serialize ECIES key label");
    let serialized_nonce_label = crate::tls_ser::serialize_to_bytes(&nonce_label)
        .expect("couldn't serialize ECIES nonce label");

    // This is the keying information that we will expand
    let prk = ring::hmac::SigningKey::new(cs.hash_alg, &shared_secret_bytes);

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

    const CIPHERSUITES: &[CipherSuite] = &[X25519_SHA256_AES128GCM];

    #[quickcheck]
    fn ecies_correctness(plaintext: Vec<u8>, rng_seed: u64) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(rng_seed);

        for cs in CIPHERSUITES {
            // Make sure there's enough room in the plaintext for the tag
            let mut extended_plaintext =
                [plaintext.clone(), vec![0u8; cs.aead_impl.tag_size()]].concat();

            // First make an identity we'll encrypt to
            let alice_scalar = cs.dh_impl.scalar_from_random(&mut rng).unwrap();
            let alice_point = cs.dh_impl.multiply_basepoint(&alice_scalar);

            // Now encrypt to Alice
            let ecies_ciphertext: EciesCiphertext = ecies_encrypt(
                cs,
                &alice_point,
                extended_plaintext.as_mut_slice(),
                &mut rng,
            )
            .expect(&format!(
                "failed to encrypt ECIES plaintext; ciphersuite {}",
                cs.name
            ));

            // Now let Alice decrypt it
            let recovered_plaintext = ecies_decrypt(cs, &alice_scalar, ecies_ciphertext)
                .expect(&format!(
                    "failed to decrypt ECIES ciphertext; ciphersuite {}",
                    cs.name
                ))
                .to_vec();

            assert_eq!(recovered_plaintext, plaintext);
        }
    }
}
