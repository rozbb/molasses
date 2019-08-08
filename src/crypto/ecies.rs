use crate::crypto::{
    aead::{AeadKey, AeadNonce},
    ciphersuite::CipherSuite,
    dh::{DhPrivateKey, DhPublicKey},
    hkdf,
    hmac::HmacKey,
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
            length,
            label: [b"mls10 ecies ", label].concat(),
        }
    }
}

/// A short ciphertext encrypted with the enclosed ephemeral DH key
#[derive(Clone, Deserialize, Serialize)]
#[cfg_attr(test, derive(Debug))]
pub(crate) struct EciesCiphertext {
    /// Pubkey the ciphertext is encrypted under
    pub(crate) ephemeral_public_key: DhPublicKey,
    /// The payload
    // opaque ciphertext<0..2^32-1>;
    #[serde(rename = "ciphertext__bound_u32")]
    ciphertext: Vec<u8>,
}

/// Performs an ECIES encryption of a given plaintext under a given DH public key and a randomly
/// chosen ephemeral key
///
/// Returns: `Ok(ciphertext)` on success. If there is an issue with random scalar generation or
/// sealing the plaintext, an `Error` is returned.
pub(crate) fn encrypt<R>(
    cs: &CipherSuite,
    others_public_key: &DhPublicKey,
    plaintext: Vec<u8>,
    csprng: &mut R,
) -> Result<EciesCiphertext, Error>
where
    R: CryptoRng,
{
    // Genarate a random secret and pass to a deterministic version of this function
    let my_ephemeral_secret = DhPrivateKey::new_from_random(cs.dh_impl, csprng)?;
    encrypt_with_scalar(cs, others_public_key, plaintext, my_ephemeral_secret)
}

// TODO: Make this function secret-aware by making it take only ClearOnDrop values

/// Performs an ECIES encryption of a given plaintext under a given DH public key and a fixed scalar
/// value. This is the deterministic function underlying `ecies_encrypt`, and is important for
/// testing purposes.
///
/// Returns: `Ok(ciphertext)` on success. If there is an issue with sealing the plaintext, an
/// `Error::EncryptionError` is returned. If there is an issue with deriving DH keys, an
/// `Error::DhError` is returned.
pub(crate) fn encrypt_with_scalar(
    cs: &CipherSuite,
    others_public_key: &DhPublicKey,
    mut plaintext: Vec<u8>,
    my_ephemeral_secret: DhPrivateKey,
) -> Result<EciesCiphertext, Error> {
    // Make room for the tag and fill it with zeros
    let tagged_plaintext_size = plaintext
        .len()
        .checked_add(cs.aead_impl.tag_size())
        .expect("plaintext is too large to be encrypted");
    plaintext.resize(tagged_plaintext_size, 0u8);

    // If my_ephermeral_secret is `a`, let this be `aP`
    let my_ephemeral_public_key =
        DhPublicKey::new_from_private_key(cs.dh_impl, &my_ephemeral_secret);

    // This is `abP` where `bP` is the other person's public key is `bP`
    let shared_secret = cs.dh_impl.diffie_hellman(&my_ephemeral_secret, &others_public_key)?;

    let (key, nonce) = derive_ecies_key_nonce(cs, shared_secret.as_bytes());

    cs.aead_impl.seal(&key, nonce, plaintext.as_mut_slice())?;
    // Rename for clarity
    let ciphertext = plaintext;

    let ret = EciesCiphertext {
        ephemeral_public_key: my_ephemeral_public_key,
        ciphertext,
    };
    Ok(ret)
}

/// Performs an ECIES decryption of a given ciphertext under a given DH ephemeral public key and
/// known secret
///
/// Returns: `Ok(plaintext)` on success. Returns an `Error::EncryptionError` if something goes
/// wrong.
pub(crate) fn decrypt(
    cs: &CipherSuite,
    my_secret_key: &DhPrivateKey,
    ciphertext: EciesCiphertext,
) -> Result<Vec<u8>, Error> {
    let EciesCiphertext {
        ephemeral_public_key,
        mut ciphertext,
    } = ciphertext;
    // This is `abP` where `bP` is the other person's public key is `bP` and my secret key is `a`
    let shared_secret = cs.dh_impl.diffie_hellman(&my_secret_key, &ephemeral_public_key)?;

    // Derive the key and nonce, then open the ciphertext. The length of the subslice it gives is
    // the length we'll truncate the plaintext to. Recall this happens because there was a MAC at
    // the end of the ciphertext.
    let (key, nonce) = derive_ecies_key_nonce(cs, shared_secret.as_bytes());
    let plaintext_len = cs.aead_impl.open(&key, nonce, ciphertext.as_mut_slice())?.len();

    // Rename for clarity
    let mut plaintext = ciphertext;

    plaintext.truncate(plaintext_len);
    Ok(plaintext)
}

/// From the spec:
/// ```ignore
/// key = HKDF-Expand(Secret, ECIESLabel("key"), Length)
/// nonce = HKDF-Expand(Secret, ECIESLabel("nonce"), Length)
///
/// Where ECIESLabel is specified as:
///
/// struct {
///   uint16 length = Length;
///   opaque label<12..255> = "mls10 ecies " + Label;
/// } ECIESLabel;
/// ```
// I think that the Length specified above is supposed to be different for keys and nonces, since
// it wouldn't make sense otherwise, so I've done that and hope I'm right.
fn derive_ecies_key_nonce(cs: &CipherSuite, shared_secret_bytes: &[u8]) -> (AeadKey, AeadNonce) {
    let key_label = EciesLabel::new(b"key", cs.aead_impl.key_size() as u16);
    let nonce_label = EciesLabel::new(b"nonce", cs.aead_impl.nonce_size() as u16);

    // This is the keying information that we will expand
    let prk = HmacKey::new_from_bytes(&shared_secret_bytes);

    let mut key_buf = vec![0u8; cs.aead_impl.key_size()];
    let mut nonce_buf = vec![0u8; cs.aead_impl.nonce_size()];

    // We're gonna used the serialized labels as the `info` parameter to HKDF-Expand. The only way
    // this call fails is because of an `HkdfLabel` serialization error. This can't happen because
    // the only possible error is if EciesLabel::label is oversized, but it is fixed as b"key" or
    // b"nonce" above.
    hkdf::expand(cs.hash_impl, &prk, &key_label, &mut key_buf[..]).unwrap();
    hkdf::expand(cs.hash_impl, &prk, &nonce_label, &mut nonce_buf[..]).unwrap();

    let key = AeadKey::new_from_bytes(cs.aead_impl, &key_buf)
        .expect("couldn't derive AEAD key from HKDF");
    let nonce = AeadNonce::new_from_bytes(cs.aead_impl, &nonce_buf)
        .expect("couldn't derive AEAD nonce from HKDF");

    (key, nonce)
}

#[cfg(test)]
mod test {
    use crate::crypto::{
        ciphersuite::{CipherSuite, X25519_SHA256_AES128GCM},
        dh::{DhPrivateKey, DhPublicKey},
        ecies::{self, EciesCiphertext},
    };

    use quickcheck_macros::quickcheck;
    use rand::SeedableRng;

    static CIPHERSUITES: &[&CipherSuite] = &[&X25519_SHA256_AES128GCM];

    // Checks that decrypt(encrypt_k(m)) == m
    #[quickcheck]
    fn ecies_correctness(plaintext: Vec<u8>, rng_seed: u64) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(rng_seed);

        for cs in CIPHERSUITES {
            // First make an identity we'll encrypt to
            let alice_scalar = DhPrivateKey::new_from_random(cs.dh_impl, &mut rng).unwrap();
            let alice_point = DhPublicKey::new_from_private_key(cs.dh_impl, &alice_scalar);

            // Now encrypt to Alice
            let ecies_ciphertext: EciesCiphertext =
                ecies::encrypt(cs, &alice_point, plaintext.clone(), &mut rng)
                    .expect(&format!("failed to encrypt ECIES plaintext; ciphersuite {}", cs.name));

            // Now let Alice decrypt it
            let recovered_plaintext = ecies::decrypt(cs, &alice_scalar, ecies_ciphertext)
                .expect(&format!("failed to decrypt ECIES ciphertext; ciphersuite {}", cs.name))
                .to_vec();

            assert_eq!(recovered_plaintext, plaintext);
        }
    }
}
