use crate::crypto::{
    aead::{AeadKey, AeadNonce},
    ciphersuite::CipherSuite,
    dh::{DhPrivateKey, DhPublicKey},
    hkdf::{self, HkdfSalt},
    rng::CryptoRng,
};
use crate::{error::Error, tls_ser};

/// A short ciphertext encrypted with the enclosed ephemeral DH key
#[derive(Clone, Deserialize, Serialize)]
#[cfg_attr(test, derive(Debug))]
pub(crate) struct HpkeCiphertext {
    /// Pubkey the ciphertext is encrypted under
    pub(crate) ephemeral_public_key: DhPublicKey,
    /// The payload
    // opaque ciphertext<0..2^32-1>;
    #[serde(rename = "ciphertext__bound_u32")]
    ciphertext: Vec<u8>,
}

/// Performs an HPKE encryption of a given plaintext under a given DH public key and a randomly
/// chosen ephemeral key
///
/// Returns: `Ok(ciphertext)` on success. If there is an issue with random scalar generation or
/// sealing the plaintext, an `Error` is returned.
pub(crate) fn encrypt<R>(
    cs: &'static CipherSuite,
    others_public_key: &DhPublicKey,
    plaintext: Vec<u8>,
    csprng: &mut R,
) -> Result<HpkeCiphertext, Error>
where
    R: CryptoRng,
{
    // Genarate a random secret and pass to a deterministic version of this function
    let my_ephemeral_secret = DhPrivateKey::new_from_random(cs.dh_impl, csprng)?;
    encrypt_with_scalar(cs, others_public_key, plaintext, my_ephemeral_secret)
}

// TODO: Make this function secret-aware by making it take only ClearOnDrop values

/// Performs an HPKE encryption of a given plaintext under a given DH public key and a fixed scalar
/// value. This is the deterministic function underlying `hpke::encrypt`, and is important for
/// testing purposes.
///
/// Returns: `Ok(ciphertext)` on success. If there is an issue with sealing the plaintext, an
/// `Error::EncryptionError` is returned. If there is an issue with deriving DH keys, an
/// `Error::DhError` is returned.
pub(crate) fn encrypt_with_scalar(
    cs: &'static CipherSuite,
    others_public_key: &DhPublicKey,
    mut plaintext: Vec<u8>,
    my_ephemeral_secret: DhPrivateKey,
) -> Result<HpkeCiphertext, Error> {
    // We need to derive the recipient public key to HPKE decap. If my_ephermeral_secret is
    // `a`, let this be `aP`
    let my_ephemeral_public_key =
        DhPublicKey::new_from_private_key(cs.dh_impl, &my_ephemeral_secret);

    // Derive the key and the nonce
    let (key, nonce) = {
        // This is `abP` where `bP` is the sender's public key and my secret key is `a`
        let shared_secret = cs.dh_impl.diffie_hellman(&my_ephemeral_secret, &others_public_key)?;

        derive_hpke_key_nonce(
            cs,
            others_public_key,
            &my_ephemeral_public_key,
            shared_secret.as_bytes(),
        )
    };

    // Do the encryption. MLS doesn't use AAD with HPKE at any point
    cs.aead_impl.seal(&key, nonce, b"", &mut plaintext)?;
    // Rename for clarity
    let ciphertext = plaintext;

    // Package the payload with the ephemeral pubkey
    Ok(HpkeCiphertext {
        ephemeral_public_key: my_ephemeral_public_key,
        ciphertext,
    })
}

/// Performs an HPKE decryption of a given ciphertext under a given DH ephemeral public key and
/// known secret
///
/// Returns: `Ok(plaintext)` on success. Returns an `Error::EncryptionError` if something goes
/// wrong.
pub(crate) fn decrypt(
    cs: &'static CipherSuite,
    my_secret_key: &DhPrivateKey,
    ciphertext: HpkeCiphertext,
) -> Result<Vec<u8>, Error> {
    let HpkeCiphertext {
        ephemeral_public_key,
        mut ciphertext,
    } = ciphertext;
    // Derive the key and nonce
    let (key, nonce) = {
        // We need to derive the recipient public key to HPKE decap
        let my_public_key = DhPublicKey::new_from_private_key(cs.dh_impl, &my_secret_key);
        // This is `abP` where `bP` is the sender's public key and my secret key is `a`
        let shared_secret = cs.dh_impl.diffie_hellman(&my_secret_key, &ephemeral_public_key)?;

        derive_hpke_key_nonce(cs, &my_public_key, &ephemeral_public_key, shared_secret.as_bytes())
    };

    // Open the ciphertext. MLS doesn't use AAD with HPKE at any point.
    let plaintext_len = cs.aead_impl.open(&key, nonce, b"", ciphertext.as_mut_slice())?.len();

    // Still some postprocessing left to do. Rename for clarity
    let mut plaintext = ciphertext;

    // The value that open() returns is the length we'll truncate the plaintext to. Recall this
    // happens because there was a MAC at the end of the ciphertext.
    plaintext.truncate(plaintext_len);
    Ok(plaintext)
}

/// The struct whose serialization makes up the contents of `context` in the `SetupCore` procedure
/// in the HPKE spec
#[derive(Serialize)]
struct SetupCoreCtx<'a> {
    cs: &'a CipherSuite,
    mode: u8,
    #[serde(rename = "kem_ctx__bound_u8")]
    kem_ctx: &'a [u8],
    #[serde(rename = "info__bound_u8")]
    info: &'a [u8],
}

// From the HPKE spec:
//     Marshal(pk): Produce a fixed-length octet string encoding the public key "pk"
//
//     def Encap(pkR):
//       skE, pkE = GenerateKeyPair()
//       zz = DH(skE, pkR)
//       enc = Marshal(pkE)
//       return zz, enc
//
//     def SetupCore(mode, secret, kemContext, info):
//       context = ciphersuite + mode + len(kemContext) + kemContext + len(info) + info
//       key = Expand(secret, "hpke key" + context, Nk)
//       nonce = Expand(secret, "hpke nonce" + context, Nn)
//       return Context(key, nonce)
//
//     def SetupBase(pkR, zz, enc, info):
//       kemContext = enc + pkR
//       secret = Extract(0\*Nh, zz)
//       return SetupCore(mode_base, secret, kemContext, info)
//
//     def SetupBaseI(pkR, info):
//       zz, enc = Encap(pkR)
//       return SetupBase(pkR, zz, enc, info)
/// Derives a key and nonce from the given shared secret using `SetupBaseI` from the HPKE spec
fn derive_hpke_key_nonce(
    cs: &'static CipherSuite,
    recipient_public_key: &DhPublicKey,
    ephemeral_public_key: &DhPublicKey,
    shared_secret_bytes: &[u8],
) -> (AeadKey, AeadNonce) {
    // We've presumably already done the DH step. We only need the `enc` output of
    // Encap(), which is an encoded form of the ephemeral pubkey

    let ephemeral_public_key_bytes = ephemeral_public_key.as_bytes();

    // SetupBase(recipient_public_key, shared_secret_bytes, ephemeral_public_key_bytes, info="")

    let kem_ctx = &[ephemeral_public_key_bytes, recipient_public_key.as_bytes()].concat();
    let salt = HkdfSalt::new_from_zeros(cs.hash_impl);
    let prk = hkdf::extract(cs.hash_impl, &salt, shared_secret_bytes);

    // SetupCore(mode=0x00, secret=prk, kem_ctx, info="")

    let serialized_ctx = {
        let ctx = SetupCoreCtx {
            cs,
            mode: 0u8,
            kem_ctx: &kem_ctx,
            info: b"",
        };
        // This should never error. The only thing that could go wrong is having `info` being
        // longer than 255 bytes (which doesn't happen because it's empty), or kem_ctx being longer
        // than 255 bytes (which does not happen for any DH scheme in use)
        tls_ser::serialize_to_bytes(&ctx).expect("error serializing SetupCoreCtx")
    };
    let key_label = &[b"hpke key", serialized_ctx.as_slice()].concat();
    let nonce_label = &[b"hpke nonce", serialized_ctx.as_slice()].concat();

    // We're gonna used the serialized labels as the `info` parameter to HKDF-Expand. The only way
    // this call fails is due to serialization errors, but key_label and nonce_label are already
    // serialized, so that can't happen.
    let key: AeadKey = hkdf::expand(cs, &prk, &key_label).unwrap();
    let nonce: AeadNonce = hkdf::expand(cs, &prk, &nonce_label).unwrap();

    (key, nonce)
}

#[cfg(test)]
mod test {
    use crate::crypto::{
        ciphersuite::{CipherSuite, X25519_SHA256_AES128GCM},
        dh::{DhPrivateKey, DhPublicKey},
        hpke::{self, HpkeCiphertext},
    };

    use quickcheck_macros::quickcheck;
    use rand::SeedableRng;

    static CIPHERSUITES: &[&CipherSuite] = &[&X25519_SHA256_AES128GCM];

    // Checks that decrypt(encrypt_k(m)) == m
    #[quickcheck]
    fn hpke_correctness(plaintext: Vec<u8>, rng_seed: u64) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(rng_seed);

        for cs in CIPHERSUITES {
            // First make an identity we'll encrypt to
            let alice_scalar = DhPrivateKey::new_from_random(cs.dh_impl, &mut rng).unwrap();
            let alice_point = DhPublicKey::new_from_private_key(cs.dh_impl, &alice_scalar);

            // Now encrypt to Alice
            let hpke_ciphertext: HpkeCiphertext =
                hpke::encrypt(cs, &alice_point, plaintext.clone(), &mut rng)
                    .expect(&format!("failed to encrypt HPKE plaintext; ciphersuite {}", cs.name));

            // Now let Alice decrypt it
            let recovered_plaintext = hpke::decrypt(cs, &alice_scalar, hpke_ciphertext)
                .expect(&format!("failed to decrypt HPKE ciphertext; ciphersuite {}", cs.name))
                .to_vec();

            assert_eq!(recovered_plaintext, plaintext);
        }
    }
}
