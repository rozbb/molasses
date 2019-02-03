use crate::error::Error;

/// A trait representing a digital signature scheme
pub(crate) trait SignatureScheme {
    const ID: u16;

    type PublicKey;
    type SecretKey;
    type Signature;

    fn public_key_from_bytes(bytes: &[u8]) -> Result<Self::PublicKey, Error>;

    fn secret_key_from_bytes(bytes: &[u8]) -> Result<Self::SecretKey, Error>;

    fn secret_key_from_random<T>(csprng: &mut T) -> Self::SecretKey
    where
        T: rand::Rng + rand::CryptoRng;

    fn public_key_from_secret_key(secret: &Self::SecretKey) -> Self::PublicKey;

    fn sign(secret: &Self::SecretKey, msg: &[u8]) -> Self::Signature;

    fn verify(public_key: &Self::PublicKey, msg: &[u8], sig: &Self::Signature)
        -> Result<(), Error>;
}

/// This represents the Ed25519 signature scheme. Notably, it implements `SignatureScheme`.
pub(crate) struct ED25519;

// We make newtypes of all of these things so that we can impl Serialize on them in codec.rs

/// A public key in the Ed25519 signature scheme
pub(crate) struct Ed25519PublicKey(ed25519_dalek::PublicKey);
/// A private key in the Ed25519 signature scheme
pub(crate) struct Ed25519SecretKey(ed25519_dalek::SecretKey);
/*
/// A key pair in the Ed25519 signature scheme. This contains a public key and a secret key.
pub(crate) struct Ed25519KeyPair {
    pub(crate) secret: Ed25519SecretKey,
    pub(crate) public: Ed25519PublicKey,
}
*/
/// A signature in the Ed25519 signature scheme
pub(crate) struct Ed25519Signature(ed25519_dalek::Signature);

impl ED25519 {
}

impl SignatureScheme for ED25519 {
    /// This is for serialization purposes. The MLS specifies that this is variant of the
    /// CipherSuite enum has value 0x0807.
    const ID: u16 = 0x0807;

    type PublicKey = Ed25519PublicKey;
    type SecretKey = Ed25519SecretKey;
    type Signature = Ed25519Signature;

    /// Creates a public key from the provided bytes
    ///
    /// Returns: `Ok(public_key)` iff no error occured. Otherwise, returns an
    /// `Err(Error::SignatureError)`.
    fn public_key_from_bytes(bytes: &[u8]) -> Result<Ed25519PublicKey, Error> {
        match ed25519_dalek::PublicKey::from_bytes(bytes) {
            Ok(pubkey) => Ok(Ed25519PublicKey(pubkey)),
            Err(_) => Err(Error::SignatureError("Invalid public key")),
        }
    }

    /// Creates a key pair from the provided secret key bytes. This expects 32 bytes.
    fn secret_key_from_bytes(bytes: &[u8]) -> Result<Ed25519SecretKey, Error> {
        match ed25519_dalek::SecretKey::from_bytes(bytes) {
            Ok(secret) => Ok(Ed25519SecretKey(secret)),
            Err(_) => Err(Error::SignatureError("Invalid secret key")),
        }
    }

    /// Generates a random key pair using the given CSPRNG
    ///
    /// Panics: Iff the CSPRNG fails on `fill_bytes`
    fn secret_key_from_random<T>(csprng: &mut T) -> Ed25519SecretKey
    where
        T: rand::Rng + rand::CryptoRng,
    {
        Ed25519SecretKey(ed25519_dalek::SecretKey::generate(csprng))
    }

    /// Computes the public key corresponding to the given secret key. This is done in the same way
    /// that ed25519_dalek does it.
    fn public_key_from_secret_key(secret: &Ed25519SecretKey) -> Ed25519PublicKey {
        Ed25519PublicKey((&secret.0).into())
    }

    /// Computes a signature of the given message under the given secret key
    fn sign(secret: &Ed25519SecretKey, msg: &[u8]) -> Ed25519Signature {
        // For simplicity, we add the overhead of recomputing the public key on every signature
        // operation instead of having it passed into the function. Sue me.
        let public = ED25519::public_key_from_secret_key(secret);
        let expanded: ed25519_dalek::ExpandedSecretKey = (&secret.0).into();

        Ed25519Signature(expanded.sign(&msg, &public.0))
    }

    /// Verifies the signature of the given message under the given public key
    ///
    /// Returns: `Ok(())` iff the signature succeeded. Otherwise, returns an
    /// `Err(Error::SignatureError)` which is a lot of errors, so you know it's bad.
    fn verify(
        public_key: &Ed25519PublicKey,
        msg: &[u8],
        sig: &Ed25519Signature,
    ) -> Result<(), Error> {
        public_key
            .0
            .verify(msg, &sig.0)
            .map_err(|_| Error::SignatureError("Invalid signature"))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use quickcheck_macros::quickcheck;
    use rand::SeedableRng;
    use rand_core::RngCore;

    // Test vectors are from
    // https://git.gnupg.org/cgi-bin/gitweb.cgi?p=libgcrypt.git;a=blob;f=tests/t-ed25519.inp;h=e13566f826321eece65e02c593bc7d885b3dbe23;hb=refs/heads/master%3E
    // via
    // https://tools.ietf.org/html/rfc8032#section-7.1
    #[test]
    fn ed25519_kat() {
        let sk_pk_msg_sig_tuples = [
            ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
             "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
             "",
             "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e\
              39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
            ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
             "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
             "72",
             "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f\
              3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
            ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
             "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
             "af82",
             "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67\
              f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
        ];

        for (secret_hex, public_hex, msg_hex, sig_hex) in sk_pk_msg_sig_tuples.iter() {
            let msg = hex::decode(msg_hex).unwrap();
            let secret = {
                let bytes = hex::decode(secret_hex).unwrap();
                ED25519::secret_key_from_bytes(&bytes).unwrap()
            };
            let expected_public = {
                let bytes = hex::decode(public_hex).unwrap();
                ED25519::public_key_from_bytes(&bytes).unwrap()
            };

            // Make sure the expected public key and the public key we derived are the same
            assert_eq!(
                expected_public.0.to_bytes(),
                ED25519::public_key_from_secret_key(&secret).0.to_bytes()
            );

            let sig = ED25519::sign(&secret, &msg);
            let expected_sig = hex::decode(sig_hex).unwrap();

            assert_eq!(sig.0.to_bytes().to_vec(), expected_sig);
        }
    }

    #[quickcheck]
    fn ed25519_correctness(msg: Vec<u8>, secret_seed: u64) {
        // Make a secret key seeded with the above seed. This is so that this function is
        // deterministic.
        let secret_key = {
            let mut rng = rand::StdRng::seed_from_u64(secret_seed);
            let mut buf = [0u8; 32];
            rng.fill_bytes(&mut buf);
            ED25519::secret_key_from_bytes(&buf).unwrap()
        };
        let public_key = ED25519::public_key_from_secret_key(&secret_key);

        // Sign the random message we were given
        let sig = ED25519::sign(&secret_key, &msg);

        // Make sure the signature we just made is valid
        assert!(ED25519::verify(&public_key, &msg, &sig).is_ok());
    }
}
