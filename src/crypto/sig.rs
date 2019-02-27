use crate::crypto::rng::CryptoRng;
use crate::error::Error;

pub(crate) const ED25519_IMPL: Ed25519 = Ed25519;

// opaque SignaturePublicKey<1..2^16-1>
/// This is the form that all `SigPublicKeyRaw`s take when being sent or received over the wire
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename = "SigPublicKeyRaw__bound_u16")]
pub(crate) struct SigPublicKeyRaw(pub(crate) Vec<u8>);

/// An enum of possible types for a signature scheme's public key, depending on the underlying
/// algorithm
#[derive(Debug)]
pub(crate) enum SigPublicKey {
    Ed25519PublicKey(ed25519_dalek::PublicKey),
    Raw(SigPublicKeyRaw),
}

impl SigPublicKey {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        match self {
            SigPublicKey::Ed25519PublicKey(p) => p.as_bytes(),
            SigPublicKey::Raw(p) => p.0.as_slice(),
        }
    }
}

/// An enum of possible types for a signature scheme's secret key, depending on the underlying
/// algorithm
pub(crate) enum SigSecretKey {
    Ed25519SecretKey(ed25519_dalek::SecretKey),
}

impl core::fmt::Debug for SigSecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        // Ensure that the secret value isn't accidentally logged
        f.write_str("SigSecretKey: CONTENTS OMITTED")
    }
}

// opaque UserInitKey::signature<0..2^16-1>
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename = "SignatureRaw__bound_u16")]
pub(crate) struct SignatureRaw(pub(crate) Vec<u8>);

/// An enum of possible types for a signature scheme's signature, depending on the underlying
/// algorithm
#[derive(Debug)]
pub(crate) enum Signature {
    Ed25519Signature(ed25519_dalek::Signature),
    Raw(SignatureRaw),
}

impl Signature {
    // TODO: make this not allocate
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        match self {
            Signature::Ed25519Signature(s) => s.to_bytes().to_vec(),
            Signature::Raw(s) => s.0.clone(),
        }
    }
}

/// A trait representing any signature scheme
pub(crate) trait SignatureScheme {
    fn name(&self) -> &'static str;

    #[cfg(test)]
    fn public_key_from_secret_key(&self, secret: &SigSecretKey) -> SigPublicKey;

    fn secret_key_from_bytes(&self, bytes: &[u8]) -> Result<SigSecretKey, Error>;

    fn secret_key_from_random(&self, csprng: &mut dyn CryptoRng) -> Result<SigSecretKey, Error>;

    fn sign(&self, secret: &SigSecretKey, msg: &[u8]) -> Signature;

    fn verify(&self, public_key: &SigPublicKey, msg: &[u8], sig: &Signature) -> Result<(), Error>;
}

impl core::fmt::Debug for SignatureScheme {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

/// This represents the Ed25519 signature scheme. Notably, it implements `SignatureScheme`.
pub(crate) struct Ed25519;

// This implementation is for Ed25519 only, currently. In the future, we should wrap Ed25519 with
// a trait, and use the same trait for other signature implementations
impl SignatureScheme for Ed25519 {
    /// Returns the signature scheme's name, as per the MLS spec. Here, it is `ed25519`
    fn name(&self) -> &'static str {
        "ed25519"
    }

    /// This is just for testing purposes. This should be the `SigPublicKey` form of whatever we do
    /// in the `sign` function to derive a public key from a secret key.
    #[cfg(test)]
    fn public_key_from_secret_key(&self, secret: &SigSecretKey) -> SigPublicKey {
        let secret = enum_variant!(secret, SigSecretKey::Ed25519SecretKey);

        let public_key: ed25519_dalek::PublicKey = secret.into();
        SigPublicKey::Ed25519PublicKey(public_key)
    }

    /// Creates a key pair from the provided secret key bytes. This expects 32 bytes.
    fn secret_key_from_bytes(&self, bytes: &[u8]) -> Result<SigSecretKey, Error> {
        match ed25519_dalek::SecretKey::from_bytes(bytes) {
            Ok(secret) => Ok(SigSecretKey::Ed25519SecretKey(secret)),
            Err(_) => Err(Error::SignatureError("Invalid secret key")),
        }
    }

    /// Generates a random key pair using the given CSPRNG
    ///
    /// Returns: `Ok(secret_key)` on success. On error, returns `Error::SignatureErrror` or
    /// `Error::OutOfEntropy`.
    fn secret_key_from_random(&self, csprng: &mut dyn CryptoRng) -> Result<SigSecretKey, Error> {
        let mut key_bytes = [0u8; 32];
        csprng
            .try_fill_bytes(&mut key_bytes)
            .map_err(|_| Error::OutOfEntropy)?;
        let key = ed25519_dalek::SecretKey::from_bytes(&key_bytes)
            .map_err(|_| Error::SignatureError("Could not make key from random"))?;
        Ok(SigSecretKey::Ed25519SecretKey(key))
    }

    /// Computes a signature of the given message under the given secret key
    fn sign(&self, secret: &SigSecretKey, msg: &[u8]) -> Signature {
        let secret = enum_variant!(secret, SigSecretKey::Ed25519SecretKey);

        // For simplicity, we add the overhead of recomputing the public key on every signature
        // operation instead of having it passed into the function. Sue me.
        let public_key: ed25519_dalek::PublicKey = secret.into();
        let expanded_secret: ed25519_dalek::ExpandedSecretKey = secret.into();

        Signature::Ed25519Signature(expanded_secret.sign(&msg, &public_key))
    }

    /// Verifies the signature of the given message under the given public key
    ///
    /// Returns: `Ok(())` iff the signature succeeded. Otherwise, returns an
    /// `Err(Error::SignatureError)` which is a lot of "Error"s, so you know it's bad.
    #[must_use]
    fn verify(&self, public_key: &SigPublicKey, msg: &[u8], sig: &Signature) -> Result<(), Error> {
        // Convert the public key bytes into the ed25519_dalek representation
        let public_key = enum_variant!(public_key, SigPublicKey::Ed25519PublicKey);
        let sig = enum_variant!(sig, Signature::Ed25519Signature);

        // Don't worry, it's okay to say "bad signature" for signature schemes, since this
        // function does not depend on any private information, there is nothing to leak.
        public_key
            .verify(msg, &sig)
            .map_err(|_| Error::SignatureError("Bad signature"))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::tls_de::TlsDeserializer;

    use quickcheck_macros::quickcheck;
    use rand_core::{RngCore, SeedableRng};
    use serde::de::Deserialize;

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
                ED25519_IMPL.secret_key_from_bytes(&bytes).unwrap()
            };
            let expected_public = {
                // The deserializer expects an 0x0020 at the beginning to indicate that the
                // public keys are 32 bytes long
                let mut bytes = hex::decode(public_hex).unwrap();
                bytes.insert(0, 0x20);
                bytes.insert(0, 0x00);

                let mut cursor = bytes.as_slice();
                let mut deserializer = TlsDeserializer::from_reader(&mut cursor);
                SigPublicKey::deserialize(&mut deserializer).unwrap()
            };
            let derived_public = ED25519_IMPL.public_key_from_secret_key(&secret);

            // Make sure the expected public key and the public key we derived are the same
            eprintln!("expected_public.len() == {}", expected_public.as_bytes().len());
            eprintln!("derived_public.len() == {}", derived_public.as_bytes().len());
            assert_eq!(expected_public.as_bytes(), derived_public.as_bytes());

            let derived_sig = ED25519_IMPL.sign(&secret, &msg);
            let expected_sig = hex::decode(sig_hex).unwrap();

            assert_eq!(&expected_sig, &derived_sig.to_bytes());
        }
    }

    #[quickcheck]
    fn ed25519_correctness(msg: Vec<u8>, secret_seed: u64) {
        // Make a secret key seeded with the above seed. This is so that this function is
        // deterministic.
        let secret_key = {
            let mut rng = rand::rngs::StdRng::seed_from_u64(secret_seed);
            let mut buf = [0u8; 32];
            rng.fill_bytes(&mut buf);
            ED25519_IMPL.secret_key_from_bytes(&buf).unwrap()
        };
        let public_key = ED25519_IMPL.public_key_from_secret_key(&secret_key);

        // Sign the random message we were given
        let sig = ED25519_IMPL.sign(&secret_key, &msg);

        // Make sure the signature we just made is valid
        assert!(ED25519_IMPL.verify(&public_key, &msg, &sig).is_ok());
    }
}
