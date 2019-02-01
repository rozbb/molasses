use crate::error::Error;

/// A trait representing a digital signature scheme
pub(crate) trait SignatureScheme {
    const ID: u16;

    type KeyPair;
    type PublicKey;
    type Signature;

    fn public_key_from_bytes(bytes: &[u8]) -> Result<Self::PublicKey, Error>;

    fn key_pair_from_bytes(byte: &[u8]) -> Result<Self::KeyPair, Error>;
    fn key_pair_from_random<T>(csprng: &mut T) -> Self::KeyPair
    where
        T: rand::Rng + rand::CryptoRng;

    fn sign(key_pair: &Self::KeyPair, msg: &[u8]) -> Self::Signature;

    fn verify(public_key: &Self::PublicKey, msg: &[u8], sig: &Self::Signature)
        -> Result<(), Error>;
}

/// This represents the Ed25519 signature scheme. Notably, it implements `SignatureScheme`.
pub(crate) struct ED25519;

// We make newtypes of all of these things so that we can impl Serialize on them in codec.rs

/// A public key in the Ed25519 signature scheme
pub(crate) struct Ed25519PublicKey(ed25519_dalek::PublicKey);
/// A key pair in the Ed25519 signature scheme. This contains a public key and a secret key.
pub(crate) struct Ed25519KeyPair(ed25519_dalek::Keypair);
/// A signature in the Ed25519 signature scheme
pub(crate) struct Ed25519Signature(ed25519_dalek::Signature);

impl SignatureScheme for ED25519 {
    /// This is for serialization purposes. The MLS specifies that this is variant of the
    /// CipherSuite enum has value 0x0807.
    const ID: u16 = 0x0807;

    type KeyPair = Ed25519KeyPair;
    type PublicKey = Ed25519PublicKey;
    type Signature = Ed25519Signature;

    /// Creates a public key from the provided bytes
    fn public_key_from_bytes(bytes: &[u8]) -> Result<Ed25519PublicKey, Error> {
        match ed25519_dalek::PublicKey::from_bytes(bytes) {
            Ok(pubkey) => Ok(Ed25519PublicKey(pubkey)),
            Err(_) => Err(Error::SignatureError("Invalid public key")),
        }
    }

    /// Creates a key pair from the provided bytes
    fn key_pair_from_bytes(bytes: &[u8]) -> Result<Ed25519KeyPair, Error> {
        match ed25519_dalek::Keypair::from_bytes(bytes) {
            Ok(keypair) => Ok(Ed25519KeyPair(keypair)),
            Err(_) => Err(Error::SignatureError("Invalid key pair")),
        }
    }

    /// Generates a random key pair using the given CSPRNG
    ///
    /// Panics: Iff the CSPRNG fails on `fill_bytes`
    fn key_pair_from_random<T>(csprng: &mut T) -> Ed25519KeyPair
    where
        T: rand::Rng + rand::CryptoRng,
    {
        Ed25519KeyPair(ed25519_dalek::Keypair::generate(csprng))
    }

    /// Computes a signature of the given message under the given secret key
    fn sign(key_pair: &Ed25519KeyPair, msg: &[u8]) -> Ed25519Signature {
        Ed25519Signature(key_pair.0.sign(msg))
    }

    /// Verifies the signature of the given message under the given public key
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
