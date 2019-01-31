use crate::error::Error;

use digest::Digest;
use rand::Rng;
use ring::aead::AES_128_GCM as AES_128_GCM_ALG;
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

// TODO: Break this out into crypto/{ciphersuite.rs, sigscheme.rs} and maybe more

const AES_GCM_128_KEY_SIZE: usize = 128 / 8;
const AES_GCM_128_TAG_SIZE: usize = 128 / 8;
const AES_GCM_128_NONCE_SIZE: usize = 96 / 8;

const X25519_POINT_SIZE: usize = 32;
const X25519_SCALAR_SIZE: usize = 32;

/// An opening / sealing key for use with the `Aes128Gcm` algorithm
// These will just be two copies of the same thing. They're different types because ring requires
// an OpeningKey for opening and a SealingKey for sealing. This incurs some 64 bytes of storage
// overhead, but I frankly don't care.
pub(crate) struct Aes128GcmKey {
    opening_key: ring::aead::OpeningKey,
    sealing_key: ring::aead::SealingKey,
}

/// A trait representing an authenticated encryption algorithm. Note that this makes no mention of
/// associated data, since it is not used anywhere in MLS.
// ring does algorithm specification at runtime, but I'd rather encode these things in the type
// system. So, similar to the Digest trait, we're making an AuthenticatedEncryption trait. I don't
// think we'll need associated data in this crate, so we leave it out for simplicity
pub(crate) trait AuthenticatedEncryption {
    /// Nonce type
    type Nonce;
    /// Key type
    type Key;

    fn key_from_bytes(key_bytes: &[u8]) -> Result<Self::Key, Error>;

    fn key_from_random<T>(csprng: &mut T) -> Result<Self::Key, Error>
    where
        T: rand_core::RngCore + rand_core::CryptoRng;

    fn open(
        key: &Self::Key,
        nonce: Self::Nonce,
        ciphertext_and_tag: Vec<u8>,
    ) -> Result<Vec<u8>, Error>;

    fn seal<T>(
        key: &Self::Key,
        plaintext: Vec<u8>,
        csprng: &mut T,
    ) -> Result<(Vec<u8>, Self::Nonce), Error>
    where
        T: rand_core::RngCore + rand_core::CryptoRng;
}

/// This represents the AES-128-GCM authenticated encryption algorithm. Notably, it implements
/// `AuthenticatedEncryption`.
pub(crate) struct Aes128Gcm;

impl AuthenticatedEncryption for Aes128Gcm {
    type Nonce = ring::aead::Nonce;
    type Key = Aes128GcmKey;

    /// Makes a new AES-GCM key from the given key bytes.
    ///
    /// Requires: `key_bytes.len() == 16`
    ///
    /// Returns: `Ok(key)` on success. On error (don't ask me why this could fail), returns an
    /// `Error`.
    fn key_from_bytes(key_bytes: &[u8]) -> Result<Aes128GcmKey, Error> {
        // TODO: Once associated consts stabilizes, I want key_byte: [u8; Self::KEY_SIZE]
        if key_bytes.len() != AES_GCM_128_KEY_SIZE {
            return Err(Error::EncryptionError("AES-GCM-128 requires 128-bit keys"));
        }

        // Again, the opening and sealing keys for AES-GCM are the same.
        let opening_key = ring::aead::OpeningKey::new(&AES_128_GCM_ALG, key_bytes)
            .map_err(|_| Error::EncryptionError("Unspecified"))?;
        let sealing_key = ring::aead::SealingKey::new(&AES_128_GCM_ALG, key_bytes)
            .map_err(|_| Error::EncryptionError("Unspecified"))?;

        Ok(Aes128GcmKey {
            opening_key,
            sealing_key,
        })
    }

    /// Makes a new secure-random AES-GCM key.
    ///
    /// Returns: `Ok(key)` on success. On error , returns `Error::OutOfEntropy`.
    fn key_from_random<T>(csprng: &mut T) -> Result<Aes128GcmKey, Error>
    where
        T: rand_core::RngCore + rand_core::CryptoRng,
    {
        let mut key = [0u8; AES_GCM_128_KEY_SIZE];
        csprng
            .try_fill_bytes(&mut key)
            .map_err(|_| Error::OutOfEntropy)?;

        Aes128Gcm::key_from_bytes(&key)
    }

    /// Does an in-place authenticated decryption of the given ciphertext and tag. The input should
    /// look like `ciphertext || tag`, that is, ciphertext concatenated with a 16-byte tag. After a
    /// successful run, the modified input will look like `plaintext || garbage` where `garbage` is
    /// 16 bytes long. If an error occurred, the modified input may be altered in an unspecified
    /// way.
    ///
    /// Returns: `Ok(plaintext)` on sucess, where `plaintext` is the decrypted form of the
    /// ciphertext, with no tags or garbage bytes (in particular, it's the same buffer as the input
    /// bytes, but without the last 16 bytes). If there is an error in any part of this process, it
    /// will be returned as an `Error::CryptoError` with description "Unspecified".
    fn open(
        key: &Aes128GcmKey,
        nonce: Self::Nonce,
        mut ciphertext_and_tag: Vec<u8>,
    ) -> Result<Vec<u8>, Error> {
        let empty_aead = ring::aead::Aad::empty();
        // We use the standard decryption function with no associated data, and no "prefix bytes".
        // The length of the buffer is checked by the ring library. The function returns a
        // plaintext = ciphertext_and_tag[..plaintext.len()], so we'll return the
        // ciphertext_and_tag vector truncated to plaintext.len();
        // For more details on this function, see docs on ring::aead::open_in_place at
        // https://briansmith.org/rustdoc/ring/aead/fn.open_in_place.html
        let plaintext_len = ring::aead::open_in_place(
            &key.opening_key,
            nonce,
            empty_aead,
            0,
            ciphertext_and_tag.as_mut_slice(),
        )
        .map_err(|_| Error::EncryptionError("Unspecified"))?
        .len();

        // Truncate and rename, since ciphertext_and_tag was modified in-place
        ciphertext_and_tag.truncate(plaintext_len);
        let plaintext = ciphertext_and_tag;
        Ok(plaintext)
    }

    /// Performs an authenticated encryption of the given plaintext. This function will generate
    /// its own random nonce using the given CSPRNG, or else fail.
    ///
    /// Returns: `Ok((ct, nonce))` upon success, where `ct` is the authenticated ciphertext, and
    /// `nonce` is the nonce that was used for encryption. If encryption or creation of a nonce
    /// fails, an `Error` is returned.
    fn seal<T>(
        key: &Aes128GcmKey,
        mut plaintext: Vec<u8>,
        csprng: &mut T,
    ) -> Result<(Vec<u8>, Self::Nonce), Error>
    where
        T: rand_core::RngCore + rand_core::CryptoRng,
    {
        // Extend the plaintext to have space at the end of AES_GCM_TAG_SIZE many bytes. This is
        // where the tag goes for ring::aead::seal_in_place
        let mut extended_plaintext = {
            let buf = [0u8; AES_GCM_128_TAG_SIZE];
            plaintext.extend_from_slice(&buf);
            plaintext
        };

        // Make new nonce
        let nonce_bytes = {
            let mut buf = [0u8; AES_GCM_128_NONCE_SIZE];
            csprng.try_fill(&mut buf).map_err(|_| Error::OutOfEntropy)?;
            buf
        };

        // The sealing algorithm consumes the nonce, so make two copies: one to return when we're
        // done, and one to give to the `seal_in_place` function.
        // The constructor used here is the trivial one (`Nonce` just holds a buffer of bytes)
        let nonce1 = ring::aead::Nonce::assume_unique_for_key(nonce_bytes);
        let nonce2 = ring::aead::Nonce::assume_unique_for_key(nonce_bytes);

        // We use the standard encryption function with no associated data. The length of the
        // buffer is checked by the ring library.
        // For more details on this function, see docs on ring::aead::seal_in_place at
        // https://briansmith.org/rustdoc/ring/aead/fn.seal_in_place.html
        let res = ring::aead::seal_in_place(
            &key.sealing_key,
            nonce1,
            ring::aead::Aad::empty(),
            &mut extended_plaintext,
            AES_GCM_128_TAG_SIZE,
        );

        // The encryption was done in-place. Rename for clarity
        let authenticated_ciphertext = extended_plaintext;

        match res {
            Ok(_) => Ok((authenticated_ciphertext, nonce2)),
            Err(e) => Err(Error::EncryptionError("Unspecified")),
        }
    }
}

/// A trait representing any DH-like key-agreement algorithm. The notation it uses in documentation
/// is that of elliptic curves, but these concepts should generalize to finite-fields, SIDH, CSIDH,
/// etc.
pub(crate) trait DiffieHellman {
    /// The type of a public value. In EC terminology, this is a scalar in the base field. In
    /// finite-field terminology, this is an exponent.
    type Scalar;
    /// The type of a private value. In EC terminology, this is a point on the curve. In
    /// finite-field terminology, this is an element of the field.
    type Point;

    fn scalar_from_bytes(bytes: &[u8]) -> Result<Self::Scalar, Error>;

    fn multiply_basepoint(scalar: &Self::Scalar) -> Self::Point;

    fn diffie_hellman(privkey: &Self::Scalar, pubkey: &Self::Point) -> Self::Point;
}

// We do not use the x25519_dalek DH API because the EphemeralSecret does not expose its internals.
// The MLS spec requires that we be able to create secrets from arbitrary bytestrings, and we can
// only do that if we can touch the buffer inside EphemeralSecret. So, we re-implement a small
// portion of the API here, without doing any actual crypto.
//
// NOTE: Although X25519Scalar can be initiated with arbitrary bytestrings, all scalars are clamped
// by x25519::diffie_hellman before they are used, so chill out please.

/// This represents the X25519 Diffie-Hellman key agreement protocol. Notably, it implements
/// `DiffieHellman`.
pub(crate) struct X25519;
/// A scalar value in Curve25519
pub(crate) struct X25519Scalar([u8; X25519_SCALAR_SIZE]);
/// A curve point in Curve25519
pub(crate) struct X25519Point([u8; X25519_POINT_SIZE]);

impl DiffieHellman for X25519 {
    type Scalar = X25519Scalar;
    type Point = X25519Point;

    /// Uses the key bytes as a scalar in GF(2^(255) - 19)
    ///
    /// Requires: `key_bytes.len() == 32`
    ///
    /// Returns: `Ok(privkey)` on success. Otherwise, if `key_bytes.len() != 32`, returns
    /// `Error::CryptoError`.
    fn scalar_from_bytes(bytes: &[u8]) -> Result<X25519Scalar, Error> {
        if bytes.len() != X25519_SCALAR_SIZE {
            return Err(Error::DHError("Wrong key size"));
        } else {
            let mut buf = [0u8; X25519_SCALAR_SIZE];
            buf.copy_from_slice(bytes);
            Ok(X25519Scalar(buf))
        }
    }

    /// Calculates `scalar * P`, where `P` is the standard X25519 basepoint. This function is used
    /// for creating public keys for DHE.
    fn multiply_basepoint(scalar: &X25519Scalar) -> X25519Point {
        let point_bytes = x25519(scalar.0, X25519_BASEPOINT_BYTES);
        X25519Point(point_bytes)
    }

    /// Computes `privkey * Pubkey` where `privkey` is your local secret (a scalar) and `Pubkey` is
    /// someone's public key (a curve point)
    fn diffie_hellman(privkey: &X25519Scalar, pubkey: &X25519Point) -> X25519Point {
        let shared_secret = x25519(privkey.0, pubkey.0);
        X25519Point(shared_secret)
    }
}

/// A trait representing the contents of an MLS ciphersuite: a DH-like key-agreement protocol, a
/// hashing algorithm, and an authenticated encryption algorithm.
pub(crate) trait CipherSuite {
    type DH: DiffieHellman;
    type Hash: Digest;
    type Aead: AuthenticatedEncryption;

    const ID: u16;

    fn derive_key_pair(
        bytes: &[u8],
    ) -> Result<
        (
            <Self::DH as DiffieHellman>::Point,
            <Self::DH as DiffieHellman>::Scalar,
        ),
        Error,
    >;
}

/// This represents the X25519-SHA256-AES128GCM ciphersuite. Notably, it implements `CipherSuite`.
#[allow(non_camel_case_types)]
pub(crate) struct X25519_SHA256_AES128GCM;

impl CipherSuite for X25519_SHA256_AES128GCM {
    type DH = X25519;
    type Hash = sha2::Sha256;
    type Aead = Aes128Gcm;

    /// This is for serialization purposes. The MLS specifies that this is variant of the
    /// CipherSuite enum has value 0x0000.
    const ID: u16 = 0;

    /// Given an arbitrary number of bytes, derives a Diffie-Hellman keypair. For this ciphersuite,
    /// the function is simply `scalar: [0u8; 32] = SHA256(bytes)`.
    fn derive_key_pair(
        bytes: &[u8],
    ) -> Result<
        (
            <X25519 as DiffieHellman>::Point,
            <X25519 as DiffieHellman>::Scalar,
        ),
        Error,
    > {
        let mut hasher = sha2::Sha256::new();
        hasher.input(bytes);
        let scalar_bytes = hasher.result();

        let privkey = X25519::scalar_from_bytes(&scalar_bytes)?;
        let pubkey = X25519::multiply_basepoint(&privkey);

        Ok((pubkey, privkey))
    }
}

/// A trait representing a digital signature scheme
pub(crate) trait SignatureScheme {
    type PublicKey;
    type SecretKey;

    const ID: u16;

    fn secret_key_from_bytes(bytes: &[u8]) -> Result<Self::SecretKey, Error>;

    fn secret_key_from_random<T>(csprng: &mut T) -> Result<Self::SecretKey, Error>
    where
        T: rand::Rng + rand::CryptoRng;
}

/// This represents the Ed25519 signature scheme. Notably, it implements `SignatureScheme`.
pub struct ED25519;

impl SignatureScheme for ED25519 {
    type PublicKey = ed25519_dalek::PublicKey;
    type SecretKey = ed25519_dalek::SecretKey;

    /// This is for serialization purposes. The MLS specifies that this is variant of the
    /// CipherSuite enum has value 0x0807.
    const ID: u16 = 0x0807;

    fn secret_key_from_bytes(byte: &[u8]) -> Result<ed25519_dalek::SecretKey, Error> {
        unimplemented!()
    }

    fn secret_key_from_random<T>(csprng: &mut T) -> Result<Self::SecretKey, Error>
    where
        T: rand::Rng + rand::CryptoRng,
    {
        unimplemented!()
    }
}

#[cfg(test)]
mod test {
    use crate::crypto::*;

    use quickcheck_macros::quickcheck;

    // TODO: AES-GCM KAT

    // Test that decrypt_k(encrypt_k(m)) == m
    #[quickcheck]
    fn aes_gcm_correctness(plaintext: Vec<u8>) {
        let mut rng = rand::thread_rng();
        let key = Aes128Gcm::key_from_random(&mut rng).expect("failed to generate key");

        let (auth_ciphertext, nonce) =
            Aes128Gcm::seal(&key, plaintext.clone(), &mut rng).expect("failed to encrypt");
        let recovered_plaintext =
            Aes128Gcm::open(&key, nonce, auth_ciphertext).expect("failed to decrypt");

        assert_eq!(plaintext, recovered_plaintext);
    }

    // Test that perturbations in encrypt_k(m) make it fail to decrypt
    #[quickcheck]
    fn aes_gcm_integrity(plaintext: Vec<u8>) {
        let mut rng = rand::thread_rng();
        let key = Aes128Gcm::key_from_random(&mut rng).expect("failed to generate key");

        let (mut auth_ciphertext, nonce) =
            Aes128Gcm::seal(&key, plaintext, &mut rng).expect("failed to encrypt");

        let mut xor_bytes = vec![0u8; auth_ciphertext.len()];
        rng.fill(xor_bytes.as_mut_slice());

        for (ct_byte, xor_byte) in auth_ciphertext.iter_mut().zip(xor_bytes.iter()) {
            *ct_byte ^= xor_byte;
        }

        let res = Aes128Gcm::open(&key, nonce, auth_ciphertext);
        assert!(res.is_err());
    }

    // Diffie Hellman test vectors from https://tools.ietf.org/html/rfc7748#section-6.1
    #[test]
    fn x25519_kat() {
        let alice_scalar = {
            let hex_str = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
            let bytes = hex::decode(hex_str).unwrap();
            X25519::scalar_from_bytes(&bytes).expect("couldn't make scalar from bytes")
        };
        let bob_scalar = {
            let hex_str = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
            let bytes = hex::decode(hex_str).unwrap();
            X25519::scalar_from_bytes(&bytes).expect("couldn't make scalar from bytes")
        };

        // Compute aP and bP where a is Alice's scalar, and b is Bob's
        let alice_pubkey = X25519::multiply_basepoint(&alice_scalar);
        let bob_pubkey = X25519::multiply_basepoint(&bob_scalar);

        // Compute b(aP) and a(bP) and make sure they are the same
        let shared_secret_a = X25519::diffie_hellman(&alice_scalar, &bob_pubkey);
        let shared_secret_b = X25519::diffie_hellman(&bob_scalar, &alice_pubkey);

        // Known-answer for aP
        assert_eq!(
            hex::encode(&alice_pubkey.0),
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        );
        // Known-answer for bP
        assert_eq!(
            hex::encode(&bob_pubkey.0),
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
        );
        // Test b(aP) == a(bP)
        assert_eq!(shared_secret_a.0, shared_secret_b.0);
        // Known-answer for abP
        assert_eq!(
            hex::encode(shared_secret_a.0),
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        );
    }

    // This comes from
    // https://github.com/mlswg/mls-implementations/blob/master/test_vectors/treesnodes.md
    #[test]
    fn node_key_derivation_kat() {
        let scalar = {
            let hex_str = "e029fbe9de859e7bd6aea95ac258ae743a9eabccde9358420d8c975365938714";
            eprintln!("hex_str.len() == {}", hex_str.len());
            let bytes = hex::decode(hex_str).unwrap();
            X25519::scalar_from_bytes(&bytes).expect("couldn't make scalar from bytes")
        };

        let pubkey = X25519::multiply_basepoint(&scalar);

        assert_eq!(
            hex::encode(pubkey.0),
            "6667b1715a0ad45b0510e850322a8d471d4485ebcbfcc0f3bcce7bcae7b44f7f"
        );
    }

    // TODO: Add randomized x25519 correctness test and derive_key_pair KAT
}
