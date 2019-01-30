use crate::error::Error;

use digest::Digest;
use ring::aead::AES_128_GCM as AES_128_GCM_ALG;
use ring::rand::SecureRandom;
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

const AES_GCM_128_KEY_LENGTH: usize = 128 / 8;
const AES_GCM_128_TAG_LENGTH: usize = 128 / 8;
const AES_GCM_128_NONCE_LENGTH: usize = 96 / 8;

const X25519_POINT_LENGTH: usize = 32;
const X25519_SCALAR_LENGTH: usize = 32;

// Any error from ring should leak zero information by default
impl From<ring::error::Unspecified> for Error {
    fn from(_: ring::error::Unspecified) -> Self {
        Error::CryptoError("Unspecified")
    }
}

// These will just be two copies of the same thing. They're different types because ring requires
// an OpeningKey for opening and a SealingKey for sealing. This incurs some 64 bytes of storage
// overhead, but I frankly don't care.
pub struct Aes128GcmKey {
    opening_key: ring::aead::OpeningKey,
    sealing_key: ring::aead::SealingKey,
}

// ring does algorithm specification at runtime, but I'd rather encode these things in the type
// system. So, similar to the Digest trait, we're making an AuthenticatedEncryption trait. I don't
// think we'll need associated data in this crate, so we leave it out for simplicity
pub trait AuthenticatedEncryption {
    /// Nonce type
    type Nonce;
    /// Key type
    type Key;

    fn key_from_bytes(key_bytes: &[u8]) -> Result<Self::Key, Error>;

    fn key_from_random<T>(csprng: &mut T) -> Result<Self::Key, Error>
    where
        T: rand_core::RngCore + rand_core::CryptoRng;

    fn open_in_place<'a>(
        key: &Self::Key,
        nonce: Self::Nonce,
        ciphertext_and_tag_modified_in_place: &'a mut [u8],
    ) -> Result<&'a mut [u8], Error>;

    fn seal_in_place(
        key: &Self::Key,
        plaintext_modified_in_place: &mut [u8],
    ) -> Result<(Self::Nonce, usize), Error>;
}

pub struct Aes128Gcm;

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
        // TODO: Once associated consts stabilizes, I want key_byte: [u8; Self::KEY_LENGTH]
        if key_bytes.len() != AES_GCM_128_KEY_LENGTH {
            return Err(Error::CryptoError("AES-GCM-128 requires 128-bit keys"));
        }

        // Again, the opening and sealing keys for AES-GCM are the same.
        let opening_key = ring::aead::OpeningKey::new(&AES_128_GCM_ALG, key_bytes)?;
        let sealing_key = ring::aead::SealingKey::new(&AES_128_GCM_ALG, key_bytes)?;

        Ok(Aes128GcmKey {
            opening_key,
            sealing_key,
        })
    }

    /// Makes a new secure-random AES-GCM key.
    ///
    /// Returns: `Ok(key)` on success. On error , returns an `Error`.
    fn key_from_random<T>(csprng: &mut T) -> Result<Aes128GcmKey, Error>
    where
        T: rand_core::RngCore + rand_core::CryptoRng,
    {
        let mut key = [0u8; AES_GCM_128_KEY_LENGTH];
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
    fn open_in_place<'a>(
        key: &Aes128GcmKey,
        nonce: Self::Nonce,
        ciphertext_and_tag_modified_in_place: &'a mut [u8],
    ) -> Result<&'a mut [u8], Error> {
        // We use the standard decryption function with no associated data, and no "prefix bytes".
        // The length of the buffer is checked by the ring library.
        // For more details on this function, see docs on ring::aead::open_in_place at
        // https://briansmith.org/rustdoc/ring/aead/fn.open_in_place.html
        ring::aead::open_in_place(
            &key.opening_key,
            nonce,
            ring::aead::Aad::empty(),
            0,
            ciphertext_and_tag_modified_in_place,
        )
        .map_err(From::from)
    }

    /// Does an in-place authenticated encryption of the given plaintext. There must be 16 extra
    /// bytes at the end of the buffer to leave room for the auth tag.
    /// This function will generate its own random nonce using `ring::rand::SystemRandom`, or else
    /// fail.
    ///
    /// Returns: `Ok((nonce, len))` upon success, where `nonce` is the nonce that was used for
    /// encryption, and `len` is the length of the tagged ciphertext, i.e.,
    /// `plaintext_modified_in_place[..len]` is of the form `ciphertext || tag`. If encryption
    /// fails, an `Error` is returned.
    fn seal_in_place<'a>(
        key: &Aes128GcmKey,
        plaintext_modified_in_place: &'a mut [u8],
    ) -> Result<(Self::Nonce, usize), Error> {
        let mut nonce = [0u8; AES_GCM_128_NONCE_LENGTH];
        let rng = ring::rand::SystemRandom::new();
        rng.fill(&mut nonce).map_err(|_| Error::OutOfEntropy)?;

        // The sealing algorithm consumes the nonce, so make a copy to return when we're done.
        // The constructor used here is the trivial one (`Nonce` just holds a buffer of bytes)
        let nonce_to_return = ring::aead::Nonce::assume_unique_for_key(nonce.clone());

        // We use the standard encryption function with no associated data. The length of the
        // buffer is checked by the ring library.
        // For more details on this function, see docs on ring::aead::seal_in_place at
        // https://briansmith.org/rustdoc/ring/aead/fn.seal_in_place.html
        let res = ring::aead::seal_in_place(
            &key.sealing_key,
            ring::aead::Nonce::assume_unique_for_key(nonce), // This is the trivial constructor
            ring::aead::Aad::empty(),
            plaintext_modified_in_place,
            AES_GCM_128_TAG_LENGTH,
        );

        match res {
            Ok(len) => Ok((nonce_to_return, len)),
            Err(e) => Err(e.into()),
        }
    }
}

pub trait DiffieHellman {
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

pub struct X25519;
pub struct X25519Scalar([u8; X25519_SCALAR_LENGTH]);
pub struct X25519Point([u8; X25519_POINT_LENGTH]);

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
        if bytes.len() != X25519_SCALAR_LENGTH {
            return Err(Error::CryptoError("Unspecified"));
        } else {
            let mut buf = [0u8; X25519_SCALAR_LENGTH];
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

pub trait CipherSuite {
    type DH: DiffieHellman;
    type Hash: Digest;
    type Aead: AuthenticatedEncryption;
}

/// This type is used to indicate a particular cipher suite
#[allow(non_camel_case_types)]
pub struct X25519_SHA256_AES128GCM;

impl CipherSuite for X25519_SHA256_AES128GCM {
    type DH = X25519;
    type Hash = sha2::Sha256;
    type Aead = Aes128Gcm;
}

#[cfg(test)]
mod test {
    use crate::crypto::*;

    use quickcheck_macros::quickcheck;
    use rand::RngCore;

    // TODO: AES-GCM KAT

    // Test that decrypt_k(encrypt_k(m)) == m
    #[quickcheck]
    fn aes_gcm_correctness(plaintext: Vec<u8>) {
        let mut rng = rand::thread_rng();
        let key = Aes128Gcm::key_from_random(&mut rng).expect("failed to generate key");

        // Recall we need free space at the end to put the tag in.
        let padding = [0u8; AES_GCM_128_TAG_LENGTH];
        let mut padded_plaintext = [plaintext.as_slice(), &padding[..]].concat();

        let (nonce, len) = Aes128Gcm::seal_in_place(&key, padded_plaintext.as_mut_slice())
            .expect("failed to encrypt");

        // The length of the tagged ciphertext should be the length of the padded plaintext
        assert_eq!(len, padded_plaintext.len());

        // Change the name for clarity's sake
        let mut authenticated_ciphertext = padded_plaintext;
        let recovered_plaintext =
            Aes128Gcm::open_in_place(&key, nonce, authenticated_ciphertext.as_mut_slice())
                .expect("failed to decrypt");

        assert_eq!(plaintext, recovered_plaintext);
    }

    // Test that perturbations in encrypt_k(m) make it fail to decrypt
    #[quickcheck]
    fn aes_gcm_integrity(plaintext: Vec<u8>) {
        let mut rng = rand::thread_rng();
        let key = Aes128Gcm::key_from_random(&mut rng).expect("failed to generate key");

        // Recall we need free space at the end to put the tag in.
        let padding = [0u8; AES_GCM_128_TAG_LENGTH];
        let mut padded_plaintext = [plaintext.as_slice(), &padding[..]].concat();

        let (nonce, len) = Aes128Gcm::seal_in_place(&key, padded_plaintext.as_mut_slice())
            .expect("failed to encrypt");

        // The length of the tagged ciphertext should be the length of the padded plaintext
        assert_eq!(len, padded_plaintext.len());

        // Change the name for clarity's sake
        let mut authenticated_ciphertext = padded_plaintext;

        let mut xor_bytes = vec![0u8; authenticated_ciphertext.len()];
        rng.fill_bytes(xor_bytes.as_mut_slice());

        for (ct_byte, xor_byte) in authenticated_ciphertext.iter_mut().zip(xor_bytes.iter()) {
            *ct_byte ^= xor_byte;
        }

        let res = Aes128Gcm::open_in_place(&key, nonce, authenticated_ciphertext.as_mut_slice());
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

    // TODO: Add randomize x25519 correctness test
}
