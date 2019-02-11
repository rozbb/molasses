use crate::crypto::rng::CryptoRng;
use crate::error::Error;

/// A singleton object representing the AES-128-GCM AEAD scheme
pub(crate) const AES128GCM_IMPL: Aes128Gcm = Aes128Gcm;

/// Size of opening / sealing keys, in bytes
const AES_128_GCM_KEY_SIZE: usize = 128 / 8;
/// Size of tag, in bytes
const AES_128_GCM_TAG_SIZE: usize = 128 / 8;
/// Size of nonces, in bytes
const AES_128_GCM_NONCE_SIZE: usize = 96 / 8;

/// An enum of possible types for an AEAD key, depending on the underlying algorithm
pub(crate) enum AeadKey {
    /// An opening / sealing key in AES-128-GCM
    Aes128GcmKey(Aes128GcmKey),
}

/// An enum of possible types for an AEAD nonce, depending on the underlying algorithm
pub(crate) enum AeadNonce {
    /// A nonce in AES-128-GCM
    Aes128GcmNonce(ring::aead::Nonce),
}

/// A trait representing an authenticated encryption algorithm. Note that this makes no mention of
/// associated data, since it is not used anywhere in MLS.
// ring does algorithm specification at runtime, but I'd rather encode these things in the type
// system. So, similar to the Digest trait, we're making an AuthenticatedEncryption trait. I don't
// think we'll need associated data in this crate, so we leave it out for simplicity
pub(crate) trait AuthenticatedEncryption {
    // Recall we can't have const trait methods if we want this to be a trait object
    fn key_size(&self) -> usize;
    fn nonce_size(&self) -> usize;
    fn tag_size(&self) -> usize;

    fn key_from_bytes(&self, key_bytes: &[u8]) -> Result<AeadKey, Error>;

    // TODO: Determine whether this method is actually necessary
    // This has to take a dyn CryptoRng because DiffieHellman is itself a trait object inside a
    // CipherSuite. Trait objects can't have associated types, associated constants, or generic
    // methods.
    fn key_from_random(&self, csprng: &mut dyn CryptoRng) -> Result<AeadKey, Error>;

    fn nonce_from_bytes(&self, nonce_bytes: &[u8]) -> Result<AeadNonce, Error>;

    fn open<'a>(
        &self,
        key: &AeadKey,
        nonce: AeadNonce,
        ciphertext_and_tag: &'a mut [u8],
    ) -> Result<&'a mut [u8], Error>;

    fn seal(&self, key: &AeadKey, nonce: AeadNonce, plaintext: &mut [u8]) -> Result<(), Error>;
}

/// This represents the AES-128-GCM authenticated encryption algorithm. Notably, it implements
/// `AuthenticatedEncryption`.
pub(crate) struct Aes128Gcm;

/// An opening / sealing key for use with the `Aes128Gcm` algorithm
// These will just be two copies of the same thing. They're different types because ring requires
// an OpeningKey for opening and a SealingKey for sealing. This incurs some 64 bytes of storage
// overhead, but I frankly don't care.
pub(crate) struct Aes128GcmKey {
    opening_key: ring::aead::OpeningKey,
    sealing_key: ring::aead::SealingKey,
}

/// A nonce for use with the `Aes128Gcm` algorithm
pub(crate) struct Aes128GcmNonce(ring::aead::Nonce);

impl AuthenticatedEncryption for Aes128Gcm {
    /// Returns `AES_128_GCM_KEY_SIZE`
    fn key_size(&self) -> usize {
        AES_128_GCM_KEY_SIZE
    }

    /// Returns `AES_128_GCM_NONCE_SIZE`
    fn nonce_size(&self) -> usize {
        AES_128_GCM_NONCE_SIZE
    }

    /// Returns `AES_128_GCM_TAG_SIZE`
    fn tag_size(&self) -> usize {
        AES_128_GCM_TAG_SIZE
    }

    /// Makes a new AES-GCM key from the given key bytes.
    ///
    /// Requires: `key_bytes.len() == AES_128_GCM_KEY_SIZE`
    ///
    /// Returns: `Ok(key)` on success. On error (don't ask me why this could fail), returns an
    /// `Error`.
    fn key_from_bytes(&self, key_bytes: &[u8]) -> Result<AeadKey, Error> {
        if key_bytes.len() != AES_128_GCM_KEY_SIZE {
            return Err(Error::EncryptionError("AES-GCM-128 requires 128-bit keys"));
        }

        // Again, the opening and sealing keys for AES-GCM are the same.
        let opening_key = ring::aead::OpeningKey::new(&ring::aead::AES_128_GCM, key_bytes)
            .map_err(|_| Error::EncryptionError("Unspecified"))?;
        let sealing_key = ring::aead::SealingKey::new(&ring::aead::AES_128_GCM, key_bytes)
            .map_err(|_| Error::EncryptionError("Unspecified"))?;

        let key = Aes128GcmKey {
            opening_key,
            sealing_key,
        };
        Ok(AeadKey::Aes128GcmKey(key))
    }

    /// Makes a new secure-random AES-GCM key.
    ///
    /// Returns: `Ok(key)` on success. On error , returns `Error::OutOfEntropy`.
    fn key_from_random(&self, csprng: &mut dyn CryptoRng) -> Result<AeadKey, Error> {
        let mut key = [0u8; AES_128_GCM_KEY_SIZE];
        // This could fail for a number of reasons, but the net result is that we don't have
        // random bytes anymore
        csprng
            .try_fill_bytes(&mut key)
            .map_err(|_| Error::OutOfEntropy)?;

        self.key_from_bytes(&key)
    }

    /// Makes a new AES-GCM nonce from the given bytes.
    ///
    /// Requires: `nonce_bytes.len() == AES_128_GCM_NONCE_SIZE`
    ///
    /// Returns: `Ok(Self::
    fn nonce_from_bytes(&self, nonce_bytes: &[u8]) -> Result<AeadNonce, Error> {
        if nonce_bytes.len() != AES_128_GCM_NONCE_SIZE {
            return Err(Error::EncryptionError("AES-GCM-128 requires 96-bit nonces"));
        }

        let mut nonce = [0u8; AES_128_GCM_NONCE_SIZE];
        nonce.copy_from_slice(nonce_bytes);
        Ok(AeadNonce::Aes128GcmNonce(
            ring::aead::Nonce::assume_unique_for_key(nonce),
        ))
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
    fn open<'a>(
        &self,
        key: &AeadKey,
        nonce: AeadNonce,
        ciphertext_and_tag_modified_in_place: &'a mut [u8],
    ) -> Result<&'a mut [u8], Error> {
        let key = enum_variant!(key, AeadKey::Aes128GcmKey);
        let nonce = enum_variant!(nonce, AeadNonce::Aes128GcmNonce);

        // We use the standard decryption function with no associated data, and no "prefix bytes".
        // The length of the buffer is checked by the ring library. The function returns a
        // plaintext = ciphertext_and_tag[..plaintext.len()] For more details on this function, see
        // docs on ring::aead::open_in_place at
        // https://briansmith.org/rustdoc/ring/aead/fn.open_in_place.html
        ring::aead::open_in_place(
            &key.opening_key,
            nonce,
            ring::aead::Aad::empty(),
            0,
            ciphertext_and_tag_modified_in_place,
        )
        .map_err(|_| Error::EncryptionError("Unspecified"))
    }

    /// Does an in-place authenticated encryption of the given plaintext. The input MUST look like
    /// `plaintext || extra`, where `extra` is 16 bytes long and its contents does note matter.
    /// After a successful run, the input will be modified to consist of a tagged ciphertext. That
    /// is, it will be of the form `ciphertext || tag` where `tag` is 16 bytes long.
    ///
    /// Requires: `plaintext.len() >= 16`
    ///
    /// Returns: `Ok(())` on sucess, indicating that the inputted buffer contains the tagged
    /// ciphertext. If there is an error in any part of this process, it will be returned as an
    /// `Error::CryptoError` with description "Unspecified".
    #[must_use]
    fn seal(&self, key: &AeadKey, nonce: AeadNonce, plaintext: &mut [u8]) -> Result<(), Error> {
        let key = enum_variant!(key, AeadKey::Aes128GcmKey);
        let nonce = enum_variant!(nonce, AeadNonce::Aes128GcmNonce);

        // We use the standard encryption function with no associated data. The length of the
        // buffer is checked by the ring library.
        // For more details on this function, see docs on ring::aead::seal_in_place at
        // https://briansmith.org/rustdoc/ring/aead/fn.seal_in_place.html
        let res = ring::aead::seal_in_place(
            &key.sealing_key,
            nonce,
            ring::aead::Aad::empty(),
            plaintext,
            AES_128_GCM_TAG_SIZE,
        );

        if res.is_ok() {
            Ok(())
        } else {
            Err(Error::EncryptionError("Unspecified"))
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use quickcheck_macros::quickcheck;
    use rand::{RngCore, SeedableRng};

    // TODO: AES-GCM KAT

    // Returns a pair of identical nonces. For testing purposes only
    fn make_nonce_pair<T: RngCore>(rng: &mut T) -> (AeadNonce, AeadNonce) {
        let mut buf = [0u8; AES_128_GCM_NONCE_SIZE];

        rng.fill_bytes(&mut buf);

        (
            AES128GCM_IMPL.nonce_from_bytes(&buf).unwrap(),
            AES128GCM_IMPL.nonce_from_bytes(&buf).unwrap(),
        )
    }

    // Test that decrypt_k(encrypt_k(m)) == m
    #[quickcheck]
    fn aes_gcm_correctness(plaintext: Vec<u8>, rng_seed: u64) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(rng_seed);
        let key = AES128GCM_IMPL
            .key_from_random(&mut rng)
            .expect("failed to generate key");
        // The open method consumes our nonce, so make two nonces
        let (nonce1, nonce2) = make_nonce_pair(&mut rng);
        // Make sure there's enough room in the plaintext for the tag
        let mut extended_plaintext = [plaintext.as_slice(), &[0u8; AES_128_GCM_TAG_SIZE]].concat();

        AES128GCM_IMPL
            .seal(&key, nonce1, extended_plaintext.as_mut_slice())
            .expect("failed to encrypt");

        // Rename for clarity, since plaintext was modified in-place
        let auth_ciphertext = extended_plaintext.as_mut_slice();

        let recovered_plaintext = AES128GCM_IMPL
            .open(&key, nonce2, auth_ciphertext)
            .expect("failed to decrypt");

        // Make sure we get out what we put in
        assert_eq!(plaintext, recovered_plaintext);
    }

    // Test that perturbations in auth_ct := encrypt_k(m) make it fail to decrypt. This includes
    // perturbations in the tag of auth_ct.
    #[quickcheck]
    fn aes_gcm_integrity_ct_and_tag(mut plaintext: Vec<u8>, rng_seed: u64) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(rng_seed);
        let key = AES128GCM_IMPL
            .key_from_random(&mut rng)
            .expect("failed to generate key");
        // The open method consumes our nonce, so make two nonces
        let (nonce1, nonce2) = make_nonce_pair(&mut rng);
        // Make sure there's enough room in the plaintext for the tag
        plaintext.extend(vec![0u8; AES_128_GCM_TAG_SIZE]);

        AES128GCM_IMPL
            .seal(&key, nonce1, plaintext.as_mut_slice())
            .expect("failed to encrypt");

        // Rename for clarity, since plaintext was modified in-place
        let auth_ciphertext = plaintext.as_mut_slice();

        // Make a random byte string that's exactly the length of the authenticated ciphertext.
        // We'll XOR these bytes with the authenticated ciphertext.
        let mut xor_bytes = vec![0u8; auth_ciphertext.len()];
        rng.fill_bytes(xor_bytes.as_mut_slice());

        // Do the XORing
        for (ct_byte, xor_byte) in auth_ciphertext.iter_mut().zip(xor_bytes.iter()) {
            *ct_byte ^= xor_byte;
        }

        // Make sure this fails to open
        let res = AES128GCM_IMPL.open(&key, nonce2, auth_ciphertext);
        assert!(res.is_err());
    }

    // Test that perturbations in auth_ct := encrypt_k(m) make it fail to decrypt. This includes
    // only perturbations to the ciphertext of auth_ct, leaving the tag alone.
    #[quickcheck]
    fn aes_gcm_integrity_ct(mut plaintext: Vec<u8>, rng_seed: u64) {
        // This is only interesting if plaintext != "". Since XORing anything into the empty string
        // is a noop, the open() operation below will actually succeed. This property is checked in
        // aes_gcm_correctness.
        if plaintext.len() == 0 {
            return;
        }

        let mut rng = rand::rngs::StdRng::seed_from_u64(rng_seed);
        let key = AES128GCM_IMPL
            .key_from_random(&mut rng)
            .expect("failed to generate key");
        // The open method consumes our nonce, so make two nonces
        let (nonce1, nonce2) = make_nonce_pair(&mut rng);
        // Make sure there's enough room in the plaintext for the tag
        plaintext.extend(vec![0u8; AES_128_GCM_TAG_SIZE]);

        AES128GCM_IMPL
            .seal(&key, nonce1, plaintext.as_mut_slice())
            .expect("failed to encrypt");

        // Rename for clarity, since plaintext was modified in-place
        let auth_ciphertext = plaintext.as_mut_slice();

        // Make a random byte string that's exactly the length of the authenticated ciphertext,
        // minus the tag length. We'll XOR these bytes with the ciphertext part.
        let mut xor_bytes = vec![0u8; auth_ciphertext.len() - AES_128_GCM_TAG_SIZE];
        rng.fill_bytes(xor_bytes.as_mut_slice());

        // Do the XORing
        for (ct_byte, xor_byte) in auth_ciphertext.iter_mut().zip(xor_bytes.iter()) {
            *ct_byte ^= xor_byte;
        }

        // Make sure this fails to open
        let res = AES128GCM_IMPL.open(&key, nonce2, auth_ciphertext);
        assert!(res.is_err());
    }
}
