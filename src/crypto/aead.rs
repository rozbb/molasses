use crate::error::Error;

use rand::Rng;
use ring::aead::AES_128_GCM as AES_128_GCM_ALG;

const AES_GCM_128_KEY_SIZE: usize = 128 / 8;
const AES_GCM_128_TAG_SIZE: usize = 128 / 8;
const AES_GCM_128_NONCE_SIZE: usize = 96 / 8;

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

    fn open<'a>(
        key: &Self::Key,
        nonce: Self::Nonce,
        ciphertext_and_tag: &'a mut [u8],
    ) -> Result<&'a mut [u8], Error>;

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
        // TODO: Once it's possible to do so, I want key_byte: [u8; Self::KEY_SIZE]. This is
        // blocked on https://github.com/rust-lang/rust/issues/39211
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
        // This could fail for a number of reasons, but the net result is that we don't have
        // random bytes anymore
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
    fn open<'a>(
        key: &Aes128GcmKey,
        nonce: Self::Nonce,
        ciphertext_and_tag_modified_in_place: &'a mut [u8],
    ) -> Result<&'a mut [u8], Error> {
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
            Err(_) => Err(Error::EncryptionError("Unspecified")),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use quickcheck_macros::quickcheck;

    // TODO: AES-GCM KAT

    // Test that decrypt_k(encrypt_k(m)) == m
    #[quickcheck]
    fn aes_gcm_correctness(plaintext: Vec<u8>) {
        let mut rng = rand::thread_rng();
        let key = Aes128Gcm::key_from_random(&mut rng).expect("failed to generate key");

        let (mut auth_ciphertext, nonce) =
            Aes128Gcm::seal(&key, plaintext.clone(), &mut rng).expect("failed to encrypt");
        let recovered_plaintext = Aes128Gcm::open(&key, nonce, auth_ciphertext.as_mut_slice())
            .expect("failed to decrypt");

        // Make sure we get out what we put in
        assert_eq!(plaintext, recovered_plaintext);
    }

    // Test that perturbations in auth_ct := encrypt_k(m) make it fail to decrypt. This includes
    // perturbations in the tag of auth_ct.
    #[quickcheck]
    fn aes_gcm_integrity_ct_and_tag(plaintext: Vec<u8>) {
        let mut rng = rand::thread_rng();
        let key = Aes128Gcm::key_from_random(&mut rng).expect("failed to generate key");

        let (mut auth_ciphertext, nonce) =
            Aes128Gcm::seal(&key, plaintext, &mut rng).expect("failed to encrypt");

        // Make a random byte string that's exactly the length of the authenticated ciphertext.
        // We'll XOR these bytes with the authenticated ciphertext.
        let mut xor_bytes = vec![0u8; auth_ciphertext.len()];
        rng.fill(xor_bytes.as_mut_slice());

        // Do the XORing
        for (ct_byte, xor_byte) in auth_ciphertext.iter_mut().zip(xor_bytes.iter()) {
            *ct_byte ^= xor_byte;
        }

        // Make sure this fails to open
        let res = Aes128Gcm::open(&key, nonce, auth_ciphertext.as_mut_slice());
        assert!(res.is_err());
    }

    // Test that perturbations in auth_ct := encrypt_k(m) make it fail to decrypt. This includes
    // only perturbations to the ciphertext of auth_ct, leaving the tag alone.
    #[quickcheck]
    fn aes_gcm_integrity_ct(plaintext: Vec<u8>) {
        // This is only interesting if plaintext != "". Since XORing anything into the empty string
        // is a noop, the open() operation below will actually succeed. This property is checked in
        // aes_gcm_correctness.
        if plaintext.len() == 0 {
            return;
        }

        let mut rng = rand::thread_rng();
        let key = Aes128Gcm::key_from_random(&mut rng).expect("failed to generate key");

        let (mut auth_ciphertext, nonce) =
            Aes128Gcm::seal(&key, plaintext, &mut rng).expect("failed to encrypt");

        // Make a random byte string that's exactly the length of the authenticated ciphertext,
        // minus the tag length. We'll XOR these bytes with the ciphertext part.
        let mut xor_bytes = vec![0u8; auth_ciphertext.len() - AES_GCM_128_TAG_SIZE];
        rng.fill(xor_bytes.as_mut_slice());

        // Do the XORing
        for (ct_byte, xor_byte) in auth_ciphertext.iter_mut().zip(xor_bytes.iter()) {
            *ct_byte ^= xor_byte;
        }

        // Make sure this fails to open
        let res = Aes128Gcm::open(&key, nonce, auth_ciphertext.as_mut_slice());
        assert!(res.is_err());
    }
}
