//! This module contains all the cryptographic utilities necessary in MLS. The main players are an
//! AEAD, a Diffie Hellman scheme, and a digital signature scheme.

// Allow this because sometimes enum_variant! is called on single-variant types, which produces
// unnecessary warnings
#![allow(unreachable_patterns)]

pub(crate) mod aead;
pub mod ciphersuite;
pub(crate) mod dh;
pub(crate) mod ecies;
pub(crate) mod hash;
pub(crate) mod hkdf;
pub(crate) mod hmac;
pub mod rng;
pub mod sig;

#[cfg(test)]
mod test {
    use crate::{
        crypto::{
            ciphersuite::X25519_SHA256_AES128GCM,
            dh::DhPublicKey,
            ecies::{self, EciesCiphertext},
            hkdf,
            hmac::HmacKey,
        },
        error::Error,
        tls_de::TlsDeserializer,
        upcast::{CryptoCtx, CryptoUpcast},
    };

    use serde::de::Deserialize;

    // The following test vector is from
    // https://github.com/mlswg/mls-implementations/tree/master/test_vectors
    //
    // File: crypto.bin
    //
    // struct {
    //   opaque hkdf_extract_out<0..255>;
    //   group_state: GroupState,
    //   opaque derive_secret_out<0..255>;
    //   DHPublicKey derive_key_pair_pub;
    //   ECIESCiphertext ecies_out;
    // } CryptoCase;
    //
    // struct {
    //   opaque hkdf_extract_salt<0..255>;
    //   opaque hkdf_extract_ikm<0..255>;
    //   opaque derive_secret_salt<0..255>;
    //   opaque derive_secret_label<0..255>;
    //   opaque derive_secret_context<0..255>;
    //   opaque derive_key_pair_seed<0..255>;
    //   opaque ecies_plaintext<0..255>;
    //
    //   CryptoCase case_p256_p256;
    //   CryptoCase case_x25519_ed25519;
    // } CryptoTestVectors;
    //
    // The CryptoTestVectors struct contains the inputs to cryptographic functions, and the
    // CryptoCase members hold the outputs when using the indicated ciphersuites.  The following
    // functions are tested:
    //
    // * HKDF-Extract
    // * Derive-Secret
    //   * The salt and label arguments are provided
    //   * The State argument should be initialized with the following contents:
    //     * group_id and transcript_hash: The zero-length octet string
    //     * epoch: 0
    //     * tree: Zero-length vector
    //   * That is, the state should serialize to a sequence of 14 zeros
    // * Derive-Key-Pair
    // * ECIES
    //   * Encryption and decryption is done using the key pair generated in the Derive-Key-Pair
    //     stage.
    //   * The encryption phase is made deterministic by deriving the ephemeral key pair from the
    //     inputs.
    //   * (skE, pkE)  = Derive-Key-Pair(pkR || plaintext), where pkR is the serialization of the
    //     recipient's public key (the body of a DHPublicKey, with no length octets), and plaintext
    //     is the plaintext being encrypted.

    #[derive(Debug, Deserialize)]
    struct CryptoCase {
        #[serde(rename = "hkdf_extract_out__bound_u8")]
        hkdf_extract_out: Vec<u8>,
        #[serde(rename = "derive_secret_out__bound_u8")]
        derive_secret_out: Vec<u8>,
        derive_key_pair_pub: DhPublicKey,
        ecies_out: EciesCiphertext,
    }

    impl CryptoUpcast for CryptoCase {
        fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<CryptoCtx, Error> {
            self.derive_key_pair_pub.upcast_crypto_values(ctx)?;
            self.ecies_out.upcast_crypto_values(ctx)?;
            Ok(*ctx)
        }
    }

    #[derive(Debug, Deserialize)]
    struct CryptoTestVectors {
        #[serde(rename = "hkdf_extract_salt__bound_u8")]
        hkdf_extract_salt: Vec<u8>,
        #[serde(rename = "hkdf_extract_ikm__bound_u8")]
        hkdf_extract_ikm: Vec<u8>,
        #[serde(rename = "derive_secret_salt__bound_u8")]
        derive_secret_salt: Vec<u8>,
        #[serde(rename = "derive_secret_label__bound_u8")]
        derive_secret_label: Vec<u8>,
        #[serde(rename = "derive_secret_context__bound_u8")]
        derive_secret_context: Vec<u8>,
        #[serde(rename = "derive_key_pair_seed__bound_u8")]
        derive_key_pair_seed: Vec<u8>,
        #[serde(rename = "ecies_plaintext__bound_u8")]
        ecies_plaintext: Vec<u8>,

        case_p256_p256: CryptoCase,
        case_x25519_ed25519: CryptoCase,
    }

    // Tests our code against the official crypto test vector
    #[test]
    fn official_crypto_kat() {
        let mut f = std::fs::File::open("test_vectors/crypto.bin").unwrap();
        let mut deserializer = TlsDeserializer::from_reader(&mut f);
        let test_vec = CryptoTestVectors::deserialize(&mut deserializer).unwrap();

        let cs = &X25519_SHA256_AES128GCM;
        let case1 = {
            let mut raw_case = test_vec.case_x25519_ed25519;
            let ctx = crate::upcast::CryptoCtx::new().set_cipher_suite(cs);
            raw_case.upcast_crypto_values(&ctx).unwrap();
            raw_case
        };

        // prk  = derive_sercret_salt
        let prk = HmacKey::new_from_bytes(&test_vec.derive_secret_salt);

        // Test Derive-Secret against known answer.
        // derive_secret_out == Derive-Secret(
        //     prk=derive_secret_salt,
        //     info=derive_secret_label,
        //     context=derive_secret_context
        //  )
        let derive_secret_out = hkdf::derive_secret(
            cs.hash_impl,
            &prk,
            &test_vec.derive_secret_label,
            &test_vec.derive_secret_context,
        )
        .unwrap();
        // Wrap the RHS in an HMAC key so we can compare it to the LHS HmacKey
        assert_eq!(derive_secret_out, HmacKey::new_from_bytes(&case1.derive_secret_out));

        // Test Derive-Key-Pair(derive_key_pair_seed) against known answer
        let (recip_public_key, recip_secret_key) =
            cs.derive_key_pair(&dbg!(test_vec.derive_key_pair_seed)).unwrap();
        let expected_recip_public_key = case1.derive_key_pair_pub;
        // Just compare the public keys
        assert_serialized_eq!(recip_public_key, expected_recip_public_key);

        // Make sure the decryption of the ECIES ciphertext is indeed the given plaintext
        let derived_plaintext =
            ecies::decrypt(cs, &recip_secret_key, case1.ecies_out.clone()).unwrap();
        let expected_plaintext = test_vec.ecies_plaintext.clone();
        assert_eq!(&derived_plaintext, &expected_plaintext);

        // Now make sure that we get the same ECIES ciphertext if we use the same ephemeral private
        // key as the test creator.
        // key_pair = Derive-Key-Pair(recip_public_key.as_bytes() || plaintext)
        let (_, sender_secret_key) = {
            // key_material = pkR || plaintext where pkR is the serialization of recip_public_key
            let key_material =
                [recip_public_key.as_bytes(), test_vec.ecies_plaintext.as_slice()].concat();
            // key_pair = Derive-Key-Pair(key_material)
            cs.derive_key_pair(&key_material).unwrap()
        };
        // ciphertext = Ecies-Encrypt_(sender_secret_key,recip_public_key)(plaintext)
        let derived_ciphertext = ecies::encrypt_with_scalar(
            cs,
            &recip_public_key,
            test_vec.ecies_plaintext,
            sender_secret_key,
        )
        .unwrap();
        // Now serialize both ciphertexts and make sure they agree
        assert_serialized_eq!(derived_ciphertext, case1.ecies_out);
    }
}
