mod aead;
pub(crate) mod ciphersuite;
pub(crate) mod dh;
pub(crate) mod ecies;
mod rng;
pub(crate) mod sig;

#[cfg(test)]
mod test {
    use crate::{
        credential::Credential,
        crypto::{
            ciphersuite::X25519_SHA256_AES128GCM,
            dh::DhPoint,
            ecies::{ecies_decrypt, EciesCiphertext},
        },
        group_state::GroupState,
        ratchet_tree::RatchetTree,
        tls_de::TlsDeserializer,
    };

    use serde::de::Deserialize;

    #[derive(Debug, Deserialize)]
    pub(crate) struct TestGroupState {
        #[serde(rename = "group_id__bound_u8")]
        group_id: Vec<u8>,
        epoch: u32,
        #[serde(rename = "roster__bound_u32")]
        roster: Vec<Option<Credential>>,
        tree: RatchetTree,
        #[serde(rename = "transcript_hash__bound_u8")]
        pub(crate) transcript_hash: Vec<u8>,
    }

    fn group_from_test_group(tgs: TestGroupState) -> GroupState {
        let cs = &X25519_SHA256_AES128GCM;
        let zeros = vec![0u8; cs.hash_alg.output_len];
        let confirmation_key = ring::hmac::SigningKey::new(cs.hash_alg, &zeros);
        GroupState {
            cs: cs,
            identity_key: cs.sig_impl.secret_key_from_bytes(&[0u8; 32]).unwrap(),
            group_id: tgs.group_id,
            epoch: tgs.epoch,
            roster: tgs.roster,
            tree: tgs.tree,
            transcript_hash: tgs.transcript_hash,
            my_position_in_roster: 0,
            init_secret: Vec::new(),
            application_secret: Vec::new(),
            confirmation_key: confirmation_key,
        }
    }

    // The following test vector is from
    // https://github.com/mlswg/mls-implementations/tree/master/test_vectors
    //
    // File: crypto.bin
    //
    // struct {
    //   opaque hkdf_extract_out<0..255>;
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
    //   uint32 derive_secret_length;
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
    //     * roster, tree: Zero-length vectors
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
        group_state: TestGroupState,
        #[serde(rename = "derive_secret_out__bound_u8")]
        derive_secret_out: Vec<u8>,
        derive_key_pair_pub: DhPoint,
        ecies_out: EciesCiphertext,
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
        derive_secret_length: u32,
        #[serde(rename = "derive_key_pair_seed__bound_u8")]
        derive_key_pair_seed: Vec<u8>,
        #[serde(rename = "ecies_plaintext__bound_u8")]
        ecies_plaintext: Vec<u8>,

        case_p256_p256: CryptoCase,
        case_x25519_ed25519: CryptoCase,
    }

    #[test]
    fn official_crypto_kat() {
        let mut f = std::fs::File::open("test_vectors/crypto.bin").unwrap();
        let mut deserializer = TlsDeserializer::from_reader(&mut f);
        let test_vec = CryptoTestVectors::deserialize(&mut deserializer).unwrap();

        let case1 = test_vec.case_x25519_ed25519;
        let group_state = group_from_test_group(case1.group_state);
        let prk =
            ring::hmac::SigningKey::new(group_state.cs.hash_alg, &test_vec.derive_secret_salt);

        let derive_secret_out = group_state.derive_secret(&prk, &test_vec.derive_secret_label);
        assert_eq!(&derive_secret_out, &case1.derive_secret_out);

        let (public_key, secret_key)  =
            X25519_SHA256_AES128GCM.derive_key_pair(&test_vec.derive_key_pair_seed).unwrap();
        let public_key_bytes =
            X25519_SHA256_AES128GCM.dh_impl.point_as_bytes(public_key);
        let expected_public_key_bytes =
            X25519_SHA256_AES128GCM.dh_impl.point_as_bytes(case1.derive_key_pair_pub);
        assert_eq!(public_key_bytes, expected_public_key_bytes);

        let derived_plaintext = ecies_decrypt(&X25519_SHA256_AES128GCM, &secret_key, case1.ecies_out).expect("could not decrypt ecies ciphertext");
        assert_eq!(&derived_plaintext, &test_vec.ecies_plaintext);
    }
}
