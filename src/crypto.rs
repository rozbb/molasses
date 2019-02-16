mod aead;
pub(crate) mod ciphersuite;
pub(crate) mod dh;
pub(crate) mod ecies;
mod rng;
pub(crate) mod sig;


/*
#[cfg(test)]
mod test {
    use crate::crypto::{
        dh::DhPoint,
    };
    #[derive(Deserialize, Serialize)]
    struct CryptoCase {
        #[serde(rename = "hkdf_extract_out__bound_u8")]
        hkdf_extract_out: Vec<u8>,
        #[serde(rename = "derive_secret_out__bound_u8")]
        derive_secret_out: Vec<u8>,
        derive_key_pair_pub: DhPoint,
        ecies_out: EciesCiphertext,
    }

    #[derive(Deserialize, Serialize)]
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
        case_p521_p521: CryptoCase,
        case_x448_ed448: CryptoCase,
    }
}
*/
