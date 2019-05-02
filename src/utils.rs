use crate::{
    crypto::{
        ciphersuite::CipherSuite,
        dh::{DhPrivateKey, DhPublicKey},
        hkdf,
    },
    error::Error,
    ratchet_tree::{NodeSecret, PathSecret},
};

/// Unwraps an enum into an expected variant. Panics if the supplied value is not of the expected
/// variant. This macro is used to succinctly ensure that ciphersuite values are kept consistent
/// throughout the library.
#[allow(unreachable_patterns)]
macro_rules! enum_variant {
    ($val:expr, $variant:path) => {
        match $val {
            $variant(x) => x,
            _ => panic!("Got wrong enum variant. Was expecting {}", stringify!($variant)),
        }
    };
    // Like the above, but with a custom message
    ($val:expr, $variant:path, $custom_msg:literal) => {
        match $val {
            $variant(x) => x,
            _ => panic!($custom_msg),
        }
    };
}

/// Returns `(node_public_key, node_private_key, node_secret, path_secret_[n])`, given
/// `path_secret_[n-1]`
///
/// Requires: `path_secret.len() == cs.hash_alg.output_len`
///
/// Panics: If above condition is not satisfied
pub(crate) fn derive_node_values(
    cs: &'static CipherSuite,
    mut path_secret: PathSecret,
) -> Result<(DhPublicKey, DhPrivateKey, NodeSecret, PathSecret), Error> {
    assert_eq!(path_secret.0.len(), cs.hash_alg.output_len, "path secret length != Hash.length");

    let prk = hkdf::prk_from_bytes(cs.hash_alg, &*path_secret.0);
    // node_secret[n] = HKDF-Expand-Label(path_secret[n], "node", "", Hash.Length)
    let mut node_secret = NodeSecret(vec![0u8; cs.hash_alg.output_len]);
    hkdf::hkdf_expand_label(&prk, b"node", b"", &mut *node_secret.0);
    // path_secret[n] = HKDF-Expand-Label(path_secret[n-1], "path", "", Hash.Length)
    hkdf::hkdf_expand_label(&prk, b"path", b"", &mut *path_secret.0);

    // Derive the private and public keys and assign them to the node
    let (node_public_key, node_private_key) = cs.derive_key_pair(&node_secret.0)?;

    Ok((node_public_key, node_private_key, node_secret, path_secret))
}
