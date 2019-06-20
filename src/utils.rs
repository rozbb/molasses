use crate::{
    crypto::{
        ciphersuite::CipherSuite,
        dh::{DhPrivateKey, DhPublicKey},
        hkdf,
        hmac::HmacKey,
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

/// Given a path secret, derives all node-specific values as well as the subsequent path secret.
///
/// Requires: `path_secret.len() == cs.hash_impl.digest_size()`
///
/// Returns: `Ok((public_key, private_key, ns, ps))` on success. If above condition is not
/// satisfied, returns an `Error::ValidationError`.
pub(crate) fn derive_node_values(
    cs: &CipherSuite,
    path_secret: PathSecret,
) -> Result<(DhPublicKey, DhPrivateKey, NodeSecret, PathSecret), Error> {
    let digest_size = cs.hash_impl.digest_size();
    if path_secret.len() != digest_size {
        return Err(Error::ValidationError("Path secret length != Hash.length"));
    }

    // PathSecrets are secretly HMAC keys
    let prk: HmacKey = path_secret.into();

    // node_secret[n] = HKDF-Expand-Label(path_secret[n], "node", "", Hash.Length)
    let mut node_secret_buf = vec![0u8; digest_size];
    hkdf::expand_label(cs.hash_impl, &prk, b"node", b"", &mut node_secret_buf);

    // path_secret[n] = HKDF-Expand-Label(path_secret[n-1], "path", "", Hash.Length)
    let mut path_secret_buf = vec![0u8; digest_size];
    hkdf::expand_label(cs.hash_impl, &prk, b"path", b"", &mut path_secret_buf);

    // Derive the private and public keys and assign them to the node
    let (node_public_key, node_private_key) = cs.derive_key_pair(&node_secret_buf)?;

    // Wrap the new values and return them
    let node_secret = NodeSecret(node_secret_buf);
    let new_path_secret = PathSecret::new_from_bytes(&path_secret_buf);
    Ok((node_public_key, node_private_key, node_secret, new_path_secret))
}
