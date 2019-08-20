use crate::{
    crypto::{
        ciphersuite::CipherSuite,
        dh::{DhPrivateKey, DhPublicKey},
        hkdf::{self, HkdfPrk},
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
/// Returns: `Ok((public_key, private_key, ps))` on success. If above condition is not satisfied,
/// returns an `Error::ValidationError`.
pub(crate) fn derive_node_values(
    cs: &'static CipherSuite,
    path_secret: PathSecret,
) -> Result<(DhPublicKey, DhPrivateKey, PathSecret), Error> {
    // PathSecrets are secretly HKDF PRKs
    let prk: HkdfPrk = path_secret.into();

    // node_secret[n] = HKDF-Expand-Label(path_secret[n], "node", "", Hash.Length)
    let node_secret: NodeSecret = hkdf::expand_label(cs, &prk, b"node", b"")?;

    // path_secret[n] = HKDF-Expand-Label(path_secret[n-1], "path", "", Hash.Length)
    let new_path_secret: PathSecret = hkdf::expand_label(cs, &prk, b"path", b"")?;

    // Derive the private and public keys and assign them to the node
    let (node_public_key, node_private_key) = cs.derive_key_pair(node_secret.as_bytes())?;

    Ok((node_public_key, node_private_key, new_path_secret))
}
