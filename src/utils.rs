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

// This was taken and modified from https://serde.rs/enum-number.html
/// This takes a definition of an enum of only unit variants and makes it serializable and
/// deserializable according to its discriminant values
#[macro_export]
macro_rules! make_enum_u8_discriminant {
    ($name:ident { $($variant:ident = $value:expr, )* }) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub enum $name {
            $($variant = $value,)*
        }

        impl serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                // Make sure the discriminant isn't too high
                if (*self as usize) > std::u8::MAX as usize {
                    panic!("variant discriminant out of range")
                }

                // Serialize the enum as a u8.
                let disc = *self as u8;
                serializer.serialize_u8(disc)
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct Visitor;

                impl<'de> serde::de::Visitor<'de> for Visitor {
                    type Value = $name;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                        formatter.write_str("a single byte")
                    }

                    fn visit_u8<E>(self, value: u8) -> Result<$name, E>
                    where
                        E: serde::de::Error,
                    {
                        // Rust does not come with a simple way of converting a number to an enum,
                        // so use a big `match`.
                        match value {
                            $( $value => Ok($name::$variant), )*
                            _ => Err(
                                     E::custom(
                                         format!(
                                             "unexpected discriminant for {}: {}",
                                             stringify!($name),
                                             value
                                         )))
                        }
                    }
                }

                // Deserialize the enum from a u8.
                deserializer.deserialize_u8(Visitor)
            }
        }
    }
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
