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
#[macro_export]
macro_rules! enum_variant {
    ($val:expr, $variant:path) => {
        match $val {
            $variant(x) => x,
            _ => panic!("Got wrong enum variant. Was expecting {}", stringify!($variant)),
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

#[cfg(test)]
pub(crate) mod test_utils {
    use crate::{
        credential::{self, BasicCredential, Credential, Roster},
        crypto::{
            ciphersuite::{CipherSuite, X25519_SHA256_AES128GCM},
            rng::CryptoRng,
            sig::{SigSecretKey, SignatureScheme, ED25519_IMPL},
        },
        group_state::GroupState,
        ratchet_tree::{PathSecret, RatchetTree, RatchetTreeNode},
        tree_math,
    };

    use core::convert::TryFrom;

    use rand::seq::SliceRandom;

    pub(crate) fn random_path_secret<R: rand::Rng>(group: &GroupState, rng: &mut R) -> PathSecret {
        let mut buf = vec![0u8; group.cs.hash_alg.output_len];
        rng.fill_bytes(buf.as_mut_slice());
        PathSecret::new(buf)
    }

    // Generates a random roster index within the given bounds, and guarantees that the output is
    // not `cannot_choose`
    pub(crate) fn random_roster_index_with_exception<R: rand::Rng>(
        roster_size: usize,
        cannot_choose: usize,
        rng: &mut R,
    ) -> u32 {
        loop {
            let idx = rng.gen_range(0, roster_size);
            if idx != cannot_choose as usize {
                return u32::try_from(idx).unwrap();
            }
        }
    }

    // Generates a random BasicCredential with the given SignatureScheme
    fn random_credential<R: rand::Rng + CryptoRng>(
        rng: &mut R,
        signature_scheme: &'static dyn SignatureScheme,
    ) -> (Credential, SigSecretKey) {
        // Make a random 16 byte identity
        let identity = {
            let mut buf = [0u8; 16];
            rng.fill_bytes(&mut buf);
            credential::Identity(buf.to_vec())
        };
        // Make a random keypair
        let secret_key = signature_scheme.secret_key_from_random(rng).unwrap();
        let public_key = signature_scheme.public_key_from_secret_key(&secret_key);

        let cred = Credential::Basic(BasicCredential {
            identity,
            signature_scheme,
            public_key,
        });

        (cred, secret_key)
    }

    // Generates a random tree of given size
    fn random_tree<R: rand::Rng + CryptoRng>(
        rng: &mut R,
        cs: &'static CipherSuite,
        num_leaves: usize,
    ) -> RatchetTree {
        // Make a tree of Blanks, then fill it with private keys
        let num_nodes = tree_math::num_nodes_in_tree(num_leaves);
        let mut tree = RatchetTree {
            nodes: vec![RatchetTreeNode::Blank; num_nodes],
        };

        // In a random order, fill the tree
        let leaf_indices: Vec<usize> = (0..num_leaves).map(|i| i.checked_mul(2).unwrap()).collect();
        for idx in leaf_indices.into_iter() {
            // Random path secret used to derive all private keys up the tree
            let path_secret = {
                let mut buf = [0u8; 32];
                rng.fill_bytes(&mut buf);
                PathSecret::new(buf.to_vec())
            };
            tree.propagate_new_path_secret(cs, path_secret, idx)
                .expect("couldn't propagate random secrets in a random tree");
        }

        tree
    }

    // Generates a random GroupState object and all the identity keys associated with the
    // credentials in the roster. The group state generated has all roster entries non-null and all
    // tree nodes Filled with known secrets.
    pub(crate) fn random_full_group_state<R: rand::Rng + CryptoRng>(
        rng: &mut R,
    ) -> (GroupState, Vec<SigSecretKey>) {
        // TODO: Expand the number of available ciphersuites once more are available
        let cipher_suites = &[X25519_SHA256_AES128GCM];
        let cs = cipher_suites.choose(rng).unwrap();

        // Group size and position in group are random
        let group_size: u32 = rng.gen_range(2, 50);
        let my_roster_idx: u32 = rng.gen_range(0, group_size);

        // Make a full roster (no empty slots) of random creds and store the identity keys
        let mut roster = Roster(Vec::new());
        let mut identity_keys = Vec::new();
        for _ in 0..group_size {
            let (cred, secret) = random_credential(rng, cs.sig_impl);
            roster.0.push(Some(cred));
            identity_keys.push(secret);
        }
        let my_identity_key = identity_keys[my_roster_idx as usize].clone();

        // Make a full tree with all secrets known
        let tree = random_tree(rng, cs, group_size as usize);

        // Make a random 16 byte group ID
        let group_id = {
            let mut buf = [0u8; 16];
            rng.fill_bytes(&mut buf);
            buf
        };
        // Make a random init_secret and transcript_hash of length Hash.length
        let init_secret = {
            let mut buf = vec![0u8; cs.hash_alg.output_len];
            rng.fill_bytes(&mut buf);
            buf
        };
        let transcript_hash = {
            let mut buf = vec![0u8; cs.hash_alg.output_len];
            rng.fill_bytes(&mut buf);
            buf
        };

        let group_state = GroupState {
            cs: cs,
            protocol_version: 0,
            identity_key: my_identity_key,
            group_id: group_id.to_vec(),
            epoch: rng.gen(),
            roster: roster,
            tree: tree,
            transcript_hash: transcript_hash,
            roster_index: Some(my_roster_idx),
            initializing_user_init_key: None,
            init_secret: init_secret,
        };

        (group_state, identity_keys)
    }

    // Returns a randomly-generated Credential along with its corresponding identity key
    pub(crate) fn random_basic_credential<R: rand::Rng + CryptoRng>(
        rng: &mut R,
    ) -> (Credential, SigSecretKey) {
        // Make a random identity
        let identity = {
            let mut buf = [0u8; 16];
            rng.fill_bytes(&mut buf);
            credential::Identity(buf.to_vec())
        };

        // TODO: Expand the number of available ciphersuites once more are available
        let signature_schemes = [&ED25519_IMPL];
        let signature_scheme = *signature_schemes.choose(rng).unwrap();

        // Generate a random keypair
        let identity_key = signature_scheme.secret_key_from_random(rng).unwrap();
        let public_key = signature_scheme.public_key_from_secret_key(&identity_key);

        let cred = Credential::Basic(BasicCredential {
            identity,
            signature_scheme,
            public_key,
        });

        (cred, identity_key)
    }

    // Returns a new GroupState where the roster index is changed to the given `new_index` and the
    // identity key is changed to correspond to that roster index. Requires that the secret keys in
    // `identity_keys` correspond to the public keys in the given group's roster
    pub(crate) fn change_self_index(
        group_state: &GroupState,
        identity_keys: &Vec<SigSecretKey>,
        new_index: u32,
    ) -> GroupState {
        assert!(new_index as usize <= group_state.roster.len());

        let mut new_group_state = group_state.clone();
        new_group_state.roster_index = Some(new_index);
        new_group_state.identity_key = identity_keys[new_index as usize].clone();

        new_group_state
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
