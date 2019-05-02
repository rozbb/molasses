use crate::{
    crypto::{
        ciphersuite::CipherSuite,
        dh::{DhPrivateKey, DhPublicKey},
        ecies,
        rng::CryptoRng,
    },
    error::Error,
    handshake::{DirectPathMessage, DirectPathNodeMessage},
    tree_math, utils,
};

use clear_on_drop::ClearOnDrop;
use subtle::ConstantTimeEq;

/// This is called the "node secret" (section 5.2). If `Hash` is the current ciphersuite's hash
/// algorithm, this MUST have length equal to `Hash.length`.
pub(crate) struct NodeSecret(pub(crate) Vec<u8>);

/// This is called the "path secret" (section 5.2). If `Hash` is the current ciphersuite's hash
/// algorithm, this MUST have length equal to `Hash.length`.
#[derive(Clone)]
pub struct PathSecret(pub(crate) ClearOnDrop<Vec<u8>>);

impl PathSecret {
    /// Wraps a `Vec<u8>` with a `ClearOnDrop` and makes it a `PathSecret`
    pub(crate) fn new(v: Vec<u8>) -> PathSecret {
        PathSecret(ClearOnDrop::new(v))
    }

    /// Generates a random `PathSecret` of the appropriate length
    pub fn new_from_random(cs: &'static CipherSuite, csprng: &mut dyn CryptoRng) -> PathSecret {
        let mut buf = vec![0u8; cs.hash_alg.output_len];
        csprng.fill_bytes(&mut buf);
        PathSecret(ClearOnDrop::new(buf))
    }
}

// Ratchet trees are serialized in DirectPath messages as optional<PublicKey> tree<1..2^32-1> So we
// encode RatchetTree as a Vec<RatchetTreeNode> with length bound u32, and we encode
// RatchetTreeNode as enum { Blank, Filled { DhPublicKey } }, which is encoded in the same way as
// an Option<DhPublicKey> would be.

/// A node in a `RatchetTree`. Every node must have a DH pubkey. It may also optionally contain the
/// corresponding private key and a secret octet string.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename = "RatchetTreeNode__enum_u8")]
pub(crate) enum RatchetTreeNode {
    Blank,
    Filled {
        public_key: DhPublicKey,
        #[serde(skip)]
        private_key: Option<DhPrivateKey>,
    },
}

impl RatchetTreeNode {
    /// Makes a new node with a known keypair, given the private key
    pub(crate) fn new_from_private_key(
        cs: &'static CipherSuite,
        private_key: DhPrivateKey,
    ) -> RatchetTreeNode {
        // Derive the pubkey and stick it in the node
        let pubkey = cs.dh_impl.derive_public_key(&private_key);
        RatchetTreeNode::Filled {
            public_key: pubkey,
            private_key: Some(private_key),
        }
    }

    /// Returns `true` iff this is the `Filled` variant
    #[rustfmt::skip]
    pub(crate) fn is_filled(&self) -> bool {
        if let RatchetTreeNode::Filled { .. } = self {
            true
        } else {
            false
        }
    }

    /// Updates the node's public key to the given one. This is the only way to convert a `Blank`
    /// node into a `Filled` one.
    pub(crate) fn update_public_key(&mut self, new_public_key: DhPublicKey) {
        match self {
            &mut RatchetTreeNode::Blank => {
                *self = RatchetTreeNode::Filled {
                    public_key: new_public_key,
                    private_key: None,
                };
            }
            &mut RatchetTreeNode::Filled {
                ref mut public_key,
                ..
            } => *public_key = new_public_key,
        }
    }

    /// Returns a node's public key. If the node is `Blank`, returns `None`.
    pub(crate) fn get_public_key(&self) -> Option<&DhPublicKey> {
        match self {
            &RatchetTreeNode::Blank => None,
            &RatchetTreeNode::Filled {
                ref public_key,
                ..
            } => Some(public_key),
        }
    }

    /// Updates the node's private key to the given one
    ///
    /// Panics: If the node is `Blank`
    pub(crate) fn update_private_key(&mut self, new_private_key: DhPrivateKey) {
        match self {
            &mut RatchetTreeNode::Blank => panic!("tried to update private key of blank node"),
            &mut RatchetTreeNode::Filled {
                public_key: _,
                ref mut private_key,
            } => {
                *private_key = Some(new_private_key);
            }
        }
    }

    /// Returns `Some(&private_key)` if the node contains a private key. Otherwise returns `None`.
    pub(crate) fn get_private_key(&self) -> Option<&DhPrivateKey> {
        match self {
            &RatchetTreeNode::Blank => None,
            &RatchetTreeNode::Filled {
                public_key: _,
                ref private_key,
            } => private_key.as_ref(),
        }
    }
}

/// A left-balanced binary tree of `RatchetTreeNode`s
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct RatchetTree {
    #[serde(rename = "nodes__bound_u32")]
    pub(crate) nodes: Vec<RatchetTreeNode>,
}

impl RatchetTree {
    /// Returns the number of nodes in the tree
    pub(crate) fn size(&self) -> usize {
        self.nodes.len()
    }

    /// Returns the node at the given index
    pub(crate) fn get(&self, idx: usize) -> Option<&RatchetTreeNode> {
        self.nodes.get(idx)
    }

    /// Returns a mutable reference to the node at the given index
    pub(crate) fn get_mut(&mut self, idx: usize) -> Option<&mut RatchetTreeNode> {
        self.nodes.get_mut(idx)
    }

    // It turns out that appending to the tree in this way preserves the left-balanced property
    // while keeping everything in place. Instead of a proof, stare this diagram where I add a new
    // leaf node to a tree of 3 leaves, and then add another leaf to that. The stars represent
    // non-leaf nodes.
    //         *                   *                        *
    //       /   \               /   \                _____/ \
    //      /     C   Add(D)    /     \    Add(E)    /        |
    //     *          =====>   *       *   =====>   *         |
    //    / \                 / \     / \         /   \       |
    //   A   B               A   B   C   D       /     \      |
    //   0 1 2 3  4          0 1 2 3 4 5 6      *       *     |
    //                                         / \     / \    |
    //                                        A   B   C   D   E
    //                                        0 1 2 3 4 5 6 7 8
    pub(crate) fn add_leaf_node(&mut self, node: RatchetTreeNode) {
        if self.nodes.is_empty() {
            self.nodes.push(node);
            return;
        } else {
            self.nodes.push(RatchetTreeNode::Blank);
            self.nodes.push(node);
        }
    }

    /// Blanks out the direct path of the given node, as well as the root node
    pub(crate) fn propagate_blank(&mut self, start_idx: usize) {
        let num_leaves = tree_math::num_leaves_in_tree(self.size());
        let direct_path = tree_math::node_extended_direct_path(start_idx, num_leaves);

        // Blank the extended direct path (direct path + root node)
        for i in direct_path {
            // No need to check index here. By construction, there's no way this is out of bounds
            self.nodes[i] = RatchetTreeNode::Blank;
        }
    }

    // This always produces a valid tree. To see this, note that truncating to a leaf node when
    // there are >1 non-blank leaf nodes gives you a vector of odd length. All vectors of odd
    // length have a unique interpretation as a binary left-balanced tree. And if there are no
    // non-blank leaf nodes, you get an empty tree.
    /// Truncates the tree down to the first non-blank leaf node. If there is all blank, this will
    /// clear the tree.
    pub(crate) fn truncate_to_last_nonblank(&mut self) {
        let num_leaves = tree_math::num_leaves_in_tree(self.size());

        // Look for the last non-blank leaf by iterating backwards through the leaves in the tree
        let mut last_nonblank_leaf = None;
        for idx in tree_math::tree_leaves(num_leaves).rev() {
            if self.nodes[idx].is_filled() {
                last_nonblank_leaf = Some(idx);
                break;
            }
        }

        match last_nonblank_leaf {
            // If there are no nonempty entries in the roster, clear it
            None => self.nodes.clear(),
            Some(i) => {
                // This can't fail, because i is an index
                let num_elements_to_retain = i + 1;
                self.nodes.truncate(num_elements_to_retain)
            }
        }
    }

    /// Returns the indices of the resolution of a given node: this an ordered sequence of minimal
    /// set of non-blank nodes that collectively cover (A "covers" B iff A is an ancestor of B) all
    /// non-blank descendants of the given node. The ordering is ascending by node index.
    pub(crate) fn resolution(&self, idx: usize) -> Vec<usize> {
        // Helper function that accumulates the resolution recursively
        fn helper(tree: &RatchetTree, i: usize, acc: &mut Vec<usize>) {
            if let RatchetTreeNode::Blank = tree.nodes[i] {
                if tree_math::node_level(i) == 0 {
                    // The resolution of a blank leaf node is the empty list
                    return;
                } else {
                    // The resolution of a blank intermediate node is the result of concatinating
                    // the resolution of its left child with the resolution of its right child, in
                    // that order
                    let num_leaves = tree_math::num_leaves_in_tree(tree.nodes.len());
                    helper(tree, tree_math::node_left_child(i), acc);
                    helper(tree, tree_math::node_right_child(i, num_leaves), acc);
                }
            } else {
                // The resolution of a non-blank node is a one element list containing the node
                // itself
                acc.push(i);
            }
        }

        let mut ret = Vec::new();
        helper(self, idx, &mut ret);
        ret
    }

    /// Overwrites all the public keys in the extended (including root) direct path of
    /// `start_tree_idx` with `public_keys`, stopping before setting the public key at
    /// `stop_before_tree_idx`. If `stop_before_tree_idx` is not found in the direct path, this
    /// will overwrite the public keys of the whole extended direct path.
    ///
    /// Returns: `Ok(())` on success. Returns `Error::ValidationError` if the direct path range of
    /// `[start_tree_idx, stop_before_tree_idx)` is longer than the `public_keys` iterator.
    #[must_use]
    pub(crate) fn set_public_keys_with_bound<'a, I: Iterator<Item = &'a DhPublicKey>>(
        &mut self,
        start_tree_idx: usize,
        stop_before_tree_idx: usize,
        mut public_keys: I,
    ) -> Result<(), Error> {
        let num_leaves = tree_math::num_leaves_in_tree(self.size());
        // Update all the public keys of the nodes in the direct path that are below our common
        // ancestor, i.e., all the ones whose secret we don't know. Note that this step is not
        // performed in apply_update, because this only happens when we're not the ones who created
        // the Update operation.
        let sender_direct_path = tree_math::node_extended_direct_path(start_tree_idx, num_leaves);
        for path_node_idx in sender_direct_path {
            let pubkey = public_keys.next().ok_or(Error::ValidationError(
                "Partial direct path is longer than public key iterator",
            ))?;
            if path_node_idx == stop_before_tree_idx {
                // We reached the stopping node
                break;
            } else {
                let node = self
                    .get_mut(path_node_idx)
                    .ok_or(Error::ValidationError("Direct path node is out of range"))?;
                node.update_public_key(pubkey.clone());
            }
        }

        Ok(())
    }

    /// Checks if the public keys on the direct path of `start_idx` agree with the public keys
    /// returned by the iterator `expected_public_keys`.
    ///
    /// Returns: `Ok(())` iff everything is in agreement and the iterator is as long as the direct
    /// path. Returns some sort of `Error::ValidationError` otherwise.
    pub(crate) fn validate_direct_path_public_keys<'a, I: Iterator<Item = &'a DhPublicKey>>(
        &self,
        start_idx: usize,
        mut expected_public_keys: I,
    ) -> Result<(), Error> {
        let num_leaves = tree_math::num_leaves_in_tree(self.size());

        // Verify that the pubkeys in the message agree with our newly-derived pubkeys all the way
        // up the tree (including the root node). We go through the iterators in lock-step. If one
        // is longer than the other, that's a problem, and we throw and error.
        let mut ext_direct_path = tree_math::node_extended_direct_path(start_idx, num_leaves);
        loop {
            match (ext_direct_path.next(), expected_public_keys.next()) {
                (Some(path_node_idx), Some(expected_pubkey)) => {
                    let existing_pubkey = self
                        .get(path_node_idx)
                        .ok_or(Error::ValidationError("Unexpected out-of-bounds path index"))?
                        .get_public_key()
                        .ok_or(Error::ValidationError("Node on direct path has no public key"))?;

                    // Constant-time compare the pubkeys (I don't think CT is necessary, but I
                    // ain't taking any chances)
                    let expected_bytes = expected_pubkey.as_bytes();
                    let existing_bytes = existing_pubkey.as_bytes();
                    // The underlying value is 1 iff expected_bytes == existing_bytes
                    if expected_bytes.ct_eq(existing_bytes).unwrap_u8() != 1 {
                        return Err(Error::ValidationError(
                            "Inconsistent public keys in Update message",
                        ));
                    }
                }
                (None, None) => {
                    // Both iterators ended at the same time. This means we're done
                    return Ok(());
                }
                (_, _) => {
                    // If one iterator ended before the other, that's an error
                    return Err(Error::ValidationError(
                        "Size of expected direct path does not match reality",
                    ));
                }
            }
        }
    }

    /// Given a path secret, constructs a `DirectPathMessage` containing encrypted copies of the
    /// appropriately ratcheted path secret for the rest of the ratchet tree. See section
    /// 5.2 in the spec for details.
    ///
    /// Requires: `starting_tree_idx` to be a leaf node. Otherwise, any child of ours would be
    /// unable to decrypt this message.
    pub(crate) fn encrypt_direct_path_secrets(
        &self,
        cs: &'static CipherSuite,
        starting_tree_idx: usize,
        starting_path_secret: PathSecret,
        csprng: &mut dyn CryptoRng,
    ) -> Result<DirectPathMessage, Error> {
        // Check if it's a leaf node
        if starting_tree_idx % 2 != 0 {
            return Err(Error::TreeError("Cannot encrypt direct paths of non-leaf nodes"));
        }

        let num_leaves = tree_math::num_leaves_in_tree(self.size());
        let direct_path = tree_math::node_direct_path(starting_tree_idx as usize, num_leaves);

        let mut node_messages = Vec::new();

        // The first message should be just the starting node's pubkey and no encrypted messages
        let (starting_node_public_key, _, _, mut parent_path_secret) =
            utils::derive_node_values(cs, starting_path_secret)?;
        node_messages.push(DirectPathNodeMessage {
            public_key: starting_node_public_key.clone(),
            node_secrets: Vec::with_capacity(0),
        });

        // Go up the direct path of the starting index
        for path_node_idx in direct_path {
            // We need to derive the new parent's public key to send in the same message as the
            // encrypted copies of the parent's path_secret
            let (parent_public_key, _, _, grandparent_path_secret) =
                utils::derive_node_values(cs, parent_path_secret.clone())?;

            // Encrypt the path secret at the current node's parent for everyone in the resolution
            // of the copath node. We can unwrap() here because self.resolution only returns
            // indices that are actually in the tree.
            let mut encrypted_path_secrets = Vec::new();
            let copath_node_idx = tree_math::node_sibling(path_node_idx, num_leaves);
            for res_node in self.resolution(copath_node_idx).iter().map(|&i| &self.nodes[i]) {
                // We can unwrap() here because self.resolution only returns indices of nodes
                // that are non-blank, by definition of "resolution"
                let others_public_key = res_node.get_public_key().unwrap();
                // Encrypt the parent's path secret with the resolution node's pubkey
                let ciphertext = ecies::ecies_encrypt(
                    cs,
                    others_public_key,
                    (&*parent_path_secret.0).to_vec(), // TODO: Make this not copy secrets
                    csprng,
                )?;
                encrypted_path_secrets.push(ciphertext);
            }

            // Push the collection to the message list
            node_messages.push(DirectPathNodeMessage {
                public_key: parent_public_key.clone(),
                node_secrets: encrypted_path_secrets,
            });

            // Ratchet up the path secret
            parent_path_secret = grandparent_path_secret;
        }

        Ok(DirectPathMessage {
            node_messages,
        })
    }

    /// Finds the (unique) ciphertext in the given direct path message that is meant for this
    /// member and decrypts it. `starting_node_idx` is the the index of the starting node of the
    /// encoded direct path.
    ///
    /// Requires: `starting_tree_idx` cannot be an ancestor of `my_tree_idx`, nor vice-versa. We
    /// cannot decrypt messages that violate this.
    ///
    /// Returns: `Ok((pt, idx))` where `pt` is the `Result` of decrypting the found ciphertext and
    /// `idx` is the common ancestor of `starting_tree_idx` and `my_tree_idx`. If no decryptable
    /// ciphertext exists, returns an `Error::TreeError`. If decryption fails, returns an
    /// `Error::EncryptionError`.
    pub(crate) fn decrypt_direct_path_message(
        &self,
        cs: &'static CipherSuite,
        direct_path_msg: &DirectPathMessage,
        starting_tree_idx: usize,
        my_tree_idx: usize,
    ) -> Result<(PathSecret, usize), Error> {
        let num_leaves = tree_math::num_leaves_in_tree(self.size());

        if starting_tree_idx >= self.size() || my_tree_idx >= self.size() {
            return Err(Error::TreeError("Input index out of range"));
        }

        if tree_math::is_ancestor(starting_tree_idx, my_tree_idx, num_leaves)
            || tree_math::is_ancestor(my_tree_idx, starting_tree_idx, num_leaves)
        {
            return Err(Error::TreeError("Cannot decrypt messages from ancestors or descendants"));
        }

        // This is the intermediate node in the direct path whose secret was encrypted for us.
        let common_ancestor_idx =
            tree_math::common_ancestor(starting_tree_idx, my_tree_idx, num_leaves);

        // This holds the secret of the intermediate node, encrypted for all the nodes in the
        // resolution of the copath node.
        let node_msg = {
            // To get this value, we have to figure out the correct index into node_message
            let (pos_in_msg_vec, _) =
                tree_math::node_extended_direct_path(starting_tree_idx, num_leaves)
                    .enumerate()
                    .find(|&(_, dp_idx)| dp_idx == common_ancestor_idx)
                    .expect("common ancestor somehow did not appear in direct path");
            direct_path_msg
                .node_messages
                .get(pos_in_msg_vec)
                .ok_or(Error::TreeError("Malformed DirectPathMessage"))?
        };

        // This is the unique acnestor of the receiver that is in the copath of the sender. This is
        // the one whose resolution is used.
        let copath_ancestor_idx = {
            let left = tree_math::node_left_child(common_ancestor_idx);
            let right = tree_math::node_right_child(common_ancestor_idx, num_leaves);
            if tree_math::is_ancestor(left, my_tree_idx, num_leaves) {
                left
            } else {
                right
            }
        };

        // We're looking for an ancestor in the resolution of this copath node. There is
        // only one such node. Furthermore, we should already know the private key of the
        // node that we find. So our strategy is to look for a node with a private key that
        // we know, then make sure that it is our ancestor.
        let resolution = self.resolution(copath_ancestor_idx);

        // Comb the resolution for a node whose private key we know
        for (pos_in_res, res_node_idx) in resolution.into_iter().enumerate() {
            let res_node = self.get(res_node_idx).expect("resolution out of bounds");
            if res_node.get_private_key().is_some()
                && tree_math::is_ancestor(res_node_idx, my_tree_idx, num_leaves)
            {
                // We found the ancestor in the resolution. Now get the decryption key and
                // corresponding ciphertext
                let decryption_key = res_node.get_private_key().unwrap();
                let ciphertext_for_me = node_msg
                    .node_secrets
                    .get(pos_in_res)
                    .ok_or(Error::TreeError("Malformed DirectPathMessage"))?;

                // Finally, decrypt the thing and return the plaintext and common ancestor
                let pt = ecies::ecies_decrypt(cs, decryption_key, ciphertext_for_me.clone())?;
                return Ok((PathSecret::new(pt), common_ancestor_idx));
            }
        }

        return Err(Error::TreeError("Cannot find node in resolution with known private key"));
    }

    /// Updates the path secret at the given index and derives the path secrets, node secrets,
    /// private keys, and public keys of all its ancestors. If this process fails, this method will
    /// _not_ roll back the operation, so the caller should expect this object to be in an invalid
    /// state.
    ///
    /// Requires: `path_secret.len() == cs.hash_alg.output_len`
    ///
    /// Panics: If above condition is not satisfied
    ///
    /// Returns: `Ok(node_secret)` on success, where `node_secret` is the node secret of the root
    /// node of the updated ratchet tree.
    pub(crate) fn propagate_new_path_secret(
        &mut self,
        cs: &'static CipherSuite,
        mut path_secret: PathSecret,
        start_idx: usize,
    ) -> Result<NodeSecret, Error> {
        let num_leaves = tree_math::num_leaves_in_tree(self.size());
        let root_node_idx = tree_math::root_idx(num_leaves);

        let mut current_node_idx = start_idx;

        // Go up the tree, setting the node secrets and keypairs. The last calculated node secret
        // is that of the root. This is our return value
        let root_node_secret = loop {
            let current_node =
                self.get_mut(current_node_idx).expect("reached invalid node in secret propagation");

            // Derive the new values
            let (node_public_key, node_private_key, node_secret, new_path_secret) =
                utils::derive_node_values(cs, path_secret)?;

            // Update the current node with all the new values. Note: the order here matters. You
            // have to update the public key first, because you can't update a Blank node's secret
            // key (it must have a public key first)
            current_node.update_public_key(node_public_key);
            current_node.update_private_key(node_private_key);

            if current_node_idx == root_node_idx {
                // If we just updated the root, we're done
                break node_secret;
            } else {
                // Otherwise, take one step up the tree
                current_node_idx = tree_math::node_parent(current_node_idx, num_leaves);
                path_secret = new_path_secret;
            }
        };

        Ok(root_node_secret)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        crypto::{
            ciphersuite::X25519_SHA256_AES128GCM,
            dh::{DhPublicKey, DhPublicKeyRaw},
        },
        tls_de::TlsDeserializer,
    };

    use quickcheck_macros::quickcheck;
    use rand::SeedableRng;
    use rand::{Rng, RngCore};
    use serde::Deserialize;

    // The following test vector is from
    // https://github.com/mlswg/mls-implementations/tree/master/test_vectors
    //
    // File: resolution.bin
    //
    // uint8_t Resolution<0..255>;
    // Resolution ResolutionCase<0..2^16-1>;
    //
    // struct {
    //   uint32_t n_leaves;
    //   ResolutionCase cases<0..2^32-1>;
    // } ResolutionTestVectors;
    //
    // These vectors represent the output of the resolution algorithm on all configurations of a
    // tree with n_leaves leaves.
    //
    // * The cases vector should have 2^(2*n_leaves - 1) entries
    //   * The entry at index t represents the set of resolutions for the tree with a blank /
    //     filled pattern matching the bit pattern of the integer t.
    //   * If (t >> n) == 1, then node n in the tree is filled; otherwise it is blank.
    // * Each ResolutionCase vector contains the resolutions of every node in the tree, in order
    // * Thus cases[t][i] contains the resolution of node i in tree t
    //
    // Your implementation should be able to reproduce these values.
    // Parses the bits of a u32 from right to left, interpreting a 0 as a Blank node and 1 as a
    // Filled node (unimportant what the pubkey is)

    #[derive(Debug, Deserialize)]
    #[serde(rename = "Resolution__bound_u8")]
    struct Resolution(Vec<u8>);

    #[derive(Debug, Deserialize)]
    #[serde(rename = "ResolutionCase__bound_u16")]
    struct ResolutionCase(Vec<Resolution>);

    #[derive(Debug, Deserialize)]
    struct ResolutionTestVectors {
        num_leaves: u32,
        #[serde(rename = "cases__bound_u32")]
        cases: Vec<ResolutionCase>,
    }

    // Test that decrypt_direct_path_message is the inverse of encrypt_direct_path_secrets
    #[quickcheck]
    fn direct_path_message_correctness(num_leaves: u8, rng_seed: u64) {
        // Turns out this test is super slow
        if num_leaves > 50 || num_leaves < 2 {
            return;
        }

        let mut rng = rand::rngs::StdRng::seed_from_u64(rng_seed);
        let num_leaves = num_leaves as usize;
        let num_nodes = tree_math::num_nodes_in_tree(num_leaves);

        // Fill a tree with Blanks
        let mut tree = RatchetTree {
            nodes: Vec::new(),
        };
        for _ in 0..num_leaves {
            tree.add_leaf_node(RatchetTreeNode::Blank);
        }

        // Fill the tree with deterministic path secrets
        let cs: &'static CipherSuite = &X25519_SHA256_AES128GCM;
        for i in 0..num_leaves {
            let leaf_idx = 2 * i;
            let initial_path_secret = PathSecret::new(vec![i as u8; 32]);
            tree.propagate_new_path_secret(cs, initial_path_secret, leaf_idx).unwrap();
        }

        // Come up with sender and receiver indices. The sender must be a leaf node, because
        // encryption function requires it. The receiver must be different from the sender, because
        // the decryption function requires it. Also the receiver cannot be an ancestor of the
        // sender, because then it doesn't lie in the copath (and also it would have no need to
        // decrypt the message, since it knows its own secret)
        let sender_tree_idx = 2 * rng.gen_range(0, num_leaves);
        let receiver_tree_idx = loop {
            let idx = rng.gen_range(0, num_nodes);
            if idx != sender_tree_idx && !tree_math::is_ancestor(idx, sender_tree_idx, num_leaves) {
                break idx;
            }
        };

        // Come up with a new path secret and encrypt it to the receiver
        let sender_path_secret = {
            let mut buf = [0u8; 32];
            rng.fill_bytes(&mut buf);
            PathSecret::new(buf.to_vec())
        };
        let direct_path_msg = tree
            .encrypt_direct_path_secrets(cs, sender_tree_idx, sender_path_secret.clone(), &mut rng)
            .expect("failed to encrypt direct path secrets");
        // Decrypt the path secret closest to the receiver
        let (derived_path_secret, common_ancestor_idx) = tree
            .decrypt_direct_path_message(cs, &direct_path_msg, sender_tree_idx, receiver_tree_idx)
            .expect("failed to decrypt direct path secret");

        // Make sure it really is the common ancestor
        assert_eq!(
            common_ancestor_idx,
            tree_math::common_ancestor(sender_tree_idx, receiver_tree_idx, num_leaves)
        );

        // The new path secret is the n-th ratcheted form of the original path secret, where n is
        // the number of hops between sender and the common ancestor
        let expected_path_secret = {
            let mut idx = sender_tree_idx;
            let mut path_secret = sender_path_secret;

            // Ratchet up the tree until we find the common ancestor
            while idx != common_ancestor_idx {
                idx = tree_math::node_parent(idx, num_leaves);
                let (_, _, _, new_path_secret) =
                    utils::derive_node_values(cs, path_secret).unwrap();
                path_secret = new_path_secret;
            }
            path_secret
        };
        assert_eq!(derived_path_secret.0, expected_path_secret.0);
    }

    // Tests against the official tree math test vector. See above comment for explanation.
    #[test]
    fn official_resolution_kat() {
        // Helper function
        fn u8_resolution(tree: &RatchetTree, idx: usize) -> Vec<u8> {
            tree.resolution(idx)
                .into_iter()
                .map(|i| {
                    // These had better be small indices
                    if i > core::u8::MAX as usize {
                        panic!("resolution node indices are too big to fit into a u8");
                    } else {
                        i as u8
                    }
                })
                .collect()
        }

        // Helper function
        fn make_tree_from_int(t: usize, num_nodes: usize) -> RatchetTree {
            let mut nodes: Vec<RatchetTreeNode> = Vec::new();
            let mut bit_mask = 0x01;

            for _ in 0..num_nodes {
                if t & bit_mask == 0 {
                    nodes.push(RatchetTreeNode::Blank);
                } else {
                    // TODO: Make a better way to put dummy values in the tree than invalid DH pubkeys
                    nodes.push(RatchetTreeNode::Filled {
                        public_key: DhPublicKey::Raw(DhPublicKeyRaw(Vec::new())),
                        private_key: None,
                    });
                }
                bit_mask <<= 1;
            }

            RatchetTree {
                nodes,
            }
        }

        let mut f = std::fs::File::open("test_vectors/resolution.bin").unwrap();
        let mut deserializer = TlsDeserializer::from_reader(&mut f);
        let test_vec = ResolutionTestVectors::deserialize(&mut deserializer).unwrap();
        let num_nodes = tree_math::num_nodes_in_tree(test_vec.num_leaves as usize);

        // encoded_tree is the index into the case; this can be decoded into a RatchetTree by
        // parsing the u32 bit by bit
        for (encoded_tree, case) in test_vec.cases.into_iter().enumerate() {
            let tree = make_tree_from_int(encoded_tree, num_nodes);

            // We compute the resolution of every node in the tree
            for (idx, expected_resolution) in case.0.into_iter().enumerate() {
                let derived_resolution = u8_resolution(&tree, idx);
                assert_eq!(derived_resolution, expected_resolution.0);
            }
        }
    }
}
