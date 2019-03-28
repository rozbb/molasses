use crate::{
    crypto::{
        ciphersuite::CipherSuite,
        dh::{DhPrivateKey, DhPublicKey},
        ecies::ecies_decrypt,
        hkdf,
    },
    error::Error,
    handshake::DirectPathMessage,
    tree_math,
};

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
        #[serde(skip)]
        secret: Option<Vec<u8>>,
    },
}

impl RatchetTreeNode {
    /// Returns `true` iff this is the `Filled` variant
    fn is_filled(&self) -> bool {
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
                    secret: None,
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
                ref public_key,
                ref mut private_key,
                ..
            } => {
                *private_key = Some(new_private_key);
            }
        }
    }

    /// Updates the node's secret to the given one
    ///
    /// Panics: If the node is `Blank`
    pub(crate) fn update_secret(&mut self, new_secret: Vec<u8>) {
        match self {
            &mut RatchetTreeNode::Blank => panic!("tried to update secret of blank node"),
            &mut RatchetTreeNode::Filled {
                ref public_key,
                ref private_key,
                ref mut secret,
            } => {
                *secret = Some(new_secret);
            }
        }
    }

    /// Returns a mutable reference to the contained node secret. If the node is `Filled` and
    /// doesn't have a node secret, one with length `secret_len` is allocated. If the node is
    /// `Blank`, then `None` is returned.
    pub(crate) fn get_mut_node_secret(&mut self, secret_len: usize) -> Option<&mut [u8]> {
        match self {
            &mut RatchetTreeNode::Blank => None,
            &mut RatchetTreeNode::Filled {
                ref public_key,
                ref private_key,
                ref mut secret,
            } => match secret {
                Some(ref mut inner) => Some(inner.as_mut_slice()),
                None => {
                    *secret = Some(vec![0u8; secret_len]);
                    secret.as_mut().map(|v| v.as_mut_slice())
                }
            },
        }
    }

    /// Returns a reference to the contained node secret. If no secret exists, `None` is returned.
    pub(crate) fn get_node_secret(&self) -> Option<&[u8]> {
        match self {
            &RatchetTreeNode::Blank => None,
            &RatchetTreeNode::Filled {
                ref public_key,
                ref private_key,
                ref secret,
            } => secret.as_ref().map(|v| v.as_slice()),
        }
    }

    /// Returns `Some(&private_key)` if the node contains a private key. Otherwise returns `None`.
    pub(crate) fn get_private_key(&self) -> Option<&DhPrivateKey> {
        match self {
            &RatchetTreeNode::Blank => None,
            &RatchetTreeNode::Filled {
                ref public_key,
                ref private_key,
                ..
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
    /// Returns an new empty `RatchetTree`
    pub fn new() -> RatchetTree {
        RatchetTree {
            nodes: Vec::new(),
        }
    }

    /// Returns the number of nodes in the tree
    pub fn size(&self) -> usize {
        self.nodes.len()
    }

    /// Returns the node at the given index
    pub fn get(&self, idx: usize) -> Option<&RatchetTreeNode> {
        self.nodes.get(idx)
    }

    /// Returns the root node. Returns `None` iff the tree is empty.
    pub fn get_root_node(&self) -> Option<&RatchetTreeNode> {
        if self.size() == 0 {
            None
        } else {
            let root_idx = tree_math::root_idx(self.size());
            self.get(root_idx)
        }
    }

    /// Returns a mutable reference to the node at the given index
    pub fn get_mut(&mut self, idx: usize) -> Option<&mut RatchetTreeNode> {
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
    pub fn add_leaf_node(&mut self, node: RatchetTreeNode) {
        if self.nodes.is_empty() {
            self.nodes.push(node);
            return;
        } else {
            self.nodes.push(RatchetTreeNode::Blank);
            self.nodes.push(node);
        }
    }

    /// Blanks out the direct path of the given node, as well as the root node
    pub(crate) fn propogate_blank(&mut self, start_idx: usize) {
        let num_leaves = tree_math::num_leaves_in_tree(self.size());
        let mut direct_path = tree_math::node_direct_path(start_idx, num_leaves);

        // Blank the direct path
        for i in direct_path {
            // No need to check index here. By construction, there's no way this is out of bounds
            self.nodes[i] = RatchetTreeNode::Blank;
        }

        // Blank the root
        let root_idx = tree_math::root_idx(num_leaves);
        self.nodes[root_idx] = RatchetTreeNode::Blank;
    }

    // TODO: Convince myself of the correctness of this pruning. Why can't this ever produce a
    // degenerate tree (i.e., a nonempty tree with an even number of nodes)?
    /// Prunes blank nodes from the right side of the tree until the rightmost node is non-blank
    pub(crate) fn prune_from_right(&mut self) {
        let mut last_nonblank_node = None;
        for (i, entry) in self.nodes.iter().rev().enumerate() {
            if entry.is_filled() {
                last_nonblank_node = Some(i);
            }
        }
        match last_nonblank_node {
            // If there are no nonempty entries in the roster, clear it
            None => self.nodes.clear(),
            Some(i) => {
                // This can't fail, because i is an index
                let num_elements_to_retain = i+1;
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

    /// Finds the (unique) ciphertext in the given direct path message that is meant for this
    /// participant and decrypts it. `leaf_idx` is the the index of the creator of `msg`. This
    /// operation clears out all `node_secrets: EciesCiphertext` values contained in `msg`.
    ///
    /// Returns: `Ok((pt, idx))` where `pt` is the `Result` of decrypting the found ciphertext
    /// and `idx` is the tree index of the ancestor for whom the plaintext was encrypted. If no
    /// decryptable ciphertext exists, returns an `Error::GroupOpError`. If decryption fails,
    /// returns an `Error::EncryptionError`.
    pub(crate) fn decrypt_direct_path_message(
        &self,
        cs: &'static CipherSuite,
        direct_path_msg: &DirectPathMessage,
        sender_tree_idx: usize,
        my_tree_idx: usize,
    ) -> Result<(Vec<u8>, usize), Error> {
        let num_leaves = tree_math::num_leaves_in_tree(self.size());
        let direct_path = tree_math::node_direct_path(sender_tree_idx as usize, num_leaves);

        // First we have to find which ciphertext is meant for us. This is means finding the
        // appropriate node in the copath of the creator of the direct path, then finding the
        // appropriate node in the resolution of that copath node.
        for (node_msg, path_node_idx) in direct_path_msg.node_messages.iter().zip(direct_path) {
            // Now see if any of the messages are meant for us
            let copath_node_idx = tree_math::node_sibling(path_node_idx, num_leaves);
            // If the copath node is an ancestor of mine, I can decrypt the message. This is the
            // case precisely once when traversing a direct path.
            if tree_math::is_ancestor(copath_node_idx, my_tree_idx as usize, num_leaves) {
                // I am looking for an ancestor in the resolution of this copath node. There is
                // only one such node. Furthermore, I should already know the private key of the
                // node that I find. So our strategy is to look for a node with a private key that
                // we know, then make sure that it is our ancestor.
                let resolution = self.resolution(copath_node_idx);

                // This value an index into the tree
                let mut ancestor_tree_idx = None;
                // This value is an index into the resolution vector
                let mut ancestor_resolution_idx = None;

                // Comb the resolution for a node whose private key we know
                for (i, res_node_idx) in resolution.into_iter().enumerate() {
                    let res_node = self.get(res_node_idx).expect("resolution out of bounds");
                    if res_node.get_private_key().is_some()
                        && tree_math::is_ancestor(res_node_idx, my_tree_idx as usize, num_leaves)
                    {
                        ancestor_tree_idx = Some(res_node_idx);
                        ancestor_resolution_idx = Some(i);
                        break;
                    }
                }

                let ancestor_tree_idx = ancestor_tree_idx.ok_or(Error::GroupOpError(
                    "Cannot find node in resolution with known private key",
                ))?;

                // These can't fail because we just did them above
                let ancestor_resolution_idx = ancestor_resolution_idx.unwrap();
                let ciphertext_for_me = &node_msg.node_secrets[ancestor_resolution_idx];
                let res_node = self.get(ancestor_tree_idx).unwrap();
                let decryption_key = res_node.get_private_key().unwrap();

                // Finally, decrypt the thing and return the plaintext and ancestor idx
                let pt = ecies_decrypt(cs, decryption_key, ciphertext_for_me.clone())?;
                return Ok((pt, ancestor_tree_idx));
            }
        }

        // Unless we were the encryptor of this message, is impossible not to hit the if-statement
        // inside the above for loop. Self-made updates are not handles here. They are handled
        // during the creation of the GroupUpdate itself.
        Err(Error::GroupOpError("Tried to decrypt self-made direct path"))
    }

    /// Updates the secret of the node at the given index and derives the path secrets, node
    /// secrets, private keys, and public keys of all its ancestors. If this process fails, this
    /// method will _not_ roll back the operation, so the caller should expect this object to be in
    /// an invalid state.
    pub(crate) fn propogate_new_path_secret(
        &mut self,
        cs: &'static CipherSuite,
        mut path_secret: Vec<u8>,
        start_idx: usize,
    ) -> Result<(), Error> {
        let num_leaves = tree_math::num_leaves_in_tree(self.size());
        let root_node_idx = tree_math::root_idx(num_leaves);

        let node_secret_len = cs.hash_alg.output_len;
        let mut current_node_idx = start_idx;

        // Go up the tree, setting the node secrets and keypairs
        loop {
            let current_node =
                self.get_mut(current_node_idx).expect("reached invalid node in secret propogation");

            let prk = hkdf::prk_from_bytes(cs.hash_alg, &path_secret);
            // node_secret[n] = HKDF-Expand-Label(path_secret[n], "node", "", Hash.Length)
            let mut node_secret = vec![0u8; node_secret_len];
            hkdf::hkdf_expand_label(&prk, b"node", b"", node_secret.as_mut_slice());
            // path_secret[n] = HKDF-Expand-Label(path_secret[n-1], "path", "", Hash.Length)
            hkdf::hkdf_expand_label(&prk, b"path", b"", path_secret.as_mut_slice());

            // Derive the private and public keys and assign them to the node
            let (node_public_key, node_private_key) = cs.derive_key_pair(&node_secret)?;
            current_node.update_public_key(node_public_key);
            current_node.update_private_key(node_private_key);
            current_node.update_secret(node_secret);

            if current_node_idx == root_node_idx {
                // If we just updated the root, we're done
                break;
            } else {
                // Otherwise, take one step up the tree
                current_node_idx = tree_math::node_parent(current_node_idx, num_leaves);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        crypto::dh::{DhPublicKey, DhPublicKeyRaw, DiffieHellman},
        tls_de::TlsDeserializer,
    };

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
                    secret: None,
                });
            }
            bit_mask <<= 1;
        }

        RatchetTree {
            nodes,
        }
    }

    fn resolution_vec(tree: &RatchetTree, idx: usize) -> Vec<u8> {
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

    // Tests against the official tree math test vector. See above comment for explanation.
    #[test]
    fn official_resolution_kat() {
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
                let derived_resolution = resolution_vec(&tree, idx);
                assert_eq!(derived_resolution, expected_resolution.0);
            }
        }
    }
}
