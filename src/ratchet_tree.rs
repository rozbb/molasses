use crate::crypto::dh::{DhPublicKey, DhPrivateKey};
use crate::tree_math;

// Ratchet trees are serialized in DirectPath messages as optional<PublicKey> tree<1..2^32-1> So we
// encode RatchetTree as a Vec<RatchetTreeNode> with length bound u32, and we encode
// RatchetTreeNode as enum { Blank, Filled { DhPublicKey } }, which is encoded in the same way as
// an Option<DhPublicKey> would be.

/// A node in a `RatchetTree`. Every node must have a DH pubkey. It may also optionally contain the
/// corresponding private key and a secret octet string.
#[derive(Debug, Deserialize, Serialize)]
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

/// A left-balanced binary tree of `RatchetTreeNode`s
// Contains a vector of nodes that could optionally be blanks
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct RatchetTree {
    #[serde(rename = "nodes__bound_u32")]
    pub(crate) nodes: Vec<RatchetTreeNode>,
}

impl RatchetTree {
    /// Returns an new empty `RatchetTree`
    pub fn new() -> RatchetTree {
        RatchetTree { nodes: Vec::new() }
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

/// Returns the indices of the resolution of a given node: this an ordered sequence of minimal set
/// of non-blank nodes that collectively cover (A "covers" B iff A is an ancestor of B) all
    /// non-blank descendants of the given node. The ordering is ascending by node index.
    pub(crate) fn resolution(&self, idx: usize) -> Vec<usize> {
    // Helper function that accumulates the resolution recursively
    fn helper(tree: &RatchetTree, i: usize, acc: &mut Vec<usize>) {
        if let RatchetTreeNode::Blank = tree.nodes[i] {
            if tree_math::node_level(i) == 0 {
                // The resolution of a blank leaf node is the empty list
                return;
            } else {
                // The resolution of a blank intermediate node is the result of concatinating the
                // resolution of its left child with the resolution of its right child, in that
                // order
                let num_leaves = tree_math::num_leaves_in_tree(tree.nodes.len());
                helper(tree, tree_math::node_left_child(i), acc);
                helper(tree, tree_math::node_right_child(i, num_leaves), acc);
            }
        } else {
            // The resolution of a non-blank node is a one element list containing the node itself
            acc.push(i);
        }
    }

    let mut ret = Vec::new();
        helper(self, idx, &mut ret);
    ret
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

        RatchetTree { nodes }
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
