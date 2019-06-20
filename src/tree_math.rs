//! This module defines all the tree operations we'll need to use when working with left-balanced
//! binary trees. For more info, see section 5.1 of the MLS spec.

// TODO: Use a type alias for the index type, and switch out usize for u32

// Suppose usize is u64. If there are k := 2^(63)+1 leaves, then there are a total of 2(k-1) + 1 =
// 2(2^(63))+1 = 2^(64)+1 nodes in the tree, which is outside the representable range. So our upper
// bound is 2^(63) leaves, which gives a tree with 2^(64)-1 nodes.
pub(crate) const MAX_LEAVES: usize = (std::usize::MAX >> 1) + 1;

/// The index of a node in the tree
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
#[cfg_attr(test, derive(Debug))]
pub(crate) struct TreeIdx(usize);

impl TreeIdx {
    pub(crate) const fn new(idx: usize) -> TreeIdx {
        TreeIdx(idx)
    }
}

// TreeIdx --> usize trivially
impl From<TreeIdx> for usize {
    fn from(idx: TreeIdx) -> usize {
        idx.0
    }
}

// So we can ask whether tree_idx == tree.size()
impl core::cmp::PartialEq<usize> for TreeIdx {
    fn eq(&self, other: &usize) -> bool {
        usize::from(*self).eq(other)
    }
}

// So we can ask whether tree_idx < tree.size()
impl core::cmp::PartialOrd<usize> for TreeIdx {
    fn partial_cmp(&self, other: &usize) -> Option<core::cmp::Ordering> {
        usize::from(*self).partial_cmp(other)
    }
}

/// Returns `Some(floor(log2(x))` when `x != 0`, and `None` otherwise
fn log2(x: usize) -> Option<usize> {
    // The log2 of x is the position of its most significant bit
    let bitlen = (0usize).leading_zeros() as usize;
    (bitlen - x.leading_zeros() as usize).checked_sub(1)
}

/// Computes the level of a given node in a binary left-balanced tree. Leaves are level 0, their
/// parents are level 1, etc. If a node's children are at different levels, then the node's level
/// is the max of its childrens', plus one.
pub(crate) fn node_level(idx: TreeIdx) -> usize {
    // The level of idx is equal to the number of trialing 1s in its binary representation.
    // Equivalently, this is just the number of trailing zeros of (NOT idx)
    (!idx.0).trailing_zeros() as usize
}

/// Computes the number of nodes needed to represent a tree with `num_leaves` many leaves
///
/// Panics: when `num_leaves == 0` or `num_leaves > MAX_LEAVES`
pub(crate) fn num_nodes_in_tree(num_leaves: usize) -> usize {
    assert!(num_leaves > 0 && num_leaves <= MAX_LEAVES);
    2 * (num_leaves - 1) + 1
}

/// Computes the number of leaves in a tree of `num_nodes` many nodes
///
/// Panics: when `num_nodes` is odd, since all left-balanced binary trees have an odd number of
/// nodes
pub(crate) fn num_leaves_in_tree(num_nodes: usize) -> usize {
    assert!(num_nodes % 2 == 1);
    // Inverting the formula for num_nodes_in_tree, we get num_leaves = (num_nodes-1)/2 + 1
    ((num_nodes - 1) >> 1) + 1
}

/// Computes the index of the root node of a tree with `num_leaves` many leaves
///
/// Panics: when `num_leaves == 0` or `num_leaves > MAX_LEAVES`
pub(crate) fn root_idx(num_leaves: usize) -> TreeIdx {
    assert!(num_leaves > 0 && num_leaves <= MAX_LEAVES);
    // Root nodes are always index 2^n - 1 where n is the smallest number such that the size of the
    // tree is less than the next power of 2, i.e., 2^(n+1).
    let n = num_nodes_in_tree(num_leaves);
    TreeIdx::new((1 << log2(n).unwrap()) - 1)
}

/// Computes the index of the left child of a given node. This does not depend on the size of the
/// tree. The child of a leaf is itself.
pub(crate) fn node_left_child(idx: TreeIdx) -> TreeIdx {
    let lvl = node_level(idx);
    // The child of a leaf is itself
    if lvl == 0 {
        idx
    } else {
        // Being on the n-th level (index 0) means your index is of the form xyz..01111...1 where
        // x,y,z are arbitrary, and there are n-many ones at the end. Stepping to the left is
        // equivalent to clearing the highest trailing 1.
        TreeIdx::new(idx.0 ^ (0x01 << (lvl - 1)))
    }
}

/// Computes the index of the left child of the given node. The child of a leaf is itself.
///
/// Panics: when `num_leaves == 0` or `num_leaves > MAX_LEAVES` or
/// `idx >= num_nodes_in_tree(num_leaves)`
pub(crate) fn node_right_child(idx: TreeIdx, num_leaves: usize) -> TreeIdx {
    assert!(num_leaves > 0 && num_leaves <= MAX_LEAVES);
    assert!(idx < num_nodes_in_tree(num_leaves));

    let lvl = node_level(idx);
    // The child of a leaf is itself
    if lvl == 0 {
        idx
    } else {
        // Being on the n-th level (index 0) means your index is of the form xyz..01111...1 where
        // x,y,z are arbitrary, and there are n-many ones at the end. Stepping to the right is
        // equivalent to setting the rightmost 0 to a 1 and the highest trailing 1 to a 0. However,
        // this node might not exist (e.g., in a tree of 3 leaves, the right child of the root node
        // (idx 3) is the node with idx 4, not 5, since the rightmost tree isn't full). So we start
        // at the conjectured node and move left until we are within the bounds of the tree. This
        // is guaranteed to terminate, because if it didn't, there couldn't be any nodes with index
        // higher than the parent, which violates the invariant that every non-leaf node has two
        // children.
        let mut r = TreeIdx::new(idx.0 ^ (0x03 << (lvl - 1)));
        let idx_threshold = num_nodes_in_tree(num_leaves);
        while r >= idx_threshold {
            r = node_left_child(r);
        }

        r
    }
}

/// Computes the index of the parent of a given node. The parent of the root is the root.
///
/// Panics: when `num_leaves == 0` or `num_leaves > MAX_LEAVES` or
/// `idx >= num_nodes_in_tree(num_leaves)`
pub(crate) fn node_parent(idx: TreeIdx, num_leaves: usize) -> TreeIdx {
    // The immediate parent of a node. May be beyond the right edge of the tree. This means weird
    // overflowing behavior when i == usize::MAX. However, this case is caught by the check below
    // that idx == root_idx(num_leaves). We hit the overflowing case iff idx is usize::MAX, which
    // is of the form 2^n - 1 for some n, which means that it's the root of a completely full tree
    // or it's the root of a subtree with more than `MAX_LEAVES` elements. The former case is
    // handled by the first if-statement below, and the latter is handled by the assert below.
    fn parent_step(i: usize) -> usize {
        // Recall that the children of xyz...0111...1 are xyz...0011...1 and xyz...1011...1 Working
        // backwards, this means that the parent of something that ends with 0011...1 or
        // 1011...1 is 0111...1. So if i is the index of the least significant 0, we must clear the
        // (i+1)-th bit and set the i-th bit.
        // This might be off the edge of the tree, since if, say, we have a tree on 3 leaves, the
        // rightmost leaf is idx 4, whose parent according to this algorithm would be idx 5, which
        // doesn't exist.
        let lvl = node_level(TreeIdx::new(i));
        let bit_to_clear = i & (0x01 << (lvl + 1));
        let bit_to_set = 0x01 << lvl;

        (i | bit_to_set) ^ bit_to_clear
    }

    assert!(num_leaves > 0 && num_leaves <= MAX_LEAVES);
    assert!(idx < num_nodes_in_tree(num_leaves));

    if idx == root_idx(num_leaves) {
        idx
    } else {
        // First assume we're in a full tree. This means we're assuming the direct path of this
        // node is maximally long.
        let mut p = parent_step(idx.0);
        let idx_threshold = num_nodes_in_tree(num_leaves);
        // This must terminate, since stepping up will eventually land us at the root node of the
        // tree, and parent_step increases the level at every step. The algorithm is correct, since
        // the direct path of the node of index i ocurring in a non-full subtree is a subpath of
        // the node of index i ocurring in a full subtree. Since they share an ancestor, we'll
        // eventually reach it if we start from the bottom and work our way up.
        while p >= idx_threshold {
            p = parent_step(p);
        }

        TreeIdx::new(p)
    }
}

/// Finds the minmal common ancestor of the given nodes. Here, minimal means having the smallest
/// node level. By convention, we say that the common ancestor of `a` and `a` is `a`.
///
/// Panics: when `num_leaves == 0` or `num_leaves > MAX_LEAVES` or `idx1 >=
/// num_nodes_in_tree(num_leaves)` or `idx2 >= num_nodes_in_tree(num_leaves)`
pub(crate) fn common_ancestor(idx1: TreeIdx, idx2: TreeIdx, num_leaves: usize) -> TreeIdx {
    // We will compute the direct paths of both and find the first location where they begin to
    // agree. If they never agree, then their common ancestor is the root node

    // We have to allocate because our implementation of node_direct_path isn't reversible as-is
    let idx1_dp: Vec<TreeIdx> = node_direct_path(idx1, num_leaves).collect();
    let idx2_dp: Vec<TreeIdx> = node_direct_path(idx2, num_leaves).collect();

    // We iterate backwards through the direct paths and stop after we find the first place where
    // they disagree
    let mut common_ancestor = root_idx(num_leaves);
    for (&a, &b) in idx1_dp.iter().rev().zip(idx2_dp.iter().rev()) {
        if a == b {
            common_ancestor = a;
        } else {
            break;
        }
    }

    common_ancestor
}

/// Returns whether the node at index `a` is an ancestor of the node at index `b`. By convention,
/// we say that `a` is its own ancestor.
///
/// Panics: when `num_leaves == 0` or `num_leaves > MAX_LEAVES` or `idx1 >=
/// num_nodes_in_tree(num_leaves)` or `idx2 >= num_nodes_in_tree(num_leaves)`
pub(crate) fn is_ancestor(a: TreeIdx, b: TreeIdx, num_leaves: usize) -> bool {
    let mut curr_idx = b;
    let root = root_idx(num_leaves);

    // Try to find a along the direct path of b by iteratively moving up the tree. Note that this
    // doesn't check the root node
    while curr_idx != root {
        if curr_idx == a {
            return true;
        }
        curr_idx = node_parent(curr_idx, num_leaves);
    }

    // If a is the root, then it's everybody's ancestor. Otherwise, we couldn't find a in b's
    // direct path, so it's not an ancestor
    a == root
}

/// Computes the index of the sibling of a given node. The sibling of the root is the root.
///
/// Panics: when `num_leaves == 0` or `num_leaves > MAX_LEAVES` or
/// `idx >= num_nodes_in_tree(num_leaves)`
pub(crate) fn node_sibling(idx: TreeIdx, num_leaves: usize) -> TreeIdx {
    assert!(num_leaves > 0 && num_leaves <= MAX_LEAVES);
    assert!(idx < num_nodes_in_tree(num_leaves));

    // Recall that the left and right children of xyz...0111...1 are xyz...0011...1 and
    // xyz...1011...1, respectively. The former is less than the initial index, and the latter is
    // greater. So left is smaller, right is greater.
    let parent = node_parent(idx, num_leaves);
    if idx < parent {
        // We were on the left child, so return the right
        node_right_child(parent, num_leaves)
    } else if idx > parent {
        // We were on the right child, so return the left
        node_left_child(parent)
    } else {
        // We're at the root, so return the root
        parent
    }
}

/// Returns an iterator for the path up the tree `i_1, i_2, ..., i_n` where `i_1` is the the given
/// starting node and `i_n` is a child of the root node.
///
/// Panics: when `num_leaves == 0` or `num_leaves > MAX_LEAVES` or
/// `start_idx >= num_nodes_in_tree(num_leaves)`
pub(crate) fn node_direct_path(
    start_idx: TreeIdx,
    num_leaves: usize,
) -> impl Iterator<Item = TreeIdx> + Clone + Copy {
    assert!(num_leaves > 0 && num_leaves <= MAX_LEAVES);
    assert!(start_idx < num_nodes_in_tree(num_leaves));

    // Start the direct path on the the given node. Since we loop inside DirectPathIter until
    // parent == root, this will be an empty iterator if we're the root node (since the parent of
    // the root is the root)
    DirectPathIter {
        num_leaves,
        successive_parent: start_idx,
    }
}

/// Returns an iterator for the path up the tree `i_1, i_2, ..., i_n` where `i_1` is the the given
/// starting node and `i_n` is the root node. This is called "extended" because direct paths do not
/// contain the root node. The extended direct path of a singleton tree is just
/// 1 node long.
///
/// Panics: when `num_leaves == 0` or `num_leaves > MAX_LEAVES` or
/// `start_idx >= num_nodes_in_tree(num_leaves)`
pub(crate) fn node_extended_direct_path(
    start_idx: TreeIdx,
    num_leaves: usize,
) -> impl Iterator<Item = TreeIdx> + Clone {
    let root = std::iter::once(root_idx(num_leaves));
    node_direct_path(start_idx, num_leaves).chain(root)
}

/// An iterator for direct paths
#[derive(Clone, Copy)]
struct DirectPathIter {
    /// Number of leaves in the tree
    num_leaves: usize,

    /// Keeps track of current position in the tree
    successive_parent: TreeIdx,
}

impl Iterator for DirectPathIter {
    type Item = TreeIdx;

    fn next(&mut self) -> Option<TreeIdx> {
        // If we're not at the root, return where we are, then move up one level
        if self.successive_parent != root_idx(self.num_leaves) {
            let ret = self.successive_parent;
            self.successive_parent = node_parent(self.successive_parent, self.num_leaves);

            Some(ret)
        } else {
            None
        }
    }
}

/// Returns a list of indices for leaf nodes in a tree of given size. The list is in ascending
/// index order.
///
/// Panics: when `num_leaves == 0` or `num_leaves > MAX_LEAVES`
pub(crate) fn tree_leaves(num_leaves: usize) -> impl DoubleEndedIterator<Item = TreeIdx> {
    assert!(num_leaves > 0 && num_leaves <= MAX_LEAVES);
    // The leaves are just all the even indices
    (0..num_leaves).map(|i| TreeIdx::new(2 * i))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::tls_de::TlsDeserializer;

    use core::convert::TryFrom;

    use quickcheck::TestResult;
    use quickcheck_macros::quickcheck;
    use rand::{Rng, SeedableRng};
    use serde::de::Deserialize;

    #[test]
    fn log2_kat() {
        assert_eq!(log2(0), None);
        assert_eq!(log2(1), Some(0));
        assert_eq!(log2(2), Some(1));
        assert_eq!(log2(3), Some(1));
        assert_eq!(log2(127), Some(6));
        assert_eq!(log2(128), Some(7));
        assert_eq!(log2(129), Some(7));
        assert_eq!(log2(255), Some(7));

        // Check log2(x/2) == log2(x/4) + 1 where x == 2^n for the biggest possible n for usize
        let bigboi = std::usize::MAX;
        assert_eq!(log2((bigboi >> 1) + 1), log2((bigboi >> 2) + 1).map(|i| i + 1));
    }

    #[test]
    fn num_nodes_in_tree_kat() {
        assert_eq!(num_nodes_in_tree(1), 1);
        assert_eq!(num_nodes_in_tree(4), 7);
        assert_eq!(num_nodes_in_tree(5), 9);

        // For explanation, see comments by definition of MAX_LEAVES
        assert_eq!(num_nodes_in_tree(MAX_LEAVES), std::usize::MAX);
    }

    #[test]
    fn num_leaves_in_tree_kat() {
        assert_eq!(num_leaves_in_tree(1), 1);
        assert_eq!(num_leaves_in_tree(7), 4);
        assert_eq!(num_leaves_in_tree(9), 5);

        // For explanation, see comments by definition of MAX_LEAVES
        assert_eq!(num_leaves_in_tree(std::usize::MAX), MAX_LEAVES);
    }

    // num_leaves_in_tree and num_nodes_in_tree are inverses of each other
    #[quickcheck]
    fn counting_correctness(num_nodes: usize) -> TestResult {
        // num_leaves_in_tree only works on odd inputs, so throw out the even ones
        if num_nodes % 2 == 0 {
            return TestResult::discard();
        }

        let n = num_nodes_in_tree(num_leaves_in_tree(num_nodes));
        TestResult::from_bool(n == num_nodes)
    }

    // Checks correctness of immediate relationships in the tree (for example, the parent of my
    // child is me)
    #[quickcheck]
    fn tree_immediate_family_correctness(num_leaves: usize, rng_seed: u64) {
        if num_leaves == 0 || num_leaves > MAX_LEAVES {
            // This is an invalid input. Do nothing.
            return;
        }

        let num_nodes = num_nodes_in_tree(num_leaves);

        // This is our starting node
        let me: TreeIdx = {
            let mut rng = rand::rngs::StdRng::seed_from_u64(rng_seed);
            TreeIdx::new(rng.gen_range(0, num_nodes))
        };
        let my_sibling = node_sibling(me, num_leaves);
        let my_parent = node_parent(my_sibling, num_leaves);

        assert_eq!(node_parent(me, num_leaves), my_parent);

        // Recall left_child < parent < right_child
        match me.cmp(&my_parent) {
            std::cmp::Ordering::Less => {
                // Check that I am the left child of my parent
                assert_eq!(node_left_child(my_parent), me);
                assert_eq!(node_right_child(my_parent, num_leaves), my_sibling);
            }
            std::cmp::Ordering::Greater => {
                // Check that I am the left child of my parent
                assert_eq!(node_left_child(my_parent), my_sibling);
                assert_eq!(node_right_child(my_parent, num_leaves), me);
            }
            std::cmp::Ordering::Equal => {
                // I am my own parent. Check that I must be the root node
                assert_eq!(root_idx(num_leaves), me);
            }
        }

        let my_left_child = node_left_child(me);
        let my_right_child = node_right_child(me, num_leaves);

        if my_left_child == me {
            // I'm a leaf. Make sure both my children are me.
            assert_eq!(my_right_child, me);
        } else {
            // I'm not a leaf. Make sure that my children are distinct, that they are siblings, and
            // that I'm their parent
            assert_ne!(my_left_child, my_right_child);
            assert_eq!(node_sibling(my_left_child, num_leaves), my_right_child);
            assert_eq!(node_sibling(my_right_child, num_leaves), my_left_child);
            assert_eq!(node_parent(my_left_child, num_leaves), me);
            assert_eq!(node_parent(my_right_child, num_leaves), me);
        }
    }

    // Checks that common_ancestor returns a minimal common ancestor
    #[quickcheck]
    fn ancestry_correctness(num_leaves: usize, rng_seed: u64) {
        // We only care about valid trees with at least 2 nodes
        if num_leaves <= 1 || num_leaves > MAX_LEAVES {
            return;
        }

        let mut rng = rand::rngs::StdRng::seed_from_u64(rng_seed);
        let num_nodes = num_nodes_in_tree(num_leaves);

        // The two nodes we want to test. This test is for cases where idx1 != idx2
        let idx1 = TreeIdx::new(rng.gen_range(0, num_nodes));
        let idx2 = loop {
            let i = rng.gen_range(0, num_nodes);
            if i != idx1.0 {
                break TreeIdx::new(i);
            }
        };

        let ancestor = common_ancestor(idx1, idx2, num_leaves);
        let left = node_left_child(ancestor);
        let right = node_right_child(ancestor, num_leaves);

        // The child of a common ancestor should not be an ancestor to both
        assert!(!(is_ancestor(left, idx1, num_leaves) && is_ancestor(left, idx2, num_leaves)));
        assert!(!(is_ancestor(right, idx1, num_leaves) && is_ancestor(right, idx2, num_leaves)));
    }

    // Tests that common_ancestor(a, b, num_leaves) always equals common_ancestor(b, a, num_leaves)
    #[quickcheck]
    fn ancestry_symmetry(a: usize, b: usize, c: usize) {
        // Make the setup idx1 <= idx2 <= num_leaves
        let mut indices = [a, b, c];
        indices.sort();
        let idx1 = TreeIdx::new(indices[0]);
        let idx2 = TreeIdx::new(indices[1]);
        let num_leaves = indices[2];

        // idx2 has to index into the tree, and num_leaves can't be too big
        if idx2 == num_leaves || num_leaves >= MAX_LEAVES {
            return;
        }

        assert_eq!(
            common_ancestor(idx1, idx2, num_leaves),
            common_ancestor(idx2, idx1, num_leaves)
        );
    }

    // We'll use this tree for known-answer tests
    //               7
    //         _____/ \
    //        /        |
    //       3         |
    //     /   \       |
    //    /     \      |
    //   1       5     |
    //  / \     / \    |
    // 0   2   4   6   8

    // Name some nodes so we can use them in the tests
    const N0: TreeIdx = TreeIdx::new(0);
    const N1: TreeIdx = TreeIdx::new(1);
    const N2: TreeIdx = TreeIdx::new(2);
    const N3: TreeIdx = TreeIdx::new(3);
    const N4: TreeIdx = TreeIdx::new(4);
    const N5: TreeIdx = TreeIdx::new(5);
    const N6: TreeIdx = TreeIdx::new(6);
    const N7: TreeIdx = TreeIdx::new(7);
    const N8: TreeIdx = TreeIdx::new(8);

    // Node names for a different tree
    const N10: TreeIdx = TreeIdx::new(10);
    const N11: TreeIdx = TreeIdx::new(11);
    const N12: TreeIdx = TreeIdx::new(12);

    // See above tree for a diagram
    #[test]
    fn node_level_simple_kat() {
        assert_eq!(node_level(N0), 0);
        assert_eq!(node_level(N1), 1);
        assert_eq!(node_level(N2), 0);
        assert_eq!(node_level(N3), 2);
        assert_eq!(node_level(N4), 0);
        assert_eq!(node_level(N5), 1);
        assert_eq!(node_level(N6), 0);
        assert_eq!(node_level(N7), 3);
        assert_eq!(node_level(N8), 0);
    }

    // See above tree for a diagram
    #[test]
    fn direct_path_kat() {
        // Convenience function. Collects a direct path
        fn direct_path_vec(start_idx: TreeIdx) -> Vec<TreeIdx> {
            let num_leaves = 5;
            node_direct_path(start_idx, num_leaves).collect()
        }

        assert_eq!(direct_path_vec(N0), vec![N0, N1, N3]);
        assert_eq!(direct_path_vec(N1), vec![N1, N3]);
        assert_eq!(direct_path_vec(N2), vec![N2, N1, N3]);
        assert_eq!(direct_path_vec(N3), vec![N3]);
        assert_eq!(direct_path_vec(N4), vec![N4, N5, N3]);
        assert_eq!(direct_path_vec(N5), vec![N5, N3]);
        assert_eq!(direct_path_vec(N6), vec![N6, N5, N3]);
        assert_eq!(direct_path_vec(N8), vec![N8]);
        assert!(direct_path_vec(N7).is_empty());
    }

    // See above tree for a diagram
    #[test]
    fn tree_relations_kat() {
        let num_leaves = 5;

        // Test parent relations
        assert_eq!(node_parent(N0, num_leaves), N1);
        assert_eq!(node_parent(N2, num_leaves), N1);
        assert_eq!(node_parent(N4, num_leaves), N5);
        assert_eq!(node_parent(N6, num_leaves), N5);
        assert_eq!(node_parent(N1, num_leaves), N3);
        assert_eq!(node_parent(N5, num_leaves), N3);
        assert_eq!(node_parent(N3, num_leaves), N7);
        assert_eq!(node_parent(N8, num_leaves), N7);
        assert_eq!(node_parent(N7, num_leaves), N7);

        // Test leaf child relations
        assert_eq!(node_left_child(N0), N0);
        assert_eq!(node_right_child(N0, num_leaves), N0);
        assert_eq!(node_left_child(N2), N2);
        assert_eq!(node_right_child(N2, num_leaves), N2);
        assert_eq!(node_left_child(N4), N4);
        assert_eq!(node_right_child(N4, num_leaves), N4);
        assert_eq!(node_left_child(N6), N6);
        assert_eq!(node_right_child(N6, num_leaves), N6);
        assert_eq!(node_left_child(N8), N8);
        assert_eq!(node_right_child(N8, num_leaves), N8);

        // Test the non-leaf left relations
        assert_eq!(node_left_child(N7), N3);
        assert_eq!(node_left_child(N3), N1);
        assert_eq!(node_left_child(N1), N0);
        assert_eq!(node_left_child(N5), N4);

        // Test the non-leaf right relations
        assert_eq!(node_right_child(N7, num_leaves), N8);
        assert_eq!(node_right_child(N3, num_leaves), N5);
        assert_eq!(node_right_child(N1, num_leaves), N2);
        assert_eq!(node_right_child(N5, num_leaves), N6);

        // Test sibling relations
        assert_eq!(node_sibling(N0, num_leaves), N2);
        assert_eq!(node_sibling(N2, num_leaves), N0);
        assert_eq!(node_sibling(N4, num_leaves), N6);
        assert_eq!(node_sibling(N6, num_leaves), N4);
        assert_eq!(node_sibling(N1, num_leaves), N5);
        assert_eq!(node_sibling(N5, num_leaves), N1);
        assert_eq!(node_sibling(N8, num_leaves), N3);
        assert_eq!(node_sibling(N3, num_leaves), N8);
        assert_eq!(node_sibling(N7, num_leaves), N7);
    }

    // See above tree for diagram
    #[test]
    fn ancestry_kat() {
        let num_leaves = 5;

        // If common_ancestor(a, b, num_leaves) was tested, there's no need to test
        // common_ancestor(b, a, num_leaves), since symmetry was already tested above

        assert_eq!(common_ancestor(N0, N0, num_leaves), N0);
        assert_eq!(common_ancestor(N0, N1, num_leaves), N1);
        assert_eq!(common_ancestor(N0, N2, num_leaves), N1);
        assert_eq!(common_ancestor(N0, N3, num_leaves), N3);
        assert_eq!(common_ancestor(N0, N4, num_leaves), N3);
        assert_eq!(common_ancestor(N0, N5, num_leaves), N3);
        assert_eq!(common_ancestor(N0, N6, num_leaves), N3);
        assert_eq!(common_ancestor(N0, N7, num_leaves), N7);
        assert_eq!(common_ancestor(N0, N8, num_leaves), N7);

        assert_eq!(common_ancestor(N1, N1, num_leaves), N1);
        assert_eq!(common_ancestor(N1, N2, num_leaves), N1);
        assert_eq!(common_ancestor(N1, N3, num_leaves), N3);
        assert_eq!(common_ancestor(N1, N4, num_leaves), N3);
        assert_eq!(common_ancestor(N1, N5, num_leaves), N3);
        assert_eq!(common_ancestor(N1, N6, num_leaves), N3);
        assert_eq!(common_ancestor(N1, N7, num_leaves), N7);
        assert_eq!(common_ancestor(N1, N8, num_leaves), N7);

        assert_eq!(common_ancestor(N2, N2, num_leaves), N2);
        assert_eq!(common_ancestor(N2, N3, num_leaves), N3);
        assert_eq!(common_ancestor(N2, N4, num_leaves), N3);
        assert_eq!(common_ancestor(N2, N5, num_leaves), N3);
        assert_eq!(common_ancestor(N2, N6, num_leaves), N3);
        assert_eq!(common_ancestor(N2, N7, num_leaves), N7);
        assert_eq!(common_ancestor(N2, N8, num_leaves), N7);

        assert_eq!(common_ancestor(N3, N3, num_leaves), N3);
        assert_eq!(common_ancestor(N3, N4, num_leaves), N3);
        assert_eq!(common_ancestor(N3, N5, num_leaves), N3);
        assert_eq!(common_ancestor(N3, N6, num_leaves), N3);
        assert_eq!(common_ancestor(N3, N7, num_leaves), N7);
        assert_eq!(common_ancestor(N3, N8, num_leaves), N7);

        assert_eq!(common_ancestor(N4, N4, num_leaves), N4);
        assert_eq!(common_ancestor(N4, N5, num_leaves), N5);
        assert_eq!(common_ancestor(N4, N6, num_leaves), N5);
        assert_eq!(common_ancestor(N4, N7, num_leaves), N7);
        assert_eq!(common_ancestor(N4, N8, num_leaves), N7);

        assert_eq!(common_ancestor(N5, N5, num_leaves), N5);
        assert_eq!(common_ancestor(N5, N6, num_leaves), N5);
        assert_eq!(common_ancestor(N5, N7, num_leaves), N7);
        assert_eq!(common_ancestor(N5, N8, num_leaves), N7);

        assert_eq!(common_ancestor(N6, N6, num_leaves), N6);
        assert_eq!(common_ancestor(N6, N7, num_leaves), N7);
        assert_eq!(common_ancestor(N6, N8, num_leaves), N7);

        assert_eq!(common_ancestor(N7, N7, num_leaves), N7);
        assert_eq!(common_ancestor(N7, N8, num_leaves), N7);

        assert_eq!(common_ancestor(N8, N8, num_leaves), N8);

        // Regression tests
        let num_leaves = 7;
        assert!(is_ancestor(N11, N12, num_leaves));
        assert_eq!(common_ancestor(N12, N10, num_leaves), N11);
    }

    // Implement PartialEq so we can compare a Vec<TreeIdx> to a Vec<u32> in official_tree_math_kat
    impl core::cmp::PartialEq<u32> for TreeIdx {
        fn eq(&self, other: &u32) -> bool {
            u32::try_from(self.0).unwrap().eq(other)
        }
    }

    // TODO: Add Panic tests

    // The following test vector is from
    // https://github.com/mlswg/mls-implementations/tree/master/test_vectors
    //
    // File: tree_math.bin
    //
    // struct {
    //   uint32 tree_size;
    //   uint32 root<0..2^32-1>;
    //   uint32 left<0..2^32-1>;
    //   uint32 right<0..2^32-1>;
    //   uint32 parent<0..2^32-1>;
    //   uint32 sibling<0..2^32-1>;
    // } TreeMathTestVectors;
    //
    // These vectors have the following meaning, where the tree relations are as defined in the
    // specification
    //
    // * tree_size specifies the size of the test tree for the left / right / parent / sibling
    //   tests.
    // * root[i] is the index of the root of a tree with i+1 leaves
    // * The remaining vectors are all within the context of a tree with 255 leaves:
    //   * left[i] is the index of the left child of node i
    //   * right[i] is the index of the right child of node i
    //   * parent[i] is the index of the parent of node i
    //   * sibling[i] is the index of the sibling of node i

    #[derive(Deserialize)]
    struct TreeMathTestVectors {
        tree_size: u32,
        #[serde(rename = "root__bound_u32")]
        root: Vec<u32>,
        #[serde(rename = "left__bound_u32")]
        left: Vec<u32>,
        #[serde(rename = "right__bound_u32")]
        right: Vec<u32>,
        #[serde(rename = "parent__bound_u32")]
        parent: Vec<u32>,
        #[serde(rename = "sibling__bound_u32")]
        sibling: Vec<u32>,
    }

    // Tests against the official tree math test vector. See above comment for explanation.
    #[test]
    fn official_tree_math_kat() {
        let mut f = std::fs::File::open("test_vectors/tree_math.bin").unwrap();
        let mut deserializer = TlsDeserializer::from_reader(&mut f);
        let test_vec = TreeMathTestVectors::deserialize(&mut deserializer).unwrap();

        let tree_size = test_vec.tree_size as usize;
        let num_root_ops = test_vec.root.len();
        let num_left_ops = test_vec.left.len();
        let num_right_ops = test_vec.right.len();
        let num_parent_ops = test_vec.parent.len();
        let num_sibling_ops = test_vec.sibling.len();

        let root: Vec<TreeIdx> = (1..=num_root_ops).map(root_idx).collect();
        let left: Vec<TreeIdx> = (0..num_left_ops).map(TreeIdx::new).map(node_left_child).collect();
        let right: Vec<TreeIdx> =
            (0..num_right_ops).map(|i| node_right_child(TreeIdx::new(i), tree_size)).collect();
        let parent: Vec<TreeIdx> =
            (0..num_parent_ops).map(|i| node_parent(TreeIdx::new(i), tree_size)).collect();
        let sibling: Vec<TreeIdx> =
            (0..num_sibling_ops).map(|i| node_sibling(TreeIdx::new(i), tree_size)).collect();

        assert_eq!(root, test_vec.root);
        assert_eq!(left, test_vec.left);
        assert_eq!(right, test_vec.right);
        assert_eq!(parent, test_vec.parent);
        assert_eq!(sibling, test_vec.sibling);
    }
}
