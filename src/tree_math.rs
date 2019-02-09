// Suppose usize is u64. If there are k := 2^(63)+1 leaves, then there are a total of 2(k-1) + 1 =
// 2(2^(63))+1 = 2^(64)+1 nodes in the tree, which is outside the representable range. So our upper
// bound is 2^(63) leaves, which gives a tree with 2^(64)-1 nodes.
const MAX_LEAVES: usize = (std::usize::MAX >> 1) + 1;

/// Returns `Some(floor(log2(x))` when `x != 0`, and `None` otherwise
fn log2(x: usize) -> Option<usize> {
    // The log2 of x is the position of its most significant bit
    let bitlen = (0usize).leading_zeros() as usize;
    (bitlen - x.leading_zeros() as usize).checked_sub(1)
}

/// Computes the level of a given node in a binary left-balanced tree. Leaves are level 0, their
/// parents are level 1, etc. If a node's children are at different level, then its level is the
/// max level of its children plus one.
pub(crate) fn node_level(idx: usize) -> usize {
    // The level of idx is equal to the number of trialing 1s in its binary representation.
    // Equivalently, this is just the number of trailing zeros of (NOT idx)
    (!idx).trailing_zeros() as usize
}

/// Computes the number of nodes needed to represent a tree with `num_leaves` many leaves
///
/// Panics: when `num_leaves == 0` or `num_leaves > MAX_LEAVES`
fn num_nodes_in_tree(num_leaves: usize) -> usize {
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
fn root_idx(num_leaves: usize) -> usize {
    assert!(num_leaves > 0 && num_leaves <= MAX_LEAVES);
    // Root nodes are always index 2^n - 1 where n is the smallest number such that the size of the
    // tree is less than the next power of 2, i.e., 2^(n+1).
    let n = num_nodes_in_tree(num_leaves);
    (1 << log2(n).unwrap()) - 1
}

/// Computes the index of the left child of a given node. This does not depend on the size of the
/// tree. The child of a leaf is itself.
pub(crate) fn node_left_child(idx: usize) -> usize {
    let lvl = node_level(idx);
    // The child of a leaf is itself
    if lvl == 0 {
        idx
    } else {
        // Being on the n-th level (index 0) means your index is of the form xyz..01111...1 where
        // x,y,z are arbitrary, and there are n-many ones at the end. Stepping to the left is
        // equivalent to clearing the highest trailing 1.
        idx ^ (0x01 << (lvl - 1))
    }
}

/// Computes the index of the left child of the given node. The child of a leaf is itself.
///
/// Panics: when `num_leaves == 0` or `num_leaves > MAX_LEAVES` or
/// `idx >= num_nodes_in_tree(num_leaves)`
pub(crate) fn node_right_child(idx: usize, num_leaves: usize) -> usize {
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
        let mut r = idx ^ (0x03 << (lvl - 1));
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
fn node_parent(idx: usize, num_leaves: usize) -> usize {
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
        let lvl = node_level(i);
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
        let mut p = parent_step(idx);
        let idx_threshold = num_nodes_in_tree(num_leaves);
        // This must terminate, since stepping up will eventually land us at the root node of the
        // tree, and parent_step increases the level at every step. The algorithm is correct, since
        // the direct path of the node of index i ocurring in a non-full subtree is a subpath of
        // the node of index i ocurring in a full subtree. Since they share an ancestor, we'll
        // eventually reach it if we start from the bottom and work our way up.
        while p >= idx_threshold {
            p = parent_step(p);
        }

        p
    }
}

/// Computes the index of the sibling of a given node. The sibling of the root is the root.
///
/// Panics: when `num_leaves == 0` or `num_leaves > MAX_LEAVES` or
/// `idx >= num_nodes_in_tree(num_leaves)`
fn node_sibling(idx: usize, num_leaves: usize) -> usize {
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

/// Returns the direct path of a given node in the form `[i_1, i_2, ..., i_n]` where
/// `i_1` is the parent of the given node and `i_n` is a child of the root node.
///
/// Panics: when `num_leaves == 0` or `num_leaves > MAX_LEAVES` or
/// `start_idx >= num_nodes_in_tree(num_leaves)`
fn node_direct_path(start_idx: usize, num_leaves: usize) -> Vec<usize> {
    assert!(num_leaves > 0 && num_leaves <= MAX_LEAVES);
    assert!(start_idx < num_nodes_in_tree(num_leaves));

    let mut path = Vec::new();
    let root = root_idx(num_leaves);
    let mut p = node_parent(start_idx, num_leaves);

    // Start on the parent of the given node. Recall that the parent of the root is itself, so if
    // we're at the root, we return the empty vector. Similarly, if we're the child of the root, we
    // still return the empty vector.
    while p != root {
        path.push(p);
        p = node_parent(p, num_leaves);
    }

    path
}

/// Returns the copath path of a given node in the form `[i_1, i_2, ..., i_n]` where
/// `i_1` is the sibling of the given node and `i_n` is a child of the root node.
///
/// Panics: when `num_leaves == 0` or `num_leaves > MAX_LEAVES` or
/// `start_idx >= num_nodes_in_tree(num_leaves)`
fn node_copath(start_idx: usize, num_leaves: usize) -> Vec<usize> {
    assert!(num_leaves > 0 && num_leaves <= MAX_LEAVES);
    assert!(start_idx < num_nodes_in_tree(num_leaves));

    let mut copath = Vec::new();
    let root = root_idx(num_leaves);
    let mut p = start_idx;

    // Iterate up the direct path starting at the given node, taking siblings along the way.
    while p != root {
        // Recall that p has no siblings iff it is the root node, so it's guaranteed that
        // sibling != p here.
        let sibling = node_sibling(p, num_leaves);
        copath.push(sibling);
        p = node_parent(p, num_leaves);
    }

    copath
}

/// Returns a list of root node indices for maximal subtrees of a tree of a given size
///
/// Panics: when `num_leaves == 0` or `num_leaves > MAX_LEAVES`
fn tree_frontier(num_leaves: usize) -> Vec<usize> {
    assert!(num_leaves > 0 && num_leaves <= MAX_LEAVES);

    // The given tree has a maximal subtree of size 2^(i+1)-1 exists iff the i-th bit (indexing at
    // 0) is set in the binary representation of num_leaves. We store the sizes by the number of
    // leaves in the tree, i.e., 2^i where i is as above.
    let mut sizes_present = Vec::new();
    for j in 0..=log2(num_leaves).unwrap() {
        let bitmask = 1 << j;
        if num_leaves & bitmask != 0 {
            sizes_present.push(bitmask);
        }
    }

    let mut base = 0;
    let mut frontier = Vec::new();
    // Iterate from largest to smallest subtrees, since the largest occur on the left.
    for num_leaves_in_subtree in sizes_present.into_iter().rev() {
        frontier.push(root_idx(num_leaves_in_subtree) + base);
        let num_nodes_in_subtree = num_nodes_in_tree(num_leaves_in_subtree);
        // Advance the index to the next relevant subtree. There's a +1 because we skip over the
        // parent of the maximal subtree we were just at.
        // Efficiency note: this is equivalent to writing base |= num_leaves_in_subtree << 1;
        base += num_nodes_in_subtree + 1;
    }

    frontier
}

/// Returns a list of indices for leaf nodes in a tree of given size
///
/// Panics: when `num_leaves == 0` or `num_leaves > MAX_LEAVES`
fn tree_leaves(num_leaves: usize) -> Vec<usize> {
    assert!(num_leaves > 0 && num_leaves <= MAX_LEAVES);
    // The leaves are just all the even indices
    (0..num_leaves).map(|i| 2 * i).collect()
}

#[cfg(test)]
mod test {
    use super::*;

    use quickcheck::TestResult;
    use quickcheck_macros::quickcheck;
    use rand::Rng;
    use serde::ser::Serialize;

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
        assert_eq!(
            log2((bigboi >> 1) + 1),
            log2((bigboi >> 2) + 1).map(|i| i + 1)
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

    // See above tree for a diagram
    #[test]
    fn node_level_simple_kat() {
        assert_eq!(node_level(0), 0);
        assert_eq!(node_level(1), 1);
        assert_eq!(node_level(2), 0);
        assert_eq!(node_level(3), 2);
        assert_eq!(node_level(4), 0);
        assert_eq!(node_level(5), 1);
        assert_eq!(node_level(6), 0);
        assert_eq!(node_level(7), 3);
        assert_eq!(node_level(8), 0);
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

    // See above tree for a diagram
    #[test]
    fn tree_relations_kat() {
        let num_leaves = 5;

        // Test parent relations
        assert_eq!(node_parent(0, num_leaves), 1);
        assert_eq!(node_parent(2, num_leaves), 1);
        assert_eq!(node_parent(4, num_leaves), 5);
        assert_eq!(node_parent(6, num_leaves), 5);
        assert_eq!(node_parent(1, num_leaves), 3);
        assert_eq!(node_parent(5, num_leaves), 3);
        assert_eq!(node_parent(3, num_leaves), 7);
        assert_eq!(node_parent(8, num_leaves), 7);
        assert_eq!(node_parent(7, num_leaves), 7);

        // Test leaf child relations
        assert_eq!(node_left_child(0), 0);
        assert_eq!(node_right_child(0, num_leaves), 0);
        assert_eq!(node_left_child(2), 2);
        assert_eq!(node_right_child(2, num_leaves), 2);
        assert_eq!(node_left_child(4), 4);
        assert_eq!(node_right_child(4, num_leaves), 4);
        assert_eq!(node_left_child(6), 6);
        assert_eq!(node_right_child(6, num_leaves), 6);
        assert_eq!(node_left_child(8), 8);
        assert_eq!(node_right_child(8, num_leaves), 8);

        // Test the non-leaf left relations
        assert_eq!(node_left_child(7), 3);
        assert_eq!(node_left_child(3), 1);
        assert_eq!(node_left_child(1), 0);
        assert_eq!(node_left_child(5), 4);

        // Test the non-leaf right relations
        assert_eq!(node_right_child(7, num_leaves), 8);
        assert_eq!(node_right_child(3, num_leaves), 5);
        assert_eq!(node_right_child(1, num_leaves), 2);
        assert_eq!(node_right_child(5, num_leaves), 6);

        // Test sibling relations
        assert_eq!(node_sibling(0, num_leaves), 2);
        assert_eq!(node_sibling(2, num_leaves), 0);
        assert_eq!(node_sibling(4, num_leaves), 6);
        assert_eq!(node_sibling(6, num_leaves), 4);
        assert_eq!(node_sibling(1, num_leaves), 5);
        assert_eq!(node_sibling(5, num_leaves), 1);
        assert_eq!(node_sibling(8, num_leaves), 3);
        assert_eq!(node_sibling(3, num_leaves), 8);
        assert_eq!(node_sibling(7, num_leaves), 7);
    }

    #[quickcheck]
    fn tree_relations_correctness(num_leaves: usize) {
        if num_leaves == 0 || num_leaves > MAX_LEAVES {
            // This is an invalid input. Do nothing.
            return;
        }

        let num_nodes = num_nodes_in_tree(num_leaves);

        // This is our starting node
        let me: usize = {
            let mut rng = rand::thread_rng();
            rng.gen_range(0, num_nodes)
        };
        let my_sibling = node_sibling(me, num_leaves);
        let my_parent = node_parent(my_sibling, num_leaves);

        assert_eq!(node_parent(me, num_leaves), my_parent);

        // Recall left_child < parent < right_child
        match me.cmp(&my_parent) {
            std::cmp::Ordering::Less => {
                // I am the left child of my parent
                assert_eq!(node_left_child(my_parent), me);
                assert_eq!(node_right_child(my_parent, num_leaves), my_sibling);
            }
            std::cmp::Ordering::Greater => {
                // I am the left child of my parent
                assert_eq!(node_left_child(my_parent), my_sibling);
                assert_eq!(node_right_child(my_parent, num_leaves), me);
            }
            std::cmp::Ordering::Equal => {
                // I am my own parent. I must be the root node
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

    // TODO: Add Panic tests

    //
    // All the following KATs are from
    // https://github.com/mlswg/mls-implementations/blob/master/test_vectors/treemath.md
    //

    // Anything that goes in this struct will get serialized with a u32 length tag
    #[derive(Serialize)]
    #[serde(rename = "ContainerU32__bound_u32")]
    struct ContainerU32<T: Serialize>(T);

    macro_rules! unitary_func_test {
        (
        $name:ident,
        $size:expr,
        [$range_low:expr, $range_high:expr],
        $test_func:ident,
        $expected:expr
    ) => {
            #[test]
            fn $name() {
                let size = 255;
                let mut test_vector = Vec::new();
                for i in $range_low..=$range_high {
                    let res = $test_func(i);
                    test_vector.push(res as u32);
                }

                let dummy_container = ContainerU32(test_vector);
                let serialized_vec = crate::tls_ser::serialize_to_bytes(&dummy_container).unwrap();

                assert_eq!(hex::encode(&serialized_vec), $expected);
            }
        };
    }

    macro_rules! binary_func_test {
        (
        $name:ident,
        $size:expr,
        [$range_low:expr, $range_high:expr],
        $test_func:ident,
        $expected:expr
    ) => {
            #[test]
            fn $name() {
                let size = 255;
                let mut test_vector = Vec::new();
                for i in $range_low..=$range_high {
                    let res = $test_func(i, size);
                    test_vector.push(res as u32);
                }

                let dummy_container = ContainerU32(test_vector);
                let serialized_vec = crate::tls_ser::serialize_to_bytes(&dummy_container).unwrap();

                assert_eq!(hex::encode(serialized_vec), $expected);
            }
        };
    }

    unitary_func_test!(
        root_idx_kat,
        255,
        [1, 254],
        root_idx,
        "000003f800000000000000010000000300000003000000070000000700000007000000070000000f0000000f0\
         000000f0000000f0000000f0000000f0000000f0000000f0000001f0000001f0000001f0000001f0000001f00\
         00001f0000001f0000001f0000001f0000001f0000001f0000001f0000001f0000001f0000001f0000001f000\
         0003f0000003f0000003f0000003f0000003f0000003f0000003f0000003f0000003f0000003f0000003f0000\
         003f0000003f0000003f0000003f0000003f0000003f0000003f0000003f0000003f0000003f0000003f00000\
         03f0000003f0000003f0000003f0000003f0000003f0000003f0000003f0000003f0000003f0000007f000000\
         7f0000007f0000007f0000007f0000007f0000007f0000007f0000007f0000007f0000007f0000007f0000007\
         f0000007f0000007f0000007f0000007f0000007f0000007f0000007f0000007f0000007f0000007f0000007f\
         0000007f0000007f0000007f0000007f0000007f0000007f0000007f0000007f0000007f0000007f0000007f0\
         000007f0000007f0000007f0000007f0000007f0000007f0000007f0000007f0000007f0000007f0000007f00\
         00007f0000007f0000007f0000007f0000007f0000007f0000007f0000007f0000007f0000007f0000007f000\
         0007f0000007f0000007f0000007f0000007f0000007f0000007f000000ff000000ff000000ff000000ff0000\
         00ff000000ff000000ff000000ff000000ff000000ff000000ff000000ff000000ff000000ff000000ff00000\
         0ff000000ff000000ff000000ff000000ff000000ff000000ff000000ff000000ff000000ff000000ff000000\
         ff000000ff000000ff000000ff000000ff000000ff000000ff000000ff000000ff000000ff000000ff000000f\
         f000000ff000000ff000000ff000000ff000000ff000000ff000000ff000000ff000000ff000000ff000000ff\
         000000ff000000ff000000ff000000ff000000ff000000ff000000ff000000ff000000ff000000ff000000ff0\
         00000ff000000ff000000ff000000ff000000ff000000ff000000ff000000ff000000ff000000ff000000ff00\
         0000ff000000ff000000ff000000ff000000ff000000ff000000ff000000ff000000ff000000ff000000ff000\
         000ff000000ff000000ff000000ff000000ff000000ff000000ff000000ff000000ff000000ff000000ff0000\
         00ff000000ff000000ff000000ff000000ff000000ff000000ff000000ff000000ff000000ff000000ff00000\
         0ff000000ff000000ff000000ff000000ff000000ff000000ff000000ff000000ff000000ff000000ff000000\
         ff000000ff000000ff000000ff000000ff000000ff000000ff000000ff000000ff000000ff000000ff"
    );

    unitary_func_test!(
        node_level_kat,
        255,
        [0, 253],
        node_level,
        "000003f8000000000000000100000000000000020000000000000001000000000000000300000000000000010\
         00000000000000200000000000000010000000000000004000000000000000100000000000000020000000000\
         00000100000000000000030000000000000001000000000000000200000000000000010000000000000005000\
         00000000000010000000000000002000000000000000100000000000000030000000000000001000000000000\
         00020000000000000001000000000000000400000000000000010000000000000002000000000000000100000\
         00000000003000000000000000100000000000000020000000000000001000000000000000600000000000000\
         01000000000000000200000000000000010000000000000003000000000000000100000000000000020000000\
         00000000100000000000000040000000000000001000000000000000200000000000000010000000000000003\
         00000000000000010000000000000002000000000000000100000000000000050000000000000001000000000\
         00000020000000000000001000000000000000300000000000000010000000000000002000000000000000100\
         00000000000004000000000000000100000000000000020000000000000001000000000000000300000000000\
         00001000000000000000200000000000000010000000000000007000000000000000100000000000000020000\
         00000000000100000000000000030000000000000001000000000000000200000000000000010000000000000\
         00400000000000000010000000000000002000000000000000100000000000000030000000000000001000000\
         00000000020000000000000001000000000000000500000000000000010000000000000002000000000000000\
         10000000000000003000000000000000100000000000000020000000000000001000000000000000400000000\
         00000001000000000000000200000000000000010000000000000003000000000000000100000000000000020\
         00000000000000100000000000000060000000000000001000000000000000200000000000000010000000000\
         00000300000000000000010000000000000002000000000000000100000000000000040000000000000001000\
         00000000000020000000000000001000000000000000300000000000000010000000000000002000000000000\
         00010000000000000005000000000000000100000000000000020000000000000001000000000000000300000\
         00000000001000000000000000200000000000000010000000000000004000000000000000100000000000000\
         0200000000000000010000000000000003000000000000000100000000000000020000000000000001"
    );

    unitary_func_test!(
        node_width_kat,
        255,
        [1, 254],
        num_nodes_in_tree,
        "000003f800000001000000030000000500000007000000090000000b0000000d0000000f00000011000000130\
         000001500000017000000190000001b0000001d0000001f000000210000002300000025000000270000002900\
         00002b0000002d0000002f00000031000000330000003500000037000000390000003b0000003d0000003f000\
         00041000000430000004500000047000000490000004b0000004d0000004f0000005100000053000000550000\
         0057000000590000005b0000005d0000005f00000061000000630000006500000067000000690000006b00000\
         06d0000006f00000071000000730000007500000077000000790000007b0000007d0000007f00000081000000\
         830000008500000087000000890000008b0000008d0000008f000000910000009300000095000000970000009\
         90000009b0000009d0000009f000000a1000000a3000000a5000000a7000000a9000000ab000000ad000000af\
         000000b1000000b3000000b5000000b7000000b9000000bb000000bd000000bf000000c1000000c3000000c50\
         00000c7000000c9000000cb000000cd000000cf000000d1000000d3000000d5000000d7000000d9000000db00\
         0000dd000000df000000e1000000e3000000e5000000e7000000e9000000eb000000ed000000ef000000f1000\
         000f3000000f5000000f7000000f9000000fb000000fd000000ff000001010000010300000105000001070000\
         01090000010b0000010d0000010f00000111000001130000011500000117000001190000011b0000011d00000\
         11f00000121000001230000012500000127000001290000012b0000012d0000012f0000013100000133000001\
         3500000137000001390000013b0000013d0000013f00000141000001430000014500000147000001490000014\
         b0000014d0000014f00000151000001530000015500000157000001590000015b0000015d0000015f00000161\
         000001630000016500000167000001690000016b0000016d0000016f000001710000017300000175000001770\
         00001790000017b0000017d0000017f00000181000001830000018500000187000001890000018b0000018d00\
         00018f00000191000001930000019500000197000001990000019b0000019d0000019f000001a1000001a3000\
         001a5000001a7000001a9000001ab000001ad000001af000001b1000001b3000001b5000001b7000001b90000\
         01bb000001bd000001bf000001c1000001c3000001c5000001c7000001c9000001cb000001cd000001cf00000\
         1d1000001d3000001d5000001d7000001d9000001db000001dd000001df000001e1000001e3000001e5000001\
         e7000001e9000001eb000001ed000001ef000001f1000001f3000001f5000001f7000001f9000001fb"
    );

    unitary_func_test!(
        node_left_child_kat,
        255,
        [0, 253],
        node_left_child,
        "000003f8000000000000000000000002000000010000000400000004000000060000000300000008000000080\
         000000a000000090000000c0000000c0000000e00000007000000100000001000000012000000110000001400\
         000014000000160000001300000018000000180000001a000000190000001c0000001c0000001e0000000f000\
         000200000002000000022000000210000002400000024000000260000002300000028000000280000002a0000\
         00290000002c0000002c0000002e0000002700000030000000300000003200000031000000340000003400000\
         0360000003300000038000000380000003a000000390000003c0000003c0000003e0000001f00000040000000\
         4000000042000000410000004400000044000000460000004300000048000000480000004a000000490000004\
         c0000004c0000004e000000470000005000000050000000520000005100000054000000540000005600000053\
         00000058000000580000005a000000590000005c0000005c0000005e0000004f0000006000000060000000620\
         00000610000006400000064000000660000006300000068000000680000006a000000690000006c0000006c00\
         00006e00000067000000700000007000000072000000710000007400000074000000760000007300000078000\
         000780000007a000000790000007c0000007c0000007e0000003f000000800000008000000082000000810000\
         008400000084000000860000008300000088000000880000008a000000890000008c0000008c0000008e00000\
         08700000090000000900000009200000091000000940000009400000096000000930000009800000098000000\
         9a000000990000009c0000009c0000009e0000008f000000a0000000a0000000a2000000a1000000a4000000a\
         4000000a6000000a3000000a8000000a8000000aa000000a9000000ac000000ac000000ae000000a7000000b0\
         000000b0000000b2000000b1000000b4000000b4000000b6000000b3000000b8000000b8000000ba000000b90\
         00000bc000000bc000000be0000009f000000c0000000c0000000c2000000c1000000c4000000c4000000c600\
         0000c3000000c8000000c8000000ca000000c9000000cc000000cc000000ce000000c7000000d0000000d0000\
         000d2000000d1000000d4000000d4000000d6000000d3000000d8000000d8000000da000000d9000000dc0000\
         00dc000000de000000cf000000e0000000e0000000e2000000e1000000e4000000e4000000e6000000e300000\
         0e8000000e8000000ea000000e9000000ec000000ec000000ee000000e7000000f0000000f0000000f2000000\
         f1000000f4000000f4000000f6000000f3000000f8000000f8000000fa000000f9000000fc000000fc"
    );

    binary_func_test!(
        node_right_child_kat,
        255,
        [0, 253],
        node_right_child,
        "000003f8000000000000000200000002000000050000000400000006000000060000000b000000080000000a0\
         000000a0000000d0000000c0000000e0000000e00000017000000100000001200000012000000150000001400\
         000016000000160000001b000000180000001a0000001a0000001d0000001c0000001e0000001e0000002f000\
         000200000002200000022000000250000002400000026000000260000002b000000280000002a0000002a0000\
         002d0000002c0000002e0000002e0000003700000030000000320000003200000035000000340000003600000\
         0360000003b000000380000003a0000003a0000003d0000003c0000003e0000003e0000005f00000040000000\
         4200000042000000450000004400000046000000460000004b000000480000004a0000004a0000004d0000004\
         c0000004e0000004e00000057000000500000005200000052000000550000005400000056000000560000005b\
         000000580000005a0000005a0000005d0000005c0000005e0000005e0000006f0000006000000062000000620\
         00000650000006400000066000000660000006b000000680000006a0000006a0000006d0000006c0000006e00\
         00006e00000077000000700000007200000072000000750000007400000076000000760000007b00000078000\
         0007a0000007a0000007d0000007c0000007e0000007e000000bf000000800000008200000082000000850000\
         008400000086000000860000008b000000880000008a0000008a0000008d0000008c0000008e0000008e00000\
         097000000900000009200000092000000950000009400000096000000960000009b000000980000009a000000\
         9a0000009d0000009c0000009e0000009e000000af000000a0000000a2000000a2000000a5000000a4000000a\
         6000000a6000000ab000000a8000000aa000000aa000000ad000000ac000000ae000000ae000000b7000000b0\
         000000b2000000b2000000b5000000b4000000b6000000b6000000bb000000b8000000ba000000ba000000bd0\
         00000bc000000be000000be000000df000000c0000000c2000000c2000000c5000000c4000000c6000000c600\
         0000cb000000c8000000ca000000ca000000cd000000cc000000ce000000ce000000d7000000d0000000d2000\
         000d2000000d5000000d4000000d6000000d6000000db000000d8000000da000000da000000dd000000dc0000\
         00de000000de000000ef000000e0000000e2000000e2000000e5000000e4000000e6000000e6000000eb00000\
         0e8000000ea000000ea000000ed000000ec000000ee000000ee000000f7000000f0000000f2000000f2000000\
         f5000000f4000000f6000000f6000000fb000000f8000000fa000000fa000000fd000000fc000000fe"
    );

    binary_func_test!(
        node_parent_kat,
        255,
        [0, 253],
        node_parent,
        "000003f8000000010000000300000001000000070000000500000003000000050000000f000000090000000b0\
         0000009000000070000000d0000000b0000000d0000001f000000110000001300000011000000170000001500\
         000013000000150000000f000000190000001b00000019000000170000001d0000001b0000001d0000003f000\
         000210000002300000021000000270000002500000023000000250000002f000000290000002b000000290000\
         00270000002d0000002b0000002d0000001f00000031000000330000003100000037000000350000003300000\
         0350000002f000000390000003b00000039000000370000003d0000003b0000003d0000007f00000041000000\
         4300000041000000470000004500000043000000450000004f000000490000004b00000049000000470000004\
         d0000004b0000004d0000005f000000510000005300000051000000570000005500000053000000550000004f\
         000000590000005b00000059000000570000005d0000005b0000005d0000003f0000006100000063000000610\
         00000670000006500000063000000650000006f000000690000006b00000069000000670000006d0000006b00\
         00006d0000005f000000710000007300000071000000770000007500000073000000750000006f00000079000\
         0007b00000079000000770000007d0000007b0000007d000000ff000000810000008300000081000000870000\
         008500000083000000850000008f000000890000008b00000089000000870000008d0000008b0000008d00000\
         09f000000910000009300000091000000970000009500000093000000950000008f000000990000009b000000\
         99000000970000009d0000009b0000009d000000bf000000a1000000a3000000a1000000a7000000a5000000a\
         3000000a5000000af000000a9000000ab000000a9000000a7000000ad000000ab000000ad0000009f000000b1\
         000000b3000000b1000000b7000000b5000000b3000000b5000000af000000b9000000bb000000b9000000b70\
         00000bd000000bb000000bd0000007f000000c1000000c3000000c1000000c7000000c5000000c3000000c500\
         0000cf000000c9000000cb000000c9000000c7000000cd000000cb000000cd000000df000000d1000000d3000\
         000d1000000d7000000d5000000d3000000d5000000cf000000d9000000db000000d9000000d7000000dd0000\
         00db000000dd000000bf000000e1000000e3000000e1000000e7000000e5000000e3000000e5000000ef00000\
         0e9000000eb000000e9000000e7000000ed000000eb000000ed000000df000000f1000000f3000000f1000000\
         f7000000f5000000f3000000f5000000ef000000f9000000fb000000f9000000f7000000fd000000fb"
    );

    binary_func_test!(
        node_sibling_kat,
        255,
        [0, 253],
        node_sibling,
        "000003f80000000200000005000000000000000b000000060000000100000004000000170000000a0000000d0\
         0000008000000030000000e000000090000000c0000002f0000001200000015000000100000001b0000001600\
         00001100000014000000070000001a0000001d00000018000000130000001e000000190000001c0000005f000\
         0002200000025000000200000002b000000260000002100000024000000370000002a0000002d000000280000\
         00230000002e000000290000002c0000000f0000003200000035000000300000003b000000360000003100000\
         034000000270000003a0000003d00000038000000330000003e000000390000003c000000bf00000042000000\
         45000000400000004b000000460000004100000044000000570000004a0000004d00000048000000430000004\
         e000000490000004c0000006f0000005200000055000000500000005b00000056000000510000005400000047\
         0000005a0000005d00000058000000530000005e000000590000005c0000001f0000006200000065000000600\
         000006b000000660000006100000064000000770000006a0000006d00000068000000630000006e0000006900\
         00006c0000004f0000007200000075000000700000007b000000760000007100000074000000670000007a000\
         0007d00000078000000730000007e000000790000007c0000017f0000008200000085000000800000008b0000\
         00860000008100000084000000970000008a0000008d00000088000000830000008e000000890000008c00000\
         0af0000009200000095000000900000009b000000960000009100000094000000870000009a0000009d000000\
         98000000930000009e000000990000009c000000df000000a2000000a5000000a0000000ab000000a6000000a\
         1000000a4000000b7000000aa000000ad000000a8000000a3000000ae000000a9000000ac0000008f000000b2\
         000000b5000000b0000000bb000000b6000000b1000000b4000000a7000000ba000000bd000000b8000000b30\
         00000be000000b9000000bc0000003f000000c2000000c5000000c0000000cb000000c6000000c1000000c400\
         0000d7000000ca000000cd000000c8000000c3000000ce000000c9000000cc000000ef000000d2000000d5000\
         000d0000000db000000d6000000d1000000d4000000c7000000da000000dd000000d8000000d3000000de0000\
         00d9000000dc0000009f000000e2000000e5000000e0000000eb000000e6000000e1000000e4000000f700000\
         0ea000000ed000000e8000000e3000000ee000000e9000000ec000000cf000000f2000000f5000000f0000000\
         fb000000f6000000f1000000f4000000e7000000fa000000fd000000f8000000f3000000fe000000f9"
    );

    // TODO: Add direct path and copath tests. Current test vectors seem weird / not correctly
    // implemented or serialized. Will look into this.
}
