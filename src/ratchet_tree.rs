use crate::crypto::{CipherSuite, DiffieHellman};
use crate::tree_math;

/// A node in a `RatchetTree` with ciphersuite `CS`. Every node must have a DH pubkey. It may also
/// optionally contain the corresponding private key and a secret octet string.
pub enum RatchetTreeNode<CS: CipherSuite> {
    Blank,
    Filled {
        // To explain this notation a bit: CS::DH is the associated DH type of the given
        // ciphersuite. This is a concrete type. However, we know that DH: DiffieHellman, and we
        // need to know that the Point type is, so we choose the DiffieHellman trait
        // representation, and pick the associated type there. Note that this explicit choice is
        // necessary, since if, hypothetically it were the case that DH: Foo + Bar and both Foo and
        // Bar had the associated type Baz, then DH::Baz would be ambiguous. Instead, you'd write
        // <DH as Foo>::Baz or <DH as Bar>::Baz.
        pubkey: <CS::DH as DiffieHellman>::Point,
        privkey: Option<<CS::DH as DiffieHellman>::Scalar>,
        secret: Option<Vec<u8>>,
    },
}

// Contains a vector of nodes that could optionally be blanks
pub struct RatchetTree<CS: CipherSuite> {
    nodes: Vec<RatchetTreeNode<CS>>,
}

impl<CS: CipherSuite> RatchetTree<CS> {
    /// Returns an new empty `RatchetTree`
    pub fn new() -> RatchetTree<CS> {
        RatchetTree { nodes: Vec::new() }
    }

    // It turns out that appending to the tree in this way preserves the left-balanced property
    // while keeping everything in place. Instead of a proof, stare this diagram where I add a new
    // leaf node to a tree of 3 leaves, and then add another leaf to that. The stars represent
    // non-leaf nodes.
    //        *                   *                        *
    //       / \                /   \                _____/ \
    //      /   \    Add(D)    /     \    Add(E)    /        |
    //     *     C   =====>   *       *   =====>   *         |
    //    / \                / \     / \         /   \       |
    //   A   B              A   B   C   D       /     \      |
    //   0 1 2 3 4          0 1 2 3 4 5 6      *       *     |
    //                                        / \     / \    |
    //                                       A   B   C   D   E
    //                                       0 1 2 3 4 5 6 7 8
    pub fn add_leaf_node(&mut self, node: RatchetTreeNode<CS>) {
        if self.nodes.is_empty() {
            self.nodes.push(node);
            return;
        } else {
            self.nodes.push(RatchetTreeNode::Blank);
            self.nodes.push(node);
        }
    }

    /// Returns the resolution of a given node: this an ordered list of non-blank nodes that
    /// collectively cover all non-blank descendants of the given node.
    fn resolution(&self, idx: usize) -> Vec<&RatchetTreeNode<CS>> {
        fn helper<'a, T: CipherSuite>(
            i: usize,
            nodes: &'a Vec<RatchetTreeNode<T>>,
            acc: &mut Vec<&'a RatchetTreeNode<T>>,
        ) {
            let num_leaves = tree_math::num_leaves_in_tree(nodes.len());
            match &nodes[i] {
                f @ RatchetTreeNode::Filled { .. } => {
                    acc.push(f);
                    return;
                }
                _ => (),
            }
            if tree_math::node_level(i) == 0 {
                return;
            }

            helper(tree_math::node_left_child(i), nodes, acc);
            helper(tree_math::node_right_child(i, num_leaves), nodes, acc);
        }

        let mut acc = Vec::new();
        helper(idx, &self.nodes, &mut acc);
        acc
    }

    // This has the same functionality as RatchetTreeIter, so one of them's got to go
    /// Turns a list of node indices into an iterator of tree nodes
    fn make_node_iter(&self, indices: Vec<usize>) -> impl Iterator<Item = &RatchetTreeNode<CS>> {
        indices
            .into_iter()
            .map(move |i| self.nodes.get(i).expect("invalid index encountered"))
    }
}

// This has the same functionality as make_node_iter, so one of them's got to go
/// An iterator that holds a queue of indices into a RatchetTree, and returns references to the
/// corresponding nodes in the tree.
struct RatchetTreeIter<'a, CS: CipherSuite> {
    underlying_tree: &'a RatchetTree<CS>,
    index_iter: std::vec::IntoIter<usize>,
}

impl<'a, CS: CipherSuite> RatchetTreeIter<'a, CS> {
    fn new(underlying_tree: &'a RatchetTree<CS>, indices: Vec<usize>) -> RatchetTreeIter<'a, CS> {
        let index_iter = indices.into_iter();

        RatchetTreeIter {
            underlying_tree,
            index_iter,
        }
    }
}

impl<'a, CS: CipherSuite> Iterator for RatchetTreeIter<'a, CS> {
    type Item = &'a RatchetTreeNode<CS>;

    fn next(&mut self) -> Option<&'a RatchetTreeNode<CS>> {
        self.index_iter.next().map(|idx| {
            self.underlying_tree
                .nodes
                .get(idx)
                .expect("RatchetTreeIter got a bad node index")
        })
    }
}

/// An iterator that holds a queue of indices into a RatchetTree, and returns references to the
/// corresponding nodes in the tree.
struct RatchetTreeIterMut<'a, CS: CipherSuite> {
    underlying_tree: &'a mut RatchetTree<CS>,
    index_iter: std::vec::IntoIter<usize>,
}

impl<'a, CS: CipherSuite> RatchetTreeIterMut<'a, CS> {
    fn new(
        underlying_tree: &'a mut RatchetTree<CS>,
        mut indices: Vec<usize>,
    ) -> RatchetTreeIterMut<'a, CS> {
        // We can't return a &mut to the same node twice, since that would violate aliasing
        // guarantees, i.e., we'd have two mutable references to the same data, which is Bad. So
        // dedup the vector beforehand. Remember that an index uniquely identifies a node, so we're
        // in the clear.
        indices.dedup();
        let index_iter = indices.into_iter();

        RatchetTreeIterMut {
            underlying_tree,
            index_iter,
        }
    }
}

// This needs unsafe code in order to exist. I might delete this if there's little use for it.
impl<'a, CS: CipherSuite> Iterator for RatchetTreeIterMut<'a, CS> {
    type Item = &'a mut RatchetTreeNode<CS>;

    fn next(&mut self) -> Option<&'a mut RatchetTreeNode<CS>> {
        self.index_iter.next().map(|idx| {
            let mut_ref = self
                .underlying_tree
                .nodes
                .get_mut(idx)
                .expect("RatchetTreeIterMut got a bad node index");

            // Okay I can explain this. It's not currently possible to have an iterator that
            // returns mutable references to the thing it's iterating over. Niko Matsakis talks
            // about it here:
            // http://smallcultfollowing.com/babysteps/blog/2013/10/24/iterators-yielding-mutable-references/
            //
            // The reason I can't just return mut_ref is because its lifetime 'a outlives the
            // lifetime of &mut self. The compiler can ensure that mut_ref is a unique mutable
            // reference for the duration of this function call, but cannot guarantee uniqueness
            // after it returns. And indeed it might not be unique. Consider the following code and
            // assume that `tree` is a mut RatchetTree<CS> for some CS:
            //     let mut iter = RatchetTreeIterMut::new(&mut tree, vec![0]);
            //     let first_mut_ref = iter.next();
            //     let another_first_mut_ref = iter.underlying_tree.get_mut(0);
            //  Since I'm able to reach back into the iterator for another mutable reference, I can
            //  force first_mut_ref and another_first_mut_ref to alias.
            //
            //  Now our job is to make sure that you cannot access `iter.underlying_tree`, and also
            //  that the iterator itself does not return the same node multiple times. We do the
            //  former by making `underlying_tree` a private member and "being careful" in this
            //  module. We do the latter by deduping the vectors of indices upon initialization.
            unsafe { std::mem::transmute(mut_ref) }
        })
    }
}
