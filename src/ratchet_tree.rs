//! Defines `RatchetTree` and all its functionality. Not much public API here.

use crate::{
    credential::Credential,
    crypto::{
        ciphersuite::CipherSuite,
        dh::{DhPrivateKey, DhPublicKey, DhScheme},
        hash::{Digest, HashFunction},
        hmac::HmacKey,
        hpke,
        rng::CryptoRng,
    },
    error::Error,
    group_ctx::{WelcomeInfoRatchetNode, WelcomeInfoRatchetTree},
    handshake::{DirectPathMessage, DirectPathNodeMessage},
    tree_math::{self, TreeIdx},
    utils,
};

use std::convert::{TryFrom, TryInto};
use subtle::ConstantTimeEq;

/// This is called the "path secret" in the "Ratchet Tree Updates" section of the spec. If `Hash`
/// is the current ciphersuite's hash algorithm, this MUST have length equal to `Hash.length`.
#[derive(Clone)]
pub struct PathSecret(pub(crate) HmacKey);

impl PathSecret {
    /// Wraps a `Vec<u8>` with a `ClearOnDrop` and makes it a `PathSecret`
    pub(crate) fn new_from_bytes(bytes: &[u8]) -> PathSecret {
        PathSecret(HmacKey::new_from_bytes(bytes))
    }

    /// Generates a random `PathSecret` of the appropriate length
    pub fn new_from_random<R>(cs: &'static CipherSuite, csprng: &mut R) -> PathSecret
    where
        R: CryptoRng,
    {
        let key = HmacKey::new_from_random(cs.hash_impl, csprng);
        PathSecret(key)
    }

    /// Returns the bytes-representation of the path secret. Do not use this method unless you
    /// really really need to.
    fn as_bytes(&self) -> &[u8] {
        // Dig into the HMAC key and pull out a slice
        (self.0).0.as_slice()
    }

    /// Returns the length of the bytes-representation of the path secret
    pub(crate) fn len(&self) -> usize {
        self.as_bytes().len()
    }
}

// PathSecret --> HmacKey trivially
impl From<PathSecret> for HmacKey {
    fn from(p: PathSecret) -> HmacKey {
        p.0
    }
}

/// The index of a member in a group. Equivalently, `MemberIdx(n)` corresponds to the `n`th leaf of
/// a given tree.
#[derive(Clone, Copy, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[cfg_attr(test, derive(Debug))]
pub struct MemberIdx(u32);

impl MemberIdx {
    pub fn new(idx: u32) -> MemberIdx {
        MemberIdx(idx)
    }
}

// MemberIdx --> u32 trivially
impl From<MemberIdx> for u32 {
    fn from(idx: MemberIdx) -> u32 {
        idx.0
    }
}

// MemberIdx --> usize trivially
impl From<MemberIdx> for usize {
    fn from(idx: MemberIdx) -> usize {
        // This cast casn't fail because molasses doesn't run on <32-bit machines
        usize::try_from(idx.0).unwrap()
    }
}

// Implement PartialEq for usize so that we can implement PartialOrd and so we can ask whether
// `member_idx == tree.num_leaves()` when processing a GroupAdd
impl core::cmp::PartialEq<usize> for MemberIdx {
    fn eq(&self, other: &usize) -> bool {
        usize::from(*self).eq(other)
    }
}

// Implement PartialOrd between MemberIdx and usize so we can ask whether
// `member_idx < tree.num_leaves()` when processing a GroupAdd
impl core::cmp::PartialOrd<usize> for MemberIdx {
    fn partial_cmp(&self, other: &usize) -> Option<core::cmp::Ordering> {
        usize::from(*self).partial_cmp(other)
    }
}

// MemberIdx --> TreeIdx by multiplying by 2
impl std::convert::TryFrom<MemberIdx> for TreeIdx {
    type Error = Error;

    /// Converts a member index into its corresponding tree index
    ///
    /// Returns: `Ok(tree_idx)` on success. If the resulting member index is out of bounds, returns
    /// an `Error::ValidationError`.
    fn try_from(member_idx: MemberIdx) -> Result<TreeIdx, Error> {
        // This is easy. The nth leaf node is at position 2n
        // The unwrap below cannot fail because molasses only runs on >32 bit systems
        usize::from(member_idx)
            .checked_mul(2)
            .ok_or(Error::ValidationError("Member index is too large"))
            .map(TreeIdx::new)
    }
}

// TreeIdx --> MemberIdx by dividing by 2
impl std::convert::TryFrom<TreeIdx> for MemberIdx {
    type Error = Error;

    /// Converts a tree index that points to a leaf into the member index for that leaf
    ///
    /// Returns: `Ok(member_idx)` on success. If something is out of bounds or if `tree_idx`
    /// doesn't point to a leaf node, returns an `Error::ValidationError`.
    fn try_from(tree_idx: TreeIdx) -> Result<MemberIdx, Error> {
        let raw_tree_idx = usize::from(tree_idx);
        // The index is even iff it's a leaf
        if raw_tree_idx % 2 == 0 {
            // Try to convert it down to a u32. If it's too big, that's an error
            let member_idx = u32::try_from(raw_tree_idx / 2)
                .map_err(|_| Error::ValidationError("Tree index is out of bounds"))?;
            Ok(MemberIdx(member_idx))
        } else {
            Err(Error::ValidationError("Tree index is not a member index"))
        }
    }
}

/// Represents the constant value of `NODE::hash_type` where `NODE` is `LeafNode` or `ParentNode`
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename = "NodeHashType__enum_u8")]
enum NodeHashType {
    /// `LeafNode::hash_type` is defined to be 0u8
    Leaf,
    /// `ParentNode::hash_type` is defined to be 0u8
    Parent,
}

/// Represents a participant in the group. Contains their identity and pubkey. This is called
/// `LeafInfo` in the spec.
#[derive(Clone, Serialize)]
#[cfg_attr(test, derive(Debug))]
pub(crate) struct MemberInfo {
    /// The DH public key of the participant
    pub(crate) public_key: DhPublicKey,

    /// The identity of the participant
    pub(crate) credential: Credential,

    /// The DH private key of the participant. This is nonzero iff this leaf is me.
    #[serde(skip)]
    pub(crate) private_key: Option<DhPrivateKey>,
}

/// A (possibly Blank) leaf node in the hash tree. Contains an optional `MemberInfo`.
#[derive(Clone, Serialize)]
#[cfg_attr(test, derive(Debug))]
pub(crate) struct LeafNode {
    /// This is always NodeHashType::Leaf (which is encoded as 0)
    hash_type: NodeHashType,

    /// The content of the leaf. This is `None` iff this leaf is Blank.
    info: Option<MemberInfo>,
}

impl LeafNode {
    /// Makes a new `LeafNode` with a known keypair, given the credential and private key
    pub(crate) fn new_from_private_key(
        dh_impl: &'static DhScheme,
        credential: Credential,
        private_key: DhPrivateKey,
    ) -> LeafNode {
        // Derive the pubkey and stick it in the info
        let public_key = DhPublicKey::new_from_private_key(dh_impl, &private_key);
        let info = MemberInfo {
            public_key,
            credential,
            private_key: Some(private_key),
        };

        // Make a non-blank LeafNode with the above info
        LeafNode {
            hash_type: NodeHashType::Leaf,
            info: Some(info),
        }
    }

    /// Makes a new `LeafNode` with a known public key and credential
    pub(crate) fn new_from_public_key(credential: Credential, public_key: DhPublicKey) -> LeafNode {
        LeafNode {
            hash_type: NodeHashType::Leaf,
            info: Some(MemberInfo {
                public_key,
                credential,
                private_key: None,
            }),
        }
    }

    /// Creates a new Blank `LeafNode`
    pub(crate) fn new_blank() -> LeafNode {
        LeafNode {
            hash_type: NodeHashType::Leaf,
            info: None,
        }
    }

    /// Returns `true` iff this `LeafNode` is Blank
    pub(crate) fn is_blank(&self) -> bool {
        // A leaf node is Blank iff its `info` field is None
        self.info.is_none()
    }

    /// Blanks out this `LeafNode`
    fn make_blank(&mut self) {
        self.info = None;
    }

    /// Returns the node's public key. If the node is Blank, returns `None`.
    pub(crate) fn get_public_key(&self) -> Option<&DhPublicKey> {
        self.info.as_ref().map(|info| &info.public_key)
    }

    /// Returns `Some(&private_key)` iff this leaf node has a known a private key. Otherwise returns
    /// `None`.
    pub(crate) fn get_private_key(&self) -> Option<&DhPrivateKey> {
        self.info.as_ref().and_then(|info| info.private_key.as_ref())
    }

    /// Updates this `LeafNode`'s public key to the given one
    ///
    /// Returns: `Ok(())` on success. Returns an `Error::ValidationError` iff this node is Blank
    pub(crate) fn update_public_key(&mut self, new_public_key: DhPublicKey) -> Result<(), Error> {
        match self.info {
            // Blank leaf nodes have to be initialized with credentials before they we can update
            // their public key
            None => {
                Err(Error::ValidationError("Cannot update the public key of a Blank leaf node"))
            }
            // If the leaf is Filled, update the pubkey and remove what we know about the private
            // key. Really, it should never be the case that we knew the private key beforehand,
            // since if we did, this leaf would represent us, and we would call update_keypair
            // instead.
            Some(ref mut leaf_info) => {
                leaf_info.public_key = new_public_key;
                leaf_info.private_key = None;
                Ok(())
            }
        }
    }

    /// Updates the node's private key to the given one and recalculates the public key
    ///
    /// Returns: `Ok(())` on success. Returns an `Error::ValidationError` iff this node is Blank
    pub(crate) fn update_keypair(
        &mut self,
        dh_impl: &'static DhScheme,
        new_private_key: DhPrivateKey,
    ) -> Result<(), Error> {
        match self.info {
            // Blank leaf nodes have to be initialized with credentials before they we can update
            // their private key
            None => {
                Err(Error::ValidationError("Cannot update the private key of a Blank leaf node"))
            }
            // If the leaf is Filled, update the private key and recalculate the pubkey
            Some(ref mut leaf_info) => {
                leaf_info.public_key = DhPublicKey::new_from_private_key(dh_impl, &new_private_key);
                leaf_info.private_key = Some(new_private_key);
                Ok(())
            }
        }
    }
}

/// A (possibly Blank) parent node in the hash tree. Contains pubkey info and the hashes of its
/// children.
#[derive(Clone, Serialize)]
#[cfg_attr(test, derive(Debug))]
pub(crate) struct ParentNode {
    /// This is always NodeHashType::Parent (which is encoded as 1)
    hash_type: NodeHashType,

    /// The node's public key. This is `None` iff the node is Blank.
    public_key: Option<DhPublicKey>,

    /// The node's private key. This is `Some` iff the node is a non-Blank ancestor of ours.
    #[serde(skip)]
    private_key: Option<DhPrivateKey>,

    /// The hash of the left subtree of this node
    left_hash: Digest,

    /// The hash of the right subtree of this node
    right_hash: Digest,
}

impl ParentNode {
    /// Creates a new Blank `ParentNode` whose hashes are initialized to the hashes of the given
    /// children.
    ///
    /// Returns: `Ok(parent_node)` on success. If serialization fails, returns an
    /// `Error::SerdeError`.
    fn new_blank(
        hash_impl: &HashFunction,
        left_child: &RatchetTreeNode,
        right_child: &RatchetTreeNode,
    ) -> Result<ParentNode, Error> {
        let left_hash = hash_impl.hash_serializable(left_child)?;
        let right_hash = hash_impl.hash_serializable(right_child)?;

        Ok(ParentNode {
            hash_type: NodeHashType::Parent,
            public_key: None,
            private_key: None,
            left_hash,
            right_hash,
        })
    }

    // Why can't this take in two RatchetTreeNodes and calculate the hashes themselves? Aliasing.
    // In normal usage, this parent node will be obtained through a mutable borrow of a
    // RatchetTree, and the children will be obtained through an immutable borrow of the same tree.
    // The issue is that all 3 of these things have to be in scope at the same time, which violates
    // aliasing rules. So instead we force the caller to calculate the hashes first, let the
    // immutable borrows of the children go out of scope, then do this mutating change.
    /// Updates the left and right child hashes of this `ParentNode`
    ///
    /// Returns: `Ok(())` on success. If serialization fails, returns an `Error::SerdeError`.
    fn update_hashes(&mut self, left_child_hash: Digest, right_child_hash: Digest) {
        self.left_hash = left_child_hash;
        self.right_hash = right_child_hash;
    }

    /// Returns `true` iff this `ParentNode` is Blank
    pub(crate) fn is_blank(&self) -> bool {
        // A parent node is Blank iff its `public_key` field is None
        self.public_key.is_none()
    }

    /// Blanks out this `ParentNode`
    fn make_blank(&mut self) {
        self.public_key = None;
    }

    /// Returns the node's public key. If the node is Blank, returns `None`.
    pub(crate) fn get_public_key(&self) -> Option<&DhPublicKey> {
        self.public_key.as_ref()
    }

    /// Returns `Some(&private_key)` iff this `ParentNode` has a known a private key. Otherwise returns
    /// `None`.
    pub(crate) fn get_private_key(&self) -> Option<&DhPrivateKey> {
        self.private_key.as_ref()
    }

    /// Updates this `ParentNode`'s public key to the given one and erases the private key
    pub(crate) fn update_public_key(&mut self, new_public_key: DhPublicKey) {
        self.public_key = Some(new_public_key);
        self.private_key = None;
    }

    /// Updates the node's private key to the given one and recalculates the public key
    ///
    /// Returns: `Ok(())` on success. Returns an `Error::ValidationError` iff this node is Blank
    pub(crate) fn update_keypair(
        &mut self,
        dh_impl: &'static DhScheme,
        new_private_key: DhPrivateKey,
    ) {
        let pubkey = DhPublicKey::new_from_private_key(dh_impl, &new_private_key);
        self.public_key = Some(pubkey);
        self.private_key = Some(new_private_key);
    }
}

/// Every node is either a `Parent` or a `Leaf`
#[derive(Clone, Serialize)]
#[cfg_attr(test, derive(Debug))]
#[serde(rename = "RatchetTreeNode__enum_untagged")]
pub(crate) enum RatchetTreeNode {
    Parent(ParentNode),
    Leaf(LeafNode),
}

impl RatchetTreeNode {
    /// Wraps the `get_public_key` methods of `ParentNode` and `LeafNode`
    fn get_public_key(&self) -> Option<&DhPublicKey> {
        match self {
            RatchetTreeNode::Parent(ref p) => p.get_public_key(),
            RatchetTreeNode::Leaf(ref l) => l.get_public_key(),
        }
    }

    /// Wraps the `is_blank` methods of `ParentNode` and `LeafNode`
    pub(crate) fn is_blank(&self) -> bool {
        match self {
            RatchetTreeNode::Parent(ref p) => p.is_blank(),
            RatchetTreeNode::Leaf(ref l) => l.is_blank(),
        }
    }

    /// Returns the opposite of `is_blank`
    pub(crate) fn is_filled(&self) -> bool {
        !self.is_blank()
    }

    /// Wraps the `make_blank` methods of `ParentNode` and `LeafNode`
    fn make_blank(&mut self) {
        match self {
            RatchetTreeNode::Parent(ref mut p) => p.make_blank(),
            RatchetTreeNode::Leaf(ref mut l) => l.make_blank(),
        }
    }

    // This wraps the `get_private_key` methods of `ParentNode` and `LeafNode`
    /// Returns `Some(&private_key)` iff this node has a known a private key. Otherwise returns
    /// `None`.
    pub(crate) fn get_private_key(&self) -> Option<&DhPrivateKey> {
        match self {
            RatchetTreeNode::Parent(ref p) => p.get_private_key(),
            RatchetTreeNode::Leaf(ref l) => l.get_private_key(),
        }
    }

    // This wraps the `update_keypair` methods of `ParentNode` and `LeafNode`
    /// Updates the node's private key to the given one and recalculates the public key
    ///
    /// Returns: `Ok(())` on success. Returns an `Error::ValidationError` iff this node is Blank
    /// leaf node.
    pub(crate) fn update_keypair(
        &mut self,
        dh_impl: &'static DhScheme,
        new_private_key: DhPrivateKey,
    ) -> Result<(), Error> {
        match self {
            RatchetTreeNode::Parent(ref mut p) => {
                // Updating a parent node can't fail
                p.update_keypair(dh_impl, new_private_key);
                Ok(())
            }
            // Updating a leaf node can fail. Namely if we tried to update one without a credential
            RatchetTreeNode::Leaf(ref mut l) => l.update_keypair(dh_impl, new_private_key),
        }
    }

    // This wraps the `update_public_key` methods of `ParentNode` and `LeafNode`
    /// Updates the node's public key to the given one and erases the private key
    ///
    /// Returns: `Ok(())` on success. Returns an `Error::ValidationError` iff this node is Blank
    /// leaf node.
    pub(crate) fn update_public_key(&mut self, new_public_key: DhPublicKey) -> Result<(), Error> {
        match self {
            RatchetTreeNode::Parent(ref mut p) => {
                // Updating a parent node can't fail
                p.update_public_key(new_public_key);
                Ok(())
            }
            // Updating a leaf node can fail. Namely if we tried to update one without a credential
            RatchetTreeNode::Leaf(ref mut l) => l.update_public_key(new_public_key),
        }
    }
}

/// A left-balanced binary tree of `RatchetTreeNode`s
#[derive(Clone)]
#[cfg_attr(test, derive(Debug))]
pub(crate) struct RatchetTree {
    hash_impl: &'static HashFunction,
    pub(crate) nodes: Vec<RatchetTreeNode>,
}

impl RatchetTree {
    /// Creates a new `RatchetTree` with no nodes. Only for testing purposes
    #[cfg(test)]
    pub(crate) fn new_empty(hash_impl: &'static HashFunction) -> RatchetTree {
        RatchetTree {
            hash_impl,
            nodes: Vec::new(),
        }
    }

    /// Creates a new `RatchetTree` with a single node
    ///
    /// Returns: `Ok(tree)` on success. If leaf node serialization fails, returns an
    /// `Error::SerdeError`.
    pub(crate) fn new_singleton(
        hash_impl: &'static HashFunction,
        node: LeafNode,
    ) -> Result<RatchetTree, Error> {
        // Make an empty tree
        let mut tree = RatchetTree {
            hash_impl,
            nodes: Vec::new(),
        };
        // Add the leaf and return the tree
        tree.add_leaf_node(node)?;
        Ok(tree)
    }

    /// Converts a `WelcomeInfoRatchetTree` into a proper `RatchetTree`
    pub(crate) fn new_from_welcome_info_ratchet_tree(
        hash_impl: &'static HashFunction,
        wi_tree: WelcomeInfoRatchetTree,
    ) -> Result<RatchetTree, Error> {
        let mut nodes: Vec<RatchetTreeNode> = Vec::with_capacity(wi_tree.0.len());

        // We consider 3 cases in the loop:
        // 1. A WelcomeInfoRatchetTree node is None: In this case, we make a Blank node
        // 2. A WelcomeInfoRatchetTree node is Some and it's a leaf: In this case, we make a Filled
        //    LeafNode. Note that this requires that the given node's credential must be Some,
        //    since leaves are tied to identities. A missing credential is considered an error.
        // 3. A WelcomeInfoRatchetTree node is Some and it'a parent: In this case, we make a Filled
        //    ParentNode. WelcomeInfo does not come with private key information, so we only have
        //    to set the parent's pubkey. Still, we check that the given node's credential field is
        //    None, since a non-None credential for a parent node makes no sense (parent nodes
        //    aren't tied to any identity)
        for (i, wi_node_opt) in wi_tree.0.into_iter().enumerate() {
            // This index is a leaf's iff its node level is 0
            let curr_idx = TreeIdx::new(i);
            let is_leaf = tree_math::node_level(curr_idx) == 0;

            let node = match wi_node_opt {
                // We got a blank node
                None => {
                    let blank_node = if is_leaf {
                        // Blank leaves are easy
                        RatchetTreeNode::Leaf(LeafNode::new_blank())
                    } else {
                        // Make a Blank parent node with dummy hashes. We'll calculate the hashes
                        // at the end of this function
                        RatchetTreeNode::Parent(ParentNode {
                            hash_type: NodeHashType::Parent,
                            public_key: None,
                            private_key: None,
                            left_hash: Digest::new_from_zeros(hash_impl),
                            right_hash: Digest::new_from_zeros(hash_impl),
                        })
                    };

                    blank_node
                }

                // We got a filled node
                Some(wi_node) => {
                    let filled_node = if is_leaf {
                        // Filled leaves MUST come with a credential
                        let credential = wi_node.credential.ok_or(Error::ValidationError(
                            "Non-Blank WelcomeInfoRatchetNodes must have a credential",
                        ))?;
                        let leaf = LeafNode::new_from_public_key(credential, wi_node.public_key);
                        RatchetTreeNode::Leaf(leaf)
                    } else {
                        // Do a quick sanity check. It makes no sense for parent nodes to come with
                        // a credential
                        if wi_node.credential.is_some() {
                            return Err(Error::ValidationError(
                                "Non-leaf WelcomeInfoRatchetNodes cannot have a credential",
                            ));
                        }
                        // Make a Filled parent node with the given public key and dummy hashes.
                        // We'll calculate the hashes at the end of this function
                        RatchetTreeNode::Parent(ParentNode {
                            hash_type: NodeHashType::Parent,
                            public_key: Some(wi_node.public_key),
                            private_key: None,
                            left_hash: Digest::new_from_zeros(hash_impl),
                            right_hash: Digest::new_from_zeros(hash_impl),
                        })
                    };

                    filled_node
                }
            };

            nodes.push(node);
        }

        // Make the tree from its components
        let mut tree = RatchetTree {
            hash_impl,
            nodes,
        };

        // Final step: calculate the node hash of all the nodes in the tree
        tree.recalculate_all_hashes()?;

        // All done
        Ok(tree)
    }

    /// Returns the number of nodes in the tree
    pub(crate) fn size(&self) -> usize {
        self.nodes.len()
    }

    /// Returns the number of members in the tree (i.e., the number of leaves)
    pub(crate) fn num_leaves(&self) -> usize {
        tree_math::num_leaves_in_tree(self.size())
    }

    /// Returns the node at the given index
    pub(crate) fn get(&self, idx: TreeIdx) -> Option<&RatchetTreeNode> {
        self.nodes.get(usize::from(idx))
    }

    /// Returns a mutable reference to the node at the given index
    fn get_mut(&mut self, idx: TreeIdx) -> Option<&mut RatchetTreeNode> {
        self.nodes.get_mut(usize::from(idx))
    }

    /// Fetches the credential corresponding to the member at the given index
    ///
    /// Returns: `Ok(None)` iff the member at the given index is Blank. Returns `Ok(Some(cred))`
    /// iff the member at the given index is Filled. Returns `Error::ValidationError` if the given
    /// index is out of bounds
    pub(crate) fn get_member_info(
        &self,
        member_idx: MemberIdx,
    ) -> Result<Option<&MemberInfo>, Error> {
        let tree_idx: TreeIdx = member_idx.try_into()?;
        // The enum_variant! macro below can only panic if we have a Parent node in the place of a
        // leaf node, which means that this tree is corrupt anyways
        let leaf = self
            .get(tree_idx.into())
            .ok_or(Error::ValidationError("Member index is out of bounds"))
            .map(|node| enum_variant!(node, RatchetTreeNode::Leaf))?;

        Ok(leaf.info.as_ref())
    }

    /// Sets the member info at a given member index and recalculates the hashes in the leaf's
    /// extended direct path
    ///
    /// Returns: `Ok(())` on success. Returns `Error::ValidationError` if the given index is out of
    /// bounds. Returns `Error::SerdeError` if something goes wrong in recalculating the hashes.
    /// Returns `Error::ValidationError` if we tried to set the member info of a non-blank node.
    pub(crate) fn set_member_info(
        &mut self,
        member_idx: MemberIdx,
        info: MemberInfo,
    ) -> Result<(), Error> {
        let tree_idx: TreeIdx = member_idx.try_into()?;

        // The enum_variant! macro below can only panic if we have a Parent node in the place of a
        // leaf node, which means that this tree is corrupt anyways
        let mut leaf = self
            .get_mut(tree_idx.into())
            .ok_or(Error::ValidationError("Member index is out of bounds"))
            .map(|node| enum_variant!(node, RatchetTreeNode::Leaf))?;

        // Check that we're not overwriting anything. The only time we should be setting member
        // info is during an Add op, when we have either appended a new blank leaf or are using an
        // existing blank leaf. Neither of these cases involve overwriting existing MemberInfo.
        if leaf.info.is_some() {
            return Err(Error::ValidationError("Tried to overwrite non-blank node"));
        }

        // Set the field
        leaf.info = Some(info);

        // Now recalculate the hashes along the extended direct path of the modified leaf
        self.recalculate_ancestor_hashes(tree_idx)
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
    /// Appends the given leaf node to the tree, making a new Blank parent node in the process.
    /// Also recalculates the hashes in the extended direct path of the added leaf.
    ///
    /// Returns: `Ok(())` on success. If serialization fails, returns an `Error::SerdeError`.
    pub(crate) fn add_leaf_node(&mut self, new_leaf: LeafNode) -> Result<(), Error> {
        let new_leaf = RatchetTreeNode::Leaf(new_leaf);

        if self.nodes.is_empty() {
            // If the tree is empty, the first thing we push is a leaf node
            self.nodes.push(new_leaf);
        } else {
            // We need to find the two children of the parent node we're about to add in order to
            // be able to calculate the hashes.

            // The index that the newly added parent node will have; it's just off the end
            let new_parent_idx = TreeIdx::new(self.size());

            // The left child of the newly added parent node
            let left_child = {
                let left_child_idx = tree_math::node_left_child(new_parent_idx);
                self.get(left_child_idx).unwrap()
            };

            // Make the parent node. The right child is guaranteed to be the new leaf
            let new_parent = ParentNode::new_blank(self.hash_impl, left_child, &new_leaf)?;

            // Push the two to the tree
            self.nodes.push(RatchetTreeNode::Parent(new_parent));
            self.nodes.push(new_leaf);
        }

        // This is the idx of the leaf we just added. The -1 here can't underflow, since the
        // tree is nonempty now
        let new_leaf_idx = TreeIdx::new(self.size() - 1);
        // Update the hashes of the ancestors of the newly-added leaf
        self.recalculate_ancestor_hashes(new_leaf_idx)
    }

    /// Blanks out the extended direct path of the given member and recalculates its hashes
    ///
    /// Returns: `Ok(())` on success. Returns an `Error::ValidationError` if something went wrong
    /// in indexing things.
    pub(crate) fn propagate_blank(&mut self, member_idx: MemberIdx) -> Result<(), Error> {
        // This is our starting point in the tree
        let tree_idx: TreeIdx = member_idx.try_into()?;

        // Blank the extended direct path (direct path + root node)
        for i in tree_math::node_extended_direct_path(tree_idx.into(), self.num_leaves()) {
            // No need to check index here. By construction, there's no way this is out of bounds
            self.nodes[usize::from(i)].make_blank();
        }

        // Recalculate along the extended direct path, since those were the only modified nodes
        self.recalculate_ancestor_hashes(tree_idx)
    }

    /// Updates the path secret at the given index and derives the path secrets, node secrets,
    /// private keys, and public keys of all its ancestors. This also recalculates the hashes of
    /// all the parents of the modified nodes. If anything described here fails, this method will
    /// _not_ roll back the operation, so the caller should expect this object to be in an invalid
    /// state.
    ///
    /// Requires: `path_secret.len() == cs.hash_alg.output_len`
    ///
    /// Panics: If above condition is not satisfied
    ///
    /// Returns: `Ok(path_secret)` on success, where `path_secret` is the path secret of the parent
    /// of the root node in the updated ratchet tree.
    pub(crate) fn propagate_new_path_secret(
        &mut self,
        cs: &CipherSuite,
        mut path_secret: PathSecret,
        start_idx: TreeIdx,
    ) -> Result<PathSecret, Error> {
        let num_leaves = self.num_leaves();
        let root_node_idx = tree_math::root_idx(num_leaves);

        let mut current_node_idx = start_idx;

        // Go up the tree, setting the node secrets and keypairs. The last calculated path secret
        // is the next one after the root (the "parent" of the root). This is our return value.
        let grand_root_path_secret = loop {
            let current_node = self
                .get_mut(current_node_idx.into())
                .expect("reached invalid node in secret propagation");

            // Derive the new values
            let (_, node_private_key, new_path_secret) =
                utils::derive_node_values(cs, path_secret)?;

            // Update the current node with the new values
            current_node.update_keypair(cs.dh_impl, node_private_key)?;

            if current_node_idx == root_node_idx {
                // If we just updated the root, we're done
                break new_path_secret;
            } else {
                // Otherwise, take one step up the tree
                current_node_idx = tree_math::node_parent(current_node_idx, num_leaves);
                path_secret = new_path_secret;
            }
        };

        // Update the hashes of all the ancestors of the starting node
        self.recalculate_ancestor_hashes(start_idx)?;

        Ok(grand_root_path_secret)
    }

    // This always produces a valid tree. To see this, note that truncating to a leaf node when
    // there are >1 non-blank leaf nodes gives you a vector of odd length. All vectors of odd
    // length have a unique interpretation as a binary left-balanced tree. And if there are no
    // non-blank leaf nodes, you get an empty tree.
    /// Truncates the tree down to the first non-blank leaf node and recalculates the hashes of the
    /// parents of the rightmost node. If there are only Blank nodes, this will clear the tree.
    pub(crate) fn truncate_to_last_nonblank(&mut self) {
        let num_leaves = self.num_leaves();

        // Look for the last non-blank leaf by iterating backwards through the leaves in the tree
        let mut last_nonblank_leaf: Option<TreeIdx> = None;
        for tree_leaf_idx in tree_math::tree_leaves(num_leaves).rev() {
            if self.nodes[usize::from(tree_leaf_idx)].is_filled() {
                last_nonblank_leaf = Some(tree_leaf_idx);
                break;
            }
        }

        match last_nonblank_leaf {
            // If there are no nonempty entries in the tree, clear it
            None => {
                // Clear the tree and return early. There are no hashes to recalculate
                self.nodes.clear();
                return;
            }
            Some(i) => {
                // This can't fail, because i is an index
                let num_elements_to_retain = usize::from(i) + 1;
                self.nodes.truncate(num_elements_to_retain)
            }
        }

        // Get the index of the last member and update the hashes in its extended direct path. The
        // -1 cannot underflow here, because if the tree were empty, we would have early-returned
        // in the match statement above.
        let last_member_idx = TreeIdx::new(self.size() - 1);

        // This unwrap() cannot fail. The only way tree hash calculation fails is via serialization
        // error. But this tree was valid before the call to this function, and no elements in the
        // tree have been modified. So serialization cannot fail.
        self.recalculate_ancestor_hashes(last_member_idx).unwrap();
    }

    /// Returns the indices of the resolution of a given node: this an ordered sequence of minimal
    /// set of non-blank nodes that collectively cover (A "covers" B iff A is an ancestor of B) all
    /// non-blank descendants of the given node. The ordering is ascending by node index.
    pub(crate) fn resolution(&self, idx: TreeIdx) -> Vec<TreeIdx> {
        // Helper function that accumulates the resolution recursively
        fn helper(tree: &RatchetTree, i: TreeIdx, acc: &mut Vec<TreeIdx>) {
            if tree.nodes[usize::from(i)].is_blank() {
                if tree_math::node_level(i) == 0 {
                    // The resolution of a blank leaf node is the empty list
                    return;
                } else {
                    // The resolution of a blank intermediate node is the result of concatinating
                    // the resolution of its left child with the resolution of its right child, in
                    // that order
                    let num_leaves = tree.num_leaves();
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

    /// Overwrites all the public keys in the extended (i.e., including root) direct path of
    /// `start_tree_idx` with `public_keys`, stopping before setting the public key at
    /// `stop_before_tree_idx`. If `stop_before_tree_idx` is not found in the direct path, this
    /// will overwrite the public keys of the whole extended direct path.
    ///
    /// Returns: `Ok(())` on success. Returns `Error::ValidationError` if the direct path range of
    /// `[start_tree_idx, stop_before_tree_idx)` is longer than the `public_keys` iterator, or if
    /// `start_tree_idx` is a Blank `LeafNode`.
    pub(crate) fn set_public_keys_with_bound<'a, I: Iterator<Item = &'a DhPublicKey>>(
        &mut self,
        start_member_idx: MemberIdx,
        stop_before_tree_idx: TreeIdx,
        mut public_keys: I,
    ) -> Result<(), Error> {
        // Update all the public keys of the nodes in the direct path that are below our common
        // ancestor, i.e., all the ones whose secret we don't know. Note that this step is not
        // performed in apply_update, because this only happens when we're not the ones who created
        // the Update operation.
        let start_tree_idx: TreeIdx = start_member_idx.try_into()?;
        let sender_direct_path =
            tree_math::node_extended_direct_path(start_tree_idx, self.num_leaves());
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
                node.update_public_key(pubkey.clone())?;
            }
        }

        // Update the hashes of all the ancestors of the starting node
        self.recalculate_ancestor_hashes(start_tree_idx)?;

        Ok(())
    }

    /// Checks if the public keys on the direct path of `start_idx` agree with the public keys
    /// returned by the iterator `expected_public_keys`.
    ///
    /// Returns: `Ok(())` iff everything is in agreement and the iterator is as long as the direct
    /// path. Returns some sort of `Error::ValidationError` otherwise.
    pub(crate) fn validate_direct_path_public_keys<'a, I>(
        &self,
        start_member_idx: MemberIdx,
        mut expected_public_keys: I,
    ) -> Result<(), Error>
    where
        I: Iterator<Item = &'a DhPublicKey>,
    {
        // Verify that the pubkeys in the message agree with our newly-derived pubkeys all the way
        // up the tree (including the root node). We go through the iterators in lock-step. If one
        // goes longer than the other, that's a problem, and we throw and error.
        let start_tree_idx: TreeIdx = start_member_idx.try_into()?;
        let mut ext_direct_path =
            tree_math::node_extended_direct_path(start_tree_idx, self.num_leaves());
        loop {
            match (ext_direct_path.next(), expected_public_keys.next()) {
                (Some(path_node_idx), Some(expected_pubkey)) => {
                    let existing_pubkey = self
                        .get(path_node_idx)
                        .ok_or(Error::ValidationError("Unexpected out-of-bounds path index"))?
                        .get_public_key()
                        .ok_or(Error::ValidationError("Node on direct path has no public key"))?;

                    // Constant-time compare the pubkeys (I don't think CT is necessary, but I
                    // ain't taking any chances). The underlying value is 1 iff expected_bytes ==
                    // existing_bytes
                    let pubkeys_match: bool = expected_pubkey.ct_eq(existing_pubkey).into();
                    if !pubkeys_match {
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
    /// appropriately ratcheted path secret for the rest of the ratchet tree. See the "Direct
    /// Paths" section in the spec for details.
    pub(crate) fn encrypt_direct_path_secrets<R>(
        &self,
        cs: &CipherSuite,
        starting_leaf_node: MemberIdx,
        starting_path_secret: PathSecret,
        csprng: &mut R,
    ) -> Result<DirectPathMessage, Error>
    where
        R: CryptoRng,
    {
        // Convert the member into to a tree index and check for errors.
        let starting_tree_idx: TreeIdx = starting_leaf_node.try_into()?;
        if starting_tree_idx >= self.size() {
            return Err(Error::TreeError("Encryption starting node index out of range"));
        }

        let num_leaves = self.num_leaves();
        let direct_path = tree_math::node_direct_path(starting_tree_idx, num_leaves);

        let mut node_messages = Vec::new();

        // The first message should be just the starting node's pubkey and no encrypted messages
        let (starting_node_public_key, _, mut parent_path_secret) =
            utils::derive_node_values(cs, starting_path_secret)?;
        node_messages.push(DirectPathNodeMessage {
            public_key: starting_node_public_key.clone(),
            encrypted_path_secrets: Vec::with_capacity(0),
        });

        // Go up the direct path of the starting index
        for path_node_idx in direct_path {
            // We need to derive the new parent's public key to send in the same message as the
            // encrypted copies of the parent's path_secret
            let (parent_public_key, _, grandparent_path_secret) =
                utils::derive_node_values(cs, parent_path_secret.clone())?;

            // Encrypt the path secret at the current node's parent for everyone in the resolution
            // of the copath node. We can unwrap() here because self.resolution only returns
            // indices that are actually in the tree.
            let mut encrypted_path_secrets = Vec::new();
            let copath_node_idx = tree_math::node_sibling(path_node_idx, num_leaves);
            for res_node_idx in self.resolution(copath_node_idx).into_iter() {
                // This node must exist in the tree because we just got the idx from resolution()
                let res_node = &self.nodes[usize::from(res_node_idx)];
                // We can unwrap() here because self.resolution only returns indices of nodes
                // that are non-blank, by definition of "resolution"
                let others_public_key = res_node.get_public_key().unwrap();
                // Encrypt the parent's path secret with the resolution node's pubkey
                let ciphertext = hpke::encrypt(
                    cs,
                    others_public_key,
                    parent_path_secret.as_bytes().to_vec(), // TODO: Make this not copy secrets
                    csprng,
                )?;
                encrypted_path_secrets.push(ciphertext);
            }

            // Push the collection to the message list
            node_messages.push(DirectPathNodeMessage {
                public_key: parent_public_key.clone(),
                encrypted_path_secrets: encrypted_path_secrets,
            });

            // Ratchet up the path secret
            parent_path_secret = grandparent_path_secret;
        }

        Ok(DirectPathMessage {
            node_messages,
        })
    }

    // This function technically makes sense with my_idx being a parent node, but that never
    // happens in practice, so we restrict the inputs to leaf nodes
    /// Finds the (unique) ciphertext in the given direct path message that is meant for this
    /// member and decrypts it. `sender_idx` is the the member index of the starting node of the
    /// encoded direct path. `my_idx` is the member index of us, i.e., a leaf node whose private
    /// key is known.
    ///
    /// Returns: `Ok((pt, ancestor))` where `pt` is the `Result` of decrypting the found ciphertext
    /// and `ancestor` is the tree index of the common ancestor of `sender_idx` and `my_idx`. If no
    /// decryptable ciphertext exists, returns an `Error::TreeError`. If decryption fails, returns
    /// an `Error::EncryptionError`.
    pub(crate) fn decrypt_direct_path_message(
        &self,
        cs: &CipherSuite,
        direct_path_msg: &DirectPathMessage,
        sender_idx: MemberIdx,
        my_idx: MemberIdx,
    ) -> Result<(PathSecret, TreeIdx), Error> {
        let num_leaves = self.num_leaves();

        // Convert member indices to tree indices and check for errors
        let my_tree_idx: TreeIdx = my_idx.try_into()?;
        let sender_tree_idx: TreeIdx = sender_idx.try_into()?;
        if sender_tree_idx >= self.size() || my_tree_idx >= self.size() {
            return Err(Error::TreeError("Input index out of range"));
        }

        // This is the intermediate node in the direct path whose secret was encrypted for us.
        let common_ancestor_tree_idx =
            tree_math::common_ancestor(sender_tree_idx, my_tree_idx, num_leaves);

        // This holds the secret of the intermediate node, encrypted for all the nodes in the
        // resolution of the copath node.
        let node_msg = {
            // To get this value, we have to figure out the correct index into node_message
            let (pos_in_msg_vec, _) =
                tree_math::node_extended_direct_path(sender_tree_idx, num_leaves)
                    .enumerate()
                    .find(|&(_, dp_idx)| dp_idx == common_ancestor_tree_idx)
                    .expect("common ancestor somehow did not appear in direct path");
            direct_path_msg
                .node_messages
                .get(pos_in_msg_vec)
                .ok_or(Error::TreeError("Malformed DirectPathMessage"))?
        };

        // This is the unique ancestor of the receiver that is in the copath of the sender. In
        // other words, this is the child of the common ancestor that's also an ancestor of the
        // receiver. This is the node whose resolution is used.
        let copath_ancestor_idx = {
            let left = tree_math::node_left_child(common_ancestor_tree_idx);
            let right = tree_math::node_right_child(common_ancestor_tree_idx, num_leaves);
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
                    .encrypted_path_secrets
                    .get(pos_in_res)
                    .ok_or(Error::TreeError("Malformed DirectPathMessage"))?;

                // Finally, decrypt the thing and return the plaintext and common ancestor
                let plaintext = hpke::decrypt(cs, decryption_key, ciphertext_for_me.clone())?;
                let path_secret = PathSecret::new_from_bytes(&plaintext);
                return Ok((path_secret, common_ancestor_tree_idx));
            }
        }

        // With the checks at the beginning of this method, this should never happen
        Err(Error::TreeError("Cannot find node in resolution with known private key"))
    }

    /// Updates the hashes of the nodes at the given indices in the order given
    ///
    /// Returns: `Ok(())` on success. If serialization fails at any point, errors with an
    /// `Error::SerdeError`.
    ///
    /// Panics: If any of the received indices are out of bounds or if any parent node is not of
    /// the `RatchetTreeNode::Parent` variant.
    fn recalculate_hashes<I>(&mut self, node_indices: I) -> Result<(), Error>
    where
        I: IntoIterator<Item = TreeIdx>,
    {
        // Copy these at the top so we don't have borrowing issues below
        let num_leaves = self.num_leaves();
        let hash_impl = self.hash_impl;

        for node_idx in node_indices.into_iter() {
            let left_child_idx = tree_math::node_left_child(node_idx);
            let right_child_idx = tree_math::node_right_child(node_idx, num_leaves);

            // Check if this node is a leaf (i.e., if it is its own child). If it's a parent, we
            // have to tell it what the the hashes of its children are
            if left_child_idx != node_idx {
                let (left_child_hash, right_child_hash) = {
                    // Get the children. This unwrap can't fail, because we got these indices from the
                    // tree math done above.
                    let left_child = self.get(left_child_idx).unwrap();
                    let right_child = self.get(right_child_idx).unwrap();

                    // Calculate their hashes
                    (
                        hash_impl.hash_serializable(left_child)?,
                        hash_impl.hash_serializable(right_child)?,
                    )
                };

                let curr_node = {
                    // Panic on bad input. Just don't call this function with bad inputs
                    let node = self.get_mut(node_idx).unwrap();
                    // This node is not a leaf, so it better be a RatchetTreeNode::Parent,
                    // otherwise we have a corrupt tree
                    enum_variant!(node, RatchetTreeNode::Parent)
                };
                // Recalculate the hashes
                curr_node.update_hashes(left_child_hash, right_child_hash);
            }
        }

        Ok(())
    }

    /// Updates the hashes of all the ancestors of the given node, including the start node itself
    ///
    /// Returns: `Ok(())` on success. If serialization fails at any point, errors with an
    /// `Error::SerdeError`.
    ///
    /// Panics: If the received index is out of bounds or if any parent node is not of the
    /// `RatchetTreeNode::Parent` variant.
    fn recalculate_ancestor_hashes(&mut self, start_idx: TreeIdx) -> Result<(), Error> {
        // Compute the extended direct path and pass it along to the real recalculation method
        let ext_direct_path = tree_math::node_extended_direct_path(start_idx, self.num_leaves());
        self.recalculate_hashes(ext_direct_path)
    }

    /// Updates all the node hashes in the tree
    ///
    /// Returns: `Ok(())` on success. If serialization fails at any point, errors with an
    /// `Error::SerdeError`.
    ///
    /// Panics: If any parent node is not of the `RatchetTreeNode::Parent` variant
    fn recalculate_all_hashes(&mut self) -> Result<(), Error> {
        // Order matters here, since we only want to calculate hashes over leaves and parents whose
        // hashes have already been calculated. So we get all the indices of all the nodes in the
        // tree, and order them by node level in increasing order. Then we run recalculate_hashes
        // on this array. This way, we end up calculating all the hashes in the tree from the
        // bottom up.
        let mut all_indices: Vec<TreeIdx> = (0..self.size()).map(TreeIdx::new).collect();
        // This is sorted in increasing order, so the leaves (level 0) are evaluated first, then
        // the parents of the leaves, etc.
        all_indices.sort_unstable_by_key(|&i| tree_math::node_level(i));
        // Pass to the real recalculation method
        self.recalculate_hashes(all_indices)
    }

    /// Returns the hash of the root node of the tree
    ///
    /// Returns: `Ok(())` on success. If serialization of the root node failed, returns
    /// `Error::SerdeError`.
    pub(crate) fn tree_hash(&self) -> Result<Digest, Error> {
        // Get the root node
        let root_idx = tree_math::root_idx(self.num_leaves());
        let root_node = self.get(root_idx).unwrap();

        // Hash the serialized form
        self.hash_impl.hash_serializable(root_node)
    }
}

// RatchetTree --> WelcomeInfoRatchetTree
impl From<&RatchetTree> for WelcomeInfoRatchetTree {
    fn from(tree: &RatchetTree) -> WelcomeInfoRatchetTree {
        // Build up the nodes in the same order as they occur in this tree
        let mut nodes: Vec<Option<WelcomeInfoRatchetNode>> = Vec::with_capacity(tree.size());

        for node in &tree.nodes {
            // We throw out hash and private key information in this conversion. We just want to
            // know if this node is Blank, and if not, which public key we can put into the
            // WelcomeInfoRatchetNode, and whether we can put a credential in.
            let welcome_node = match node {
                RatchetTreeNode::Parent(ref p) => {
                    // All Blank nodes are None
                    if p.is_blank() {
                        None
                    } else {
                        // Filled parent nodes get their public key copied
                        Some(WelcomeInfoRatchetNode {
                            public_key: p.public_key.as_ref().unwrap().clone(),
                            credential: None,
                        })
                    }
                }

                RatchetTreeNode::Leaf(ref l) => {
                    // All Blank nodes are None
                    if l.is_blank() {
                        None
                    } else {
                        // Filled leaf nodes get their public key and credential copied
                        let MemberInfo {
                            ref public_key,
                            ref credential,
                            ..
                        } = l.info.as_ref().unwrap();
                        Some(WelcomeInfoRatchetNode {
                            public_key: public_key.clone(),
                            credential: Some(credential.clone()),
                        })
                    }
                }
            };

            // Add this node to the list
            nodes.push(welcome_node)
        }

        // All done. Make a tree out of these nodes.
        WelcomeInfoRatchetTree(nodes)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        credential::{BasicCredential, Credential, Identity},
        crypto::{
            ciphersuite::X25519_SHA256_AES128GCM,
            dh::{DhPublicKey, X25519_IMPL},
            hash::SHA256_IMPL,
            sig::{SigPublicKey, SigPublicKeyRaw, SignatureScheme, ED25519_IMPL},
        },
        test_utils,
        tls_de::TlsDeserializer,
    };

    use quickcheck_macros::quickcheck;
    use rand::Rng;
    use rand::SeedableRng;
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

        let cs: &'static CipherSuite = &X25519_SHA256_AES128GCM;
        let ss: &'static SignatureScheme = &ED25519_IMPL;

        let (tree, _) = test_utils::random_tree(&mut rng, cs, ss, num_leaves);

        // Come up with sender and receiver indices. The sender must be a leaf node, because
        // encryption function requires it. The receiver must be different from the sender, because
        // the decryption function requires it.
        let sender_member_idx = MemberIdx(rng.gen_range(0, num_leaves as u32));
        let receiver_member_idx = test_utils::random_member_index_with_exceptions(
            num_leaves,
            &[sender_member_idx],
            &mut rng,
        );

        // Come up with a new path secret and encrypt it to the receiver
        let sender_path_secret = PathSecret::new_from_random(cs, &mut rng);
        let direct_path_msg = tree
            .encrypt_direct_path_secrets(
                cs,
                sender_member_idx,
                sender_path_secret.clone(),
                &mut rng,
            )
            .expect("failed to encrypt direct path secrets");
        // Decrypt the path secret closest to the receiver
        let (derived_path_secret, common_ancestor) = tree
            .decrypt_direct_path_message(
                cs,
                &direct_path_msg,
                sender_member_idx,
                receiver_member_idx,
            )
            .expect("failed to decrypt direct path secret");

        // Make sure it really is the common ancestor
        let sender_tree_idx: TreeIdx = sender_member_idx.try_into().unwrap();
        let receiver_tree_idx: TreeIdx = receiver_member_idx.try_into().unwrap();
        assert_eq!(
            common_ancestor,
            tree_math::common_ancestor(sender_tree_idx, receiver_tree_idx, num_leaves)
        );

        // The new path secret is the n-th ratcheted form of the original path secret, where n is
        // the number of hops between sender and the common ancestor
        let expected_path_secret = {
            let mut idx = sender_tree_idx;
            let mut path_secret = sender_path_secret;

            // Ratchet up the tree until we find the common ancestor
            while idx != common_ancestor {
                idx = tree_math::node_parent(idx, num_leaves);
                let (_, _, new_path_secret) = utils::derive_node_values(cs, path_secret).unwrap();
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
        fn u8_resolution(tree: &RatchetTree, idx: TreeIdx) -> Vec<u8> {
            tree.resolution(idx)
                .into_iter()
                .map(|i| {
                    // Convert to usize and then u8. These had better be small indices
                    let i = usize::from(i);
                    if i > core::u8::MAX as usize {
                        panic!("resolution node indices are too big to fit into a u8");
                    } else {
                        i as u8
                    }
                })
                .collect()
        }

        // Helper function. Makes a RatchetTree from an integer, where each bit corresopnds to a
        // Blank or Filled node in the tree. The values of the nodes do not matter.
        fn make_tree_from_int(t: usize, num_nodes: usize) -> RatchetTree {
            let mut nodes: Vec<RatchetTreeNode> = Vec::new();

            for node_idx in (0..num_nodes).map(TreeIdx::new) {
                let bit_mask = 0x01 << usize::from(node_idx);
                if t & bit_mask == 0 {
                    // Make a Blank node
                    let blank = if tree_math::node_level(node_idx) == 0 {
                        // It's a leaf
                        RatchetTreeNode::Leaf(LeafNode::new_blank())
                    } else {
                        // It's a parent. Make a dummy child
                        let child = RatchetTreeNode::Leaf(LeafNode::new_blank());
                        let parent = ParentNode::new_blank(&SHA256_IMPL, &child, &child).unwrap();
                        RatchetTreeNode::Parent(parent)
                    };

                    // Add the Blank node
                    nodes.push(blank);
                } else {
                    // Make a random dummy keypair
                    let dummy_dh_privkey =
                        DhPrivateKey::new_from_random(&X25519_IMPL, &mut rand::thread_rng())
                            .unwrap();
                    let dummy_dh_pubkey =
                        DhPublicKey::new_from_private_key(&X25519_IMPL, &dummy_dh_privkey);
                    let filled = if tree_math::node_level(node_idx) == 0 {
                        // It's a leaf. Make a dummy credentials and identity key.
                        let dummy_cred = {
                            let sig_pubkey = SigPublicKey::Raw(SigPublicKeyRaw(Vec::new()));
                            let id = Identity::from_bytes(b"dummy".to_vec());
                            let bc = BasicCredential::new(id, &ED25519_IMPL, sig_pubkey);
                            Credential::Basic(bc)
                        };

                        // Now make the leaf with all these values and return it
                        let dummy_leaf = LeafNode::new_from_private_key(
                            &X25519_IMPL,
                            dummy_cred,
                            dummy_dh_privkey,
                        );
                        RatchetTreeNode::Leaf(dummy_leaf)
                    } else {
                        // It's a parent. Make a dummy child
                        let child = RatchetTreeNode::Leaf(LeafNode::new_blank());
                        let mut dummy_parent =
                            ParentNode::new_blank(&SHA256_IMPL, &child, &child).unwrap();

                        // Now give the parent a dummy pubkey
                        dummy_parent.public_key = Some(dummy_dh_pubkey);
                        RatchetTreeNode::Parent(dummy_parent)
                    };

                    // Add the Filled node
                    nodes.push(filled);
                }
            }

            RatchetTree {
                hash_impl: &SHA256_IMPL,
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
                let derived_resolution = u8_resolution(&tree, TreeIdx::new(idx));
                assert_eq!(derived_resolution, expected_resolution.0);
            }
        }
    }
}
