use crate::{
    credential::{self, BasicCredential, Credential},
    crypto::{
        ciphersuite::{CipherSuite, X25519_SHA256_AES128GCM},
        dh::DhPrivateKey,
        hash::Digest,
        hmac::HmacKey,
        rng::CryptoRng,
        sig::{SigPublicKey, SigSecretKey, SignatureScheme, ED25519_IMPL},
    },
    group_state::{GroupContext, GroupId},
    handshake::MLS_DUMMY_VERSION,
    ratchet_tree::{MemberIdx, PathSecret, RatchetTree},
    tree_math::TreeIdx,
};

use core::convert::TryFrom;

use rand::seq::SliceRandom;

macro_rules! assert_serialized_eq {
    ($left:expr, $right:expr $(,$fmt:tt)*) => {
        let (left_bytes, right_bytes) = (
            crate::tls_ser::serialize_to_bytes(&$left).unwrap(),
            crate::tls_ser::serialize_to_bytes(&$right).unwrap(),
        );
        assert_eq!(left_bytes, right_bytes, $($fmt,)*);
    };
}

// Generates a random member index within the given bounds, and guarantees that the output is not
// in `forbidden_indices`
pub(crate) fn random_member_index_with_exceptions<R: rand::Rng>(
    group_size: usize,
    forbidden_indices: &[MemberIdx],
    rng: &mut R,
) -> MemberIdx {
    loop {
        let idx = {
            let raw_idx = rng.gen_range(0, group_size);
            MemberIdx::new(u32::try_from(raw_idx).unwrap())
        };
        if forbidden_indices.contains(&idx) {
            continue;
        } else {
            return idx;
        }
    }
}

// Generates a random BasicCredential with the given SignatureScheme
fn random_credential<R: rand::Rng + CryptoRng>(
    rng: &mut R,
    ss: &'static SignatureScheme,
) -> (Credential, SigSecretKey) {
    // Make a random 16 byte identity
    let identity = {
        let mut buf = [0u8; 16];
        rng.fill_bytes(&mut buf);
        credential::Identity(buf.to_vec())
    };
    // Make a random keypair
    let secret_key = SigSecretKey::new_from_random(ss, rng).unwrap();
    let public_key = SigPublicKey::new_from_secret_key(ss, &secret_key);

    let cred = Credential::Basic(BasicCredential {
        identity,
        signature_scheme: ss,
        public_key,
    });

    (cred, secret_key)
}

// Generates a random tree of given size and return the identity keys
pub(crate) fn random_tree<R: rand::Rng + CryptoRng>(
    rng: &mut R,
    cs: &'static CipherSuite,
    ss: &'static SignatureScheme,
    num_leaves: usize,
) -> (RatchetTree, Vec<SigSecretKey>) {
    // Start with an empty tree. The plan is to fill up the leaves with real info, and then
    // propagate path secrets to make sure no node in the tree is Blank
    let mut tree = RatchetTree::new_empty(cs.hash_impl);
    // Make up credentials and identity keys as we generate leaves for the tree
    let mut identity_keys = Vec::with_capacity(num_leaves);

    for _ in 0..num_leaves {
        // Make a leaf with the credential and DH privkey, and add the signing key to the list of
        // identity keys
        let (cred, signing_key) = random_credential(rng, ss);
        let dh_privkey = DhPrivateKey::new_from_random(cs.dh_impl, rng).unwrap();
        let leaf =
            crate::ratchet_tree::LeafNode::new_from_private_key(cs.dh_impl, cred, dh_privkey);

        tree.add_leaf_node(leaf).unwrap();
        identity_keys.push(signing_key);
    }

    // Propagate path secrets through the tree so we don't have any Blank parents
    for idx in 0..num_leaves {
        let member_idx = MemberIdx::new(u32::try_from(idx).unwrap());
        let tree_idx = TreeIdx::try_from(member_idx).unwrap();

        // Random path secret used to derive all private keys up the tree
        let path_secret = {
            let mut buf = [0u8; 32];
            rng.fill_bytes(&mut buf);
            PathSecret::new_from_bytes(&buf)
        };
        tree.propagate_new_path_secret(cs, path_secret, tree_idx)
            .expect("couldn't propagate random secrets in a random tree");
    }

    (tree, identity_keys)
}

// Generates a random GroupContext object (of at least min_size many members) and all the identity
// keys associated with the credentials in the tree. The group state generated has all leaf nodes
// Filled with creds and all parent nodes Filled with known secrets.
pub(crate) fn random_full_group_ctx<R: rand::Rng + CryptoRng>(
    min_size: u32,
    rng: &mut R,
) -> (GroupContext, Vec<SigSecretKey>) {
    // TODO: Expand the number of available ciphersuites once more are available
    let cipher_suites = &[X25519_SHA256_AES128GCM];
    let sig_schemes = &[ED25519_IMPL];

    let cs = cipher_suites.choose(rng).unwrap();
    let ss = sig_schemes.choose(rng).unwrap();

    // Group size and position in group are random
    let group_size: u32 = rng.gen_range(min_size, 50);
    let my_member_idx = MemberIdx::new(rng.gen_range(0, group_size));

    // Make a full tree with all secrets known
    let (tree, identity_keys) = random_tree(rng, cs, ss, usize::try_from(group_size).unwrap());
    let my_identity_key = identity_keys[usize::from(my_member_idx)].clone();

    // Make a random 16 byte group ID
    let group_id = {
        let mut buf = [0u8; 16];
        rng.fill_bytes(&mut buf);
        buf
    };

    // Make a random init_secret and a zero transcript_hash
    let init_secret = HmacKey::new_from_random(cs.hash_impl, rng);
    let transcript_hash = Digest::new_from_zeros(cs.hash_impl);

    // Copy the root hash before we move the tree
    let tree_hash = tree.tree_hash().unwrap();

    let group_ctx = GroupContext {
        cs,
        protocol_version: MLS_DUMMY_VERSION,
        identity_key: my_identity_key,
        group_id: GroupId::new(group_id.to_vec()),
        epoch: rng.gen(),
        tree,
        tree_hash,
        transcript_hash,
        member_index: Some(my_member_idx),
        initializing_user_init_key: None,
        init_secret,
    };

    (group_ctx, identity_keys)
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
    let ss = *signature_schemes.choose(rng).unwrap();

    // Generate a random keypair
    let identity_key = SigSecretKey::new_from_random(ss, rng).unwrap();
    let public_key = SigPublicKey::new_from_secret_key(ss, &identity_key);

    let cred = Credential::Basic(BasicCredential {
        identity,
        signature_scheme: ss,
        public_key,
    });

    (cred, identity_key)
}

// Returns a new GroupContext where the member index is changed to the given `new_index` and the
// identity key is changed to correspond to that member index. Requires that the secret keys in
// `identity_keys` correspond to the public keys in the given group's leaves
pub(crate) fn change_self_index(
    group_ctx: &GroupContext,
    identity_keys: &Vec<SigSecretKey>,
    new_index: MemberIdx,
) -> GroupContext {
    assert!(usize::from(new_index) <= group_ctx.tree.num_leaves());

    let mut new_group_ctx = group_ctx.clone();
    new_group_ctx.member_index = Some(new_index);
    new_group_ctx.identity_key = identity_keys[usize::from(new_index)].clone();

    new_group_ctx
}
