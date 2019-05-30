use crate::{
    credential::{self, BasicCredential, Credential, Roster},
    crypto::{
        ciphersuite::{CipherSuite, X25519_SHA256_AES128GCM},
        hash::Digest,
        hmac::HmacKey,
        rng::CryptoRng,
        sig::{SigPublicKey, SigSecretKey, SignatureScheme, ED25519_IMPL},
    },
    group_state::GroupState,
    handshake::MLS_DUMMY_VERSION,
    ratchet_tree::{PathSecret, RatchetTree, RatchetTreeNode},
    tree_math,
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

// Generates a random roster index within the given bounds, and guarantees that the output is not in
// `forbidden_indices`
pub(crate) fn random_roster_index_with_exceptions<R: rand::Rng>(
    roster_size: usize,
    forbidden_indices: &[usize],
    rng: &mut R,
) -> u32 {
    loop {
        let idx = rng.gen_range(0, roster_size);
        if forbidden_indices.contains(&idx) {
            continue;
        } else {
            return u32::try_from(idx).unwrap();
        }
    }
}

// Generates a random BasicCredential with the given SignatureScheme
fn random_credential<R: rand::Rng + CryptoRng>(
    rng: &mut R,
    signature_scheme: &'static SignatureScheme,
) -> (Credential, SigSecretKey) {
    // Make a random 16 byte identity
    let identity = {
        let mut buf = [0u8; 16];
        rng.fill_bytes(&mut buf);
        credential::Identity(buf.to_vec())
    };
    // Make a random keypair
    let secret_key = SigSecretKey::new_from_random(signature_scheme, rng).unwrap();
    let public_key = SigPublicKey::new_from_secret_key(signature_scheme, &secret_key);

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
    // We cannot say the word "leaf index" because that means something else
    let indices_of_leaves = (0..num_leaves).map(|i| i.checked_mul(2).unwrap());
    for idx in indices_of_leaves {
        // Random path secret used to derive all private keys up the tree
        let path_secret = {
            let mut buf = [0u8; 32];
            rng.fill_bytes(&mut buf);
            PathSecret::new_from_bytes(&buf)
        };
        tree.propagate_new_path_secret(cs, path_secret, idx)
            .expect("couldn't propagate random secrets in a random tree");
    }

    tree
}

// Generates a random GroupState object (of at least min_size many members) and all the identity
// keys associated with the credentials in the roster. The group state generated has all roster
// entries non-null and all tree nodes Filled with known secrets.
pub(crate) fn random_full_group_state<R: rand::Rng + CryptoRng>(
    min_size: u32,
    rng: &mut R,
) -> (GroupState, Vec<SigSecretKey>) {
    // TODO: Expand the number of available ciphersuites once more are available
    let cipher_suites = &[X25519_SHA256_AES128GCM];
    let sig_schemes = &[ED25519_IMPL];

    let cs = cipher_suites.choose(rng).unwrap();
    let ss = sig_schemes.choose(rng).unwrap();

    // Group size and position in group are random
    let group_size: u32 = rng.gen_range(min_size, 50);
    let my_roster_idx: u32 = rng.gen_range(0, group_size);

    // Make a full roster (no empty slots) of random creds and store the identity keys
    let mut roster = Roster(Vec::new());
    let mut identity_keys = Vec::new();
    for _ in 0..group_size {
        let (cred, secret) = random_credential(rng, ss);
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

    // Make a random init_secret and a zero transcript_hash
    let init_secret = HmacKey::new_from_random(cs.hash_impl, rng);
    let transcript_hash = Digest::new_from_zeros(cs.hash_impl);

    let group_state = GroupState {
        cs: cs,
        protocol_version: MLS_DUMMY_VERSION,
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
    let identity_key = SigSecretKey::new_from_random(signature_scheme, rng).unwrap();
    let public_key = SigPublicKey::new_from_secret_key(signature_scheme, &identity_key);

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
