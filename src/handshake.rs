//! Defines group operations and the `Handshake` object. Not much public API here.

use crate::{
    client_init_key::ClientInitKey,
    crypto::{
        dh::DhPublicKey,
        hash::{Digest, HashFunction},
        hmac::{self, Mac},
        hpke::HpkeCiphertext,
    },
    group_ctx::{ConfirmationKey, WelcomeInfoHash},
    ratchet_tree::MemberIdx,
};

/// Contains a node's new public key and the new node's secret, encrypted for everyone in that
/// node's resolution
#[derive(Clone, Deserialize, Serialize)]
#[cfg_attr(test, derive(Debug))]
pub(crate) struct DirectPathNodeMessage {
    pub(crate) public_key: DhPublicKey,
    // HPKECiphertext encrypted_path_secrets<0..2^16-1>;
    #[serde(rename = "encrypted_path_secrets__bound_u16")]
    pub(crate) encrypted_path_secrets: Vec<HpkeCiphertext>,
}

// This is called a DirectPath in the spec
/// Contains a direct path of node messages. The length of `encrypted_path_secrets` for the first
/// `DirectPathNodeMessage` MUST be zero.
#[derive(Clone, Deserialize, Serialize)]
#[cfg_attr(test, derive(Debug))]
pub(crate) struct DirectPathMessage {
    // DirectPathNodeMessage nodes<0..2^16-1>;
    #[serde(rename = "node_messages__bound_u16")]
    pub(crate) node_messages: Vec<DirectPathNodeMessage>,
}

/// This is currently not defined by the spec. See open issue in section 8.1
#[derive(Deserialize, Serialize)]
#[cfg_attr(test, derive(Debug))]
pub(crate) struct GroupInit;

/// Operation to add a partcipant to a group
#[derive(Deserialize, Serialize)]
#[cfg_attr(test, derive(Debug))]
pub(crate) struct GroupAdd {
    // uint32 index;
    /// Indicates where to add the new member. This may index into a Blank leaf or be equal to the
    /// number of leaves.
    pub(crate) member_index: MemberIdx,

    // ClientInitKey init_key;
    /// Contains the public key used to add the new member
    pub(crate) init_key: ClientInitKey,

    // opaque welcome_info_hash<0..255>;
    /// Contains the hash of the `WelcomeInfo` object that preceded this `Add`
    pub(crate) welcome_info_hash: WelcomeInfoHash,
}

/// Operation to add entropy to the group
#[derive(Deserialize, Serialize)]
#[cfg_attr(test, derive(Debug))]
pub(crate) struct GroupUpdate {
    pub(crate) path: DirectPathMessage,
}

/// Operation to remove a partcipant from the group
#[derive(Deserialize, Serialize)]
#[cfg_attr(test, derive(Debug))]
pub(crate) struct GroupRemove {
    /// The member index of the removed member
    pub(crate) removed_member_index: MemberIdx,

    /// New entropy for the tree
    pub(crate) path: DirectPathMessage,
}

/// Enum of possible group operations
#[derive(Deserialize, Serialize)]
#[cfg_attr(test, derive(Debug))]
#[serde(rename = "GroupOperation__enum_u8")]
pub(crate) enum GroupOperation {
    Init(GroupInit),
    Add(GroupAdd),
    Update(GroupUpdate),
    Remove(GroupRemove),
}

// TODO: Make confirmation a Mac enum for more type safety

/// A `Handshake` message, as defined in section 8 of the MLS spec
#[derive(Deserialize, Serialize)]
#[cfg_attr(test, derive(Debug))]
pub struct Handshake {
    /// The operation this `Handshake` is perofrming
    pub(crate) operation: GroupOperation,

    // opaque confirmation<1..255>;
    /// HMAC over the group state and `Handshake` signature
    /// `confirmation_data = GroupContext.transcript_hash || Handshake.signature`
    /// `Handshake.confirmation = HMAC(confirmation_key, confirmation_data)`
    pub(crate) confirmation: Mac,
}

impl Handshake {
    /// Creates a new `Handshake` object from a group operation, the transcript hash of the group
    /// context after the operation has been applied, and the confirmation key of the new group
    /// context
    pub(crate) fn new(
        hash_impl: &HashFunction,
        operation: GroupOperation,
        post_op_transcript_hash: &Digest,
        confirmation_key: ConfirmationKey,
    ) -> Handshake {
        // MLSPlaintext.confirmation = HMAC(confirmation_key, GroupContext.transcript_hash)
        let confirmation =
            hmac::sign(hash_impl, &confirmation_key.into(), post_op_transcript_hash.as_bytes());

        Handshake {
            operation,
            confirmation,
        }
    }
}

#[cfg(test)]
mod test {
    use super::Handshake;

    use crate::{
        client_init_key::{ClientInitKey, MLS_DUMMY_VERSION},
        crypto::{
            ciphersuite::{CipherSuite, P256_SHA256_AES128GCM, X25519_SHA256_AES128GCM},
            sig::SignatureScheme,
        },
        error::Error,
        group_ctx::{GroupContext, Welcome, WelcomeInfo},
        ratchet_tree::{MemberIdx, PathSecret},
        test_utils,
        tls_de::TlsDeserializer,
        tls_ser,
        upcast::{CryptoCtx, CryptoUpcast},
    };

    use core::convert::TryFrom;
    use std::io::Read;

    use quickcheck_macros::quickcheck;
    use rand::{RngCore, SeedableRng};
    use serde::Deserialize;

    // Make sure GroupCtx::process_handshake rejects Hanshakes with the wrong sender index.
    // Disclaimer: We only test this failure on Update ops.
    #[quickcheck]
    fn wrong_sender_idx(rng_seed: u64) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(rng_seed);

        // Make a starting group of at least 2 people
        let (group_ctx1, identity_keys) = test_utils::random_full_group_ctx(2, &mut rng);
        let member_idx1 = group_ctx1.member_index.unwrap();

        // Make a copy of this group, but from another perspective. That is, we want the same group
        // but with a different member index
        let new_index = test_utils::random_member_index_with_exceptions(
            group_ctx1.tree.num_leaves(),
            &[member_idx1],
            &mut rng,
        );
        let group_ctx2 = test_utils::change_self_index(&group_ctx1, &identity_keys, new_index);

        // Make a new path secret and make an Update object out of it
        let new_path_secret = PathSecret::new_from_random(group_ctx1.cs, &mut rng);
        let (handshake, group_ctx1, _) =
            group_ctx1.create_and_apply_update_handshake(new_path_secret, &mut rng).unwrap();

        // We're going to apply the Handshake to the clone of the first group, but with the wrong
        // sender index. The sender is actually member_idx1.
        let wrong_idx = test_utils::random_member_index_with_exceptions(
            group_ctx1.tree.num_leaves(),
            &[member_idx1],
            &mut rng,
        );

        // Make sure that this handshake fails
        assert!(group_ctx2.process_handshake(&handshake, wrong_idx).is_err());
    }

    // Check that Update operations are consistent
    #[quickcheck]
    fn update_correctness(rng_seed: u64) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(rng_seed);
        // Make a starting group of at least 2 people
        let (group_ctx1, identity_keys) = test_utils::random_full_group_ctx(2, &mut rng);
        let member_idx1 = group_ctx1.member_index.unwrap();

        // Make a copy of this group, but from another perspective. That is, we want the same group
        // but with a different member index
        let new_index = test_utils::random_member_index_with_exceptions(
            group_ctx1.tree.num_leaves(),
            &[member_idx1],
            &mut rng,
        );
        let group_ctx2 = test_utils::change_self_index(&group_ctx1, &identity_keys, new_index);

        // Make a new path secret and make an Update object out of it
        let new_path_secret = PathSecret::new_from_random(group_ctx1.cs, &mut rng);
        let (handshake, group_ctx1, _) =
            group_ctx1.create_and_apply_update_handshake(new_path_secret, &mut rng).unwrap();

        // Apply the Handshake to the clone of the first group
        let (group_ctx2, _) = group_ctx2.process_handshake(&handshake, member_idx1).unwrap();

        // Now see if the group states agree
        assert_serialized_eq!(group_ctx1, group_ctx2, "GroupContexts disagree after Update");
    }

    // Check that Remove operations are consistent
    #[quickcheck]
    fn remove_correctness(rng_seed: u64) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(rng_seed);
        // Make a starting group of at least 3 members
        let (starting_group, identity_keys) = test_utils::random_full_group_ctx(3, &mut rng);

        // Let's remove someone from the group who isn't us. Pick the member index of the removed
        // member here
        let starting_member_idx = starting_group.member_index.unwrap();
        let remove_member_idx = test_utils::random_member_index_with_exceptions(
            starting_group.tree.num_leaves(),
            &[starting_member_idx],
            &mut rng,
        );
        // Let's also make a new group that isn't the removed party and isn't the starting party.
        // Pick their member index here.
        let other_member_idx = test_utils::random_member_index_with_exceptions(
            starting_group.tree.num_leaves(),
            &[starting_member_idx, remove_member_idx],
            &mut rng,
        );

        // Make a group from the perspective of the removed person and a group from the perspective
        // of that other person
        let removed_group =
            test_utils::change_self_index(&starting_group, &identity_keys, remove_member_idx);
        let other_group =
            test_utils::change_self_index(&starting_group, &identity_keys, other_member_idx);

        // Make a new path secret and make an Update object out of it and then make a Handshake
        // object out of that Update
        let new_path_secret = PathSecret::new_from_random(&starting_group.cs, &mut rng);

        // Make a Remove handshake and let starting_group reflect the change
        let (remove_handshake, starting_group, _) = starting_group
            .create_and_apply_remove_handshake(remove_member_idx, new_path_secret, &mut rng)
            .expect("failed to create/apply remove op");

        // Apply the Handshake to the removed group. Since this is the party that got removed, this
        // should give an Error::IAmRemoved
        let res = removed_group.process_handshake(&remove_handshake, starting_member_idx);
        match res {
            Ok(_) => panic!("Removed party didn't give an error"),
            Err(Error::IAmRemoved) => (),
            Err(e) => panic!("Removed party didn't give an Error::IAmRemoved, instead got {}", e),
        }

        // Apply the Handshake to the other non-removed group. This should not error
        let (other_group, _) =
            other_group.process_handshake(&remove_handshake, starting_member_idx).unwrap();

        // See if the non-removed group states agree after the remove
        assert_serialized_eq!(starting_group, other_group, "GroupContexts disagree after Remove");

        // Now run an update on the non-removed groups just to make sure everything is working
        let new_path_secret = PathSecret::new_from_random(starting_group.cs, &mut rng);
        let (update_handshake, starting_group, _) = starting_group
            .create_and_apply_update_handshake(new_path_secret, &mut rng)
            .expect("failed to create/apply remove op");
        let (other_group, _) =
            other_group.process_handshake(&update_handshake, starting_member_idx).unwrap();

        // See if the non-removed group states agree after the update
        assert_serialized_eq!(
            starting_group,
            other_group,
            "GroupContexts disagree after post-Remove Update"
        );
    }

    // Check that multiple consecutive Remove operations are processed correctly
    #[quickcheck]
    fn multi_remove_correctness(rng_seed: u64) {
        // Our goal with this test is to force a large truncation to happen

        let mut rng = rand::rngs::StdRng::seed_from_u64(rng_seed);

        // Make a starting group of at least 3 members
        let (mut group_ctx1, identity_keys) = test_utils::random_full_group_ctx(3, &mut rng);
        let member_idx1 = group_ctx1.member_index.unwrap();

        // Designate another person in the group to be someone we care about. We won't remove them.
        let non_removed_member_idx = test_utils::random_member_index_with_exceptions(
            group_ctx1.tree.num_leaves(),
            &[member_idx1],
            &mut rng,
        );
        let mut group_ctx2 =
            test_utils::change_self_index(&group_ctx1, &identity_keys, non_removed_member_idx);

        // The maximum (i.e., rightmost) of the two member indices we have. We will remove everyone
        // to the right of this person
        let max_member_idx =
            core::cmp::max(group_ctx1.member_index.unwrap(), group_ctx2.member_index.unwrap());

        // Starting after max(person1, person2), remove members from the group 1 by 1
        for remove_idx in (usize::from(max_member_idx) + 1)..group_ctx1.tree.num_leaves() {
            // Remove the member at the current index
            let remove_idx = MemberIdx::new(u32::try_from(remove_idx).unwrap());
            let new_path_secret = PathSecret::new_from_random(group_ctx1.cs, &mut rng);

            // Create the handshake and apply it to both groups
            let (remove_handshake, new_group_ctx1, _) = group_ctx1
                .create_and_apply_remove_handshake(remove_idx, new_path_secret, &mut rng)
                .unwrap();
            let (new_group_ctx2, _) =
                group_ctx2.process_handshake(&remove_handshake, member_idx1).unwrap();

            // Update the groups (remember, the above methods are non-mutating)
            group_ctx1 = new_group_ctx1;
            group_ctx2 = new_group_ctx2;
        }

        // See if the group states agree after the removals
        assert_serialized_eq!(
            group_ctx1,
            group_ctx2,
            "GroupContexts disagree after multiple Removes"
        );

        // The last removal should've truncated the tree leaves down to max(person1, person2).
        // Check that this is true
        assert_eq!(group_ctx1.tree.num_leaves(), usize::from(max_member_idx) + 1);

        // Now run an update on the non-removed groups just to make sure everything is working
        let new_path_secret = PathSecret::new_from_random(group_ctx1.cs, &mut rng);
        let (update_handshake, group_ctx1, _) = group_ctx1
            .create_and_apply_update_handshake(new_path_secret, &mut rng)
            .expect("failed to create/apply remove op");
        let (group_ctx2, _) = group_ctx2.process_handshake(&update_handshake, member_idx1).unwrap();

        // See if our group states agree after the update
        assert_serialized_eq!(
            group_ctx1,
            group_ctx2,
            "GroupContexts disagree after post-Remove Update"
        );
    }

    // Check that removing yourself doesn't work
    #[quickcheck]
    fn self_remove_failure(rng_seed: u64) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(rng_seed);

        // Make a starting group of at least 2 members
        let (group_ctx1, identity_keys) = test_utils::random_full_group_ctx(2, &mut rng);
        let my_member_idx = group_ctx1.member_index.unwrap();

        // Pick a member that we're gonna remove
        let member_to_remove = test_utils::random_member_index_with_exceptions(
            group_ctx1.tree.num_leaves(),
            &[my_member_idx],
            &mut rng,
        );
        let group_ctx2 =
            test_utils::change_self_index(&group_ctx1, &identity_keys, member_to_remove);

        // Prep for a removal
        let new_path_secret = PathSecret::new_from_random(group_ctx1.cs, &mut rng);

        // First try to remove myself. This should error with a ValidationError
        let res = group_ctx1.create_and_apply_remove_handshake(
            my_member_idx,
            new_path_secret.clone(),
            &mut rng,
        );

        // An attempt at self-removal should result in a ValidationError
        match res {
            Err(Error::ValidationError(_)) => (),
            Ok(_) => panic!("self removal didn't give an error at all!"),
            Err(e) => panic!("self removal gave an unexpected error {}", e),
        }

        // Now try to remove the other member. This part should succeed
        let (handshake, _, _) = group_ctx1
            .create_and_apply_remove_handshake(member_to_remove, new_path_secret, &mut rng)
            .unwrap();
        // The removed member should try to process this Handshake and get an Error::IAmRemoved
        match group_ctx2.process_handshake(&handshake, my_member_idx) {
            Err(Error::IAmRemoved) => (),
            Ok(_) => panic!("receipt of a Remove of myself didn't given an error at all!"),
            Err(e) => panic!("receipt of a Remove of myself gave an unexpected Error: {}", e),
        }
    }

    // Checks that
    //
    //   Welcome(B), Add(B)
    // A -----------------> B
    //
    //    Add(B)
    // A -------
    //         |
    // A <------
    //
    // produces identital groups A, B
    #[quickcheck]
    fn add_correctness(rng_seed: u64) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(rng_seed);
        // Make a starting group of at least 1 person
        let (mut group_ctx1, _) = test_utils::random_full_group_ctx(1, &mut rng);

        // Pick data for a new member of this group. The new member's index cannot be the same as
        // that of the current member's. The index can also be equal to the number of leaves, which
        // signifies an appending Add.
        let new_member_idx = test_utils::random_member_index_with_exceptions(
            group_ctx1.tree.num_leaves() + 1,
            &[group_ctx1.member_index.unwrap()],
            &mut rng,
        );
        let (new_credential, new_identity_key) = test_utils::random_basic_credential(&mut rng);

        // Quick modification: if we're gonna do an in-place Add, the node we overwrite to better
        // be blank. So let's just blank that direct path out right now
        let is_in_place = new_member_idx < group_ctx1.tree.num_leaves();
        if is_in_place {
            group_ctx1.tree.propagate_blank(new_member_idx).unwrap();
        }

        // Make the data necessary for a Welcome message
        let cipher_suites = vec![&X25519_SHA256_AES128GCM];
        let supported_versions = vec![MLS_DUMMY_VERSION; cipher_suites.len()];
        // Key ID is random
        let client_init_key_id = {
            let mut buf = [0u8; 16];
            rng.fill_bytes(&mut buf);
            buf.to_vec()
        };
        // The ClientInitKey has all the information necessary to add a new member to the group and
        // Welcome them
        let init_key = ClientInitKey::new_from_random(
            &new_identity_key,
            client_init_key_id,
            new_credential.clone(),
            cipher_suites,
            supported_versions,
            &mut rng,
        )
        .unwrap();

        // Make the welcome object
        let (welcome, welcome_info_hash) =
            Welcome::from_group_ctx(&group_ctx1, &init_key, &mut rng).unwrap();

        // Make the add op and use the new group state
        let (add_handshake, group_ctx1, _) = group_ctx1
            .create_and_apply_add_handshake(new_member_idx, init_key.clone(), &welcome_info_hash)
            .unwrap();
        let member_idx1 = group_ctx1.member_index.unwrap();

        // Now unwrap the Welcome back a GroupContext. This should be identical to the starting group
        // state, except maybe for the member_idx, credential, initiailizing ClientInitKey, and
        // identity key. None of those things are serialized though, since they are unique to each
        // member's perspective.
        let group_ctx2 = GroupContext::from_welcome(welcome, new_identity_key, init_key).unwrap();

        // Apply the Add operation on group 2
        let (new_group_ctx2, _) =
            group_ctx2.process_handshake(&add_handshake, member_idx1).unwrap();
        let group_ctx2 = new_group_ctx2;

        // Now see if the resulting group states agree
        assert_serialized_eq!(group_ctx1, group_ctx2, "GroupContexts disagree after Add");
    }

    // File: messages.bin
    //
    // struct {
    //   CipherSuite cipher_suite;
    //   SignatureScheme sig_scheme;
    //
    //   opaque client_init_key<0..2^32-1>;
    //   opaque welcome_info<0..2^32-1>;
    //   opaque welcome<0..2^32-1>;
    //   opaque add<0..2^32-1>;
    //   opaque update<0..2^32-1>;
    //   opaque remove<0..2^32-1>;
    // } MessagesCase;
    //
    // struct {
    //   uint32_t epoch;
    //   uint32_t signer_index;
    //   uint32_t removed;
    //   opaque user_id<0..255>;
    //   opaque group_id<0..255>;
    //   opaque cik_id<0..255>;
    //   opaque dh_seed<0..255>;
    //   opaque sig_seed<0..255>;
    //   opaque random<0..255>;
    //
    //   SignatureScheme cik_all_scheme;
    //   ClientInitKey client_init_key_all;
    //
    //   MessagesCase case_p256_p256;
    //   MessagesCase case_x25519_ed25519;
    // } MessagesTestVectors;
    //
    // The elements of the struct have the following meanings:
    //
    // * The first several fields contain the values used to construct the example messages.
    // * client_init_key_all contains a ClientInitKey that offers all four ciphersuites.  It is
    //   validly signed with an Ed25519 key.
    // * The remaining cases each test message processing for a given ciphersuite:
    //   * case_p256_p256 uses P256 for DH and ECDSA-P256 for signing
    //   * case_x25519_ed25519 uses X25519 for DH and Ed25519 for signing
    // * In each case:
    //   * client_init_key contains a ClientInitKey offering only the indicated ciphersuite, validly
    //     signed with the corresponding signature scheme
    //   * welcome_info contains a WelcomeInfo message with syntactically valid but bogus contents
    //   * welcome contains a Welcome message generated by encrypting welcome_info for a
    //     Diffie-Hellman public key derived from the dh_seed value.
    //   * add, update, and remove each contain a Handshake message with a GroupOperation of the
    //     corresponding type.  The signatures on these messages are not valid
    //
    // Your implementation should be able to pass the following tests:
    //
    // * client_init_key_all should parse successfully
    // * The test cases for any supported ciphersuites should parse successfully
    // * All of the above parsed values should survive a marshal / unmarshal round-trip

    #[derive(Debug, Deserialize, Serialize)]
    struct MessagesCase {
        cipher_suite: &'static CipherSuite,
        signature_scheme: &'static SignatureScheme,
        _client_init_key_len: u32,
        client_init_key: ClientInitKey,
        _welcome_info_len: u32,
        welcome_info: WelcomeInfo,
        _welcome_len: u32,
        welcome: Welcome,
        _add_len: u32,
        add: Handshake,
        _update_len: u32,
        update: Handshake,
        _remove_len: u32,
        remove: Handshake,
    }

    impl CryptoUpcast for MessagesCase {
        fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<CryptoCtx, Error> {
            let new_ctx =
                ctx.set_cipher_suite(self.cipher_suite).set_signature_scheme(self.signature_scheme);
            self.client_init_key.upcast_crypto_values(&new_ctx)?;
            self.welcome_info.upcast_crypto_values(&new_ctx)?;
            self.welcome.upcast_crypto_values(&new_ctx)?;
            self.add.upcast_crypto_values(&new_ctx)?;
            self.update.upcast_crypto_values(&new_ctx)?;
            self.remove.upcast_crypto_values(&new_ctx)?;

            Ok(*ctx)
        }
    }

    #[derive(Debug, Deserialize, Serialize)]
    struct MessagesTestVectors {
        epoch: u32,
        signer_index: u32,
        removed: u32,
        #[serde(rename = "user_id__bound_u8")]
        user_id: Vec<u8>,
        #[serde(rename = "group_id__bound_u8")]
        group_id: Vec<u8>,
        #[serde(rename = "cik_id__bound_u8")]
        cik_id: Vec<u8>,
        #[serde(rename = "dh_seed__bound_u8")]
        dh_seed: Vec<u8>,
        #[serde(rename = "sig_seed__bound_u8")]
        sig_seed: Vec<u8>,
        #[serde(rename = "random__bound_u8")]
        random: Vec<u8>,
        cik_all_scheme: &'static SignatureScheme,
        _client_init_key_all_len: u32,
        client_init_key_all: ClientInitKey,

        case_p256_p256: MessagesCase,
        case_x25519_ed25519: MessagesCase,
    }

    impl CryptoUpcast for MessagesTestVectors {
        fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<CryptoCtx, Error> {
            let new_ctx = ctx.set_signature_scheme(self.cik_all_scheme);
            self.client_init_key_all.upcast_crypto_values(&new_ctx)?;

            let new_ctx = ctx.set_cipher_suite(&P256_SHA256_AES128GCM);
            self.case_p256_p256.upcast_crypto_values(&new_ctx)?;

            let new_ctx = ctx.set_cipher_suite(&X25519_SHA256_AES128GCM);
            self.case_x25519_ed25519.upcast_crypto_values(&new_ctx)?;

            Ok(*ctx)
        }
    }

    // Tests our code against the official key schedule test vector. All this has to do is make
    // sure that the given test vector parses without error, and that the bytes are the same after
    // being reserialized
    #[test]
    fn official_message_parsing_kat() {
        // Read in the file. We'll use these bytes at the end to compare to the reserialization of
        // the test vectors
        let mut original_bytes = Vec::new();
        let mut f = std::fs::File::open("test_vectors/messages.bin").unwrap();
        f.read_to_end(&mut original_bytes).unwrap();

        // Deserialize the file's contents
        let test_vec = {
            let mut cursor = original_bytes.as_slice();
            let mut deserializer = TlsDeserializer::from_reader(&mut cursor);
            let raw = MessagesTestVectors::deserialize(&mut deserializer).unwrap();
            // We can't do the upcasting here. The documentation lied when it said that
            // ClientInitKeys are validly signed. They are [0xd6; 32], which is not a valid Ed25519
            // signature. So skip this step and call it a mission success.
            //raw.upcast_crypto_values(&CryptoCtx::new()).unwrap();
            raw
        };

        // Reserialized the deserialized input and make sure it's the same as the original
        let reserialized_bytes = tls_ser::serialize_to_bytes(&test_vec).unwrap();
        assert_eq!(reserialized_bytes, original_bytes);
    }
}
