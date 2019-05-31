//! Defines group handshake-related data structures and operations. Not much public API here.

use crate::{
    credential::Credential,
    crypto::{
        ciphersuite::CipherSuite,
        dh::{DhPrivateKey, DhPublicKey},
        ecies::EciesCiphertext,
        hmac::Mac,
        rng::CryptoRng,
        sig::{SigSecretKey, Signature},
    },
    error::Error,
    group_state::WelcomeInfoHash,
    tls_ser,
};

/// Represents a version of the MLS protocol
// uint8 ProtocolVersion;
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProtocolVersion(u8);

/// A dummy protocol version
// TODO: Remove this before going into production. Final last words, amirite
pub const MLS_DUMMY_VERSION: ProtocolVersion = ProtocolVersion(0xba);

/// Contains a node's new public key and the new node's secret, encrypted for everyone in that
/// node's resolution
#[derive(Deserialize, Serialize)]
#[cfg_attr(test, derive(Debug))]
pub(crate) struct DirectPathNodeMessage {
    pub(crate) public_key: DhPublicKey,
    // ECIESCiphertext node_secrets<0..2^16-1>;
    #[serde(rename = "node_secrets__bound_u16")]
    pub(crate) node_secrets: Vec<EciesCiphertext>,
}

/// Contains a direct path of node messages. The length of `node_secrets` for the first
/// `DirectPathNodeMessage` MUST be zero.
#[derive(Deserialize, Serialize)]
#[cfg_attr(test, derive(Debug))]
pub(crate) struct DirectPathMessage {
    // DirectPathNodeMessage nodes<0..2^16-1>;
    #[serde(rename = "node_messages__bound_u16")]
    pub(crate) node_messages: Vec<DirectPathNodeMessage>,
}

/// This is used in lieu of negotiating public keys when a member is added. This has a bunch of
/// published ephemeral keys that can be used to initiated communication with a previously
/// uncontacted member.
#[derive(Clone, Deserialize, Serialize)]
#[cfg_attr(test, derive(Debug))]
pub struct UserInitKey {
    // opaque user_init_key_id<0..255>
    /// An identifier for this init key. This MUST be unique among the `UserInitKey` generated by
    /// the client
    #[serde(rename = "user_init_key_id__bound_u8")]
    pub(crate) user_init_key_id: Vec<u8>,

    // ProtocolVersion supported_versions<0..255>;
    /// The protocol versions supported by the member. Each entry is the supported protocol version
    /// of the entry in `init_keys` of the same index. This MUST have the same length as
    /// `init_keys`.
    #[serde(rename = "supported_versions__bound_u8")]
    supported_versions: Vec<ProtocolVersion>,

    // CipherSuite cipher_suites<0..255>
    /// The cipher suites supported by the member. Each cipher suite here corresponds uniquely to a
    /// DH public key in `init_keys`. As such, this MUST have the same length as `init_keys`.
    #[serde(rename = "cipher_suites__bound_u8")]
    pub(crate) cipher_suites: Vec<&'static CipherSuite>,

    // HPKEPublicKey init_keys<1..2^16-1>
    /// The DH public keys owned by the member. Each public key corresponds uniquely to a cipher
    /// suite in `cipher_suites`. As such, this MUST have the same length as `cipher_suites`.
    #[serde(rename = "init_keys__bound_u16")]
    pub(crate) init_keys: Vec<DhPublicKey>,

    /// The DH private keys owned by the member. This is only `Some` if this member is the creator
    /// of this `UserInitKey`. Each private key corresponds uniquely to a public key in
    /// `init_keys`. As such, this MUST have the same length as `init_keys`.
    #[serde(skip)]
    pub(crate) private_keys: Option<Vec<DhPrivateKey>>,

    /// The identity information of the member
    pub(crate) credential: Credential,

    /// Contains the signature of all the other fields of this struct, under the identity key of
    /// the client.
    pub(crate) signature: Signature,
}

// This struct is everything but the last field in UserInitKey. We use the serialized form
// of this as the message that the signature is computed over
#[derive(Serialize)]
struct PartialUserInitKey<'a> {
    #[serde(rename = "user_init_key_id__bound_u8")]
    user_init_key_id: &'a [u8],
    #[serde(rename = "supported_versions__bound_u8")]
    supported_versions: &'a [ProtocolVersion],
    #[serde(rename = "cipher_suites__bound_u8")]
    cipher_suites: &'a [&'static CipherSuite],
    #[serde(rename = "init_keys__bound_u16")]
    init_keys: &'a [DhPublicKey],
    credential: &'a Credential,
}

impl UserInitKey {
    /// Generates a new `UserInitKey` with the key ID, credential, ciphersuites, and supported
    /// versions. The identity key is needed to sign the resulting structure.
    pub fn new_from_random<R>(
        identity_key: &SigSecretKey,
        user_init_key_id: Vec<u8>,
        credential: Credential,
        mut cipher_suites: Vec<&'static CipherSuite>,
        supported_versions: Vec<ProtocolVersion>,
        csprng: &mut R,
    ) -> Result<UserInitKey, Error>
    where
        R: CryptoRng,
    {
        // Check the ciphersuite list for duplicates. We don't like this
        let old_cipher_suite_len = cipher_suites.len();
        cipher_suites.dedup();
        if cipher_suites.len() != old_cipher_suite_len {
            return Err(Error::ValidationError(
                "Cannot make a UserInitKey with duplicate ciphersuites",
            ));
        }
        // Check that the ciphersuite and supported version vectors are the same length
        if cipher_suites.len() != supported_versions.len() {
            return Err(Error::ValidationError(
                "Supported ciphersuites and supported version vectors differ in length",
            ));
        }

        let mut init_keys = Vec::new();
        let mut private_keys = Vec::new();

        // Collect a keypair for every ciphersuite in the given vector
        for cs in cipher_suites.iter() {
            let scalar = DhPrivateKey::new_from_random(cs.dh_impl, csprng)?;
            let public_key = DhPublicKey::new_from_private_key(cs.dh_impl, &scalar);

            init_keys.push(public_key);
            private_keys.push(scalar);
        }
        // The UserInitKey has this as an Option
        let private_keys = Some(private_keys);

        // Now to compute the signature: Make the partial structure, serialize it, sign that
        let partial = PartialUserInitKey {
            user_init_key_id: user_init_key_id.as_slice(),
            supported_versions: supported_versions.as_slice(),
            cipher_suites: cipher_suites.as_slice(),
            init_keys: init_keys.as_slice(),
            credential: &credential,
        };

        let serialized_uik = tls_ser::serialize_to_bytes(&partial)?;
        let sig_scheme = credential.get_signature_scheme();
        let signature = sig_scheme.sign(identity_key, &serialized_uik);

        Ok(UserInitKey {
            user_init_key_id,
            supported_versions,
            cipher_suites,
            init_keys,
            private_keys,
            credential,
            signature,
        })
    }

    /// Verifies this `UserInitKey` under the identity key specified in the `credential` field
    ///
    /// Returns: `Ok(())` on success, `Error::SignatureError` on verification failure, and
    /// `Error::SerdeError` on some serialization failure.
    #[must_use]
    pub(crate) fn verify_sig(&self) -> Result<(), Error> {
        let partial = PartialUserInitKey {
            user_init_key_id: self.user_init_key_id.as_slice(),
            supported_versions: self.supported_versions.as_slice(),
            cipher_suites: self.cipher_suites.as_slice(),
            init_keys: self.init_keys.as_slice(),
            credential: &self.credential,
        };
        let serialized_uik = tls_ser::serialize_to_bytes(&partial)?;

        let sig_scheme = self.credential.get_signature_scheme();
        let public_key = self.credential.get_public_key();

        sig_scheme.verify(public_key, &serialized_uik, &self.signature)
    }

    // TODO: URGENT: Figure out how to implement the mandatory check specified in section 6:
    // "UserInitKeys also contain an identifier chosen by the client, which the client MUST assure
    // uniquely identifies a given UserInitKey object among the set of UserInitKeys created by this
    // client."

    /// Validates the invariants that `UserInitKey` must satisfy, as in section 7 of the MLS spec
    #[must_use]
    pub(crate) fn validate(&self) -> Result<(), Error> {
        // All three of supported_versions, cipher_suites, and init_keys MUST have the same length.
        // And if private_keys is non-null, it must have the same length as the other three.
        if self.supported_versions.len() != self.cipher_suites.len() {
            return Err(Error::ValidationError(
                "UserInitKey::supported_verions.len() != UserInitKey::cipher_suites.len()",
            ));
        }
        if self.init_keys.len() != self.cipher_suites.len() {
            return Err(Error::ValidationError(
                "UserInitKey::init_keys.len() != UserInitKey::cipher_suites.len()",
            ));
        }
        if let Some(ref ks) = self.private_keys {
            if ks.len() != self.cipher_suites.len() {
                return Err(Error::ValidationError(
                    "UserInitKey::private_keys.len() != UserInitKey::cipher_suites.len()",
                ));
            }
        }

        // The elements of cipher_suites MUST be unique. Sort them, dedup them, and see if the
        // number has decreased.
        let mut cipher_suites = self.cipher_suites.clone();
        let original_len = cipher_suites.len();
        cipher_suites.sort_by_key(|c| c.name);
        cipher_suites.dedup_by_key(|c| c.name);
        if cipher_suites.len() != original_len {
            return Err(Error::ValidationError(
                "UserInitKey has init keys with duplicate ciphersuites",
            ));
        }

        Ok(())
    }

    /// Retrieves the public key in this `UserInitKey` corresponding to the given cipher suite
    ///
    /// Returns: `Ok(Some(pubkey))` on success. Returns `Ok(None)` iff there is no public key
    /// corresponding to the given cipher suite. Returns `Err(Error::ValidationError)` iff
    /// validation (via `UserInitKey::validate()`) failed.
    pub(crate) fn get_public_key<'a>(
        &'a self,
        cs_to_find: &'static CipherSuite,
    ) -> Result<Option<&'a DhPublicKey>, Error> {
        // First validate. If this were not valid, then the output of this function might be
        // dependent on the order of occurrence of cipher suites, and that is undesirable
        self.validate()?;

        let cipher_suites = &self.cipher_suites;
        let init_keys = &self.init_keys;

        // Look for the ciphersuite in lock-step with the public key. If we find the ciphersuite at
        // index i, then the pubkey we want is also at index i These two lists are the same length,
        // because this property is checked in validate() above. Furthermore, all ciphersuites in
        // cipher_suites are unique, because this property is also checked in validate() above.
        for (cs, key) in cipher_suites.iter().zip(init_keys.iter()) {
            if cs == &cs_to_find {
                return Ok(Some(key));
            }
        }

        // No such public key was found
        Ok(None)
    }

    /// Retrieves the private key in this `UserInitKey` corresponding to the given cipher suite.
    /// The private key is only known if this member is the creator of this `UserInitKey`.
    ///
    /// Returns: `Ok(Some(privkey))` on success. Returns `Ok(None)` if the private key is not known
    /// or there is no private key corresponding to the given cipher suite. Returns
    /// `Err(Error::ValidationError)` iff validation (via `UserInitKey::validate()`) failed.
    pub(crate) fn get_private_key<'a>(
        &'a self,
        cs_to_find: &'static CipherSuite,
    ) -> Result<Option<&'a DhPrivateKey>, Error> {
        // First validate. If this were not valid, then the output of this function might be
        // dependent on the order of occurrence of cipher suites, and that is undesirable
        self.validate()?;

        let cipher_suites = &self.cipher_suites;
        // If we are the creator, we have a chance of finding the private key
        if let Some(ref private_keys) = self.private_keys {
            // Look for the ciphersuite in lock-step with the private key. If we find the
            // ciphersuite at index i, then the privkey we want is also at index i These two lists
            // are the same length, because this property is checked in validate() above.
            // Furthermore, all ciphersuites in cipher_suites are unique, because this property is
            // also checked in validate() above.
            for (cs, key) in cipher_suites.iter().zip(private_keys.iter()) {
                if cs == &cs_to_find {
                    return Ok(Some(key));
                }
            }
        }

        // No such private key was found (or we aren't the creator of this UserInitKey)
        Ok(None)
    }

    /// Retrieves the supported protocol version in this `UserInitKey` that corresponds to the
    /// given cipher suite
    ///
    /// Returns: `Ok(Some(supported_version))` on success. Returns `Ok(None)` iff there is no
    /// supported version corresponding to the given ciphersuite Returns
    /// `Err(Error::ValidationError)` iff validation (via `UserInitKey::validate()`) failed.
    pub(crate) fn get_supported_version(
        &self,
        cs_to_find: &'static CipherSuite,
    ) -> Result<Option<ProtocolVersion>, Error> {
        // First validate. If this were not valid, then the output of this function might be
        // dependent on the order of occurrence of cipher suites, and that is undesirable
        self.validate()?;

        let cipher_suites = &self.cipher_suites;
        let supported_versions = &self.supported_versions;

        // Look for the ciphersuite in lock-step with the public key. If we find the ciphersuite at
        // index i, then the pubkey we want is also at index i These two lists are the same length,
        // because this property is checked in validate() above. Furthermore, all ciphersuites in
        // cipher_suites are unique, because this property is also checked in validate() above.
        for (cs, version) in cipher_suites.iter().zip(supported_versions.iter()) {
            if cs == &cs_to_find {
                return Ok(Some(*version));
            }
        }

        // No such version was found
        Ok(None)
    }
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
    /// Indicates where to add the new member. This may index into an empty roster entry or be equal
    /// to the size of the roster.
    pub(crate) roster_index: u32,

    // UserInitKey init_key;
    /// Contains the public key used to add the new member
    pub(crate) init_key: UserInitKey,

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
    /// The roster index of the removed member
    pub(crate) removed_roster_index: u32,

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
    /// This is equal to the epoch of the current `GroupState`
    pub(crate) prior_epoch: u32,
    /// The operation this `Handshake` is perofrming
    pub(crate) operation: GroupOperation,
    /// Position of the signer in the roster
    pub(crate) signer_index: u32,
    /// Signature over the `Group`'s history:
    /// `Handshake.signature = Sign(identity_key, GroupState.transcript_hash)`
    pub(crate) signature: Signature,
    // opaque confirmation<1..255>;
    /// HMAC over the group state and `Handshake` signature
    /// `confirmation_data = GroupState.transcript_hash || Handshake.signature`
    /// `Handshake.confirmation = HMAC(confirmation_key, confirmation_data)`
    pub(crate) confirmation: Mac,
}

#[cfg(test)]
mod test {
    use crate::{
        crypto::{
            ciphersuite::{CipherSuite, P256_SHA256_AES128GCM, X25519_SHA256_AES128GCM},
            sig::SignatureScheme,
        },
        error::Error,
        group_state::{GroupState, Welcome, WelcomeInfo},
        handshake::{Handshake, ProtocolVersion, UserInitKey, MLS_DUMMY_VERSION},
        ratchet_tree::PathSecret,
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

    // Check that Update operations are consistent
    #[quickcheck]
    fn update_correctness(rng_seed: u64) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(rng_seed);
        // Make a starting group of at least 2 people
        let (group_state1, identity_keys) = test_utils::random_full_group_state(2, &mut rng);

        // Make a copy of this group, but from another perspective. That is, we want the same group
        // but with a different roster index
        let new_index = test_utils::random_roster_index_with_exceptions(
            group_state1.roster.len(),
            &[group_state1.roster_index.unwrap() as usize],
            &mut rng,
        );
        let group_state2 = test_utils::change_self_index(&group_state1, &identity_keys, new_index);

        // Make a new path secret and make an Update object out of it and then make a Handshake
        // object out of that Update
        let new_path_secret = PathSecret::new_from_random(group_state1.cs, &mut rng);
        let (handshake, group_state1, _) =
            group_state1.create_and_apply_update_handshake(new_path_secret, &mut rng).unwrap();

        // Apply the Handshake to the clone of the first group
        let (group_state2, _) = group_state2.process_handshake(&handshake).unwrap();

        // Now see if the group states agree
        assert_serialized_eq!(group_state1, group_state2, "GroupStates disagree after Update");
    }

    // Check that Remove operations are consistent
    #[quickcheck]
    fn remove_correctness(rng_seed: u64) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(rng_seed);
        // Make a starting group of at least 3 members
        let (starting_group, identity_keys) = test_utils::random_full_group_state(3, &mut rng);

        // Let's remove someone from the group who isn't us. Pick the roster index of the removed
        // member here
        let remove_roster_idx = test_utils::random_roster_index_with_exceptions(
            starting_group.roster.len(),
            &[starting_group.roster_index.unwrap() as usize],
            &mut rng,
        );
        // Let's also make a new group that isn't the removed party and isn't the starting party.
        // Pick their roster index here.
        let other_roster_idx = test_utils::random_roster_index_with_exceptions(
            starting_group.roster.len(),
            &[starting_group.roster_index.unwrap() as usize, remove_roster_idx as usize],
            &mut rng,
        );

        // Make a group from the perspective of the removed person and a group from the perspective
        // of that other person
        let removed_group =
            test_utils::change_self_index(&starting_group, &identity_keys, remove_roster_idx);
        let other_group =
            test_utils::change_self_index(&starting_group, &identity_keys, other_roster_idx);

        // Make a new path secret and make an Update object out of it and then make a Handshake
        // object out of that Update
        let new_path_secret = PathSecret::new_from_random(&starting_group.cs, &mut rng);

        // Make a Remove handshake and let starting_group reflect the change
        let (remove_handshake, starting_group, _) = starting_group
            .create_and_apply_remove_handshake(remove_roster_idx, new_path_secret, &mut rng)
            .expect("failed to create/apply remove op");

        // Apply the Handshake to the removed group. Since this is the party that got removed, this
        // should give an Error::IAmRemoved
        let res = removed_group.process_handshake(&remove_handshake);
        match res {
            Ok(_) => panic!("Removed party didn't give an error"),
            Err(Error::IAmRemoved) => (),
            Err(e) => panic!("Removed party didn't give an Error::IAmRemoved, instead got {}", e),
        }

        // Apply the Handshake to the other non-removed group. This should not error
        let (other_group, _) = other_group.process_handshake(&remove_handshake).unwrap();

        // See if the non-removed group states agree after the remove
        assert_serialized_eq!(starting_group, other_group, "GroupStates disagree after Remove");

        // Now run an update on the non-removed groups just to make sure everything is working
        let new_path_secret = PathSecret::new_from_random(starting_group.cs, &mut rng);
        let (update_handshake, starting_group, _) = starting_group
            .create_and_apply_update_handshake(new_path_secret, &mut rng)
            .expect("failed to create/apply remove op");
        let (other_group, _) = other_group.process_handshake(&update_handshake).unwrap();

        // See if the non-removed group states agree after the update
        assert_serialized_eq!(
            starting_group,
            other_group,
            "GroupStates disagree after post-Remove Update"
        );
    }

    // Check that multiple consecutive Remove operations are processed correctly
    #[quickcheck]
    fn multi_remove_correctness(rng_seed: u64) {
        // Our goal with this test is to force a large truncation to happen

        let mut rng = rand::rngs::StdRng::seed_from_u64(rng_seed);

        // Make a starting group of at least 3 members
        let (mut group_state1, identity_keys) = test_utils::random_full_group_state(3, &mut rng);

        // Designate another person in the group to be someone we care about. We won't remove them.
        let non_removed_member_idx = test_utils::random_roster_index_with_exceptions(
            group_state1.roster.len(),
            &[group_state1.roster_index.unwrap() as usize],
            &mut rng,
        );
        let mut group_state2 =
            test_utils::change_self_index(&group_state1, &identity_keys, non_removed_member_idx);

        // The maximum (i.e., rightmost) of the two roster indices we have. We will remove everyone
        // to the right of this person
        let max_roster_idx =
            core::cmp::max(group_state1.roster_index.unwrap(), group_state2.roster_index.unwrap());

        // Starting after max(person1, person2), remove members from the group 1 by 1
        for remove_idx in (max_roster_idx as usize + 1)..(group_state1.roster.len()) {
            // Remove the member at the current index
            let remove_idx = u32::try_from(remove_idx).unwrap();
            let new_path_secret = PathSecret::new_from_random(group_state1.cs, &mut rng);

            // Create the handshake and apply it to both groups
            let (remove_handshake, new_group_state1, _) = group_state1
                .create_and_apply_remove_handshake(remove_idx, new_path_secret, &mut rng)
                .unwrap();
            let (new_group_state2, _) = group_state2.process_handshake(&remove_handshake).unwrap();

            // Update the groups (remember, the above methods are non-mutating)
            group_state1 = new_group_state1;
            group_state2 = new_group_state2;
        }

        // See if the group states agree after the removals
        assert_serialized_eq!(
            group_state1,
            group_state2,
            "GroupStates disagree after multiple Removes"
        );

        // The last removal should've truncated the roster down to max(person1, person2). Check
        // that this is true
        assert_eq!(group_state1.roster.len(), max_roster_idx as usize + 1);

        // It also should've truncated the tree down to the max(person1, person2)
        let max_tree_idx = GroupState::roster_index_to_tree_index(max_roster_idx).unwrap();
        assert_eq!(group_state1.tree.size(), max_tree_idx + 1);

        // Now run an update on the non-removed groups just to make sure everything is working
        let new_path_secret = PathSecret::new_from_random(group_state1.cs, &mut rng);
        let (update_handshake, group_state1, _) = group_state1
            .create_and_apply_update_handshake(new_path_secret, &mut rng)
            .expect("failed to create/apply remove op");
        let (group_state2, _) = group_state2.process_handshake(&update_handshake).unwrap();

        // See if our group states agree after the update
        assert_serialized_eq!(
            group_state1,
            group_state2,
            "GroupStates disagree after post-Remove Update"
        );
    }

    // Check that removing yourself doesn't work
    #[quickcheck]
    fn self_remove_failure(rng_seed: u64) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(rng_seed);

        // Make a starting group of at least 1 members
        let (group_state, _) = test_utils::random_full_group_state(1, &mut rng);
        let my_roster_index = group_state.roster_index.unwrap();

        // Now try to remove myself
        let new_path_secret = PathSecret::new_from_random(group_state.cs, &mut rng);
        let res = group_state.create_and_apply_remove_handshake(
            my_roster_index,
            new_path_secret,
            &mut rng,
        );

        // The middle case is what we expect
        match res {
            Ok(_) => panic!("self removal didn't give an error at all!"),
            Err(Error::IAmRemoved) => (),
            Err(e) => panic!("self removal didn't give an Error::IAmRemoved, instead got {}", e),
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
        let (mut group_state1, _) = test_utils::random_full_group_state(1, &mut rng);

        // Pick data for a new member of this group. The new member's roster index cannot be the
        // same as that of the current member's. The index can also be equal to the roster size,
        // which signifies an appending Add.
        let new_roster_index = test_utils::random_roster_index_with_exceptions(
            group_state1.roster.len() + 1,
            &[group_state1.roster_index.unwrap() as usize],
            &mut rng,
        ) as usize;
        let (new_credential, new_identity_key) = test_utils::random_basic_credential(&mut rng);

        // Quick modification: if we're gonna do an in-place Add, the node we overwrite to better
        // be blank. So let's just blank that direct path out right now
        let is_in_place = new_roster_index < group_state1.roster.len();
        if is_in_place {
            let new_tree_index =
                GroupState::roster_index_to_tree_index(u32::try_from(new_roster_index).unwrap())
                    .unwrap();
            group_state1.tree.propagate_blank(new_tree_index);
            group_state1.roster.0[new_roster_index] = None;
        }

        // Make the data necessary for a Welcome message
        let cipher_suites = vec![&X25519_SHA256_AES128GCM];
        let supported_versions: Vec<ProtocolVersion> = vec![MLS_DUMMY_VERSION; cipher_suites.len()];
        // Key ID is random
        let user_init_key_id = {
            let mut buf = [0u8; 16];
            rng.fill_bytes(&mut buf);
            buf.to_vec()
        };
        // The UserInitKey has all the information necessary to add a new member to the group and
        // Welcome them
        let init_key = UserInitKey::new_from_random(
            &new_identity_key,
            user_init_key_id,
            new_credential.clone(),
            cipher_suites,
            supported_versions,
            &mut rng,
        )
        .unwrap();

        // Make the welcome object
        let (welcome, welcome_info_hash) =
            Welcome::from_group_state(&group_state1, &init_key, &mut rng).unwrap();

        // Make the add op and use the new group state
        let (add_handshake, group_state1, _) = group_state1
            .create_and_apply_add_handshake(
                u32::try_from(new_roster_index).unwrap(),
                init_key.clone(),
                &welcome_info_hash,
            )
            .unwrap();

        // Now unwrap the Welcome back a GroupState. This should be identical to the starting group
        // state, except maybe for the roster_index, credential, initiailizing UserInitKey, and
        // identity key. None of those things are serialized though, since they are unique to each
        // member's perspective.
        let group_state2 = GroupState::from_welcome(welcome, new_identity_key, init_key).unwrap();

        // Apply the Add operation on group 2
        let (new_group_state2, _) = group_state2.process_handshake(&add_handshake).unwrap();
        let group_state2 = new_group_state2;

        // Now see if the resulting group states agree
        assert_serialized_eq!(group_state1, group_state2, "GroupStates disagree after Add");
    }

    // File: messages.bin
    //
    // struct {
    //   CipherSuite cipher_suite;
    //   SignatureScheme sig_scheme;
    //
    //   opaque user_init_key<0..2^32-1>;
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
    //   opaque uik_id<0..255>;
    //   opaque dh_seed<0..255>;
    //   opaque sig_seed<0..255>;
    //   opaque random<0..255>;
    //
    //   SignatureScheme uik_all_scheme;
    //   UserInitKey user_init_key_all;
    //
    //   MessagesCase case_p256_p256;
    //   MessagesCase case_x25519_ed25519;
    // } MessagesTestVectors;
    //
    // The elements of the struct have the following meanings:
    //
    // * The first several fields contain the values used to construct the example messages.
    // * user_init_key_all contains a UserInitKey that offers all four ciphersuites.  It is validly
    //   signed with an Ed25519 key.
    // * The remaining cases each test message processing for a given ciphersuite:
    //   * case_p256_p256 uses P256 for DH and ECDSA-P256 for signing
    //   * case_x25519_ed25519 uses X25519 for DH and Ed25519 for signing
    // * In each case:
    //   * user_init_key contains a UserInitKey offering only the indicated ciphersuite, validly
    //     signed with the corresponding signature scheme
    //   * welcome_info contains a WelcomeInfo message with syntactically valid but bogus contents
    //   * welcome contains a Welcome message generated by encrypting welcome_info for a
    //     Diffie-Hellman public key derived from the dh_seed value.
    //   * add, update, and remove each contain a Handshake message with a GroupOperation of the
    //     corresponding type.  The signatures on these messages are not valid
    //
    // Your implementation should be able to pass the following tests:
    //
    // * user_init_key_all should parse successfully
    // * The test cases for any supported ciphersuites should parse successfully
    // * All of the above parsed values should survive a marshal / unmarshal round-trip

    #[derive(Debug, Deserialize, Serialize)]
    struct MessagesCase {
        cipher_suite: &'static CipherSuite,
        signature_scheme: &'static SignatureScheme,
        _user_init_key_len: u32,
        user_init_key: UserInitKey,
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
            self.user_init_key.upcast_crypto_values(&new_ctx)?;
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
        #[serde(rename = "uik_id__bound_u8")]
        uik_id: Vec<u8>,
        #[serde(rename = "dh_seed__bound_u8")]
        dh_seed: Vec<u8>,
        #[serde(rename = "sig_seed__bound_u8")]
        sig_seed: Vec<u8>,
        #[serde(rename = "random__bound_u8")]
        random: Vec<u8>,
        uik_all_scheme: &'static SignatureScheme,
        _user_init_key_all_len: u32,
        user_init_key_all: UserInitKey,

        case_p256_p256: MessagesCase,
        case_x25519_ed25519: MessagesCase,
    }

    impl CryptoUpcast for MessagesTestVectors {
        fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<CryptoCtx, Error> {
            let new_ctx = ctx.set_signature_scheme(self.uik_all_scheme);
            self.user_init_key_all.upcast_crypto_values(&new_ctx)?;

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
            // UserInitKeys are validly signed. They are [0xd6; 32], which is not a valid Ed25519
            // signature. So skip this step and call it a mission success.
            //raw.upcast_crypto_values(&CryptoCtx::new()).unwrap();
            raw
        };

        // Reserialized the deserialized input and make sure it's the same as the original
        let reserialized_bytes = tls_ser::serialize_to_bytes(&test_vec).unwrap();
        assert_eq!(reserialized_bytes, original_bytes);
    }
}
