use crate::{
    credential::{Credential, Identity},
    crypto::{ciphersuite::CipherSuite, hkdf, sig::SigSecretKey},
    error::Error,
    handshake::{GroupAdd, GroupOperation, GroupRemove, GroupUpdate, Handshake, ProtocolVersion},
    ratchet_tree::{RatchetTree, RatchetTreeNode},
    tree_math,
};

/// These are a bunch of secrets derived from `epoch_secret` via HKDF-Expand. See section 5.9.
#[derive(Clone)]
pub(crate) struct EpochSecrets {
    /// The initial secret used to derive all the rest
    pub(crate) init_secret: Vec<u8>,

    /// Used for deriving enryption keys in the Message Protection Layer
    pub(crate) application_secret: Vec<u8>,

    /// Used for computing MACs over `Handshake` messages
    pub(crate) confirmation_key: Vec<u8>,
}

/// Contains all group state
#[derive(Clone, Serialize)]
pub(crate) struct GroupState {
    /// You can think of this as a context variable. It helps us implement crypto ops and
    /// disambiguate serialized data structures
    #[serde(skip)]
    pub(crate) cs: &'static CipherSuite,

    /// Version info
    #[serde(skip)]
    pub(crate) protocol_version: ProtocolVersion,

    /// A long-lived signing key used to authenticate the sender of a message
    #[serde(skip)]
    pub(crate) identity_key: SigSecretKey,

    // opaque group_id<0..255>;
    /// An application-defined identifier for the group
    #[serde(rename = "group_id__bound_u8")]
    pub(crate) group_id: Vec<u8>,

    /// Represents the current version of the group key
    pub(crate) epoch: u32,

    // optional<Credential> roster<1..2^32-1>;
    /// Contains credentials for the occupied slots in the tree, including the identity and
    /// signature public key for the holder of the slot
    #[serde(rename = "roster__bound_u32")]
    pub(crate) roster: Vec<Option<Credential>>,

    // optional<PublicKey> tree<1..2^32-1>;
    /// The tree field contains the public keys corresponding to the nodes of the ratchet tree for
    /// this group. The number of leaves in this tree MUST be equal to the length of `roster`
    pub(crate) tree: RatchetTree,

    // opaque transcript_hash<0..255>;
    /// Contains a running hash of `GroupOperation` messages that led to this state
    #[serde(rename = "transcript_hash__bound_u8")]
    pub(crate) transcript_hash: Vec<u8>,

    /// This participant's position in the roster. This is also known as `signer_index`.
    #[serde(skip)]
    pub(crate) roster_index: u32,

    /// These are the secrets derived from `epoch_secret`
    #[serde(skip)]
    pub(crate) epoch_secrets: EpochSecrets,
}

// TODO: Write the method to create a one-man group from scratch. The spec says that
// transcript_hash is initialized to all zeros.

impl GroupState {
    /// Initializes a `GroupState` with the given `Welcome` information, this participant's
    /// identity, and this participant's identity key
    fn from_welcome_info(
        cs: &'static CipherSuite,
        w: WelcomeInfo,
        my_identity: &Identity,
        my_identity_key: SigSecretKey,
    ) -> GroupState {
        // We're not told where we are in the roster, so we first find ourselves
        let roster_index: u32 = {
            let pos = w
                .roster
                .iter()
                .position(|cred| match cred {
                    Some(Credential::Basic(basic_cred)) => &basic_cred.identity == my_identity,
                    None => false,
                    Some(_) => unimplemented!("X.509 is not a thing yet"),
                })
                .expect("could not find myself in roster");
            assert!(pos <= std::u32::MAX as usize, "roster index out of range");
            pos as u32
        };

        GroupState {
            cs: cs,
            protocol_version: w.protocol_version,
            identity_key: my_identity_key,
            group_id: w.group_id,
            epoch: w.epoch,
            roster: w.roster,
            tree: w.tree,
            transcript_hash: w.transcript_hash,
            roster_index: roster_index,
            epoch_secrets: EpochSecrets {
                init_secret: w.init_secret,
                // All these fields will be populated on the next call to `derive_epoch_secrets`
                application_secret: Vec::new(),
                confirmation_key: Vec::new(),
            },
        }
    }

    fn as_welcome_info(&self) -> WelcomeInfo {
        WelcomeInfo {
            protocol_version: self.protocol_version,
            group_id: self.group_id.clone(),
            epoch: self.epoch,
            roster: self.roster.clone(),
            tree: self.tree.clone(),
            transcript_hash: self.transcript_hash.clone(),
            init_secret: self.epoch_secrets.init_secret.clone(),
        }
    }

    /// Increments the epoch counter by 1
    ///
    /// Returns: An `Error::GroupOpError` if it's at its max
    #[must_use]
    fn update_epoch(&mut self) -> Result<(), Error> {
        let new_epoch = self
            .epoch
            .checked_add(1)
            .ok_or(Error::GroupOpError("Cannot increment epoch past its maximum"))?;
        self.epoch = new_epoch;

        Ok(())
    }

    /// Computes and updates the transcript hash, given a new `Handshake` message.
    ///
    /// Returns: An `Error::SerdeError` if there was an issue during serialization
    #[must_use]
    fn update_transcript_hash(&mut self, handshake: &Handshake) -> Result<(), Error> {
        // Compute the new transcript hash
        // From section 5.7: transcript_hash_[n] = Hash(transcript_hash_[n-1] || operation)
        let new_transcript_hash = {
            let operation_bytes = crate::tls_ser::serialize_to_bytes(&handshake.operation)?;
            let mut ctx = ring::digest::Context::new(self.cs.hash_alg);
            ctx.update(&self.transcript_hash);
            ctx.update(&operation_bytes);
            ctx.finish().as_ref().to_vec()
        };
        self.transcript_hash = new_transcript_hash;

        Ok(())
    }

    /// Derives and sets the next generation of Group secrets as per section 5.9 in the spec
    #[must_use]
    fn update_epoch_secrets(&mut self, update_secret: &[u8]) -> Result<(), Error> {
        // epoch_secret = HKDF-Extract(salt=init_secret_[n-1] (or 0), ikm=update_secret)
        let salt = hkdf::prk_from_bytes(self.cs.hash_alg, &self.epoch_secrets.init_secret);
        let epoch_secret: ring::hmac::SigningKey = hkdf::hkdf_extract(&salt, &update_secret);

        let serialized_self = crate::tls_ser::serialize_to_bytes(self)?;
        self.epoch_secrets = EpochSecrets {
            // application_secret = Derive-Secret(epoch_secret, "app", GroupState_[n])
            application_secret: hkdf::derive_secret(&epoch_secret, b"app", &serialized_self),
            // confirmation_key = Derive-Secret(epoch_secret, "confirm", GroupState_[n])
            confirmation_key: hkdf::derive_secret(&epoch_secret, b"confirm", &serialized_self),
            // init_secret_[n] = Derive-Secret(epoch_secret, "init", GroupState_[n])
            init_secret: hkdf::derive_secret(&epoch_secret, b"init", &serialized_self),
        };

        Ok(())
    }

    /// Converts an index into the participant roster to an index to the corresponding leaf node of
    /// the ratchet tree
    fn roster_index_to_tree_index(signer_index: u32) -> u32 {
        // This is easy. The nth leaf node is at position 2n
        signer_index.checked_mul(2).expect("roster/tree size invariant violated")
    }

    /// Performs and validates an Update operation on the `GroupState`.
    #[must_use]
    fn process_update_op(
        &mut self,
        update: &GroupUpdate,
        sender_tree_idx: u32,
    ) -> Result<(), Error> {
        // We do three things: compute the new ratchet tree, compute the new transcript hash, and
        // compute the new epoch secrets. We shove all these new values into a delta. To validate
        // the operation, we check that the derived public keys match the ones in the message. If
        // they do not, this is an error.

        // Decrypt the path secret from the GroupUpdate and propogate it through our tree
        // Recall that roster_index is just another (IMO clearer) name for signer_index
        let my_tree_idx = GroupState::roster_index_to_tree_index(self.roster_index);
        let (path_secret, ancestor_idx) = self.tree.decrypt_direct_path_message(
            self.cs,
            &update.path,
            sender_tree_idx as usize,
            my_tree_idx as usize,
        )?;
        self.tree.propogate_new_path_secret(self.cs, path_secret, ancestor_idx)?;

        // "The update secret resulting from this change is the secret for the root node of the
        // ratchet tree."
        let root_node_secret = {
            let root_node = self.tree.get_root_node().expect("tried to update empty tree");
            root_node.get_node_secret().expect("root node has no secret").to_vec()
        };
        self.update_epoch_secrets(&root_node_secret)?;

        //
        // Validation
        //

        // Make the tree we're validating immutable
        let new_tree = &self.tree;
        let num_leaves = tree_math::num_leaves_in_tree(new_tree.size());
        let direct_path = tree_math::node_direct_path(sender_tree_idx as usize, num_leaves);

        // Verify that the pubkeys in the message agree with our newly-derived pubkeys
        for (node_msg, path_node_idx) in update.path.node_messages.iter().zip(direct_path) {
            let received_public_key = &node_msg.public_key;
            let expected_public_key = new_tree
                .get(path_node_idx)
                .ok_or(Error::GroupOpError("Unexpected out-of-bounds path index"))?
                .get_public_key()
                .ok_or(Error::GroupOpError("Node on updated path has no public key"))?;

            if expected_public_key.as_bytes() != received_public_key.as_bytes() {
                return Err(Error::GroupOpError("Inconsistent public keys in Update message"));
            }
        }

        Ok(())
    }

    /// Performs and validates a Remove operation on the `GroupState`
    #[must_use]
    fn process_remove_op(
        &mut self,
        remove: &GroupRemove,
        sender_tree_idx: u32,
    ) -> Result<(), Error> {
        // * Update the roster by setting the credential in the removed slot to the null optional
        //   value
        // * Update the ratchet tree by replacing nodes in the direct path from the removed leaf
        //   using the information in the Remove message
        // * Reduce the size of the roster and the tree until the rightmost element roster element
        //   and leaf node are non-null
        // * Update the ratchet tree by setting to blank all nodes in the direct path of the
        //   removed leaf

        // Blank out the roster location
        let remove_idx = remove.removed as usize;
        self.roster.insert(remove_idx, None);

        // Update the ratchet tree with the entropy provided in remove.path
        let my_tree_idx = GroupState::roster_index_to_tree_index(self.roster_index);
        let (path_secret, ancestor_idx) = self.tree.decrypt_direct_path_message(
            self.cs,
            &remove.path,
            sender_tree_idx as usize,
            my_tree_idx as usize,
        )?;
        self.tree.propogate_new_path_secret(self.cs, path_secret, ancestor_idx)?;

        // "The update secret resulting from this change is the secret for the root node of the
        // ratchet tree after the second step"
        let update_secret = {
            let root_node = self.tree.get_root_node().expect("tried to update empty tree");
            root_node.get_node_secret().expect("root node has no secret").to_vec()
        };

        // Truncate the roster to the last non-None credential
        let mut last_nonempty_roster_entry = None;
        for (i, entry) in self.roster.iter().rev().enumerate() {
            if entry.is_some() {
                last_nonempty_roster_entry = Some(i);
            }
        }
        match last_nonempty_roster_entry {
            // If there are no nonempty entries in the roster, clear it
            None => self.roster.clear(),
            Some(i) => {
                // This can't fail, because i is an index
                let num_elements_to_retain = i + 1;
                self.roster.truncate(num_elements_to_retain)
            }
        }

        // Truncate the tree in a similar fashion
        self.tree.prune_from_right();

        // Blank out the direct path of remove_idx
        self.tree.propogate_blank(remove_idx);

        // All the modifications have been made. Update the epoch secrets with old root node secret
        // as the update secret
        self.update_epoch_secrets(&update_secret)?;

        Ok(())
    }

    /// Performs and validates an Add operation on the `GroupState`. Requires a `WelcomeInfo`
    /// representing the `GroupState` before this handshake was received.
    #[must_use]
    fn process_add_op(
        &mut self,
        add: &GroupAdd,
        prior_welcome_info: &WelcomeInfo,
    ) -> Result<(), Error> {
        // What we have to do, in order
        // 1. If the index value is equal to the size of the group, increment the size of the
        //    group, and extend the tree and roster accordingly
        // 2. Verify the signature on the included UserInitKey; if the signature verification
        //    fails, abort
        // 3. Generate a WelcomeInfo object describing the state prior to the add, and verify that
        //    its hash is the same as the value of the welcome_info_hash field
        // 4. Set the roster entry at position index to the credential in the included UserInitKey
        // 5. Update the ratchet tree by setting to blank all nodes in the direct path of the new
        //    node
        // 6. Set the leaf node in the tree at position index to a new node containing the public
        //    key from the UserInitKey in the Add corresponding to the ciphersuite in use

        let new_index = add.index as usize;
        if new_index > self.tree.size() {
            return Err(Error::GroupOpError("Invalid insertion index in Add operation"));
        }

        // Check the WelcomeInfo hash
        let my_prior_welcome_info_hash = {
            let serialized = crate::tls_ser::serialize_to_bytes(&prior_welcome_info)?;
            ring::digest::digest(self.cs.hash_alg, &serialized)
        };
        if my_prior_welcome_info_hash.as_ref() != add.welcome_info_hash.as_slice() {
            return Err(Error::GroupOpError("Invalid WelcomeInfo hash in Add operation"));
        }

        // Verify the UserInitKey's signature, then validate its contents
        add.init_key.verify_sig()?;
        add.init_key.validate()?;

        // Update the roster
        self.roster.insert(new_index, Some(add.init_key.credential.clone()));

        let cipher_suites = &add.init_key.cipher_suites;
        let init_keys = &add.init_key.init_keys;

        // The public key we associate to the new participant is the one that corresponds to our
        // current ciphersuite. These two lists must be the same length, because this property is
        // checked in validate() above
        let mut public_key = None;
        for (cs, key) in cipher_suites.iter().zip(init_keys.iter()) {
            if cs == &self.cs {
                public_key = Some(key)
            }
        }
        let public_key = public_key
            .ok_or(Error::GroupOpError("UserInitKey has no public keys for group's ciphersuite"))?;
        let new_node = RatchetTreeNode::Filled {
            public_key: public_key.clone(),
            private_key: None,
            secret: None,
        };

        let is_append = new_index == self.tree.size();
        if is_append {
            // If we're adding a new node to the end tree, we have to make new nodes
            self.tree.add_leaf_node(new_node);
        } else {
            // Otherwise, it's an in-place Add. In this case, check that we're only overwriting a
            // Blank node.
            let node_to_overwrite = self.tree.get_mut(new_index).unwrap();
            if let RatchetTreeNode::Filled {
                ..
            } = node_to_overwrite
            {
                return Err(Error::GroupOpError("Add tried to overwrite non-blank node"));
            } else {
                *node_to_overwrite = new_node;
            }
        }

        // "The update secret resulting from this change is an all-zero octet string of length
        // Hash.length."
        self.update_epoch_secrets(&vec![0u8; self.cs.hash_alg.output_len])?;

        Ok(())
    }

    // According to the spec, this is how we process handshakes:
    // 1. Verify that the prior_epoch field of the Handshake message is equal the epoch field of
    //    the current GroupState object.
    // 2. Use the operation message to produce an updated, provisional GroupState object
    //    incorporating the proposed changes.
    // 3. Look up the public key for slot index signer_index from the roster in the current
    //    GroupState object (before the update).
    // 4. Use that public key to verify the signature field in the Handshake message, with the
    //    updated GroupState object as input.
    // 5. If the signature fails to verify, discard the updated GroupState object and consider the
    //    Handshake message invalid.
    // 6. Use the confirmation_key for the new group state to compute the confirmation MAC for this
    //    message, as described below, and verify that it is the same as the confirmation field.
    // 7. If the the above checks are successful, consider the updated GroupState object as the
    //    current state of the group.
    #[must_use]
    pub(crate) fn process_handshake(&mut self, handshake: &Handshake) -> Result<(), Error> {
        if handshake.prior_epoch != self.epoch {
            return Err(Error::GroupOpError("Handshake's prior epoch isn't the current epoch"));
        }

        let sender_tree_idx = GroupState::roster_index_to_tree_index(handshake.signer_index);
        let sender_credential = self
            .roster
            .get(handshake.signer_index as usize)
            .ok_or(Error::GroupOpError("Signer index is out of bounds"))?;
        let sender_public_key = sender_credential
            .as_ref()
            .ok_or(Error::GroupOpError("Credential at signer's index is empty"))?
            .get_public_key();

        // Make a preliminary new state with updated transcript_hash and epoch. The rest of the
        // updates are handled in the branches of the match statement below
        let mut new_state = self.clone();
        new_state.update_transcript_hash(handshake)?;
        new_state.update_epoch()?;

        // Do the handshake operation on the preliminary new state. If there are no errors, we set
        // the actual state to the new one.
        match handshake.operation {
            GroupOperation::Update(ref update) => {
                new_state.process_update_op(update, sender_tree_idx)?
            }
            GroupOperation::Add(ref add) => {
                let prior_welcome_info = self.as_welcome_info();
                new_state.process_add_op(add, &prior_welcome_info)?;
            }
            GroupOperation::Remove(ref remove) => {
                new_state.process_remove_op(remove, sender_tree_idx)?
            }
            GroupOperation::Init(_) => unimplemented!(),
        };

        //
        // Now validate the new state
        //

        // Make the state immutable for the rest of this function
        let new_state = new_state;

        // Check the signature. From section 7 of the spec:
        // signature_data = GroupState.transcript_hash
        // Handshake.signature = Sign(identity_key, signature_data)
        let sig_data = &new_state.transcript_hash;
        new_state.cs.sig_impl.verify(sender_public_key, sig_data, &handshake.signature)?;

        // Check the MAC. From section 7 of the spec:
        // confirmation_data = GroupState.transcript_hash || Handshake.signature
        // Handshake.confirmation = HMAC(confirmation_key, confirmation_data)
        let conf_key = ring::hmac::VerificationKey::new(
            self.cs.hash_alg,
            &self.epoch_secrets.confirmation_key,
        );
        let conf_data =
            [new_state.transcript_hash.as_slice(), handshake.signature.to_bytes().as_slice()]
                .concat();
        // It's okay to reveal that the MAC is incorrect, because the ring::hmac::verify runs in
        // constant time
        ring::hmac::verify(&conf_key, &conf_data, &handshake.confirmation)
            .map_err(|_| Error::SignatureError("Handshake confirmation is invalid"))?;

        //
        // If we've made it this far. We commit the changes
        //

        core::mem::replace(self, new_state);
        Ok(())
    }
}

// TODO: Make this COW so we don't have to clone everything in GroupState::as_welcome_info

/// Contains everything a new user needs to know to join a Group
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct WelcomeInfo {
    // ProtocolVersion version;
    /// The protocol version
    protocol_version: ProtocolVersion,

    // opaque group_id<0..255>;
    /// An application-defined identifier for the group
    #[serde(rename = "group_id__bound_u8")]
    group_id: Vec<u8>,

    /// Represents the current version of the group key
    epoch: u32,

    // optional<Credential> roster<1..2^32-1>;
    /// Contains credentials for the occupied slots in the tree, including the identity and
    /// signature public key for the holder of the slot
    #[serde(rename = "roster__bound_u32")]
    pub(crate) roster: Vec<Option<Credential>>,

    // optional<PublicKey> tree<1..2^32-1>;
    /// The tree field contains the public keys corresponding to the nodes of the ratchet tree for
    /// this group. The number of leaves in this tree MUST be equal to the length of `roster`
    tree: RatchetTree,

    // opaque transcript_hash<0..255>;
    /// Contains a running hash of `GroupOperation` messages that led to this state
    #[serde(rename = "transcript_hash__bound_u8")]
    transcript_hash: Vec<u8>,

    // opaque init_secret<0..255>;
    /// The initial secret used to derive all the rest
    #[serde(rename = "init_secret__bound_u8")]
    init_secret: Vec<u8>,
}

#[cfg(test)]
mod test {
    use crate::{
        crypto::ciphersuite::CipherSuite,
        tls_de::TlsDeserializer,
        utils::{group_from_test_group, TestGroupState},
    };

    use serde::de::Deserialize;

    // The following test vector is from
    // https://github.com/mlswg/mls-implementations/tree/master/test_vectors
    //
    // File key_schedule.bin
    //
    // struct {
    //   opaque update_secret<0..255>;
    //   opaque epoch_secret<0..255>;
    //   opaque application_secret<0..255>;
    //   opaque confirmation_key<0..255>;
    //   opaque init_secret<0..255>;
    // } KeyScheduleEpoch;
    //
    // struct {
    //   CipherSuite suite;
    //   Epoch epochs<0..2^16-1>;
    // } KeyScheduleCase;
    //
    // struct {
    //   uint32_t n_epochs;
    //   uint32_t garbage;
    //   GroupState base_group_state;
    //
    //   KeyScheduleCase case_p256;
    //   KeyScheduleCase case_x25519;
    // } KeyScheduleTestVectors;
    //
    // For each ciphersuite, the `KeyScheduleTestVectors` struct provides a `KeyScheduleCase` that
    // describes the outputs of the MLS key schedule over the course of several epochs.
    //
    // * The init_secret input to the first stage of the key schedule is the all-zero vector of
    //   length Hash.length for the hash indicated by the ciphersuite.
    // * For future epochs, the init_secret is the value output at the previous stage of the key
    //   schedule.
    // * The initial GroupState object input to the key schedule should be deserialized from the
    //   base_group_state object.
    // * incremented after being provided to the key schedule. This is to say, the key schedule is
    //   run on the base_group_state object before its epoch is incremented for the first time.
    //
    // For each epoch, given inputs as described above, your implementation should replacate the
    // epoch_secret, application_secret, confirmation_key, and init_secret outputs of the key
    // schedule.

    #[derive(Debug, Deserialize)]
    struct KeyScheduleEpoch {
        #[serde(rename = "update_secret__bound_u8")]
        update_secret: Vec<u8>,
        #[serde(rename = "epoch_secret__bound_u8")]
        epoch_secret: Vec<u8>,
        #[serde(rename = "application_secret__bound_u8")]
        application_secret: Vec<u8>,
        #[serde(rename = "confirmation_key__bound_u8")]
        confirmation_key: Vec<u8>,
        #[serde(rename = "init_secret__bound_u8")]
        init_secret: Vec<u8>,
    }

    #[derive(Debug, Deserialize)]
    struct KeyScheduleCase {
        ciphersuite: &'static CipherSuite,
        #[serde(rename = "epoch__bound_u16")]
        epochs: Vec<KeyScheduleEpoch>,
    }

    #[derive(Debug, Deserialize)]
    struct KeyScheduleTestVectors {
        n_epochs: u32,
        _garbage: u32,
        base_group_state: TestGroupState,
        case_p256: KeyScheduleCase,
        case_x25519: KeyScheduleCase,
    }

    // Tests our code against the official key schedule test vector
    #[test]
    fn official_key_schedule_kat() {
        let mut f = std::fs::File::open("test_vectors/key_schedule.bin").unwrap();
        let mut deserializer = TlsDeserializer::from_reader(&mut f);
        let test_vec = KeyScheduleTestVectors::deserialize(&mut deserializer).unwrap();
        let case1 = test_vec.case_x25519;
        let mut group_state = group_from_test_group(test_vec.base_group_state);

        // Keep deriving new secrets with respect to the given update secret. Check all the
        // resulting keys against the test vector.
        for epoch in case1.epochs.into_iter() {
            group_state.update_epoch_secrets(&epoch.update_secret).unwrap();
            let derived_secrets = &group_state.epoch_secrets;

            // We don't save the derived epoch_secret anywhere, since it's just an intermediate
            // value. We do test all the things derived from it, though.
            assert_eq!(&derived_secrets.application_secret, &epoch.application_secret);
            assert_eq!(&derived_secrets.confirmation_key, &epoch.confirmation_key);
            assert_eq!(&derived_secrets.init_secret, &epoch.init_secret);

            // Increment the state epoch every time we do a key derivation. This is what happens in
            // the actual protocol.
            group_state.epoch += 1;
        }
    }
}
