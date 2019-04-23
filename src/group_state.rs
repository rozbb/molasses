use crate::{
    application::ApplicationKeyChain,
    credential::Roster,
    crypto::{
        ciphersuite::CipherSuite,
        ecies::{ecies_encrypt, EciesCiphertext},
        hkdf,
        rng::CryptoRng,
        sig::SigSecretKey,
    },
    error::Error,
    handshake::{
        GroupAdd, GroupOperation, GroupRemove, GroupUpdate, Handshake, ProtocolVersion, UserInitKey,
    },
    ratchet_tree::{PathSecret, RatchetTree, RatchetTreeNode},
    tls_de::TlsDeserializer,
    tls_ser, tree_math,
    upcast::{self, CryptoUpcast},
};

use clear_on_drop::ClearOnDrop;
use serde::de::Deserialize;

/// This is called the `application_secret` in the MLS key schedule (section 5.9)
pub(crate) struct ApplicationSecret(pub(crate) ClearOnDrop<Vec<u8>>);

impl ApplicationSecret {
    fn new(v: Vec<u8>) -> ApplicationSecret {
        ApplicationSecret(ClearOnDrop::new(v))
    }
}

/// This is called the `confirmation_key` in the MLS key schedule (section 5.9)
pub(crate) struct ConfirmationKey(ClearOnDrop<Vec<u8>>);

impl ConfirmationKey {
    fn new(v: Vec<u8>) -> ConfirmationKey {
        ConfirmationKey(ClearOnDrop::new(v))
    }
}

/// This is called the `update_secret` in the MLS key schedule (section 5.9)
pub(crate) struct UpdateSecret(ClearOnDrop<Vec<u8>>);

impl UpdateSecret {
    fn new(v: Vec<u8>) -> UpdateSecret {
        UpdateSecret(ClearOnDrop::new(v))
    }
}

/// Contains all group state
#[derive(Clone, Serialize)]
pub struct GroupState {
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
    pub(crate) roster: Roster,

    // optional<PublicKey> tree<1..2^32-1>;
    /// The tree field contains the public keys corresponding to the nodes of the ratchet tree for
    /// this group. The number of leaves in this tree MUST be equal to the length of `roster`
    pub(crate) tree: RatchetTree,

    // opaque transcript_hash<0..255>;
    /// Contains a running hash of `GroupOperation` messages that led to this state
    #[serde(rename = "transcript_hash__bound_u8")]
    pub(crate) transcript_hash: Vec<u8>,

    /// The participant's position in the roster. This is also known as `signer_index`. It is
    /// `None` iff this `GroupState` is in a preliminary state, i.e., iff it is between a `Welcome`
    /// and `Add` operation.
    #[serde(skip)]
    pub(crate) roster_index: Option<u32>,

    /// The `UserInitKey` used in the creation of this group from a `Welcome`. This is `Some` iff
    /// this `GroupState` is in a preliminary state, i.e., if it is between a `Welcome` and `Add`
    /// operation.
    #[serde(skip)]
    pub(crate) initializing_user_init_key: Option<UserInitKey>,

    /// The initial secret used to derive `application_secret` and `confirmation_key`
    #[serde(skip)]
    pub(crate) init_secret: Vec<u8>,
}

// TODO: Write the method to create a one-man group from scratch. The spec says that
// transcript_hash is initialized to all zeros.

impl GroupState {
    /// Initializes a preliminary `GroupState` with the given `WelcomeInfo` information, this
    /// this participant's identity key, and the `UserInitKey` used to encrypt the `Welcome` that
    /// the `WelcomeInfo` came from.
    ///
    /// Returns: A `GroupState` in a "preliminary state", meaning that `roster_index` is `None` and
    /// `initializing_user_init_key` is `Some`. The only thing to do with a preliminary
    /// `GroupState` is give it an `Add` operation to add yourself to it.
    pub(crate) fn from_welcome_info(
        cs: &'static CipherSuite,
        w: WelcomeInfo,
        my_identity_key: SigSecretKey,
        initializing_user_init_key: UserInitKey,
    ) -> GroupState {
        GroupState {
            cs: cs,
            protocol_version: w.protocol_version,
            identity_key: my_identity_key,
            group_id: w.group_id,
            epoch: w.epoch,
            roster: w.roster,
            tree: w.tree,
            transcript_hash: w.transcript_hash,
            roster_index: None,
            initializing_user_init_key: Some(initializing_user_init_key),
            init_secret: w.init_secret,
        }
    }

    /// Creates a `WelcomeInfo` object with all the current state information
    pub(crate) fn as_welcome_info(&self) -> WelcomeInfo {
        WelcomeInfo {
            protocol_version: self.protocol_version,
            group_id: self.group_id.clone(),
            epoch: self.epoch,
            roster: self.roster.clone(),
            tree: self.tree.clone(),
            transcript_hash: self.transcript_hash.clone(),
            init_secret: self.init_secret.clone(),
        }
    }

    /// Increments the epoch counter by 1
    ///
    /// Returns: An `Error::ValidationError` if the epoch value is at its max
    #[must_use]
    fn increment_epoch(&mut self) -> Result<(), Error> {
        let new_epoch = self
            .epoch
            .checked_add(1)
            .ok_or(Error::ValidationError("Cannot increment epoch past its maximum"))?;
        self.epoch = new_epoch;

        Ok(())
    }

    /// Computes and updates the transcript hash, given a new `Handshake` message.
    ///
    /// Returns: An `Error::SerdeError` if there was an issue during serialization
    #[must_use]
    fn update_transcript_hash(&mut self, operation: &GroupOperation) -> Result<(), Error> {
        // Compute the new transcript hash
        // From section 5.7: transcript_hash_[n] = Hash(transcript_hash_[n-1] || operation)
        let operation_bytes = tls_ser::serialize_to_bytes(operation)?;
        let new_transcript_hash = {
            let mut ctx = ring::digest::Context::new(self.cs.hash_alg);
            ctx.update(&self.transcript_hash);
            ctx.update(&operation_bytes);
            ctx.finish().as_ref().to_vec()
        };
        self.transcript_hash = new_transcript_hash;

        Ok(())
    }

    /// Derives and sets the next generation of Group secrets as per section 5.9 in the spec.
    /// Specifically, this sets the init secret of the group, and returns the confirmation key and
    /// application secret. This is done this way because the latter two values must be used
    /// immediately in `process_handshake`.
    #[must_use]
    fn update_epoch_secrets(
        &mut self,
        update_secret: &UpdateSecret,
    ) -> Result<(ApplicationSecret, ConfirmationKey), Error> {
        // epoch_secret = HKDF-Extract(salt=init_secret_[n-1] (or 0), ikm=update_secret)
        let salt = hkdf::prk_from_bytes(self.cs.hash_alg, &self.init_secret);
        let epoch_secret: ring::hmac::SigningKey = hkdf::hkdf_extract(&salt, &*update_secret.0);

        let serialized_self = tls_ser::serialize_to_bytes(self)?;

        // Set my new init_secret first
        // init_secret_[n] = Derive-Secret(epoch_secret, "init", GroupState_[n])
        self.init_secret = hkdf::derive_secret(&epoch_secret, b"init", &serialized_self);

        // application_secret = Derive-Secret(epoch_secret, "app", GroupState_[n])
        let application_secret = hkdf::derive_secret(&epoch_secret, b"app", &serialized_self);

        // confirmation_key = Derive-Secret(epoch_secret, "confirm", GroupState_[n])
        let confirmation_key = hkdf::derive_secret(&epoch_secret, b"confirm", &serialized_self);

        Ok((ApplicationSecret::new(application_secret), ConfirmationKey::new(confirmation_key)))
    }

    /// Converts the index of a roster entry into the index of the corresponding leaf node of the
    /// ratchet tree
    ///
    /// Returns: `Ok(n)` on success, where `n` is the corresponding tree index. Returns an
    /// `Error::ValidationError` if `roster_index` is out of bounds.
    pub(crate) fn roster_index_to_tree_index(roster_index: u32) -> Result<usize, Error> {
        // This is easy. The nth leaf node is at position 2n
        roster_index
            .checked_mul(2)
            .map(|n| n as usize)
            .ok_or(Error::ValidationError("roster/tree size invariant violated"))
    }

    /// Performs an update operation on the `GroupState`, where `new_path_secret` is the node
    /// secret we will propagate starting at the index `start_idx`. This is the core updating logic
    /// that is used in `process_incoming_update_op` and `create_and_apply_update_op`.
    ///
    /// Returns: `Ok(update_secret)` on success, where `update_secret` is the update secret
    /// necessary for generating new epoch secrets
    fn apply_update(
        &mut self,
        new_path_secret: PathSecret,
        start_idx: usize,
    ) -> Result<UpdateSecret, Error> {
        // The main part of doing an update is updating node secrets, private keys, and public keys
        let root_node_secret =
            self.tree.propagate_new_path_secret(self.cs, new_path_secret, start_idx)?;

        // "The update secret resulting from this change is the secret for the root node of the
        // ratchet tree."
        Ok(UpdateSecret::new(root_node_secret.0))
    }

    /// Performs and validates an incoming (i.e., one we did not generate) Update operation on the
    /// `GroupState`, where `sender_tree_idx` is the tree index of the sender of this operation
    ///
    /// Returns: `Ok(update_secret)` on success, where `update_secret` is the update secret
    /// necessary for generating new epoch secrets.
    #[must_use]
    fn process_incoming_update_op(
        &mut self,
        update: &GroupUpdate,
        sender_tree_idx: usize,
    ) -> Result<UpdateSecret, Error> {
        // We do three things: compute the new ratchet tree, compute the new transcript hash, and
        // compute the new epoch secrets. We shove all these new values into a delta. To validate
        // the operation, we check that the derived public keys match the ones in the message. If
        // they do not, this is an error.

        // Decrypt the path secret from the GroupUpdate and propagate it through our tree
        // Recall that roster_index is just another (IMO clearer) name for signer_index
        let num_leaves = tree_math::num_leaves_in_tree(self.tree.size());
        let my_tree_idx = {
            // Safely unwrap the roster index. A preliminary GroupState is one that has just been
            // initialized with a Welcome message
            let roster_index = self
                .roster_index
                .ok_or(Error::ValidationError("Cannot do an Update on a preliminary GroupState"))?;
            GroupState::roster_index_to_tree_index(roster_index)?
        };
        let (path_secret, common_ancestor) = self.tree.decrypt_direct_path_message(
            self.cs,
            &update.path,
            sender_tree_idx,
            my_tree_idx,
        )?;
        let update_secret = self.apply_update(path_secret, common_ancestor)?;

        // Update all the public keys of the nodes in the direct path that are below our common
        // ancestor, i.e., all the ones whose secret we don't know. Note that this step is not
        // performed in apply_update, because this only happens when we're not the ones who created
        // the Update operation.
        let direct_path_public_keys =
            update.path.node_messages.iter().map(|node_msg| &node_msg.public_key);
        self.tree.set_public_keys_with_bound(
            sender_tree_idx,
            common_ancestor,
            direct_path_public_keys.clone(),
        )?;

        // Make sure the public keys in the message match the ones we derived
        self.tree.validate_direct_path_public_keys(sender_tree_idx, direct_path_public_keys)?;

        // All done
        Ok(update_secret)
    }

    /// Performs and validates Remove operation on the `GroupState`. This will (necessarily) error
    /// if this member is the one being removed.
    ///
    /// Returns: `Ok(update_secret)` on success, where `update_secret` is the update secret
    /// necessary for generating new epoch secrets. Returns an `Error::Removed` iff this member is
    /// the one who has been removed. Otherwise returns some other kind of `Error`.
    // NOTE: There is no corresponding "apply_remove" method because the creator of a Remove is
    // able to process the Remove, whereas the creator of an Update cannot process their own
    // operation (this is because the creator's own path secret is never put into the
    // DirectPathMessage).
    #[must_use]
    fn process_remove_op(&mut self, remove: &GroupRemove) -> Result<UpdateSecret, Error> {
        // Find the entropy provided in remove.path that we'll use to update the tree before
        // blanking out the removed node
        let my_tree_idx = {
            // Safely unwrap the roster index. A preliminary GroupState is one that has just been
            // initialized with a Welcome message
            let roster_index = self
                .roster_index
                .ok_or(Error::ValidationError("Cannot do a Remove on a preliminary GroupState"))?;
            GroupState::roster_index_to_tree_index(roster_index)?
        };
        let remove_tree_idx = GroupState::roster_index_to_tree_index(remove.removed_roster_index)?;

        if my_tree_idx == remove_tree_idx {
            // Oh no, we've been kicked! May as well throw an error now, since the
            // decrypt_direct_path_message below would throw an error anyway: you can't decrypt
            // DirectPathMessages where you are the starting node.
            return Err(Error::Removed);
        }

        // Get the new entropy for the tree
        let (new_path_secret, common_ancestor) = self.tree.decrypt_direct_path_message(
            self.cs,
            &remove.path,
            remove_tree_idx,
            my_tree_idx,
        )?;

        // Game plan as per the spec:
        // * Update the roster by setting the credential in the removed slot to the null optional
        //   value
        // * Update the ratchet tree by replacing nodes in the direct path from the removed leaf
        //   using the information in the Remove message
        // * Reduce the size of the roster and the tree until the rightmost element roster element
        //   and leaf node are non-null
        // * Update the ratchet tree by setting to blank all nodes in the direct path of the
        //   removed leaf

        // Update the ratchet tree with the entropy provided in path_secret
        let root_node_secret =
            self.tree.propagate_new_path_secret(self.cs, new_path_secret, common_ancestor)?;
        // Update the public keys whose path secret we don't know
        let direct_path_public_keys =
            remove.path.node_messages.iter().map(|node_msg| &node_msg.public_key);
        self.tree.set_public_keys_with_bound(
            remove_tree_idx,
            common_ancestor,
            direct_path_public_keys.clone(),
        )?;

        // "The update secret resulting from this change is the secret for the root node of the
        // ratchet tree after the second step". This will be our return value.
        let update_secret = UpdateSecret::new(root_node_secret.0);

        // Before blank out the direct path of the removed node, check that all the public keys in
        // the message match the ones we derived
        self.tree.validate_direct_path_public_keys(remove_tree_idx, direct_path_public_keys)?;

        // Blank out the roster location and prune the blanks from the end
        self.roster
            .0
            .get_mut(remove.removed_roster_index as usize)
            .map(|cred| *cred = None)
            .ok_or(Error::ValidationError("Invalid roster index"))?;
        self.roster.truncate_to_last_nonblank();

        // Blank out the direct path of remove_tree_idx
        self.tree.propagate_blank(remove_tree_idx);
        // Truncate the tree in a similar fashion to the roster
        self.tree.truncate_to_last_nonblank();

        // And that's it
        Ok(update_secret)
    }

    /// Performs and validates an Add operation on the `GroupState`. Requires a `WelcomeInfo`
    /// representing the `GroupState` before this handshake was received.
    ///
    /// Requires: If the member being added is this member, then this `GroupState` must be
    /// "preliminary", i.e., its `roster_index` must be `None`, i.e., it must have just been
    /// created from a `Welcome`.
    ///
    /// Returns: `Ok(update_secret)` on success, where `update_secret` is the update secret
    /// necessary for generating new epoch secrets.
    // NOTE: There is no corresponding "apply_add" method because the creator of an Add is able to
    // process the Add, whereas the creator of an Update cannot process their own operation (this
    // is because the creator's own path secret is never put into the DirectPathMessage).
    #[must_use]
    fn process_add_op(
        &mut self,
        add: &GroupAdd,
        prior_welcome_info: &WelcomeInfo,
    ) -> Result<UpdateSecret, Error> {
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

        let add_roster_index = add.roster_index;
        if add_roster_index as usize > self.tree.size() {
            return Err(Error::ValidationError("Invalid insertion index in Add operation"));
        }

        // Check the WelcomeInfo hash
        let my_prior_welcome_info_hash = {
            let serialized = tls_ser::serialize_to_bytes(&prior_welcome_info)?;
            ring::digest::digest(self.cs.hash_alg, &serialized)
        };
        if my_prior_welcome_info_hash.as_ref() != add.welcome_info_hash.as_slice() {
            return Err(Error::ValidationError("Invalid WelcomeInfo hash in Add operation"));
        }

        // Check if we're a "preliminary" GroupState, i.e., whether or not we were just created by
        // a Welcome. This is true iff self.roster_index is null and iff
        // self.initializing_user_init_key is non-null.
        let is_preliminary = self.roster_index.is_none();

        // Check all the UserInitKeys involved
        add.init_key.verify_sig()?;
        add.init_key.validate()?;
        self.initializing_user_init_key.as_ref().map(|uik| uik.verify_sig()).transpose()?;
        self.initializing_user_init_key.as_ref().map(|uik| uik.validate()).transpose()?;

        // If we just received a WelcomeInfo, we want to use the UserInitKey we created, since it
        // contains the private key to our ratchet tree node
        let init_key = if is_preliminary {
            let uik = self.initializing_user_init_key.as_ref().ok_or(Error::ValidationError(
                "Preliminary GroupState has no initializing UserInitKey",
            ))?;
            // If it's an initializing key, let's make sure that its ID matches that of the
            // provided UserInitKey
            if uik.user_init_key_id != add.init_key.user_init_key_id {
                return Err(Error::ValidationError(
                    "Add's UserInitKey and GroupState's initialized UserInitKey differ",
                ));
            }
            uik
        } else {
            &add.init_key
        };

        // Is this an appending Add or is it an in-place Add? If in-place, we have to make sure
        // we're not overwriting any existing members in the group
        let is_append = add_roster_index as usize == self.roster.len();

        // Update the roster
        let new_credential = init_key.credential.clone();
        if is_append {
            self.roster.0.push(Some(new_credential))
        } else {
            // It's an in-place add. Check that we're only overwriting an empty roster entry
            let entry_to_update = self
                .roster
                .0
                .get_mut(add_roster_index as usize)
                .ok_or(Error::ValidationError("Out of bounds roster index"))?;

            if entry_to_update.is_some() {
                return Err(Error::ValidationError("Add tried to overwrite non-null roster entry"));
            } else {
                *entry_to_update = Some(new_credential);
            }
        }

        // Update the tree. We add a new blank node in the correct position, then set the leaf node
        // to the appropriate value
        if is_append {
            // If we're adding a new node to the end of the tree, we have to make new nodes
            self.tree.add_leaf_node(RatchetTreeNode::Blank);
        }

        let add_tree_index = GroupState::roster_index_to_tree_index(add_roster_index)?;
        if is_preliminary {
            // If we're one being Added, then this index is us
            self.roster_index = Some(add_roster_index);
        }

        // Propagate the blank up the tree before we overwrite the new leaf with the new
        // member's pubkey info
        self.tree.propagate_blank(add_tree_index);

        // Now find the node keypair information and make our node in the ratchet tree. The keypair
        // we associate to the new participant is the one that corresponds to our current
        // ciphersuite.
        let public_key = init_key.get_public_key(self.cs)?.ok_or(Error::ValidationError(
            "UserInitKey has no public keys for group's ciphersuite",
        ))?;
        let private_key = init_key.get_private_key(self.cs)?.cloned();

        // The new node we add has the public key we found, and no known secrets
        let new_node = RatchetTreeNode::Filled {
            public_key: public_key.clone(),
            private_key: private_key,
        };

        // Check that we're only overwriting a Blank node.
        let node_to_overwrite = self.tree.get_mut(add_tree_index).unwrap();
        if node_to_overwrite.is_filled() {
            return Err(Error::ValidationError("Add tried to overwrite non-blank node"));
        }

        // Finally, do the overwrite
        *node_to_overwrite = new_node;

        // Alright, we're done with the init_key. Make sure that we don't have our initializing
        // UserInitKey hanging around after this
        // TODO: Make this erasure secure
        self.initializing_user_init_key = None;

        // "The update secret resulting from this change is an all-zero octet string of length
        // Hash.length."
        Ok(UpdateSecret::new(vec![0u8; self.cs.hash_alg.output_len]))
    }

    /// Processes the given `Handshake` and, if successful, produces a new `GroupState` and
    /// associated `ApplicationKeyChain`
    ///
    /// NOTE: This does not mutate the current `GroupState`. Instead, it returns the next version
    /// of the `GroupState`, assuming that the `Handshake` is valid.
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
    pub(crate) fn process_handshake(
        &self,
        handshake: &Handshake,
    ) -> Result<(GroupState, ApplicationKeyChain), Error> {
        if handshake.prior_epoch != self.epoch {
            return Err(Error::ValidationError("Handshake's prior epoch isn't the current epoch"));
        }

        let sender_tree_idx = GroupState::roster_index_to_tree_index(handshake.signer_index)?;
        if sender_tree_idx >= self.tree.size() {
            return Err(Error::ValidationError("Handshake sender tree index is out of range"));
        }

        // Make a preliminary new state and  update its epoch and transcript hash. The state is
        // further mutated in the branches of the match statement below
        let mut new_state = self.clone();
        new_state.update_transcript_hash(&handshake.operation)?;
        new_state.increment_epoch()?;

        let sender_credential = self
            .roster
            .0
            .get(handshake.signer_index as usize)
            .ok_or(Error::ValidationError("Signer index is out of bounds"))?;
        let sender_public_key = sender_credential
            .as_ref()
            .ok_or(Error::ValidationError("Credential at signer's index is empty"))?
            .get_public_key();

        // Do the handshake operation on the preliminary new state. This returns an update secret
        // that the new epoch secrets are derived from.
        let update_secret = match handshake.operation {
            GroupOperation::Update(ref update) => {
                new_state.process_incoming_update_op(update, sender_tree_idx)?
            }
            GroupOperation::Remove(ref remove) => new_state.process_remove_op(remove)?,
            GroupOperation::Add(ref add) => {
                let prior_welcome_info = self.as_welcome_info();
                new_state.process_add_op(add, &prior_welcome_info)?
            }
            GroupOperation::Init(_) => unimplemented!(),
        };

        let (app_secret, confirmation_key_bytes) =
            new_state.update_epoch_secrets(&update_secret)?;

        //
        // Now validate the new state. If it's valid, we set the current state to the new one.
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
        let confirmation_key =
            ring::hmac::VerificationKey::new(new_state.cs.hash_alg, &*confirmation_key_bytes.0);
        let confirmation_data =
            [new_state.transcript_hash.as_slice(), handshake.signature.to_bytes().as_slice()]
                .concat();
        // It's okay to reveal that the MAC is incorrect, because the ring::hmac::verify runs in
        // constant time
        ring::hmac::verify(&confirmation_key, &confirmation_data, &handshake.confirmation)
            .map_err(|_| Error::SignatureError("Handshake confirmation is invalid"))?;

        // All is well. Make the new application key chain and send it along
        let app_key_chain = ApplicationKeyChain::from_application_secret(&new_state, app_secret);
        Ok((new_state, app_key_chain))
    }

    /// Creates and applies a `GroupUpdate` operation, determined by the given inputs. This also
    /// returns the newly derived applications secret and confirmation key.
    pub(crate) fn create_and_apply_update_op(
        &mut self,
        new_path_secret: PathSecret,
        csprng: &mut dyn CryptoRng,
    ) -> Result<(GroupOperation, ApplicationKeyChain, ConfirmationKey), Error> {
        let my_tree_idx = {
            // Safely unwrap the roster index. A preliminary GroupState is one that has just been
            // initialized with a Welcome message
            let roster_index = self.roster_index.ok_or(Error::ValidationError(
                "Cannot make an Update from a preliminary GroupState",
            ))?;
            GroupState::roster_index_to_tree_index(roster_index)?
        };

        // Do the update and increment the epoch
        let update_secret = self.apply_update(new_path_secret.clone(), my_tree_idx)?;
        self.increment_epoch()?;

        // Now package the update into a GroupUpdate structure
        let direct_path_msg =
            self.tree.encrypt_direct_path_secrets(self.cs, my_tree_idx, new_path_secret, csprng)?;
        let update = GroupUpdate {
            path: direct_path_msg,
        };
        let op = GroupOperation::Update(update);

        self.update_transcript_hash(&op)?;

        // Final modification: update my epoch secrets and make the new ApplicationKeyChain
        let (app_secret, confirmation_key) = self.update_epoch_secrets(&update_secret)?;
        let app_key_chain = ApplicationKeyChain::from_application_secret(self, app_secret);

        Ok((op, app_key_chain, confirmation_key))
    }

    /// Creates and applies a `GroupAdd` operation for a member at index `new_roster_index` with
    /// the target `init_key`. This also returns the newly derived applications secret and
    /// confirmation key.
    // Technically, there's no reason that this has to mutate the GroupState, since GroupStates can
    // consume the Add ops they produce (unlike Updates). But for consistency with the other
    // create_*_op functions, this should mutate the GroupState too.
    pub(crate) fn create_and_apply_add_op(
        &mut self,
        new_roster_index: u32,
        init_key: UserInitKey,
        prior_welcome_info: &WelcomeInfo,
    ) -> Result<(GroupOperation, ApplicationKeyChain, ConfirmationKey), Error> {
        // Make the add op
        let prior_welcome_info_hash = {
            let serialized = tls_ser::serialize_to_bytes(prior_welcome_info)?;
            ring::digest::digest(self.cs.hash_alg, &serialized).as_ref().to_vec()
        };
        let add = GroupAdd {
            roster_index: new_roster_index,
            init_key: init_key,
            welcome_info_hash: prior_welcome_info_hash,
        };

        // Apply the Add, log the operation in the transcript hash, increment the epoch, update
        // the epoch secrets, and make the new ApplicationKeyChain
        let update_secret = self.process_add_op(&add, prior_welcome_info)?;
        let op = GroupOperation::Add(add);
        self.update_transcript_hash(&op)?;
        self.increment_epoch()?;
        let (app_secret, confirmation_key) = self.update_epoch_secrets(&update_secret)?;
        let app_key_chain = ApplicationKeyChain::from_application_secret(self, app_secret);

        Ok((op, app_key_chain, confirmation_key))
    }

    /// Creates and applies a `GroupRemove` operation for a member at roster index
    /// `removed_roster_index` and introduces a new path secret `new_path_secret` at the removed
    /// index.
    // Technically, there's no reason that this has to mutate the GroupState, since GroupStates can
    // consume the Remove ops they produce (unlike Updates). But for consistency with the other
    // create_*_op functions, this should mutate the GroupState too.
    pub(crate) fn create_and_apply_remove_op(
        &mut self,
        removed_roster_index: u32,
        new_path_secret: PathSecret,
        csprng: &mut dyn CryptoRng,
    ) -> Result<(GroupOperation, ApplicationKeyChain, ConfirmationKey), Error> {
        let removed_tree_index = GroupState::roster_index_to_tree_index(removed_roster_index)?;
        // Encrypt the new entropy for the tree
        let direct_path_msg = self.tree.encrypt_direct_path_secrets(
            self.cs,
            removed_tree_index,
            new_path_secret,
            csprng,
        )?;

        // Make the remove
        let remove = GroupRemove {
            removed_roster_index: removed_roster_index,
            path: direct_path_msg,
        };

        // Apply the Remove, log the operation in the transcript hash, increment the epoch, update
        // the epoch secrets, and make the new ApplicationKeyChain
        let update_secret = self.process_remove_op(&remove)?;
        let op = GroupOperation::Remove(remove);
        self.update_transcript_hash(&op)?;
        self.increment_epoch()?;
        let (app_secret, confirmation_key) = self.update_epoch_secrets(&update_secret)?;
        let app_key_chain = ApplicationKeyChain::from_application_secret(self, app_secret);

        Ok((op, app_key_chain, confirmation_key))
    }

    /// Creates a `Handshake` message by packaging the given `GroupOperation`.
    ///
    /// NOTE: This is intended to be called only after `create_*_op` is called, where `*` is `add`
    /// or `update` or `remove`. This makes no sense otherwise.
    pub(crate) fn create_handshake(
        &self,
        operation: GroupOperation,
        confirmation_key: ConfirmationKey,
    ) -> Result<Handshake, Error> {
        // signature = Sign(identity_key, GroupState.transcript_hash)
        let signature = self.cs.sig_impl.sign(&self.identity_key, &self.transcript_hash);

        let prior_epoch = self.epoch.checked_sub(1).ok_or(Error::ValidationError(
            "Cannot create a handshake from a brand new GroupState",
        ))?;

        // TODO: Use application_secret for application key schedule
        // Update the epoch secrets and use the resulting key to compute the MAC of the Handshake

        // confirmation = HMAC(confirmation_key, confirmation_data)
        // where confirmation_data = GroupState.transcript_hash || Handshake.signature
        let confirmation = {
            let mac_key = ring::hmac::SigningKey::new(self.cs.hash_alg, &*confirmation_key.0);

            let mut ctx = ring::hmac::SigningContext::with_key(&mac_key);
            ctx.update(&self.transcript_hash);
            ctx.update(&signature.to_bytes());

            ctx.sign()
        };

        // Safely unwrap the roster index. A preliminary GroupState is one that has just been
        // initialized with a Welcome message
        let roster_index = self.roster_index.ok_or(Error::ValidationError(
            "Cannot make a Handshake from a preliminary GroupState",
        ))?;

        let handshake = Handshake {
            prior_epoch: prior_epoch,
            operation: operation,
            signer_index: roster_index,
            signature: signature,
            confirmation: confirmation.as_ref().to_vec(),
        };
        Ok(handshake)
    }
}

// TODO: Make this COW so we don't have to clone everything in GroupState::as_welcome_info

/// Contains everything a new user needs to know to join a group. This is always followed by an
/// `Add` operation.
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
    pub(crate) roster: Roster,

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

/// This contains the encrypted `WelcomeInfo` for new group participants
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Welcome {
    // opaque user_init_key_id<0..255>;
    #[serde(rename = "user_init_key_id__bound_u8")]
    user_init_key_id: Vec<u8>,
    pub(crate) cipher_suite: &'static CipherSuite,
    pub(crate) encrypted_welcome_info: EciesCiphertext,
}

impl Welcome {
    /// Packages up a `WelcomeInfo` object with a preferred cipher suite, and encrypts it to the
    /// specified `UserInitKey` (under the appropriate public key)
    pub(crate) fn from_welcome_info(
        cs: &'static CipherSuite,
        init_key: &UserInitKey,
        welcome_info: &WelcomeInfo,
        csprng: &mut dyn CryptoRng,
    ) -> Result<Welcome, Error> {
        // Get the public key from the supplied UserInitKey corresponding to the given cipher suite
        let public_key = init_key
            .get_public_key(cs)?
            .ok_or(Error::ValidationError("No corresponding public key for given ciphersuite"))?;

        // Serialize and encrypt the WelcomeInfo
        let serialized_welcome_info = tls_ser::serialize_to_bytes(welcome_info)?;
        let ciphertext = ecies_encrypt(cs, &public_key, serialized_welcome_info, csprng)?;

        // All done
        Ok(Welcome {
            user_init_key_id: init_key.user_init_key_id.clone(),
            cipher_suite: cs,
            encrypted_welcome_info: ciphertext,
        })
    }

    /// Decrypts the `Welcome` with the given `UserInitKey` and returns the contained `WelcomeInfo`
    ///
    /// Requires: That the `init_key` is the `UserInitKey` that the `Welcome` was encrypted with
    /// (i.e., `init_key.user_init_key_id == self.user_init_key_id`) and `init_key.private_keys`
    /// is not `None`
    pub(crate) fn into_welcome_info(self, init_key: &UserInitKey) -> Result<WelcomeInfo, Error> {
        // Verify the UserInitKey signature and validate its contents
        init_key.verify_sig()?;
        init_key.validate()?;
        // Verify that the supplied UserInitKey is the one that the Welcome message references
        if self.user_init_key_id != init_key.user_init_key_id {
            return Err(Error::ValidationError("Supplied UserInitKey ID doesn't match Welcome's"));
        }
        // Get the ciphersuite and private key we'll use to decrypt the wrapped WelcomeInfo
        let cs = self.cipher_suite;
        let dh_private_key = init_key
            .get_private_key(cs)?
            .ok_or(Error::ValidationError("Can't decrypt Welcome without a private key"))?;

        // Decrypt the WelcomeInfo, deserialize it, and return it
        let welcome_info_bytes =
            crate::crypto::ecies::ecies_decrypt(cs, dh_private_key, self.encrypted_welcome_info)?;
        let welcome_info = {
            let mut cursor = welcome_info_bytes.as_slice();
            let mut deserializer = TlsDeserializer::from_reader(&mut cursor);
            let mut w = WelcomeInfo::deserialize(&mut deserializer)?;

            // Once it's deserialized, make it nice and typesafe
            w.upcast_crypto_values(&upcast::CryptoCtx::new())?;
            w
        };

        Ok(welcome_info)
    }
}

#[cfg(test)]
mod test {
    use crate::{
        credential::Roster,
        crypto::{
            ciphersuite::{CipherSuite, X25519_SHA256_AES128GCM},
            sig::SignatureScheme,
        },
        error::Error,
        group_state::{GroupState, UpdateSecret, Welcome},
        handshake::{ProtocolVersion, UserInitKey},
        ratchet_tree::RatchetTree,
        tls_de::TlsDeserializer,
        tls_ser,
        utils::test_utils,
    };

    use quickcheck_macros::quickcheck;
    use rand::{RngCore, SeedableRng};
    use serde::de::Deserialize;

    // Checks that
    // GroupState::from_welcome(Welcome::from_welcome_info(group.as_welcome_info())) == group
    #[quickcheck]
    fn welcome_correctness(rng_seed: u64) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(rng_seed);
        // Make a starting group
        let (group_state1, _) = test_utils::random_full_group_state(&mut rng);

        // Make the data necessary for a Welcome message
        let cipher_suites = vec![&X25519_SHA256_AES128GCM];
        let supported_versions: Vec<ProtocolVersion> = vec![0; cipher_suites.len()];
        // These values really don't matter. They're only important if we do anything with the
        // GroupStates after the Welcome
        let (new_credential, new_identity_key) = test_utils::random_basic_credential(&mut rng);
        // Key ID is random
        let user_init_key_id = {
            let mut buf = [0u8; 16];
            rng.fill_bytes(&mut buf);
            buf.to_vec()
        };
        // The UserInitKey has all the key / identity information necessary to add a new member to
        // the group and Welcome them
        let init_key = UserInitKey::new_from_random(
            &new_identity_key,
            user_init_key_id,
            new_credential.clone(),
            cipher_suites,
            supported_versions,
            &mut rng,
        )
        .unwrap();

        // Make the welcome objects
        let cipher_suite = group_state1.cs;
        let welcome_info = group_state1.as_welcome_info();
        let welcome =
            Welcome::from_welcome_info(cipher_suite, &init_key, &welcome_info, &mut rng).unwrap();

        // Now unwrap the Welcome back into a WelcomeInfo and create a GroupState from that. This
        // should be identical to the starting group state, except maybe for the roster_index,
        // credential, initiailizing UserInitKey, and identity key. None of those things are
        // serialized though, since they are unique to each member's perspective
        let welcome_info = welcome.into_welcome_info(&init_key).unwrap();
        let group_state2 =
            GroupState::from_welcome_info(cipher_suite, welcome_info, new_identity_key, init_key);

        // Now see if the resulting group states agree
        let (group1_bytes, group2_bytes) = (
            tls_ser::serialize_to_bytes(&group_state1).unwrap(),
            tls_ser::serialize_to_bytes(&group_state2).unwrap(),
        );
        assert_eq!(group1_bytes, group2_bytes, "GroupStates disagree after a Welcome");
    }

    // This is all the serializable bits of a GroupState. We have this separate because GroupState
    // is only ever meant to be serialized. The fields in it that are for us and not for
    // serialization require a Default instance in order for GroupState to impl Deserialize. Since
    // I don't think that's a good idea, I'll just initialize all those things to 0 myself. See
    // group_from_test_group.
    #[derive(Debug, Deserialize)]
    pub(crate) struct TestGroupState {
        #[serde(rename = "group_id__bound_u8")]
        group_id: Vec<u8>,
        epoch: u32,
        #[serde(rename = "roster__bound_u32")]
        roster: Roster,
        tree: RatchetTree,
        #[serde(rename = "transcript_hash__bound_u8")]
        pub(crate) transcript_hash: Vec<u8>,
    }

    impl crate::upcast::CryptoUpcast for TestGroupState {
        fn upcast_crypto_values(&mut self, ctx: &crate::upcast::CryptoCtx) -> Result<(), Error> {
            self.roster.upcast_crypto_values(ctx)
        }
    }

    // Makes a mostly empty GroupState from a recently-deserialized TestGroupState
    pub(crate) fn group_from_test_group(tgs: TestGroupState) -> GroupState {
        let cs = &X25519_SHA256_AES128GCM;
        GroupState {
            cs: cs,
            protocol_version: 0,
            identity_key: cs.sig_impl.secret_key_from_bytes(&[0u8; 32]).unwrap(),
            group_id: tgs.group_id,
            epoch: tgs.epoch,
            roster: tgs.roster,
            tree: tgs.tree,
            transcript_hash: tgs.transcript_hash,
            roster_index: Some(0),
            initializing_user_init_key: None,
            init_secret: Vec::new(),
        }
    }

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
            let update_secret = UpdateSecret::new(epoch.update_secret);
            let (app_secret, conf_key) = group_state.update_epoch_secrets(&update_secret).unwrap();

            // We don't save the derived epoch_secret anywhere, since it's just an intermediate
            // value. We do test all the things derived from it, though.
            assert_eq!(&*app_secret.0, epoch.application_secret.as_slice());
            assert_eq!(&*conf_key.0, epoch.confirmation_key.as_slice());
            assert_eq!(&*group_state.init_secret, epoch.init_secret.as_slice());

            // Increment the state epoch every time we do a key derivation. This is what happens in
            // the actual protocol.
            group_state.epoch += 1;
        }
    }
}
