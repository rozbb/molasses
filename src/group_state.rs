use crate::{
    credential::{Credential, Identity},
    crypto::{ciphersuite::CipherSuite, hkdf, sig::SigSecretKey},
    error::Error,
    handshake::{GroupOperation, Handshake},
    ratchet_tree::RatchetTree,
    tree_math,
};

/// These are a bunch of secrets derived from `epoch_secret` via HKDF-Expand. See section 5.9.
pub(crate) struct EpochSecrets {
    /// The initial secret used to derive all the rest
    pub(crate) init_secret: Vec<u8>,

    /// Used for deriving enryption keys in the Message Protection Layer
    pub(crate) application_secret: Vec<u8>,

    /// Used for computing MACs over `Handshake` messages
    pub(crate) confirmation_key: Vec<u8>,
}

/// This is like a patch that can be applied to a GroupState object via `GroupState::apply_delta`.
/// This only contains values that would be updated in a normal group operation.
struct GroupStateDelta {
    epoch: u32,
    transcript_hash: Vec<u8>,
    tree: Option<RatchetTree>,
    epoch_secrets: EpochSecrets,
}

/// Contains all group state
#[derive(Serialize)]
pub(crate) struct GroupState {
    /// You can think of this as a context variable. It helps us implement crypto ops and
    /// disambiguate serialized data structures
    #[serde(skip)]
    pub(crate) cs: &'static CipherSuite,

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

    /// Swaps out all the none-`None` values in the delta with the corresponding values in the
    /// `GroupState`. The returned object contains all the old values. So to rollback a delta
    /// application, you just apply the delta you received from the first invocation.
    fn apply_delta(&mut self, delta: GroupStateDelta) -> GroupStateDelta {
        // Replace all the values
        let old_epoch = core::mem::replace(&mut self.epoch, delta.epoch);
        let old_transcript_hash =
            core::mem::replace(&mut self.transcript_hash, delta.transcript_hash);
        let old_tree = delta.tree.map(|t| core::mem::replace(&mut self.tree, t));
        let old_epoch_secrets = core::mem::replace(&mut self.epoch_secrets, delta.epoch_secrets);

        // Return a delta with the old values
        GroupStateDelta {
            epoch: old_epoch,
            transcript_hash: old_transcript_hash,
            tree: old_tree,
            epoch_secrets: old_epoch_secrets,
        }
    }

    /// Derives the next generation of Group secrets as per section 5.9 in the spec
    pub fn derive_epoch_secrets(&self, update_secret: &[u8]) -> Result<EpochSecrets, Error> {
        // epoch_secret = HKDF-Extract(salt=init_secret_[n-1] (or 0), ikm=update_secret)
        let salt = hkdf::prk_from_bytes(self.cs.hash_alg, &self.epoch_secrets.init_secret);
        let epoch_secret: ring::hmac::SigningKey = hkdf::hkdf_extract(&salt, &update_secret);

        let serialized_self = crate::tls_ser::serialize_to_bytes(self)?;

        let res = EpochSecrets {
            // application_secret = Derive-Secret(epoch_secret, "app", GroupState_[n])
            application_secret: hkdf::derive_secret(&epoch_secret, b"app", &serialized_self),
            // confirmation_key = Derive-Secret(epoch_secret, "confirm", GroupState_[n])
            confirmation_key: hkdf::derive_secret(&epoch_secret, b"confirm", &serialized_self),
            // init_secret_[n] = Derive-Secret(epoch_secret, "init", GroupState_[n])
            init_secret: hkdf::derive_secret(&epoch_secret, b"init", &serialized_self),
        };
        Ok(res)
    }

    /// Converts an index into the participant roster to an index to the corresponding leaf node of
    /// the ratchet tree
    fn roster_index_to_tree_index(signer_index: u32) -> u32 {
        // This is easy. The nth leaf node is at position 2n
        signer_index.checked_mul(2).expect("roster/tree size invariant violated")
    }

    /// Performs and validates an update operation on the `GroupState`.
    ///
    /// Requires: `update_op` is a `GroupOperation::Update` variant.
    ///
    /// Returns: `Ok(delta)` on success, where `delta` contains all the changes to the
    /// `GroupState`. Otherwise, returns some sort of `Error`.
    fn process_update(
        &self,
        update_op: &GroupOperation,
        sender_tree_idx: u32,
    ) -> Result<GroupStateDelta, Error> {
        // We do three things: compute the new ratchet tree, compute the new transcript hash, and
        // compute the new epoch secrets. We shove all these new values into a delta. To validate
        // the operation, we check that the derived public keys match the ones in the message. If
        // they do not, this is an error.

        // Compute the new transcript hash
        // From section 5.7: transcript_hash_[n] = Hash(transcript_hash_[n-1] || operation)
        let new_transcript_hash = {
            let operation_bytes = crate::tls_ser::serialize_to_bytes(update_op)?;
            let mut ctx = ring::digest::Context::new(self.cs.hash_alg);
            ctx.update(&self.transcript_hash);
            ctx.update(&operation_bytes);
            ctx.finish().as_ref().to_vec()
        };

        // The only reason we required that update_op is a GroupOperation is because
        // transcript_hash needs to be computed over a GroupOperation object.
        let update = enum_variant!(update_op, GroupOperation::Update);

        // Decrypt the path secret from the GroupUpdate and propogate it through our tree
        // Recall that roster_index is just another (IMO clearer) name for signer_index
        let my_tree_idx = GroupState::roster_index_to_tree_index(self.roster_index);
        let mut new_tree = self.tree.clone();
        let (path_secret, ancestor_idx) = new_tree.decrypt_direct_path_message(
            self.cs,
            &update.path,
            sender_tree_idx as usize,
            my_tree_idx as usize,
        )?;
        new_tree.propogate_new_path_secret(self.cs, path_secret, ancestor_idx)?;

        // We update the epoch secrets using the root node secret as the update secret.
        // That's a lot of secrets
        let new_epoch_secrets = {
            let root_node = new_tree.get_root_node().expect("tried to update empty tree");
            let root_node_secret = root_node.get_node_secret().expect("root node has no secret");
            self.derive_epoch_secrets(root_node_secret)?
        };

        // Now for update validation. Make the updated tree immutable for this step
        let new_tree = new_tree;
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

        let new_epoch = self
            .epoch
            .checked_add(1)
            .ok_or(Error::GroupOpError("Cannot increment epoch past its maximum"))?;

        // All this new info goes into a delta
        let delta = GroupStateDelta {
            epoch: new_epoch,
            transcript_hash: new_transcript_hash,
            tree: Some(new_tree),
            epoch_secrets: new_epoch_secrets,
        };

        Ok(delta)
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
    pub(crate) fn process_handshake(&mut self, handshake: &Handshake) -> Result<(), Error> {
        if handshake.prior_epoch != self.epoch {
            return Err(Error::GroupOpError("Handshake's prior epoch isn't the current epoch"));
        }
        let sender_credential = self
            .roster
            .get(handshake.signer_index as usize)
            .ok_or(Error::GroupOpError("Signer index is out of bounds"))?;
        let sender_public_key = sender_credential
            .as_ref()
            .ok_or(Error::GroupOpError("Credential at signer's index is empty"))?
            .get_public_key();

        let delta = match &handshake.operation {
            update_op @ &GroupOperation::Update(_) => {
                let sender_tree_idx =
                    GroupState::roster_index_to_tree_index(handshake.signer_index);
                self.process_update(update_op, sender_tree_idx)?
            }
            _ => unimplemented!(),
        };

        //
        // Now validate the delta
        //

        // Check the signature. From section 7 of the spec:
        // signature_data = GroupState.transcript_hash
        // Handshake.signature = Sign(identity_key, signature_data)
        let sig_data = &delta.transcript_hash;
        self.cs.sig_impl.verify(sender_public_key, sig_data, &handshake.signature)?;

        // Check the MAC. From section 7 of the spec:
        // confirmation_data = GroupState.transcript_hash || Handshake.signature
        // Handshake.confirmation = HMAC(confirmation_key, confirmation_data)
        let conf_key = ring::hmac::VerificationKey::new(
            self.cs.hash_alg,
            &self.epoch_secrets.confirmation_key,
        );
        let conf_data =
            [self.transcript_hash.as_slice(), handshake.signature.to_bytes().as_slice()].concat();
        // It's okay to reveal that the MAC is incorrect, because the ring::hmac::verify runs in
        // constant time
        ring::hmac::verify(&conf_key, &conf_data, &handshake.confirmation)
            .map_err(|_| Error::SignatureError("Handshake confirmation is invalid"))?;

        //
        // If we've made it this far. We commit the changes
        //

        self.apply_delta(delta);
        Ok(())
    }
}

/// Contains everything a new user needs to know to join a Group
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct WelcomeInfo {
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
            let derived_secrets = group_state.derive_epoch_secrets(&epoch.update_secret).unwrap();

            // We don't save the derived epoch_secret anywhere, since it's just an intermediate
            // value. We do test all the things derived from it, though.
            assert_eq!(&derived_secrets.application_secret, &epoch.application_secret);
            assert_eq!(&derived_secrets.confirmation_key, &epoch.confirmation_key);
            assert_eq!(&derived_secrets.init_secret, &epoch.init_secret);

            // Save the new derived secrets
            group_state.epoch_secrets = derived_secrets;

            // Increment the state epoch every time we do a key derivation. This is what happens in
            // the actual protocol.
            group_state.epoch += 1;
        }
    }
}
