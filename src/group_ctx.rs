//! Defines the `GroupContext` object, which is the primary interface for creating and processing
//! MLS group operations

use crate::{
    application::ApplicationKeyChain,
    client_init_key::{ClientInitKey, ProtocolVersion},
    credential::Credential,
    crypto::{
        ciphersuite::CipherSuite,
        dh::{DhPrivateKey, DhPublicKey},
        hash::{Digest, HashFunction},
        hkdf::{self, HkdfPrk, HkdfSalt},
        hmac::{self, HmacKey},
        hpke::{self, HpkeCiphertext},
        rng::CryptoRng,
        sig::{SigSecretKey, SignatureScheme},
    },
    error::Error,
    framing::Framer,
    handshake::{GroupAdd, GroupInit, GroupOperation, GroupRemove, GroupUpdate, Handshake},
    ratchet_tree::{LeafNode, MemberIdx, MemberInfo, PathSecret, RatchetTree},
    tls_de::TlsDeserializer,
    tls_ser,
    tree_math::TreeIdx,
    upcast::{CryptoCtx, CryptoUpcast},
};

use core::convert::TryInto;

use serde::de::Deserialize;
use subtle::ConstantTimeEq;

/// The secret used to seed the symmetric ratchet called `ApplicationKeyChain`
pub(crate) struct ApplicationSecret(HkdfPrk);

impl ApplicationSecret {
    pub(crate) fn new(prk: HkdfPrk) -> ApplicationSecret {
        ApplicationSecret(prk)
    }
}

// ApplicationSecret --> HkdfPrk trivially
impl<'a> From<&'a ApplicationSecret> for &'a HkdfPrk {
    fn from(s: &'a ApplicationSecret) -> &'a HkdfPrk {
        &s.0
    }
}

/// The secret used to generate the key/nonce to encrypt sender metadata
pub(crate) struct SenderDataSecret(HkdfPrk);

impl SenderDataSecret {
    pub(crate) fn new(prk: HkdfPrk) -> SenderDataSecret {
        SenderDataSecret(prk)
    }
}

// SenderDataSecret --> HkdfPrk trivially
impl<'a> From<&'a SenderDataSecret> for &'a HkdfPrk {
    fn from(s: &'a SenderDataSecret) -> &'a HkdfPrk {
        &s.0
    }
}

/// The secret used to generate the key/nonce to encrypt `Handshake` messages
pub(crate) struct HandshakeSecret(HkdfPrk);

impl HandshakeSecret {
    pub(crate) fn new(prk: HkdfPrk) -> HandshakeSecret {
        HandshakeSecret(prk)
    }
}

// HandshakeSecret --> HkdfPrk trivially
impl<'a> From<&'a HandshakeSecret> for &'a HkdfPrk {
    fn from(s: &'a HandshakeSecret) -> &'a HkdfPrk {
        &s.0
    }
}

/// This is called the `confirmation_key` in the MLS key schedule
pub(crate) struct ConfirmationKey(HmacKey);

impl ConfirmationKey {
    fn new(key: HmacKey) -> ConfirmationKey {
        ConfirmationKey(key)
    }
}

// ConfirmationKey --> HmacKey trivially
impl<'a> From<&'a ConfirmationKey> for &'a HmacKey {
    fn from(s: &'a ConfirmationKey) -> &'a HmacKey {
        &s.0
    }
}

/// This is called the `update_secret` in the MLS key schedule. It's used to derive epoch secrets
/// in `update_epoch_secrets`.
pub(crate) struct UpdateSecret(Vec<u8>);

impl UpdateSecret {
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The update secret is all zeros after Add operations, with length `Hash.length`
    fn new_from_zeros(hash_impl: &HashFunction) -> UpdateSecret {
        UpdateSecret(vec![0u8; hash_impl.digest_size()])
    }
}

// PathSecret --> UpdateSecret by rewrapping the underlying vector
impl From<PathSecret> for UpdateSecret {
    fn from(n: PathSecret) -> UpdateSecret {
        // This will panic iff n is of the HkdfPrk::Opaque variant. That should never happen, since
        // the only thing that should ever be Opaque is epoch_secret, since that is derived from an
        // HKDF-Extract operation.
        UpdateSecret((n.0).as_bytes().to_vec())
    }
}

// From the definition of GroupContext: opaque group_id<0..255>;
/// An application-defined identifier for a group
#[derive(Clone, Deserialize, Serialize)]
#[cfg_attr(test, derive(Debug))]
#[serde(rename = "GroupId__bound_u8")]
pub struct GroupId(Vec<u8>);

impl GroupId {
    pub fn new(v: Vec<u8>) -> Result<GroupId, Error> {
        if v.len() > 255 {
            return Err(Error::ValidationError("Cannot make a GroupID of length > 255"));
        } else {
            Ok(GroupId(v))
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

// Do constant-time comparison by comparing the vectors
impl subtle::ConstantTimeEq for GroupId {
    fn ct_eq(&self, other: &GroupId) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

/// Contains all group context
#[derive(Clone, Serialize)]
pub struct GroupContext {
    /// The ciphersuite of this group. You can think of this as a context variable. It helps us
    /// implement crypto ops and disambiguate serialized data structures
    #[serde(skip)]
    pub(crate) cs: &'static CipherSuite,

    /// Version info
    #[serde(skip)]
    pub(crate) protocol_version: ProtocolVersion,

    /// This member's long-lived signing key, used to authenticate the sender of a message
    #[serde(skip)]
    pub(crate) identity_key: SigSecretKey,

    /// An application-defined identifier for the group
    pub group_id: GroupId,

    /// Represents the current version of the group key
    pub(crate) epoch: u32,

    /// Contains the hash of the root node of the ratchet tree
    pub(crate) tree_hash: Digest,

    /// Contains a running hash of `GroupOperation` messages that led to this state
    pub(crate) transcript_hash: Digest,

    /// The tree field contains the public keys corresponding to the nodes of the ratchet tree for
    /// this group
    #[serde(skip)]
    pub(crate) tree: RatchetTree,

    /// The member's position in the list of group members, i.e., the member's leaf index. This is
    /// also known as `signer_index`. It is `None` iff this `GroupContext` is in a preliminary
    /// state, i.e., iff it is between a `Welcome` and `Add` operation.
    #[serde(skip)]
    pub(crate) member_index: Option<MemberIdx>,

    /// The `ClientInitKey` used in the creation of this group from a `Welcome`. This is `Some` iff
    /// this `GroupContext` is in a preliminary state, i.e., if it is between a `Welcome` and `Add`
    /// operation.
    #[serde(skip)]
    pub(crate) initializing_client_init_key: Option<ClientInitKey>,

    /// The initial secret used to derive `application_secret` and `confirmation_key`
    #[serde(skip)]
    pub(crate) init_secret: HkdfSalt,
}

impl GroupContext {
    /// Creates a new one-person `GroupContext` from this member's information and some group
    /// information.
    ///
    /// Returns: `Ok((group_ctx, framer))` on success. If there was an issue creating an ephemeral
    /// private key, returns some sort of `Error`. If `my_credential` cannot be serialized, returns
    /// an `Error::SerdeError`.
    pub fn new_singleton_group<R>(
        cs: &'static CipherSuite,
        protocol_version: ProtocolVersion,
        identity_key: SigSecretKey,
        group_id: GroupId,
        my_credential: Credential,
        csprng: &mut R,
    ) -> Result<(GroupContext, Framer), Error>
    where
        R: CryptoRng,
    {
        // This is the only node there is
        let my_member_idx = MemberIdx::new(0);

        // Make an ephemeral keypair and turn it into a tree
        let tree = {
            let my_ephemeral_secret = DhPrivateKey::new_from_random(cs.dh_impl, csprng)?;
            let my_node =
                LeafNode::new_from_private_key(cs.dh_impl, my_credential, my_ephemeral_secret);
            RatchetTree::new_singleton(cs.hash_impl, my_node)?
        };

        // Now make the GroupContext normally
        let group_ctx = GroupContext::new_from_parts(
            cs,
            protocol_version,
            identity_key,
            group_id,
            tree,
            my_member_idx,
        )?;

        // Now make a Framer with arbitrarily chosen secrets. Ordinarily, these would be derived
        // from the epoch_secret, which itself is derived from init_secret and update_secret. But
        // this is a brand new group, and there is no update_secret to speak of. So we pick
        // arbitrary values for handshake_secret and sender_data_secret, because the only logical
        // operation we can do is an Add, in which we explicitly tell the Addee these secrets in
        // WelcomeInfo::add_unframing_secrets.
        let framer = {
            let handshake_secret = {
                let prk = HkdfPrk::new_from_random(cs.hash_impl, csprng);
                HandshakeSecret(prk)
            };
            let sender_data_secret = {
                let prk = HkdfPrk::new_from_random(cs.hash_impl, csprng);
                SenderDataSecret(prk)
            };
            Framer::new(&group_ctx, handshake_secret, sender_data_secret)
        };

        Ok((group_ctx, framer))
    }

    /// Creates a new `GroupContext` from its constituent parts
    ///
    /// Returns: `Ok(group_ctx)` on success. If there is an issue computing the hash of the
    /// serialized `tree`, returns an `Error::SerdeError`.
    pub(crate) fn new_from_parts(
        cs: &'static CipherSuite,
        protocol_version: ProtocolVersion,
        identity_key: SigSecretKey,
        group_id: GroupId,
        tree: RatchetTree,
        my_idx: MemberIdx,
    ) -> Result<GroupContext, Error> {
        // Transcript hash and init secrets are both zeros to begin with
        let transcript_hash = Digest::new_from_zeros(cs.hash_impl);
        let init_secret = HkdfSalt::new_from_zeros(cs.hash_impl);
        let tree_hash = tree.tree_hash()?;

        Ok(GroupContext {
            cs,
            protocol_version,
            identity_key,
            group_id,
            epoch: 0,
            tree,
            tree_hash,
            transcript_hash,
            member_index: Some(my_idx),
            initializing_client_init_key: None,
            init_secret,
        })
    }

    /// Creates a new `GroupContext` and corresponding `Init` object to send to other members
    ///
    /// Returns: `Ok((group_ctx, app_key_chain, group_op, confirmation_key))` on success, where
    /// `group_ctx` is the group context after having applied the Init operation, `app_key_chain`
    /// is the resulting application key chain (again, after having applied the init operation),
    /// `group_op` is a `GroupOperation` with the `Init` variant, and `confirmation_key` is the
    /// derived confirmation key we'll use to compute the MAC in the `Handshake` that will end up
    /// containing the `Init`.
    pub(crate) fn new_with_init<R>(
        cs: &'static CipherSuite,
        protocol_version: ProtocolVersion,
        identity_key: SigSecretKey,
        group_id: GroupId,
        members: Vec<ClientInitKey>,
        my_idx: MemberIdx,
        csprng: &mut R,
    ) -> Result<(GroupContext, Framer, ApplicationKeyChain, GroupOperation, ConfirmationKey), Error>
    where
        R: CryptoRng,
    {
        // Let the GroupInit constructor make an GroupInit object and also construct the ratchet
        // tree for us. This constructor also generates and propagates our path secret through the
        // tree.  We'll use the tree and send out the GroupInit.
        let (init, tree, update_secret) =
            GroupInit::new(cs, protocol_version, group_id.clone(), members, my_idx, csprng)?;
        let op = GroupOperation::Init(init);

        // We now have all the info to make a group context
        let mut group_ctx = GroupContext::new_from_parts(
            cs,
            protocol_version,
            identity_key,
            group_id,
            tree,
            my_idx,
        )?;

        // Log the operation in the transcript hash, update the tree hash, and increment the epoch
        // counter
        group_ctx.update_transcript_hash(&op)?;
        group_ctx.update_tree_hash()?;
        group_ctx.increment_epoch()?;

        // Update the epoch secrets, and make the new ApplicationKeyChain and framer
        let (app_secret, sender_data_secret, handshake_secret, confirmation_key) =
            group_ctx.update_epoch_secrets(&update_secret)?;
        let framer = Framer::new(&group_ctx, handshake_secret, sender_data_secret);
        let app_key_chain = ApplicationKeyChain::new(&group_ctx, app_secret);

        Ok((group_ctx, framer, app_key_chain, op, confirmation_key))
    }

    /// Initializes a preliminary `GroupContext` with the given `WelcomeInfo` information, this
    /// member's identity key, and the `ClientInitKey` used to encrypt the `Welcome` that the
    /// `WelcomeInfo` came from.
    ///
    /// Returns: `Ok(group_ctx)` on success, where `group_ctx` is a `GroupContext` in a
    /// "preliminary state", meaning that `member_index` is `None` and
    /// `initializing_client_init_key` is `Some`. The only thing to do with a preliminary
    /// `GroupContext` is give it an `Add` operation to add yourself to it. If there was an error
    /// in converting the ratchet tree in the given `WelcomeInfo` to a real `RatchetTree`, this
    /// returns some other `Error`.
    // This is different from new_from_parts in that the epoch is not 0, the transcript hash is not
    // 0, the init secret is not 0, and the member index is None
    pub(crate) fn from_welcome_info(
        cs: &'static CipherSuite,
        w: WelcomeInfo,
        my_identity_key: SigSecretKey,
        initializing_client_init_key: ClientInitKey,
    ) -> Result<GroupContext, Error> {
        let tree = RatchetTree::new_from_welcome_info_ratchet_tree(cs.hash_impl, w.tree)?;
        let tree_hash = tree.tree_hash()?;
        // Make a new preliminary group (notice how member_index is None and
        // initializing_client_init_key is Some)
        Ok(GroupContext {
            cs,
            protocol_version: w.protocol_version,
            identity_key: my_identity_key,
            group_id: w.group_id,
            epoch: w.epoch,
            tree_hash,
            transcript_hash: w.transcript_hash,
            tree,
            member_index: None,
            initializing_client_init_key: Some(initializing_client_init_key),
            init_secret: w.init_secret,
        })
    }

    /// Creates a new `GroupContext` from a `Welcome` message, this member's identity key, and the
    /// `ClientInitKey` this member used to introduce themselves to the group
    ///
    /// Requires: That the `init_key` is the `ClientInitKey` that the `Welcome` was encrypted with
    /// (i.e., `init_key.client_init_key_id == self.client_init_key_id`) and `init_key.private_keys`
    /// is not `None`
    // This is just a convenient wrapper around welcome.into_welcome_info_cipher_suite and
    // GroupContext::from_welcome_info
    pub fn from_welcome(
        welcome: Welcome,
        identity_secret_key: SigSecretKey,
        init_key: ClientInitKey,
    ) -> Result<GroupContext, Error> {
        // Decrypt the `WelcomeInfo` and make a group out of it
        let (welcome_info, cipher_suite) = welcome.into_welcome_info_cipher_suite(&init_key)?;
        GroupContext::from_welcome_info(cipher_suite, welcome_info, identity_secret_key, init_key)
    }

    /// Creates a `WelcomeInfo` object with all the current state information
    fn as_welcome_info(&self) -> WelcomeInfo {
        let wi_tree = WelcomeInfoRatchetTree::from(&self.tree);
        WelcomeInfo {
            protocol_version: self.protocol_version,
            group_id: self.group_id.clone(),
            epoch: self.epoch,
            tree: wi_tree,
            transcript_hash: self.transcript_hash.clone(),
            init_secret: self.init_secret.clone(),
        }
    }

    /// Returns the signature scheme of this member of the group. This is determined by the
    /// signature scheme of this member's credential.
    pub(crate) fn get_my_signature_scheme(&self) -> &'static SignatureScheme {
        // We look for our credential first, since this contains our signature scheme. If this is a
        // preliminary group, i.e., if this group was just created from a WelcomeInfo, then we
        // don't know our member index, so we can't get our credential from the tree. In this case,
        // we look in the initializing ClientInitKey for our credential. For any valid GroupContext,
        // precisely one of these has to happen, so this function is always well-defined.

        let my_credential = if let Some(member_idx) = self.member_index {
            // My own member information. This better be in range and non-Blank, otherwise this a
            // very broken GroupContext, and does not merit a nice Error
            let my_leaf: Option<&MemberInfo> = self
                .tree
                .get_member_info(member_idx)
                .expect("this member's member index is out of bounds");
            // My own credential. This also better exist.
            &my_leaf.expect("this member's leaf entry is empty").credential
        } else {
            // initializing_client_init_key is Some iff self.member_index is None
            let cik = self
                .initializing_client_init_key
                .as_ref()
                .expect("group has no member index or initializing client init key");
            &cik.credential
        };

        my_credential.get_signature_scheme()
    }

    /// Increments the epoch counter by 1
    ///
    /// Returns: An `Error::ValidationError` if the epoch value is at its max
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
    fn update_transcript_hash(&mut self, operation: &GroupOperation) -> Result<(), Error> {
        // Compute the new transcript hash
        // From section 5.7: transcript_hash_[n] = Hash(transcript_hash_[n-1] || operation)
        self.transcript_hash = {
            let mut ctx = self.cs.hash_impl.new_context();
            ctx.feed_bytes(self.transcript_hash.as_bytes());
            ctx.feed_serializable(&operation)?;
            ctx.finalize()
        };

        Ok(())
    }

    /// Computes and updates the ratchet tree hash. This should be run after every modification to
    /// `self.tree`
    ///
    /// Returns: An `Error::SerdeError` iff there was an issue during serialization
    fn update_tree_hash(&mut self) -> Result<(), Error> {
        // Set the tree hash to the hash of the root node of the ratchet tree
        self.tree_hash = self.tree.tree_hash()?;
        Ok(())
    }

    /// Derives and sets the next generation of Group secrets as per the "Key Schedule" section of
    /// the spec. Specifically, this sets the init secret of the group, and returns the derived app
    /// secret, sender secret, handshake secret, and confirmation key. This is done this way
    /// because init_secret has to be remembered in the `GroupCtx`, and the rest of the values have
    /// to be used in framing and encrypting application/handshake messages.
    fn update_epoch_secrets(
        &mut self,
        update_secret: &UpdateSecret,
    ) -> Result<(ApplicationSecret, SenderDataSecret, HandshakeSecret, ConfirmationKey), Error>
    {
        // epoch_secret = HKDF-Extract(salt=init_secret_[n-1] (or 0), ikm=update_secret)
        let ikm = update_secret.as_bytes();
        let epoch_secret = hkdf::extract(self.cs.hash_impl, &self.init_secret, ikm);

        // Set my new init_secret first. We don't have to worry about this update affecting
        // subsequent serializations of this GroupContext object in the lines below, since
        // init_secret is not included in the serialized form of a GroupContext.

        // init_secret_[n] = Derive-Secret(epoch_secret, "init", GroupContext_[n])
        self.init_secret = hkdf::derive_secret(self.cs, &epoch_secret, b"init", self)?;

        // application_secret = Derive-Secret(epoch_secret, "app", GroupContext_[n])
        let app_secret: HkdfPrk = hkdf::derive_secret(self.cs, &epoch_secret, b"app", self)?;

        // confirmation_key = Derive-Secret(epoch_secret, "confirm", GroupContext_[n])
        let conf_key: HmacKey = hkdf::derive_secret(self.cs, &epoch_secret, b"confirm", self)?;

        // sender_data_secret = Derive-Secret(., "sender data", GroupContext_[n])
        let sender_data_secret: HkdfPrk =
            hkdf::derive_secret(self.cs, &epoch_secret, b"sender data", self)?;

        // handshake_secret = Derive-Secret(., "handshake", GroupContext_[n])
        let handshake_secret: HkdfPrk =
            hkdf::derive_secret(self.cs, &epoch_secret, b"handshake", self)?;

        Ok((
            ApplicationSecret::new(app_secret),
            SenderDataSecret::new(sender_data_secret),
            HandshakeSecret::new(handshake_secret),
            ConfirmationKey::new(conf_key),
        ))
    }

    /// Performs and validates an incoming (i.e., one we did not generate) Update operation on the
    /// `GroupContext`, where `sender_tree_idx` is the tree index of the sender of this operation
    ///
    /// Returns: `Ok(update_secret)` on success, where `update_secret` is the update secret
    /// necessary for generating new epoch secrets.
    fn process_incoming_update_op(
        &mut self,
        update: &GroupUpdate,
        sender_idx: MemberIdx,
    ) -> Result<UpdateSecret, Error> {
        // We apply the new values to the ratchet tree, and compute the new epoch secrets. To
        // validate the operation, we check that the derived public keys match the ones in the
        // message. If they do not, this is an error.

        // Safely unwrap the member index. A preliminary GroupContext is one that has just been
        // initialized with a Welcome message
        let my_member_idx = self
            .member_index
            .ok_or(Error::ValidationError("Cannot do an Update on a preliminary GroupContext"))?;

        // Decrypt the path secret from the GroupUpdate and propagate it through our tree. "The
        // update_secret resulting from this change is the path_secret[i+1] derived from the
        // path_secret[i] associated to the root node."
        let (path_secret, common_ancestor) = self.tree.decrypt_direct_path_message(
            self.cs,
            &update.path,
            sender_idx,
            my_member_idx,
        )?;
        let update_secret: UpdateSecret =
            self.tree.propagate_new_path_secret(self.cs, path_secret, common_ancestor)?.into();

        // Update all the public keys of the nodes in the direct path that are below our common
        // ancestor, i.e., all the ones whose secret we don't know. Note that this step is not
        // performed in propagate_new_path_secret, because this only happens when we're not the
        // ones who created the Update operation.
        let direct_path_public_keys =
            update.path.node_messages.iter().map(|node_msg| &node_msg.public_key);
        self.tree.set_public_keys_with_bound(
            sender_idx,
            common_ancestor,
            direct_path_public_keys.clone(),
        )?;

        // Make sure the public keys in the message match the ones we derived
        self.tree.validate_direct_path_public_keys(sender_idx, direct_path_public_keys)?;

        // All done
        Ok(update_secret)
    }

    /// Performs and validates Remove operation on the `GroupContext`. This will (necessarily) error
    /// if this member is the one being removed.
    ///
    /// Returns: `Ok(update_secret)` on success, where `update_secret` is the update secret
    /// necessary for generating new epoch secrets. Returns an `Error::IAmRemoved` iff this member
    /// is the one who has been removed. Otherwise returns some other kind of `Error`.
    fn process_incoming_remove_op(
        &mut self,
        remove: &GroupRemove,
        sender_idx: MemberIdx,
    ) -> Result<UpdateSecret, Error> {
        let removed_member_idx = remove.removed_member_index;
        let my_member_idx = self
            .member_index
            .ok_or(Error::ValidationError("Cannot do a Remove on a preliminary GroupContext"))?;

        if my_member_idx == removed_member_idx {
            // Oh no, we've been kicked! May as well throw an error now, since we wouldn't be able
            // to decrypt the DirectPathMessage anyway; path secrets are not encrypted for
            // Blanked-out nodes.
            return Err(Error::IAmRemoved);
        }

        // Game plan as per the spec:
        // * Update the ratchet tree by setting to blank all nodes in the direct path of the
        //   removed leaf, and also setting the root node to blank
        // * Truncate the tree such that the rightmost non-blank leaf is the last node of the tree
        // * Update the ratchet tree by replacing nodes in the direct path from the sender’s leaf
        //   using the information in the Remove message

        // Blank out the removed node and the rest of its extended direct path
        self.tree.propagate_blank(removed_member_idx)?;

        // Try to prune the blanks from the end. Finding yourself in an empty group after a Remove
        // operation should be an impossible state.
        self.tree.truncate_to_last_nonblank();

        let upd = GroupUpdate {
            path: remove.path.clone(),
        };
        self.process_incoming_update_op(&upd, sender_idx)
    }

    /// Performs and validates an Add operation on the `GroupContext`. Requires a `WelcomeInfo`
    /// representing the `GroupContext` before this handshake was received.
    ///
    /// Requires: If the member being added is this member, then this `GroupContext` must be
    /// "preliminary", i.e., its `member_index` must be `None`, i.e., it must have just been
    /// created from a `Welcome`.
    ///
    /// Returns: `Ok(update_secret)` on success, where `update_secret` is the update secret
    /// necessary for generating new epoch secrets.
    // NOTE: There is no corresponding "apply_add" method because the creator of an Add is able to
    // process the Add, whereas the creator of an Update cannot process their own operation (this
    // is because the creator's own path secret is never put into the DirectPathMessage).
    fn process_add_op(
        &mut self,
        add: &GroupAdd,
        prior_welcome_info_hash: &WelcomeInfoHash,
    ) -> Result<UpdateSecret, Error> {
        // What we have to do, in order
        // 1. If the index value is equal to the size of the group, extend the tree accordingly
        // 2. Verify the signature on the included ClientInitKey and abort on failure
        // 3. Verify that the hash of a WelcomeInfo object describing the state prior to the add is
        //    the same as the value of the welcome_info_hash field
        // 4. Update the ratchet tree by blanking all nodes in the extended direct path of the new
        //    node
        // 5. Set the leaf node in the tree at position index to a new node containing the public
        //    key from the ClientInitKey in the Add corresponding to the ciphersuite in use, as
        //    well as the credential under which the ClientInitKey was signed

        // Check for out-of-bounds condition
        let add_member_idx = add.member_index;
        if add_member_idx > self.tree.num_leaves() {
            return Err(Error::ValidationError("Invalid insertion index in Add operation"));
        }

        // Constant-time compare the WelcomeInfo hashes (no reason for constant-time other than it
        // feels icky not to do it)
        let hashes_match: bool = prior_welcome_info_hash.ct_eq(&add.welcome_info_hash).into();
        if !hashes_match {
            return Err(Error::ValidationError("Invalid WelcomeInfo hash in Add operation"));
        }

        // Check if we're a "preliminary" GroupContext, i.e., whether or not we were just created
        // by a Welcome. This is true iff self.member_index is null and iff
        // self.initializing_client_init_key is non-null.
        let is_preliminary = self.member_index.is_none();

        // Check all the ClientInitKeys involved
        add.init_key.verify_sig()?;
        add.init_key.validate()?;
        self.initializing_client_init_key.as_ref().map(|cik| cik.verify_sig()).transpose()?;
        self.initializing_client_init_key.as_ref().map(|cik| cik.validate()).transpose()?;

        // If we just received a WelcomeInfo, we want to use the ClientInitKey we created, since it
        // contains the private key to our ratchet tree node
        let init_key = if is_preliminary {
            let cik = self.initializing_client_init_key.as_ref().ok_or(Error::ValidationError(
                "Preliminary GroupContext has no initializing ClientInitKey",
            ))?;
            // If it's an initializing key, let's make sure that its ID matches that of the
            // provided ClientInitKey
            if cik.client_init_key_id != add.init_key.client_init_key_id {
                return Err(Error::ValidationError(
                    "Add's ClientInitKey and GroupContext's initialized ClientInitKey differ",
                ));
            }
            cik
        } else {
            &add.init_key
        };

        // Is this an appending Add or is it an in-place Add? If in-place, we have to make sure
        // we're not overwriting any existing members in the group
        let is_append = add_member_idx == self.tree.num_leaves();
        // Update the tree. We add a new blank node in the correct position, propogate the blank,
        // then set the leaf node to the appropriate value
        if is_append {
            // If we're adding a new node to the end of the tree, we have to make new nodes.
            // The unwrap() is fine because a Blank leaf can't fail to serialize.
            self.tree.add_leaf_node(LeafNode::new_blank()).unwrap();
        }

        if is_preliminary {
            // If we're one being Added, then this index is us
            self.member_index = Some(add_member_idx);
        }

        // Propagate a blank up the tree before we set the new leaf's credential and pubkey info
        self.tree.propagate_blank(add_member_idx)?;

        // Now find the node keypair information and make our node in the ratchet tree. The keypair
        // we associate to the new member is the one that corresponds to our current ciphersuite.
        let public_key = init_key
            .get_public_key(self.cs)?
            .ok_or(Error::ValidationError(
                "ClientInitKey has no public keys for group's ciphersuite",
            ))?
            .clone();
        let private_key: Option<DhPrivateKey> = init_key.get_private_key(self.cs)?.cloned();
        let new_member_info = MemberInfo {
            public_key,
            credential: init_key.credential.clone(),
            private_key,
        };

        // Set the MemberInfo of the new leaf. This method makes sure that we're not overwriting
        // anything that wasn't already Blank.
        self.tree.set_member_info(add_member_idx, new_member_info)?;

        // Alright, we're done with the init_key. Make sure that we don't have our initializing
        // ClientInitKey hanging around after this
        // TODO: Make this erasure secure
        self.initializing_client_init_key = None;

        // "The update secret resulting from this change is an all-zero octet string of length
        // Hash.length."
        Ok(UpdateSecret::new_from_zeros(self.cs.hash_impl))
    }

    /// Processes the given `Handshake` and, if successful, produces a new `GroupContext` and
    /// associated `ApplicationKeyChain` This does not mutate the current `GroupContext`. Instead,
    /// it returns the next version of the `GroupContext`, where the operation contained by the
    /// `Handshake` has been applied.
    ///
    /// Returns: `Ok((group_ctx, app_key_chain))` on success, where `group_ctx` is the
    /// `GroupContext` after the given handshake has been applied, and `app_key_chain` is the
    /// `ApplicationKeyChain` belonging to `group_ctx`. Returns `Error::IAmRemoved` iff this
    /// member is the subject of a group `Remove` operation. Otherwise, returns some other sort of
    /// `Error`.
    pub fn process_handshake(
        &self,
        handshake: &Handshake,
        sender_idx: MemberIdx,
    ) -> Result<(GroupContext, Framer, ApplicationKeyChain), Error> {
        // Make a preliminary new state and  update its epoch and transcript hash. The state is
        // further mutated in the branches of the match statement below
        let mut new_group_ctx = self.clone();

        // Do the handshake operation on the preliminary new state. This returns an update secret
        // that the new epoch secrets are derived from.
        let update_secret = match handshake.operation {
            GroupOperation::Update(ref update) => {
                new_group_ctx.process_incoming_update_op(update, sender_idx)?
            }
            GroupOperation::Remove(ref remove) => {
                new_group_ctx.process_incoming_remove_op(remove, sender_idx)?
            }
            GroupOperation::Add(ref add) => {
                // Compute the hash of the welcome_info that created this group, which is
                // just the state of this group
                let prior_welcome_info_hash = {
                    let prior_welcome_info = self.as_welcome_info();
                    let digest = self.cs.hash_impl.hash_serializable(&prior_welcome_info)?;
                    WelcomeInfoHash::from(digest)
                };
                new_group_ctx.process_add_op(add, &prior_welcome_info_hash)?
            }
            // The spec hasn't weighed on group Init yet
            GroupOperation::Init(_) => unimplemented!(),
        };

        // Log the operation in the transcript hash, update the tree hash, and increment the epoch
        // counter
        new_group_ctx.update_transcript_hash(&handshake.operation)?;
        new_group_ctx.update_tree_hash()?;
        new_group_ctx.increment_epoch()?;

        // Recalculate the group's secrets given the new values we have
        let (app_secret, sender_data_secret, handshake_secret, confirmation_key) =
            new_group_ctx.update_epoch_secrets(&update_secret)?;

        //
        // Now validate the new state. If it's valid, we set the current state to the new one.
        //

        // Make the state immutable for the rest of this function
        let new_group_ctx = new_group_ctx;

        // Check the MAC:
        // Handshake.confirmation = HMAC(confirmation_key, GroupContext.transcript_hash)
        hmac::verify(
            self.cs.hash_impl,
            &confirmation_key.0,
            &new_group_ctx.transcript_hash.as_bytes(),
            &handshake.confirmation,
        )?;

        // All is well. Make the new application key chain and framer and send it along
        let app_key_chain = ApplicationKeyChain::new(&new_group_ctx, app_secret);
        let framer = Framer::new(&new_group_ctx, handshake_secret, sender_data_secret);
        Ok((new_group_ctx, framer, app_key_chain))
    }

    /// Creates and applies a `GroupUpdate` operation with the given path secret information. This
    /// method does not mutate this `GroupContext`, the operation is rather applied to the returned
    /// `GroupContext`.
    ///
    /// Returns: `Ok((group_ctx, app_key_chain, group_op, confirmation_key))` on success, where
    /// `group_ctx` is the group context after having applied the update operation, `app_key_chain`
    /// is the resulting application key chain (again, after having applied the update operation),
    /// `group_op` is the raw `GroupOperation` object, and `confirmation_key` is the derived
    /// confirmation key we'll use to compute the MAC in the `Handshake` that will end up
    /// containing the `GroupOperation`.
    pub(crate) fn create_and_apply_update_op<R>(
        &self,
        new_path_secret: PathSecret,
        csprng: &mut R,
    ) -> Result<(GroupContext, Framer, ApplicationKeyChain, GroupOperation, ConfirmationKey), Error>
    where
        R: CryptoRng,
    {
        // Ugh, a full group context clone, I know
        let mut new_group_ctx = self.clone();

        // Safely unwrap the member index. A preliminary GroupContext is one that has just been
        // initialized with a Welcome message
        let my_member_idx = new_group_ctx.member_index.ok_or(Error::ValidationError(
            "Cannot make an Update from a preliminary GroupContext",
        ))?;
        let my_tree_idx: TreeIdx = my_member_idx.try_into()?;

        // Do the update
        let update_secret: UpdateSecret = new_group_ctx
            .tree
            .propagate_new_path_secret(self.cs, new_path_secret.clone(), my_tree_idx)?
            .into();

        // Now package the update into a GroupUpdate structure
        let direct_path_msg = new_group_ctx.tree.encrypt_direct_path_secrets(
            new_group_ctx.cs,
            my_member_idx,
            new_path_secret,
            csprng,
        )?;
        let update = GroupUpdate {
            path: direct_path_msg,
        };
        let op = GroupOperation::Update(update);

        // Log the operation in the transcript hash, update the tree hash, and increment the epoch
        // counter
        new_group_ctx.update_transcript_hash(&op)?;
        new_group_ctx.update_tree_hash()?;
        new_group_ctx.increment_epoch()?;

        // Final modification: update my epoch secrets and make the new ApplicationKeyChain and
        // Framer
        let (app_secret, sender_data_secret, handshake_secret, confirmation_key) =
            new_group_ctx.update_epoch_secrets(&update_secret)?;
        let framer = Framer::new(&new_group_ctx, handshake_secret, sender_data_secret);
        let app_key_chain = ApplicationKeyChain::new(&new_group_ctx, app_secret);

        Ok((new_group_ctx, framer, app_key_chain, op, confirmation_key))
    }

    /// Creates and applies a `GroupAdd` operation for a member at index `new_member_index` with
    /// the target `init_key`. This method does not mutate this `GroupContext`, the operation is
    /// rather applied to the returned `GroupContext`.
    ///
    /// Returns: `Ok((group_ctx, app_key_chain, group_op, confirmation_key))` on success, where
    /// `group_ctx` is the group context after having applied the add operation, `app_key_chain`
    /// is the resulting application key chain (again, after having applied the add operation),
    /// `group_op` is the raw `GroupOperation` object, and `confirmation_key` is the derived
    /// confirmation key we'll use to compute the MAC in the `Handshake` that will end up
    /// containing the `GroupOperation`.
    // Technically, there's no reason that this has to mutate the GroupContext, since GroupContexts
    // can consume the Add ops they produce (unlike Updates). But for consistency with the other
    // create_*_op functions, this should mutate the GroupContext too.
    pub(crate) fn create_and_apply_add_op(
        &self,
        new_member_idx: MemberIdx,
        init_key: ClientInitKey,
        prior_welcome_info_hash: &WelcomeInfoHash,
    ) -> Result<(GroupContext, Framer, ApplicationKeyChain, GroupOperation, ConfirmationKey), Error>
    {
        // Ugh, a full group context clone, I know
        let mut new_group_ctx = self.clone();

        // Make the Add op
        let add = GroupAdd {
            member_index: new_member_idx,
            init_key,
            welcome_info_hash: prior_welcome_info_hash.clone(),
        };
        // Apply the Add and make the op
        let update_secret = new_group_ctx.process_add_op(&add, prior_welcome_info_hash)?;
        let op = GroupOperation::Add(add);

        // Log the operation in the transcript hash, update the tree hash, and increment the epoch
        // counter
        new_group_ctx.update_transcript_hash(&op)?;
        new_group_ctx.update_tree_hash()?;
        new_group_ctx.increment_epoch()?;

        // Update the epoch secrets, and make the new ApplicationKeyChain and framer
        let (app_secret, sender_data_secret, handshake_secret, confirmation_key) =
            new_group_ctx.update_epoch_secrets(&update_secret)?;
        let framer = Framer::new(&new_group_ctx, handshake_secret, sender_data_secret);
        let app_key_chain = ApplicationKeyChain::new(&new_group_ctx, app_secret);

        Ok((new_group_ctx, framer, app_key_chain, op, confirmation_key))
    }

    /// Creates and applies a `GroupRemove` operation for a member at `removed_member_index` and
    /// introduces a new path secret `new_path_secret` at the removed index. This method does not
    /// mutate this `GroupContext`, the operation is rather applied to the returned `GroupContext`.
    ///
    /// Returns: `Ok((group_ctx, app_key_chain, group_op, confirmation_key))` on success, where
    /// `group_ctx` is the group context after having applied the add operation, `app_key_chain`
    /// is the resulting application key chain (again, after having applied the add operation),
    /// `group_op` is the raw `GroupOperation` object, and `confirmation_key` is the derived
    /// confirmation key we'll use to compute the MAC in the `Handshake` that will end up
    /// containing the `GroupOperation`. Returns an `Error::IAmRemoved` iff this member is the one
    /// who is being removed.
    pub(crate) fn create_and_apply_remove_op<R>(
        &self,
        removed_member_idx: MemberIdx,
        new_path_secret: PathSecret,
        csprng: &mut R,
    ) -> Result<(GroupContext, Framer, ApplicationKeyChain, GroupOperation, ConfirmationKey), Error>
    where
        R: CryptoRng,
    {
        let my_member_idx = self
            .member_index
            .ok_or(Error::ValidationError("Cannot do a Remove on a preliminary GroupContext"))?;

        // The spec says you cannot use a Remove to leave a group
        if my_member_idx == removed_member_idx {
            return Err(Error::ValidationError("Cannot Remove self from group"));
        }

        // Ugh, a full group context clone, I know
        let mut new_group_ctx = self.clone();

        // Blank out the direct path of the member we want to delete and then prune the tree if
        // possible
        new_group_ctx.tree.propagate_blank(removed_member_idx)?;
        new_group_ctx.tree.truncate_to_last_nonblank();

        // Now that the removed user has been blanked out, apply fresh entropy to the tree
        let my_tree_idx: TreeIdx = my_member_idx.try_into()?;
        let update_secret = new_group_ctx
            .tree
            .propagate_new_path_secret(self.cs, new_path_secret.clone(), my_tree_idx)?
            .into();

        // Encrypt the new entropy for everyone else to see
        let direct_path_msg = new_group_ctx.tree.encrypt_direct_path_secrets(
            new_group_ctx.cs,
            my_member_idx,
            new_path_secret.clone(),
            csprng,
        )?;

        // Make the remove op
        let remove = GroupRemove {
            removed_member_index: removed_member_idx,
            path: direct_path_msg,
        };
        let op = GroupOperation::Remove(remove);

        // Log the operation in the transcript hash, update the tree hash, and increment the epoch
        // counter
        new_group_ctx.update_transcript_hash(&op)?;
        new_group_ctx.update_tree_hash()?;
        new_group_ctx.increment_epoch()?;

        // Update the epoch secrets, and make the new ApplicationKeyChain and Framer
        let (app_secret, sender_data_secret, handshake_secret, confirmation_key) =
            new_group_ctx.update_epoch_secrets(&update_secret)?;
        let framer = Framer::new(&new_group_ctx, handshake_secret, sender_data_secret);
        let app_key_chain = ApplicationKeyChain::new(&new_group_ctx, app_secret);

        Ok((new_group_ctx, framer, app_key_chain, op, confirmation_key))
    }
}

// Implement public API for Handshake creation

impl GroupContext {
    /// Creates and applies a `GroupUpdate` operation with the given path secret information. This
    /// method does not mutate this `GroupContext`, the operation is rather applied to the returned
    /// `GroupContext`.
    ///
    /// Returns: `Ok((handshake, group_ctx, framer, app_key_chain))` on success, where `handshake`
    /// is the `Handshake` message representing the specified add operation, `group_ctx` is the new
    /// group context after the add has been applied, `framer` is the newly derived MLS message
    /// framing object, and `app_key_chain` is the newly derived application key schedule object
    // This is just a wrapper around self.create_and_apply_update_op
    pub fn create_and_apply_update_handshake<R>(
        &self,
        new_path_secret: PathSecret,
        csprng: &mut R,
    ) -> Result<(Handshake, GroupContext, Framer, ApplicationKeyChain), Error>
    where
        R: CryptoRng,
    {
        let (new_group_ctx, framer, app_key_chain, update_op, conf_key) =
            self.create_and_apply_update_op(new_path_secret, csprng)?;
        let handshake =
            Handshake::new(self.cs.hash_impl, update_op, &new_group_ctx.transcript_hash, conf_key);

        Ok((handshake, new_group_ctx, framer, app_key_chain))
    }

    /// Creates and applies a `GroupAdd` operation for a member at index `new_member_index` with
    /// the target `init_key`. This method does not mutate this `GroupContext`, the operation is
    /// rather applied to the returned `GroupContext`.
    ///
    /// Returns: `Ok((handshake, group_ctx, framer, app_key_chain))` on success, where `handshake`
    /// is the `Handshake` message representing the specified add operation, `group_ctx` is the new
    /// group context after the add has been applied, `framer` is the newly derived MLS message
    /// framing object, and `app_key_chain` is the newly derived application key schedule object
    // This is just a wrapper around self.create_and_apply_add_op
    pub fn create_and_apply_add_handshake(
        &self,
        new_member_idx: MemberIdx,
        init_key: ClientInitKey,
        prior_welcome_info_hash: &WelcomeInfoHash,
    ) -> Result<(Handshake, GroupContext, Framer, ApplicationKeyChain), Error> {
        let (new_group_ctx, framer, app_key_chain, add_op, conf_key) =
            self.create_and_apply_add_op(new_member_idx, init_key, prior_welcome_info_hash)?;
        let handshake =
            Handshake::new(self.cs.hash_impl, add_op, &new_group_ctx.transcript_hash, conf_key);

        Ok((handshake, new_group_ctx, framer, app_key_chain))
    }

    // This is just a wrapper around self.create_and_apply_remove_op
    /// Creates and applies a `GroupRemove` operation for a member at `removed_member_index` and
    /// introduces a new path secret `new_path_secret` at the removed index. This method does not
    /// mutate this `GroupContext`, the operation is rather applied to the returned `GroupContext`.
    ///
    /// Requires: `removed_member_index != self.member_index`. That is, a member cannot remove
    /// themselves from the group. An attempt to do so will result in an `Error::IAmRemoved`.
    ///
    /// Returns: `Ok((handshake, group_ctx, framer, app_key_chain))` on success, where `handshake`
    /// is the `Handshake` message representing the specified add operation, `group_ctx` is the new
    /// group context after the add has been applied, `framer` is the newly derived MLS message
    /// framing object, and `app_key_chain` is the newly derived application key schedule object
    pub fn create_and_apply_remove_handshake<R>(
        &self,
        removed_member_idx: MemberIdx,
        new_path_secret: PathSecret,
        csprng: &mut R,
    ) -> Result<(Handshake, GroupContext, Framer, ApplicationKeyChain), Error>
    where
        R: CryptoRng,
    {
        let (new_group_ctx, framer, app_key_chain, remove_op, conf_key) =
            self.create_and_apply_remove_op(removed_member_idx, new_path_secret, csprng)?;
        let handshake =
            Handshake::new(self.cs.hash_impl, remove_op, &new_group_ctx.transcript_hash, conf_key);

        Ok((handshake, new_group_ctx, framer, app_key_chain))
    }
}

/// This is a `RatchetTreeNode` formatted just for `WelcomeInfo`. Ugh
#[derive(Deserialize, Serialize)]
#[cfg_attr(test, derive(Debug))]
pub(crate) struct WelcomeInfoRatchetNode {
    pub(crate) public_key: DhPublicKey,
    pub(crate) credential: Option<Credential>,
}

/// This is a `RatchetTree` formatted just for `WelcomeInfo`. Ugh
#[derive(Deserialize, Serialize)]
#[cfg_attr(test, derive(Debug))]
#[serde(rename = "WelcomeInfoRatchetTree__bound_u32")]
pub(crate) struct WelcomeInfoRatchetTree(pub(crate) Vec<Option<WelcomeInfoRatchetNode>>);

// TODO: Make this COW so we don't have to clone everything in GroupContext::as_welcome_info

/// Contains everything a new user needs to know to join a group. This is always followed by an
/// `Add` operation.
#[derive(Deserialize, Serialize)]
#[cfg_attr(test, derive(Debug))]
pub(crate) struct WelcomeInfo {
    // ProtocolVersion version;
    /// The protocol version
    protocol_version: ProtocolVersion,

    /// An application-defined identifier for the group
    group_id: GroupId,

    /// Represents the current version of the group key
    epoch: u32,

    // optional<RatchetNode> tree<1..2^32-1>;
    /// Contains a serialization-friendly form of a `RatchetTree`
    pub(crate) tree: WelcomeInfoRatchetTree,

    // opaque transcript_hash<0..255>;
    /// Contains a running hash of `GroupOperation` messages that led to this state
    transcript_hash: Digest,

    // opaque init_secret<0..255>;
    /// The initial secret used to derive all the rest
    init_secret: HkdfSalt,
}

// This is public-facing
/// Represents the hash of a `WelcomeInfo` object
#[derive(Clone, Deserialize, Serialize)]
#[cfg_attr(test, derive(Debug))]
pub struct WelcomeInfoHash(Digest);

// Digest --> WelcomeInfoHash trivially
impl From<Digest> for WelcomeInfoHash {
    fn from(d: Digest) -> WelcomeInfoHash {
        WelcomeInfoHash(d)
    }
}

// Do constant-time comparison by comparing the underlying digests
impl subtle::ConstantTimeEq for WelcomeInfoHash {
    fn ct_eq(&self, other: &WelcomeInfoHash) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

/// This contains an encrypted `WelcomeInfo` for new group members
#[derive(Deserialize, Serialize)]
#[cfg_attr(test, derive(Debug))]
pub struct Welcome {
    // opaque client_init_key_id<0..255>;
    #[serde(rename = "client_init_key_id__bound_u8")]
    client_init_key_id: Vec<u8>,
    pub(crate) cipher_suite: &'static CipherSuite,
    pub(crate) encrypted_welcome_info: HpkeCiphertext,
}

impl Welcome {
    /// Packages up a `WelcomeInfo` object with a preferred cipher suite, and encrypts it to the
    /// specified `ClientInitKey` (under the appropriate public key)
    fn from_welcome_info<R>(
        cs: &'static CipherSuite,
        init_key: &ClientInitKey,
        welcome_info: &WelcomeInfo,
        csprng: &mut R,
    ) -> Result<Welcome, Error>
    where
        R: CryptoRng,
    {
        // Get the public key from the supplied ClientInitKey corresponding to the given cipher
        // suite
        let public_key = init_key
            .get_public_key(cs)?
            .ok_or(Error::ValidationError("No corresponding public key for given ciphersuite"))?;

        // Serialize and encrypt the WelcomeInfo
        let serialized_welcome_info = tls_ser::serialize_to_bytes(welcome_info)?;
        let ciphertext = hpke::encrypt(cs, &public_key, serialized_welcome_info, csprng)?;

        // All done
        Ok(Welcome {
            client_init_key_id: init_key.client_init_key_id.clone(),
            cipher_suite: cs,
            encrypted_welcome_info: ciphertext,
        })
    }

    /// Creates a `Welcome` object for the target `ClientInitKey`. The `Welcome` contains all the
    /// current state information. This operation ordinarily precedes an `Add`.
    ///
    /// Returns: `Ok((welcome, welcome_info_hash))` on success where `welcome` is a `Welcome`
    /// message representing the group's current state, and `welcome_info_hash` is the hash of the
    /// underlying `WelcomeInfo` object. The hash is relevant for `Add` operations.
    // This is a convenient wrapper around GroupContext::as_welcome_info and
    // Welcome::from_welcome_info
    pub fn from_group_ctx<R>(
        group_ctx: &GroupContext,
        init_key: &ClientInitKey,
        csprng: &mut R,
    ) -> Result<(Welcome, WelcomeInfoHash), Error>
    where
        R: CryptoRng,
    {
        // Make a WelcomeInfo from the group
        let welcome_info = group_ctx.as_welcome_info();

        // Take the hash of the WelcomeInfo. This is necessary if the caller wants to make an Add.
        // The caller can't derive it themselves, because we wrap the WelcomeInfo in a Welcome in
        // the next step.
        let welcome_info_hash = group_ctx.cs.hash_impl.hash_serializable(&welcome_info)?;

        // Encrypt it up
        let welcome = Welcome::from_welcome_info(&group_ctx.cs, init_key, &welcome_info, csprng)?;

        Ok((welcome, welcome_info_hash.into()))
    }

    /// Decrypts the `Welcome` with the given `ClientInitKey`
    ///
    /// Requires: That the `init_key` is the `ClientInitKey` that the `Welcome` was encrypted with
    /// (i.e., `init_key.client_init_key_id == self.client_init_key_id`) and `init_key.private_keys`
    /// is not `None`
    ///
    /// Returns: `Ok((welcome_info, cs))` on success, where `welcome_info` is the decrypted
    /// `WelcomeInfo` that this `Welcome` contained, and `cs` is this group's cipher suite
    fn into_welcome_info_cipher_suite(
        self,
        init_key: &ClientInitKey,
    ) -> Result<(WelcomeInfo, &'static CipherSuite), Error> {
        // Verify the ClientInitKey signature and validate its contents
        init_key.verify_sig()?;
        init_key.validate()?;
        // Verify that the supplied ClientInitKey is the one that the Welcome message references
        if self.client_init_key_id != init_key.client_init_key_id {
            return Err(Error::ValidationError(
                "Supplied ClientInitKey ID doesn't match Welcome's",
            ));
        }
        // Get the ciphersuite and private key we'll use to decrypt the wrapped WelcomeInfo
        let cs = self.cipher_suite;
        let dh_private_key = init_key
            .get_private_key(cs)?
            .ok_or(Error::ValidationError("Can't decrypt Welcome without a private key"))?;

        // Decrypt the WelcomeInfo, deserialize it, upcast it, and return it
        let welcome_info_bytes = hpke::decrypt(cs, dh_private_key, self.encrypted_welcome_info)?;
        let welcome_info = {
            let mut cursor = welcome_info_bytes.as_slice();
            let mut deserializer = TlsDeserializer::from_reader(&mut cursor);
            let mut w = WelcomeInfo::deserialize(&mut deserializer)?;

            // Once it's deserialized, make it nice and typesafe
            let ctx = CryptoCtx::new().set_cipher_suite(cs);
            w.upcast_crypto_values(&ctx)?;
            w
        };

        // TODO: Figure out if a versioning scheme should accept versions that are less than the
        // requested one.

        // Check that the WelcomeInfo has precisely the supported version. We can unwrap here
        // because we already found the private key corresponding to this ciphersuite above.
        let supported_version = init_key.get_supported_version(cs)?.unwrap();
        if welcome_info.protocol_version != supported_version {
            return Err(Error::ValidationError(
                "WelcomeInfo's supported protocol version does not match the ClientInitKey's",
            ));
        }

        Ok((welcome_info, cs))
    }

    /// Returns the `client_init_key_id` associated with this `Welcome`
    pub fn get_client_init_key_id(&self) -> &[u8] {
        self.client_init_key_id.as_slice()
    }
}

#[cfg(test)]
mod test {
    use crate::{
        client_init_key::{ClientInitKey, ProtocolVersion, MLS_DUMMY_VERSION},
        crypto::{
            ciphersuite::{CipherSuite, X25519_SHA256_AES128GCM},
            hash::Digest,
            hkdf::{HkdfPrk, HkdfSalt},
            hmac::HmacKey,
            sig::{SigSecretKey, ED25519_IMPL},
        },
        error::Error,
        group_ctx::{GroupContext, GroupId, UpdateSecret, Welcome, WelcomeInfoRatchetTree},
        ratchet_tree::{MemberIdx, RatchetTree},
        test_utils,
        tls_de::TlsDeserializer,
        upcast::{CryptoCtx, CryptoUpcast},
    };

    use quickcheck_macros::quickcheck;
    use rand::{RngCore, SeedableRng};
    use serde::de::Deserialize;

    // Checks that
    // GroupContext::from_welcome(Welcome::from_welcome_info(group.as_welcome_info())) == group
    #[quickcheck]
    fn welcome_correctness(rng_seed: u64) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(rng_seed);
        // Make a starting group of at least 1 person
        let (group_ctx1, _) = test_utils::random_full_group_ctx(1, &mut rng);

        // Make the data necessary for a Welcome message
        let cipher_suites = vec![&X25519_SHA256_AES128GCM];
        let supported_versions: Vec<ProtocolVersion> = vec![MLS_DUMMY_VERSION; cipher_suites.len()];
        // These values really don't matter. They're only important if we do anything with the
        // GroupContexts after the Welcome
        let (new_credential, new_identity_key) = test_utils::random_basic_credential(&mut rng);
        // Key ID is random
        let client_init_key_id = {
            let mut buf = [0u8; 16];
            rng.fill_bytes(&mut buf);
            buf.to_vec()
        };
        // The ClientInitKey has all the key / identity information necessary to add a new member to
        // the group and Welcome them
        let init_key = ClientInitKey::new_from_random(
            &new_identity_key,
            client_init_key_id,
            new_credential.clone(),
            cipher_suites,
            supported_versions,
            &mut rng,
        )
        .unwrap();

        // Make the welcome objects
        let welcome_info = group_ctx1.as_welcome_info();
        let welcome =
            Welcome::from_welcome_info(group_ctx1.cs, &init_key, &welcome_info, &mut rng).unwrap();

        // Now unwrap the Welcome back into a GroupContext. This should be identical to the
        // starting group context, except maybe for the member_index, credential, initiailizing
        // ClientInitKey, and identity key. None of those things are serialized though, since they
        // are unique to each member's perspective
        let group_ctx2 = GroupContext::from_welcome(welcome, new_identity_key, init_key).unwrap();

        // Now see if the resulting group contexts agree
        assert_serialized_eq!(group_ctx1, group_ctx2, "GroupContexts disagree after a Welcome");
    }

    // This is all the serializable bits of a GroupContext. We have this separate because
    // GroupContext is only ever meant to be serialized. The fields in it that are for us and not
    // for serialization require a Default instance in order for GroupContext to impl Deserialize.
    // Since I don't think that's a good idea, I'll just initialize all those things to 0 myself.
    // See group_from_test_group.
    #[derive(Debug, Deserialize)]
    pub(crate) struct TestGroupContext {
        group_id: GroupId,
        epoch: u32,
        tree: WelcomeInfoRatchetTree,
        pub(crate) transcript_hash: Digest,
    }

    impl CryptoUpcast for TestGroupContext {
        fn upcast_crypto_values(&mut self, ctx: &CryptoCtx) -> Result<CryptoCtx, Error> {
            self.tree.upcast_crypto_values(ctx)
        }
    }

    // Makes a mostly empty GroupContext from a recently-deserialized TestGroupContext
    pub(crate) fn group_from_test_group(tgs: TestGroupContext) -> GroupContext {
        let cs = &X25519_SHA256_AES128GCM;
        let ss = &ED25519_IMPL;
        let tree = RatchetTree::new_from_welcome_info_ratchet_tree(cs.hash_impl, tgs.tree).unwrap();
        GroupContext {
            cs,
            protocol_version: MLS_DUMMY_VERSION,
            identity_key: SigSecretKey::new_from_bytes(ss, &[0u8; 32]).unwrap(),
            group_id: tgs.group_id,
            epoch: tgs.epoch,
            tree_hash: tree.tree_hash().unwrap(),
            transcript_hash: tgs.transcript_hash,
            tree,
            member_index: Some(MemberIdx::new(0)),
            initializing_client_init_key: None,
            init_secret: HkdfSalt::new_from_zeros(cs.hash_impl),
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
    //   GroupContext base_group_ctx;
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
    // * The initial GroupContext object input to the key schedule should be deserialized from the
    //   base_group_ctx object.
    // * incremented after being provided to the key schedule. This is to say, the key schedule is
    //   run on the base_group_ctx object before its epoch is incremented for the first time.
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
        base_group_ctx: TestGroupContext,
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
        let mut group_ctx = group_from_test_group(test_vec.base_group_ctx);
        let hash_impl = group_ctx.cs.hash_impl;

        // Keep deriving new secrets with respect to the given update secret. Check all the
        // resulting keys against the test vector.
        for epoch in case1.epochs.into_iter() {
            let update_secret = UpdateSecret(epoch.update_secret);
            let (app_secret, _, _, conf_key) =
                group_ctx.update_epoch_secrets(&update_secret).unwrap();

            // Wrap all the inputs in the appropriate types so we can compare them to our values
            let epoch_application_secret =
                HkdfPrk::new_from_bytes(hash_impl, &epoch.application_secret);
            let epoch_confirmation_key =
                HmacKey::new_from_bytes(hash_impl, &epoch.confirmation_key);
            let epoch_init_secret = HkdfSalt::new_from_bytes(hash_impl, &epoch.init_secret);

            // Unwrap the newtypes into the underlying types
            let app_secret: &HkdfPrk = (&app_secret).into();
            let conf_key: &HmacKey = (&conf_key).into();

            // We don't save the derived epoch_secret anywhere, since it's just an intermediate
            // value. We do test all the things derived from it, though. We convert the LHS to
            // HmacKeys so we can compare them to the RHS.
            assert_eq!(app_secret, &epoch_application_secret);
            assert_eq!(conf_key, &epoch_confirmation_key);
            assert_eq!(group_ctx.init_secret, epoch_init_secret);

            // Increment the state epoch every time we do a key derivation. This is what happens in
            // the actual protocol.
            group_ctx.epoch += 1;
        }
    }
}
