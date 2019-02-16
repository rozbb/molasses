use crate::{
    credential::{Credential, Identity},
    crypto::{ciphersuite::CipherSuite, sig::SigSecretKey},
    ratchet_tree::RatchetTree,
};

/// Contains all group state
#[derive(Serialize)]
pub(crate) struct GroupState {
    /// You can think of this as a context variable. It helps us implement crypto ops and
    /// disambiguate serialized data structures
    #[serde(skip)]
    cs: &'static CipherSuite,
    /// A long-lived signing key used to authenticate the sender of a message
    #[serde(skip)]
    pub(crate) identity_key: SigSecretKey,
    // opaque group_id<0..255>;
    /// An application-defined identifier for the group
    group_id: Vec<u8>,
    /// Represents the current version of the group key
    pub(crate) epoch: u32,
    // optional<Credential> roster<1..2^32-1>;
    /// Contains credentials for the occupied slots in the tree, including the identity and
    /// signature public key for the holder of the slot
    roster: Vec<Option<Credential>>,
    // optional<PublicKey> tree<1..2^32-1>;
    /// The tree field contains the public keys corresponding to the nodes of the ratchet tree for
    /// this group. The number of leaves in this tree MUST be equal to the length of `roster`
    tree: RatchetTree,
    // opaque transcript_hash<0..255>;
    /// Contains a running hash of `GroupOperation` messages that led to this state
    pub(crate) transcript_hash: Vec<u8>,
    /// This is also known as the signer index
    #[serde(skip)]
    pub(crate) my_position_in_roster: u32,
    //
    // These are a bunch of secrets derived via HKDF-Expand
    //
    /// The initial secret used to derive all the rest
    #[serde(skip)]
    init_secret: Vec<u8>,
    #[serde(skip)]
    application_secret: Vec<u8>,
    #[serde(skip)]
    pub(crate) confirmation_key: ring::hmac::SigningKey,
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
        // We're not told where we are in the roster, so we first find ourselves. The index is used
        // as the signer index in Handshake messages
        let my_position_in_roster: u32 = {
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

        // This will get populated on the next call to `derive_new_secrets`
        let empty_confirmation_key = ring::hmac::SigningKey::new(cs.hash_alg, &[]);

        GroupState {
            cs: cs,
            identity_key: my_identity_key,
            group_id: w.group_id,
            epoch: w.epoch,
            roster: w.roster,
            tree: w.tree,
            transcript_hash: w.transcript_hash,
            init_secret: w.init_secret,
            // All these fields will be populated on the next call to `derive_new_secrets`
            application_secret: Vec::new(),
            confirmation_key: empty_confirmation_key,
            my_position_in_roster: my_position_in_roster,
        }
    }

    /// This is the `Derive-Secret` function defined in section 5.9 of the spec. It's used as a
    /// helper function for `derive_new_secrets`
    fn derive_secret(
        prk: &ring::hmac::SigningKey,
        label_info: &[u8],
        state: &GroupState,
    ) -> Vec<u8> {
        // This struct is only used for `derive_secret` calculations
        #[derive(Serialize)]
        struct HkdfLabel<'a> {
            length: u16,
            // opaque label<6..255> = "mls10 " + Label;
            label: Vec<u8>,
            state: &'a GroupState,
        }

        // The output is suppose to be the size of the hash algorithm's digest size
        let mut out_buf = vec![0u8; prk.digest_algorithm().output_len];
        // The output length is also supposed to be representable by a u16
        assert!(out_buf.len() <= std::u16::MAX as usize);

        // We're gonna used the serialized label as the `info` parameter to HKDF-Expand
        let label = HkdfLabel {
            length: out_buf.len() as u16,
            // Recall the def: opaque label<6..255> = "mls10 " + Label;
            label: [b"mls10 ", label_info].concat(),
            state: state,
        };
        // Serialize the label
        let serialized_label =
            crate::tls_ser::serialize_to_bytes(&label).expect("couldn't serialize HKDF label");

        // Finally, do the HKDF-Expand operation
        ring::hkdf::expand(prk, &serialized_label, out_buf.as_mut_slice());
        out_buf
    }

    /// Derives the next generation of Group secrets as per section 5.9 in the spec
    fn derive_new_secrets(&mut self, update_secret: &[u8]) {
        // epoch_secret = HKDF-Extract(salt=init_secret_[n-1] (or 0), ikm=update_secret)
        let salt = ring::hmac::SigningKey::new(self.cs.hash_alg, &self.init_secret);
        let epoch_secret: ring::hmac::SigningKey = ring::hkdf::extract(&salt, &update_secret);

        // application_secret = Derive-Secret(epoch_secret, "app", GroupState_[n])
        let application_secret = GroupState::derive_secret(&epoch_secret, b"app", self);
        // confirmation_key = Derive-Secret(epoch_secret, "confirm", GroupState_[n])
        let confirmation_key = {
            let key_bytes = GroupState::derive_secret(&epoch_secret, b"confirm", self);
            ring::hmac::SigningKey::new(self.cs.hash_alg, &key_bytes)
        };
        // init_secret_[n] = Derive-Secret(epoch_secret, "init", GroupState_[n])
        let init_secret = GroupState::derive_secret(&epoch_secret, b"init", self);

        self.application_secret = application_secret;
        self.confirmation_key = confirmation_key;
        self.init_secret = init_secret;
    }
}

/// Contains everything a new user needs to know to join a Group
#[derive(Serialize)]
struct WelcomeInfo {
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
    roster: Vec<Option<Credential>>,
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
