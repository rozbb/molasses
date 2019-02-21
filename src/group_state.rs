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

    /// This is also known as the signer index
    #[serde(skip)]
    pub(crate) my_position_in_roster: u32,

    //
    // These are a bunch of secrets derived via HKDF-Expand
    //
    /// The initial secret used to derive all the rest
    #[serde(skip)]
    pub(crate) init_secret: Vec<u8>,

    #[serde(skip)]
    pub(crate) application_secret: Vec<u8>,

    #[serde(skip)]
    pub(crate) confirmation_key: Vec<u8>,
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
            confirmation_key: Vec::new(),
            my_position_in_roster: my_position_in_roster,
        }
    }

    /// This is the `Derive-Secret` function defined in section 5.9 of the spec. It's used as a
    /// helper function for `derive_new_secrets`
    pub(crate) fn derive_secret(&self, prk: &ring::hmac::SigningKey, label_info: &[u8]) -> Vec<u8> {
        // This struct is only used for `derive_secret` calculations
        #[derive(Serialize)]
        struct HkdfLabel<'a> {
            length: u16,
            // opaque label<6..255> = "mls10 " + Label;
            #[serde(rename = "label__bound_u8")]
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
            state: self,
        };
        // Serialize the label
        let serialized_label =
            crate::tls_ser::serialize_to_bytes(&label).expect("couldn't serialize HKDF label");

        // Finally, do the HKDF-Expand operation
        ring::hkdf::expand(prk, &serialized_label, out_buf.as_mut_slice());
        out_buf
    }

    /// Derives the next generation of Group secrets as per section 5.9 in the spec
    pub(crate) fn derive_new_secrets(&mut self, update_secret: &[u8]) {
        // epoch_secret = HKDF-Extract(salt=init_secret_[n-1] (or 0), ikm=update_secret)
        let salt = ring::hmac::SigningKey::new(self.cs.hash_alg, &self.init_secret);
        let epoch_secret: ring::hmac::SigningKey = ring::hkdf::extract(&salt, &update_secret);

        // application_secret = Derive-Secret(epoch_secret, "app", GroupState_[n])
        let application_secret = self.derive_secret(&epoch_secret, b"app");
        // confirmation_key = Derive-Secret(epoch_secret, "confirm", GroupState_[n])
        let confirmation_key = self.derive_secret(&epoch_secret, b"confirm");
        // init_secret_[n] = Derive-Secret(epoch_secret, "init", GroupState_[n])
        let init_secret = self.derive_secret(&epoch_secret, b"init");

        self.application_secret = application_secret;
        self.confirmation_key = confirmation_key;
        self.init_secret = init_secret;
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

#[cfg(test)]
mod test {
    use crate::{
        credential::Credential,
        crypto::ciphersuite::CipherSuite,
        ratchet_tree::RatchetTree,
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
            group_state.derive_new_secrets(&epoch.update_secret);

            // We don't save the derived epoch_secret anywhere, since it's just an intermediate
            // value. We do test all the things derived from it, though.
            assert_eq!(&group_state.application_secret, &epoch.application_secret);
            assert_eq!(&group_state.confirmation_key, &epoch.confirmation_key);
            assert_eq!(&group_state.init_secret, &epoch.init_secret);

            // Increment the state epoch every time we do a key derivation. This is what happens in
            // the actual protocol.
            group_state.epoch += 1;
        }
    }
}
