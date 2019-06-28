//! Contains the data structures for the application key schedule as well as application-level
//! messages

use crate::{
    crypto::{
        aead::{AeadKey, AeadNonce},
        ciphersuite::CipherSuite,
        hkdf,
        hmac::HmacKey,
    },
    error::Error,
    group_ctx::{ApplicationSecret, GroupContext, GroupId},
    ratchet_tree::MemberIdx,
    tls_ser,
};

use core::convert::TryFrom;

/// Contains a secret that is unique to a member of the group. This is part of the application key
/// schedule defined in the "Encryption Keys" section of the spec.
#[derive(Clone)]
pub(crate) struct WriteSecret(HmacKey);

// WriteSecret --> HmacKey trivially
impl From<WriteSecret> for HmacKey {
    fn from(ws: WriteSecret) -> HmacKey {
        ws.0
    }
}

/// Encodes the generation of a `WriteSecret` in an `ApplicationKeyChain`
#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(test, derive(Debug))]
pub(crate) struct WriteSecretGeneration(u32);

/// Contains the secrets for every member of the group. These are called "application_secrets" in
/// the spec, but that's kinda confusing since "application_secret" is also something that the
/// `GroupContext` creates and uses to seed this struct.
///
/// This is intended to be used with the `encrypt_application_message` and
/// `decrypt_application_message` functions.
pub struct ApplicationKeyChain {
    /// Contains write secrets and their respective generations, starting at 0
    write_secrets_and_gens: Vec<(WriteSecret, WriteSecretGeneration)>,

    /// The creating group's ciphersuite
    group_cs: &'static CipherSuite,

    /// The creating group's ID
    group_id: GroupId,

    /// The creating group's epoch at the time of creation. This is important for making the
    /// `ApplicationKeyChain` work independently from the creating `GroupContext`.
    group_epoch_at_creation: u32,

    /// The member index of this user in the creating group
    my_member_idx: MemberIdx,
}

impl ApplicationKeyChain {
    /// Creates an `ApplicationKeyChain` object from the given application secret and current group
    pub(crate) fn new(
        group_ctx: &GroupContext,
        app_secret: ApplicationSecret,
    ) -> ApplicationKeyChain {
        // Remember that member indices are u32. This fact matters when we serialize it in the
        // calculation of write_secret_[sender].
        let num_leaves = group_ctx.tree.num_leaves();

        // The application secret is secretly an HMAC key
        let prk: HmacKey = app_secret.into();

        // Make a write secret for every member, and let its generation be 0
        let write_secrets_and_gens = (0..num_leaves)
            .map(|i: usize| {
                // Interpret the index as a MemberIdx
                let member_idx = {
                    // It doesn't seem likely that we can get to this point without this error
                    // being caught
                    let i = u32::try_from(i).expect("number of leaves exceeds u32::MAX");
                    MemberIdx::new(i)
                };
                // write_secret_[sender] =
                //     HKDF-Expand-Label(application_secret, "app sender", sender, Hash.length)
                //  where sender is serialized as usual as a u32
                let mut write_secret_buf = vec![0u8; group_ctx.cs.hash_impl.digest_size()];
                let serialized_member_idx = tls_ser::serialize_to_bytes(&member_idx).unwrap();
                hkdf::expand_label(
                    group_ctx.cs.hash_impl,
                    &prk,
                    b"app sender",
                    &serialized_member_idx,
                    write_secret_buf.as_mut_slice(),
                );
                let write_secret = WriteSecret(HmacKey::new_from_bytes(&write_secret_buf));

                // (write_secret, generation=0)
                (write_secret, WriteSecretGeneration(0))
            })
            .collect();

        // This should never error. ApplicationKeyChains can only be made after a group is out of
        // preliminary mode anyway
        let my_member_idx = group_ctx
            .member_index
            .expect("cannot make an ApplicationKeyChain from a preliminary group");

        ApplicationKeyChain {
            write_secrets_and_gens,
            group_cs: group_ctx.cs,
            group_id: group_ctx.group_id.clone(),
            group_epoch_at_creation: group_ctx.epoch,
            my_member_idx,
        }
    }

    /// Retrieves `write_secrets_[member_idx]` and derives a key and nonce from it, as per the
    /// "Encryption Keys" section of the MLS spec
    ///
    /// Returns: `Ok((gen, write_key_[member_idx]_[gen], write_nonce_[member_idx]_[gen]))` on
    /// sucess, where `gen` is the current generation of the `WriteSecret` of the member indexed by
    /// `member_idx`. Returns an `Error` if `member_idx` is out of bounds or something goes wrong
    /// in the creation of the key/nonce from bytes.
    fn get_key_nonce_gen(
        &self,
        idx: MemberIdx,
    ) -> Result<(AeadKey, AeadNonce, WriteSecretGeneration), Error> {
        // Get a reference to the write secret and current generation. We update these in-place at
        // the end.
        let (write_secret, generation) = self
            .write_secrets_and_gens
            .get(usize::from(idx))
            .ok_or(Error::ValidationError("Member index out of bounds of application key chain"))?;

        // Derive the key and nonce
        let mut key_buf = vec![0u8; self.group_cs.aead_impl.key_size()];
        let mut nonce_buf = vec![0u8; self.group_cs.aead_impl.nonce_size()];
        hkdf::expand_label(
            self.group_cs.hash_impl,
            &write_secret.0,
            b"key",
            b"",
            key_buf.as_mut_slice(),
        );
        hkdf::expand_label(
            self.group_cs.hash_impl,
            &write_secret.0,
            b"nonce",
            b"",
            nonce_buf.as_mut_slice(),
        );

        let key = AeadKey::new_from_bytes(self.group_cs.aead_impl, &key_buf)?;
        let nonce = AeadNonce::new_from_bytes(self.group_cs.aead_impl, &nonce_buf)?;
        Ok((key, nonce, *generation))
    }

    /// Ratchets `write_secrets_[member_idx]` forward, as per section 9.1 of the MLS spec
    ///
    /// Returns: `Ok(())` on success. If the write secret is out of bounds, returns an
    /// `Error::ValidationError`. If the write secret's generation is `u32::MAX`, returns an
    /// `Error::KdfError`.
    fn ratchet(&mut self, member_idx: MemberIdx) -> Result<(), Error> {
        // We rename application_secret_[sender] to write_secret_[sender] for disambiguation's
        // sake. From the spec, we derive the new keys as follows:
        //     application_secret_[sender]_[N-1]
        //               |
        //               +--> HKDF-Expand-Label(.,"nonce", "", nonce_length)
        //               |    = write_nonce_[sender]_[N-1]
        //               |
        //               +--> HKDF-Expand-Label(.,"key", "", key_length)
        //               |    = write_key_[sender]_[N-1]
        //               V
        //     HKDF-Expand-Label(., "app sender", [sender], Hash.length)
        //               |
        //               V
        //     application_secret_[sender]_[N]

        // Get the current write secret and generation
        let (write_secret, generation) = self
            .write_secrets_and_gens
            .get_mut(usize::from(member_idx))
            .ok_or(Error::ValidationError("Member index out of bounds of application key chain"))?;

        // Ratchet the write secret, using its current value as a key
        // write_secret_[sender]_[n] =
        //     HKDF-Expand-Label(write_secret_[sender]_[n-1], "app sender", sender, Hash.length)
        // This serialization can't fail, since it's just a u32
        let serialized_member_idx = tls_ser::serialize_to_bytes(&member_idx).unwrap();
        let prk: HmacKey = write_secret.clone().into();
        hkdf::expand_label(
            self.group_cs.hash_impl,
            &prk,
            b"app sender",
            &serialized_member_idx,
            (write_secret.0).0.as_mut_slice(), // Overwrite the undelrying HmacKey
        );

        // Increment the generation
        generation.0 = generation
            .0
            .checked_add(1)
            .ok_or(Error::KdfError("Write secret's generation has hit its max"))?;

        Ok(())
    }

    /// Encrypts the given plaintext with the appropriate key and nonce derived from the sender's
    /// current `WriteSecret` in this application key chain. It then ratchets that `WriteSecret`
    /// forward.
    ///
    /// Returns: `Ok(app_message)` on success. If one of myriad things goes wrong, returns some
    /// sort of `Error`.
    pub fn encrypt_application_message(
        &mut self,
        mut plaintext: Vec<u8>,
    ) -> Result<ApplicationMessage, Error> {
        let (key, nonce, gen) = self.get_key_nonce_gen(self.my_member_idx)?;
        let ciphertext = {
            // Make room for the tag
            plaintext.extend(vec![0u8; self.group_cs.aead_impl.tag_size()]);
            // Encrypt it
            self.group_cs.aead_impl.seal(&key, nonce, &mut plaintext)?;
            plaintext
        };

        // All good. Now ratchet the write secret forward
        self.ratchet(self.my_member_idx)?;

        Ok(ApplicationMessage {
            ciphertext,
            gen,
            group_id: self.group_id.clone(),
            group_epoch: self.group_epoch_at_creation,
        })
    }

    /// Decrypts the given plaintext with the appropriate key and nonce derived from the sender's
    /// current `WriteSecret` in this application key chain. It then ratchets that `WriteSecret`
    /// forward.
    ///
    /// Returns: `Ok(app_message)` on success. If one of myriad things goes wrong, returns some
    /// sort of `Error`.
    pub fn decrypt_application_message(
        &mut self,
        mut msg: ApplicationMessage,
        sender: MemberIdx,
    ) -> Result<Vec<u8>, Error> {
        // Do some validation first
        if msg.group_id != self.group_id {
            return Err(Error::ValidationError(
                "Tried to decrypt ApplicationMessage from the wrong group",
            ));
        } else if msg.group_epoch != self.group_epoch_at_creation {
            return Err(Error::ValidationError(
                "Tried to decrypt ApplicationMessage from the wrong epoch",
            ));
        }

        let (key, nonce, gen) = self.get_key_nonce_gen(sender)?;
        if msg.gen != gen {
            return Err(Error::ValidationError(
                "Tried to decrypt ApplicationMessage with key from the wrong generation",
            ));
        }

        // Alright, enough sanity checks. Do the decryption and ratchet the keys.
        let plaintext = self.group_cs.aead_impl.open(&key, nonce, &mut msg.ciphertext)?;
        self.ratchet(sender)?;

        Ok(plaintext.to_vec())
    }
}

//
// Everything after this (not including tests) is non-standard
//

/// An MLS application message. This retains the ID and epoch of the creating group so that it
/// cannot be used with a different group or a group at a different epoch. This is not for security
/// purposes, but to prevent user error.
#[derive(Clone, Serialize)]
#[serde(rename = "ApplicationMessage__bound_u32")]
pub struct ApplicationMessage {
    /// The encrypted payload. This need not have any particular structure
    #[serde(rename = "msg__bound_u32")]
    ciphertext: Vec<u8>,

    /// The generation of the `WriteSecret` used to encrypt this message
    #[serde(skip)]
    gen: WriteSecretGeneration,

    /// The group ID of the group that created the ApplicationKeyChain that created this
    /// ApplicationMessage
    #[serde(skip)]
    group_id: GroupId,

    /// The epoch of the group that created the ApplicationKeyChain that created this
    /// ApplicationMessage
    #[serde(skip)]
    group_epoch: u32,
}

#[cfg(test)]
mod test {
    use crate::{
        application::ApplicationKeyChain,
        crypto::{
            aead::{AeadKey, AeadNonce, AeadScheme},
            ciphersuite::X25519_SHA256_AES128GCM,
            hmac::HmacKey,
            rng::CryptoRng,
        },
        group_ctx::{ApplicationSecret, GroupContext, GroupId},
        ratchet_tree::{MemberIdx, PathSecret},
        test_utils,
        tls_de::TlsDeserializer,
    };

    use core::convert::TryFrom;

    use quickcheck_macros::quickcheck;
    use rand::{self, SeedableRng};
    use serde::de::Deserialize;

    // Does an update operation on the two given groups and returns the resulting key chains
    fn do_update_op<R: CryptoRng>(
        group1: &mut GroupContext,
        group2: &mut GroupContext,
        rng: &mut R,
    ) -> (ApplicationKeyChain, ApplicationKeyChain) {
        let new_path_secret = PathSecret::new_from_random(group1.cs, rng);
        // Make a handshake and update group1
        let (handshake, new_group1, keychain1) =
            group1.create_and_apply_update_handshake(new_path_secret, rng).unwrap();
        *group1 = new_group1;

        // Process the handshake and update group2
        let member_idx1 = group1.member_index.unwrap();
        let (new_group2, keychain2) = group2.process_handshake(&handshake, member_idx1).unwrap();
        *group2 = new_group2;

        (keychain1, keychain2)
    }

    // Check that ApplicationKeyChain operations are consistent with a naive test encrypt/decrypt.
    // This is not at all how the application key schedule is supposed to be used. We only do sample
    // encryption/decryption because 1) it's fun and 2) we can't directly compare AES keys and
    // nonces because Eq is not implemented for them and I don't feel like implementing it for this
    // one test.
    #[quickcheck]
    fn app_key_schedule_correctness(rng_seed: u64) {
        // Prove key1 == key2 and nonce1 == nonce2 by having one pair encrypt a test plaintext and
        // the other pair decrypt it
        fn key_nonce_eq(
            aead_impl: &AeadScheme,
            key1: AeadKey,
            nonce1: AeadNonce,
            key2: AeadKey,
            nonce2: AeadNonce,
        ) -> bool {
            let orig_msg = b"hello world";
            // Encrypt orig_msg with (key1, nonce1)
            let mut ciphertext = {
                // Make room for the tag
                let mut plaintext = orig_msg.to_vec();
                plaintext.extend(vec![0u8; aead_impl.tag_size()]);

                // Encrypt in-place
                aead_impl.seal(&key1, nonce1, &mut plaintext).unwrap();
                plaintext
            };

            // Decrypt ciphertext with (key2, nonce2)
            let plaintext = aead_impl.open(&key2, nonce2, &mut ciphertext).unwrap().to_vec();

            // Check that the round-trip value is the same as orig_msg
            plaintext == orig_msg
        }

        let mut rng = rand::rngs::StdRng::seed_from_u64(rng_seed);

        // Make a starting group of at least 2 people
        let (mut group_ctx1, identity_keys) = test_utils::random_full_group_ctx(2, &mut rng);
        let member_idx1 = group_ctx1.member_index.unwrap();
        let aead_impl = group_ctx1.cs.aead_impl;

        // Make a copy of this group, but from another perspective. That is, we want the same group
        // but with a different member index
        let member_idx2 = test_utils::random_member_index_with_exceptions(
            group_ctx1.tree.num_leaves(),
            &[member_idx1],
            &mut rng,
        );
        let mut group_ctx2 =
            test_utils::change_self_index(&group_ctx1, &identity_keys, member_idx2);

        // Process any kind of Handshake, just so that we get a keychain out of it. We'll make an
        // Update operation starting at group_ctx1.
        let (mut app_key_chain1, mut app_key_chain2) =
            do_update_op(&mut group_ctx1, &mut group_ctx2, &mut rng);

        // Check that both chains agree on the key/nonce from index1
        let (key1, nonce1, gen1) = app_key_chain1.get_key_nonce_gen(member_idx1).unwrap();
        let (key2, nonce2, gen2) = app_key_chain2.get_key_nonce_gen(member_idx1).unwrap();
        assert!(key_nonce_eq(aead_impl, key1, nonce1, key2, nonce2));
        assert_eq!(gen1, gen2);

        // Check that both chains agree on the key/nonce from index2
        let (key1, nonce1, gen1) = app_key_chain1.get_key_nonce_gen(member_idx2).unwrap();
        let (key2, nonce2, gen2) = app_key_chain2.get_key_nonce_gen(member_idx2).unwrap();
        assert!(key_nonce_eq(aead_impl, key1, nonce1, key2, nonce2));
        assert_eq!(gen1, gen2);

        // Ratchet the values
        app_key_chain1.ratchet(member_idx1).unwrap();
        app_key_chain2.ratchet(member_idx1).unwrap();

        // Check that both chains agree on the key/nonce from index1
        let (key1, nonce1, gen1) = app_key_chain1.get_key_nonce_gen(member_idx1).unwrap();
        let (key2, nonce2, gen2) = app_key_chain2.get_key_nonce_gen(member_idx1).unwrap();
        assert!(key_nonce_eq(aead_impl, key1, nonce1, key2, nonce2));
        assert_eq!(gen1, gen2);

        // Check that both chains agree on the key/nonce from index2
        let (key1, nonce1, gen1) = app_key_chain1.get_key_nonce_gen(member_idx2).unwrap();
        let (key2, nonce2, gen2) = app_key_chain2.get_key_nonce_gen(member_idx2).unwrap();
        assert!(key_nonce_eq(aead_impl, key1, nonce1, key2, nonce2));
        assert_eq!(gen1, gen2);
    }

    // The following test vector is from
    // https://github.com/mlswg/mls-implementations/tree/68d1cf562d6e489c3025a4b6d0e4e18725674349/test_vectors
    //
    // File: app_key_schedule.bin
    //
    // struct {
    //   opaque secret<0..255>;
    //   opaque key<0..255>;
    //   opaque nonce<0..255>;
    // } AppKeyStep;
    //
    // AppKeyScheduleStep AppKeySequence<0..2^32-1>;
    // KeySequence AppKeyScheduleCase<0..2^32-1>;
    //
    // struct {
    //   uint32_t n_members;
    //   uint32_t n_generations;
    //   opaque application_secret<0..255>;
    //
    //   AppKeyScheduleCase case_p256;
    //   AppKeyScheduleCase case_x25519;
    // } AppKeyScheduleTestVectors;
    //
    // For each ciphersuite, the AppKeyScheduleTestVectors struct provides an AppKeyScheduleCase
    // that describes the outputs of the MLS application key schedule, for each participant in a
    // group over several generations.
    //
    // * The n_members field specifies the number of members in the group. Each AppKeyScheduleCase
    //   vector should have this many entries. The entry case[j] represents the vector of
    //   application keys for participant j.
    // * The n_generations field specifies the number of generations of application keys that are
    //   generated per participant. Each vector case[j] should have this many entries. The entry
    //   case[j][k] represents the values at generation k for participant j.
    // * The application_secret field represents the root application secret for this epoch (the
    //   one derived from the epoch_secret).
    // * For a given participant and generation, the AppKeyStep, the fields in the AppKeyStep
    //   object represent the following values:
    //   * secret represents application_secret_[j]_[k]
    //   * key represents write_key_[j]_[k]
    //   * nonce represents write_nonce_[j]_[k]
    //
    // Given the inputs as described above, your implementation should replicate the outputs of the
    // key schedule for each participant and generation.

    #[derive(Debug, Deserialize)]
    struct AppKeyStep {
        #[serde(rename = "secret__bound_u8")]
        secret: Vec<u8>,
        #[serde(rename = "key__bound_u8")]
        key: Vec<u8>,
        #[serde(rename = "nonce__bound_u8")]
        nonce: Vec<u8>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename = "AppKeySequence__bound_u32")]
    struct AppKeySequence(Vec<AppKeyStep>);

    #[derive(Debug, Deserialize)]
    #[serde(rename = "AppKeyScheduleCase__bound_u32")]
    struct AppKeyScheduleCase(Vec<AppKeySequence>);

    #[derive(Debug, Deserialize)]
    struct AppKeyScheduleVectors {
        num_members: u32,
        num_generations: u32,
        #[serde(rename = "application_secret__bound_u8")]
        application_secret: Vec<u8>,
        case_p256: AppKeyScheduleCase,
        case_x25519: AppKeyScheduleCase,
    }

    #[test]
    fn application_key_schedule_kat() {
        // There's no need to make this a quickcheck test, since it's pretty much impossible for
        // this to succeed due to random chance. But still, we need an rng for some of these ops,
        // and the test should still be deterministic, so just seed it with 0.
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);

        // Deserialize the test vectors (no need to upcast, there's nothing but vectors here)
        let mut f = std::fs::File::open("test_vectors/app_key_schedule.bin").unwrap();
        let mut deserializer = TlsDeserializer::from_reader(&mut f);
        let test_vecs = AppKeyScheduleVectors::deserialize(&mut deserializer).unwrap();

        // These values hold for all test vectors
        let num_members = test_vecs.num_members as usize;
        let app_secret = {
            let key = HmacKey::new_from_bytes(&test_vecs.application_secret);
            ApplicationSecret::new(key)
        };

        // Test the X25519 case
        // TODO: Test P256 when it's ready
        let case = test_vecs.case_x25519;

        // The ciphersuite and signature scheme for this test case
        let cs = &X25519_SHA256_AES128GCM;

        // Make a dummy GroupContext, just so we can pass it to
        // ApplicationKeyChain::from_application_secret. The only thing that matters is that the
        // number of leaves in the tree is at least num_members
        let (dummy_group_ctx, _) =
            test_utils::random_full_group_ctx(test_vecs.num_members, &mut rng);
        // Finally make the application key chain with the given application secret and correct
        // number of members
        let mut app_key_chain = ApplicationKeyChain::new(&dummy_group_ctx, app_secret);

        // The element at index i of this vector is a sequence of write_secrets belonging to member
        // i of the group. The sequence goes in generational order, starting at 0.
        let member_key_sequences = case.0;
        // Check that the number of members is what the test vector says it is
        assert_eq!(member_key_sequences.len(), num_members);

        // Go through each member in the group
        for (i, member_key_seq) in member_key_sequences.into_iter().enumerate() {
            let member_idx = MemberIdx::new(u32::try_from(i).unwrap());

            // Check that the number of generations we're checking is  what the test vector says
            assert_eq!(member_key_seq.0.len(), test_vecs.num_generations as usize);

            // Go through each generation of this members write_secret/write_key/write_nonce
            for key_step in member_key_seq.0.into_iter() {
                // We don't test write_secret directly, because we don't actually expose that
                // anywhere. Instead, we test the key and nonce values. This ought to be enough
                // because the key and nonce are derived from the write_secret.
                let given_key = AeadKey::new_from_bytes(cs.aead_impl, &key_step.key).unwrap();
                let given_nonce = AeadNonce::new_from_bytes(cs.aead_impl, &key_step.nonce).unwrap();

                // Ok so we don't actually test equality of keys or nonces, because I've wrapped
                // them in a bunch of opaque types. So let's do a sample encryption/decryption
                // instead. That should be enough, right? Right?!

                let orig_msg = b"No future, no future, no future for you";

                // The given key/nonce will be used to encrypt
                let mut ciphertext = {
                    // Make room for the tag
                    let mut plaintext = orig_msg.to_vec();
                    plaintext.extend(vec![0u8; cs.aead_impl.tag_size()]);

                    // Encrypt the thing in-place and return the mutated plaintext
                    cs.aead_impl.seal(&given_key, given_nonce, &mut plaintext).unwrap();
                    plaintext
                };

                // We'll use the derived key/nonce will decrypt it. The unwrap() inside this block
                // should fail if the key/nonce aren't the ones used above.
                let plaintext = {
                    let (derived_key, derived_nonce, _) =
                        app_key_chain.get_key_nonce_gen(member_idx).unwrap();
                    cs.aead_impl.open(&derived_key, derived_nonce, &mut ciphertext).unwrap()
                };

                // Make sure the decrypted ciphertext is equal to the original message
                assert_eq!(plaintext, &orig_msg[..]);

                // Ratchet forward this member's secrets
                app_key_chain.ratchet(member_idx).unwrap();
            }
        }
    }

    //
    // Everything after this is non-standard
    //

    #[quickcheck]
    fn application_message_correctness(rng_seed: u64) {
        fn encrypt_decrypt_test(
            orig_msg: &[u8],
            app_key_chain1: &mut ApplicationKeyChain,
            app_key_chain2: &mut ApplicationKeyChain,
        ) {
            // Group 1 will encrypt a message
            let app_message =
                app_key_chain1.encrypt_application_message(orig_msg.to_vec()).unwrap();

            // Group 2 will decrypt it
            let plaintext = app_key_chain2
                .decrypt_application_message(app_message, app_key_chain1.my_member_idx)
                .unwrap();

            // Make sure it's the same after a round trip
            assert_eq!(plaintext, orig_msg);
        }

        let mut rng = rand::rngs::StdRng::seed_from_u64(rng_seed);

        // Make a starting group of at least 2 people
        let (mut group_ctx1, identity_keys) = test_utils::random_full_group_ctx(2, &mut rng);

        // Make a copy of this group, but from another perspective. That is, we want the same group
        // but with a different member index
        let new_member_idx = test_utils::random_member_index_with_exceptions(
            group_ctx1.tree.num_leaves(),
            &[group_ctx1.member_index.unwrap()],
            &mut rng,
        );
        let mut group_ctx2 =
            test_utils::change_self_index(&group_ctx1, &identity_keys, new_member_idx);

        // Process any kind of Handshake, just so that we get a keychain out of it. We'll make an
        // Update operation starting at group_ctx1.
        let (mut app_key_chain1_epoch1, mut app_key_chain2_epoch1) =
            do_update_op(&mut group_ctx1, &mut group_ctx2, &mut rng);

        // This is the plaintext we'll be encrypting and decrypting
        let orig_msg = b"I'm gonna go over the Berlin wall";

        //
        // Epoch 1
        //

        // 1 --> 2
        encrypt_decrypt_test(orig_msg, &mut app_key_chain1_epoch1, &mut app_key_chain2_epoch1);
        // 2 --> 1
        encrypt_decrypt_test(orig_msg, &mut app_key_chain2_epoch1, &mut app_key_chain1_epoch1);

        //
        // Update
        //

        let (mut app_key_chain1_epoch2, mut app_key_chain2_epoch2) =
            do_update_op(&mut group_ctx1, &mut group_ctx2, &mut rng);

        //
        // Epoch 2
        //

        // 1 --> 2
        encrypt_decrypt_test(orig_msg, &mut app_key_chain1_epoch2, &mut app_key_chain2_epoch2);
        // 2 --> 1
        encrypt_decrypt_test(orig_msg, &mut app_key_chain2_epoch2, &mut app_key_chain1_epoch2);

        //
        // Back to Epoch 1
        //

        // 1 --> 2
        encrypt_decrypt_test(orig_msg, &mut app_key_chain1_epoch1, &mut app_key_chain2_epoch1);
        // 2 --> 1
        encrypt_decrypt_test(orig_msg, &mut app_key_chain2_epoch1, &mut app_key_chain1_epoch1);
    }

    // A cursory test that our validation checks and ratcheting mechanism is working sufficiently
    // well to prevent misuse
    #[quickcheck]
    fn application_message_soundness(rng_seed: u64) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(rng_seed);

        // Make two perspectives of the same group
        let (mut group_ctx1, identity_keys) = test_utils::random_full_group_ctx(2, &mut rng);
        let member_idx1 = group_ctx1.member_index.unwrap();

        // The second perspective cannot be the same as the first
        let member_idx2 = test_utils::random_member_index_with_exceptions(
            group_ctx1.tree.num_leaves(),
            &[member_idx1],
            &mut rng,
        );
        let mut group_ctx2 =
            test_utils::change_self_index(&group_ctx1, &identity_keys, member_idx2);

        // Process any kind of Handshake, just so that we get a keychain out of it. We'll make an
        // Update operation starting at group_ctx1.
        let (mut app_key_chain1, mut app_key_chain2) =
            do_update_op(&mut group_ctx1, &mut group_ctx2, &mut rng);

        // Group 1 encrypts a message
        let orig_msg = b"I want to be anarchy".to_vec();
        let mut app_message = app_key_chain1.encrypt_application_message(orig_msg).unwrap();

        // Group 1 tries to decrypt it. This should error, since the generations don't match up.
        assert!(app_key_chain1
            .decrypt_application_message(app_message.clone(), member_idx1)
            .is_err());

        // Group 2 tries to decrypt it with the wrong sender index. This should fail to decrypt.
        assert!(app_key_chain2
            .decrypt_application_message(app_message.clone(), member_idx2)
            .is_err());

        // Change the group ID to make sure that this difference is caught
        app_message.group_id = GroupId::new(b"wrong_group_id".to_vec()).unwrap();
        // Try to decrypt with everything correct except for the group ID
        assert!(app_key_chain2
            .decrypt_application_message(app_message.clone(), member_idx1)
            .is_err());
    }
}
