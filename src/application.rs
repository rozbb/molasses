//! This module contains the data structures for the application key schedule as well as
//! application-level messages

use crate::{
    credential::Credential,
    crypto::{
        aead::{AeadKey, AeadNonce},
        ciphersuite::CipherSuite,
        hkdf::{self, hkdf_expand_label},
    },
    error::Error,
    group_state::{ApplicationSecret, GroupState},
    tls_de::TlsDeserializer,
    tls_ser,
};

use clear_on_drop::ClearOnDrop;
use serde::de::Deserialize;

/// Contains a secret that is unique to a member of the group. This is part of the application key
/// schedule (section 9.1)
#[derive(Clone)]
pub(crate) struct WriteSecret(ClearOnDrop<Vec<u8>>);

impl WriteSecret {
    fn new(v: Vec<u8>) -> WriteSecret {
        WriteSecret(ClearOnDrop::new(v))
    }
}

/// Contains the secrets for every member of the group. These are called "application_secrets" in
/// the spec, but that's kinda confusing since "application_secret" is also something that the
/// `GroupState` creates and uses to seed this struct.
pub struct ApplicationKeyChain {
    /// Contains write secrets and their respective generations, starting at 0
    write_secrets_and_gens: Vec<(WriteSecret, u32)>,

    /// The creating group's ciphersuite
    group_cs: &'static CipherSuite,

    /// The creating group's ID
    group_id: Vec<u8>,

    /// The creating group's epoch at the time of creation. This is important for making the
    /// `ApplicationKeyChain` work independently from the creating `GroupState`.
    group_epoch_at_creation: u32,
}

impl ApplicationKeyChain {
    /// Creates an `ApplicationKeyChain` object from the given application secret and size of the
    /// current group (really, the size of the current roster, including blanks)
    pub(crate) fn from_application_secret(
        group_state: &GroupState,
        app_secret: ApplicationSecret,
    ) -> ApplicationKeyChain {
        // Make a write secret for every roster entry, and let its generation be 0
        let write_secrets_and_gens = (0..group_state.roster.len())
            .map(|roster_idx| {
                // write_secret_[sender] =
                //     HKDF-Expand-Label(application_secret, "app sender", sender, Hash.length)
                //  where sender is serialized as usual
                let secret = hkdf::prk_from_bytes(group_state.cs.hash_alg, &app_secret.0);
                let mut buf = vec![0u8; group_state.cs.hash_alg.output_len];
                let serialized_roster_idx = tls_ser::serialize_to_bytes(&roster_idx).unwrap();
                hkdf_expand_label(
                    &secret,
                    b"app sender",
                    &serialized_roster_idx,
                    buf.as_mut_slice(),
                );

                // (write_secret, generation=0)
                (WriteSecret::new(buf), 0)
            })
            .collect();

        ApplicationKeyChain {
            write_secrets_and_gens: write_secrets_and_gens,
            group_cs: group_state.cs,
            group_id: group_state.group_id.clone(),
            group_epoch_at_creation: group_state.epoch,
        }
    }

    /// Retrieves `write_secrets_[roster_idx]` and derives a key and nonce from it, as per section
    /// 9.1 of the MLS spec
    ///
    /// Returns: `Ok((gen, write_key_[roster_idx]_[gen], write_nonce_[roster_idx]_[gen]))` on
    /// sucess, where `gen` is the current generation of the `WriteSecret` of the member indexed by
    /// `roster_idx`. Returns an `Error` if `roster_idx` is out of bounds or something goes wrong
    /// in the creation of the key/nonce from bytes.
    fn get_key_nonce_gen(&self, roster_idx: usize) -> Result<(AeadKey, AeadNonce, u32), Error> {
        // Get a reference to the write secret and current generation. We update these in-place at
        // the end.
        let (write_secret, generation) = self
            .write_secrets_and_gens
            .get(roster_idx)
            .ok_or(Error::ValidationError("Roster index out of bounds of application key chain"))?;

        // Derive the key and nonce
        let prk = hkdf::prk_from_bytes(self.group_cs.hash_alg, &write_secret.0);
        let mut key_buf = vec![0u8; self.group_cs.aead_impl.key_size()];
        let mut nonce_buf = vec![0u8; self.group_cs.aead_impl.nonce_size()];
        hkdf_expand_label(&prk, b"key", b"", key_buf.as_mut_slice());
        hkdf_expand_label(&prk, b"nonce", b"", nonce_buf.as_mut_slice());

        Ok((
            self.group_cs.aead_impl.key_from_bytes(&key_buf)?,
            self.group_cs.aead_impl.nonce_from_bytes(&nonce_buf)?,
            *generation,
        ))
    }

    /// Ratchets `write_secrets_[roster_idx]` forward, as per section 9.1 of the MLS spec
    ///
    /// Returns: `Ok(())` on success. If the write secret is out of bounds, returns an
    /// `Error::ValidationError`. If the write secret's generation is `u32::MAX`, returns an
    /// `Error::KdfError`.
    fn ratchet(&mut self, roster_idx: usize) -> Result<(), Error> {
        // How to derive the new write key:
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
            .get_mut(roster_idx)
            .ok_or(Error::ValidationError("Roster index out of bounds of application key chain"))?;
        let current_secret = write_secret.clone();

        // Ratchet the write secret, using its current value as a key
        let serialized_roster_idx = tls_ser::serialize_to_bytes(&roster_idx).unwrap();
        let prk = hkdf::prk_from_bytes(self.group_cs.hash_alg, &current_secret.0);
        hkdf_expand_label(&prk, b"app sender", &serialized_roster_idx, &mut *write_secret.0);

        // Increment the generation
        *generation = generation
            .checked_add(1)
            .ok_or(Error::KdfError("Write secret's generation has hit its max"))?;

        Ok(())
    }
}

//
// Everything after this (not including tests) is non-standard
//

/// A signed payload of an application message. This can be padded at the end by an arbitrary
/// number of zeros. This property is checked in constant time upon deserialization
#[derive(Deserialize, Serialize)]
#[serde(rename = "ApplicationMessageContent__zero_padded")]
struct ApplicationMessageContent {
    // opaque content<0..2^32-1>;
    /// The unencrypted message bytes
    #[serde(rename = "content__bound_u32")]
    content: Vec<u8>,

    // opaque signature<0..2^16-1>;
    /// A signature over this message's associated `SignatureContent`
    #[serde(rename = "signature__bound_u16")]
    signature: Vec<u8>,
}

/// An application message that's strongly bound to the state of the group and application key
/// schedule at the time of sending
#[derive(Clone, Deserialize, Serialize)]
pub struct ApplicationMessage {
    #[serde(rename = "group_id__bound_u8")]
    group_id: Vec<u8>,
    epoch: u32,
    generation: u32,
    sender: u32,
    #[serde(rename = "encrypted_content__bound_u32")]
    encrypted_content: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
struct SignatureContent<'a> {
    #[serde(rename = "group_id__bound_u8")]
    group_id: &'a [u8],
    epoch: u32,
    generation: u32,
    sender: u32,
    #[serde(rename = "content__bound_u32")]
    content: &'a [u8],
}

/// Encrypts the given plaintext with the appropriate key and nonce derived from the sender's
/// current `WriteSecret` in this application key chain
///
/// Returns: `Ok(app_message)` on success. Otherwise, if one of myriad things goes wrong, returns
/// some sort of `Error`.
// Note that this still has to take in a `GroupState` because it needs to know the group member's
// roster index and identity key, and I don't want to copy a long-term identity key into a symmetric
// key chain. That's right. Sue me.
pub fn encrypt_application_message(
    plaintext: Vec<u8>,
    group_state: &GroupState,
    app_key_chain: &mut ApplicationKeyChain,
) -> Result<ApplicationMessage, Error> {
    // Check ownership first
    if group_state.group_id != app_key_chain.group_id {
        return Err(Error::ValidationError("Key chain does not belong to this group state"));
    }
    // This shouldn't happen. The app_key_chain should inherit the ciphersuite it was created from
    if group_state.cs != app_key_chain.group_cs {
        return Err(Error::ValidationError(
            "Key chain and GroupState aren't on the same ciphersuite",
        ));
    }
    let group_id = &group_state.group_id;
    let cs = group_state.cs;

    // This really really shouldn't be able to happen. A preliminary GroupState couldn't even
    // produce an ApplicationSecret to make this key chain in the first place.
    let my_roster_idx = group_state
        .roster_index
        .ok_or(Error::ValidationError("Cannot encrypt a message with a preliminary GroupState"))?;
    let (key, nonce, generation) = app_key_chain.get_key_nonce_gen(my_roster_idx as usize)?;

    // Sign the message. The epoch we use is the one that was current at the time of the creation of
    // the key chain. This way, we could have multiple key chains in use at the same time and still
    // be able to update the GroupState
    let signature_content = SignatureContent {
        group_id: &group_id,
        epoch: app_key_chain.group_epoch_at_creation,
        generation: generation,
        sender: my_roster_idx,
        content: &plaintext,
    };
    let serialized_signature_content = tls_ser::serialize_to_bytes(&signature_content)?;
    let hashed_signature_content = ring::digest::digest(cs.hash_alg, &serialized_signature_content);
    let sig = cs.sig_impl.sign(&group_state.identity_key, hashed_signature_content.as_ref());

    // Pack the plaintext and signature together and encrypt it
    let message_content = ApplicationMessageContent {
        content: plaintext,
        signature: sig.to_bytes(),
    };
    let encrypted_content = {
        // Serialize the ApplicationMessageContent and make room for the tag
        let mut serialized_message_content = tls_ser::serialize_to_bytes(&message_content)?;
        serialized_message_content.extend(vec![0u8; cs.aead_impl.tag_size()]);

        // Encrypt it
        cs.aead_impl.seal(&key, nonce, &mut serialized_message_content)?;
        serialized_message_content
    };

    // All good. Now ratchet the write secret forward
    app_key_chain.ratchet(my_roster_idx as usize)?;

    Ok(ApplicationMessage {
        group_id: group_state.group_id.clone(),
        epoch: app_key_chain.group_epoch_at_creation,
        generation: generation,
        sender: my_roster_idx,
        encrypted_content: encrypted_content,
    })
}

/// Decrypts the given application message with the appropriate key and nonce derived from the
/// sender's current `WriteSecret` in this application key chain
///
/// Returns: `Ok(plaintext)` on success. Otherwise, if one of myriad things goes wrong, returns some
/// sort of `Error`.
// Note that this still has to take in a `GroupState` because the group's roster is liable to change
// over time, and the roster is necessary to verify message signatures.
pub fn decrypt_application_message(
    mut app_message: ApplicationMessage,
    group_state: &GroupState,
    app_key_chain: &mut ApplicationKeyChain,
) -> Result<Vec<u8>, Error> {
    // Check ownership first
    if group_state.group_id != app_key_chain.group_id {
        return Err(Error::ValidationError("Key chain does not belong to this group"));
    }
    // Check that the ciphersuites match
    if group_state.cs != app_key_chain.group_cs {
        return Err(Error::ValidationError("Key chain's ciphersuite differs from the group's"));
    }
    let cs = group_state.cs;
    let group_id = &group_state.group_id;

    // Check that the message was for this group
    if &app_message.group_id != group_id {
        return Err(Error::ValidationError(
            "Application message's group_id differs from the key chain's",
        ));
    }

    // Again, the reason we use the current epoch at the time of the creation of this key chain is
    // so we could have multiple key chains in use at the same time and be able to update the
    // GroupState independently
    if app_message.epoch != app_key_chain.group_epoch_at_creation {
        return Err(Error::ValidationError(
            "Application message's epoch differs from the key chain's",
        ));
    }

    // Get the secrets necessary to decrypt it
    let (key, nonce, generation) = app_key_chain.get_key_nonce_gen(app_message.sender as usize)?;

    // The WriteSecret generations need to match up
    if app_message.generation != generation {
        return Err(Error::ValidationError(
            "Application message's generation differs from the write secret's",
        ));
    }

    // Reconstruct the content of the message as well as its signature
    let serialized_message_content =
        cs.aead_impl.open(&key, nonce, &mut app_message.encrypted_content)?;
    let message_content = {
        let mut cursor: &[u8] = serialized_message_content;
        let mut deserializer = TlsDeserializer::from_reader(&mut cursor);
        ApplicationMessageContent::deserialize(&mut deserializer)?
    };
    let plaintext = message_content.content;
    let signature = cs.sig_impl.signature_from_bytes(&message_content.signature)?;

    // Get the sender's public key from the roster. There are two things that can go wrong here:
    // either the sender index is phony, or the index is real but the roster entry is empty.
    let sender_opt: &Option<Credential> = group_state
        .roster
        .0
        .get(app_message.sender as usize)
        .ok_or(Error::ValidationError("Application message's sender index is out of bounds"))?;
    let sender_pubkey = sender_opt
        .as_ref()
        .ok_or(Error::ValidationError("Application message's sender is blank"))?
        .get_public_key();

    // Create the stuff that the signature is over, then verify the signature. See above for why we
    // use group_epoch_at_creation
    let signature_content = SignatureContent {
        group_id: group_id,
        epoch: app_key_chain.group_epoch_at_creation,
        generation: generation,
        sender: app_message.sender,
        content: &plaintext,
    };
    let serialized_signature_content = tls_ser::serialize_to_bytes(&signature_content)?;
    let hashed_signature_content = ring::digest::digest(cs.hash_alg, &serialized_signature_content);
    cs.sig_impl.verify(sender_pubkey, hashed_signature_content.as_ref(), &signature)?;

    // All good. Now ratchet the write secret forward
    app_key_chain.ratchet(app_message.sender as usize)?;

    Ok(plaintext)
}

#[cfg(test)]
mod test {
    use crate::{
        application::{
            decrypt_application_message, encrypt_application_message, ApplicationKeyChain,
        },
        crypto::rng::CryptoRng,
        group_state::GroupState,
        utils::test_utils,
    };

    use quickcheck_macros::quickcheck;
    use rand::{self, SeedableRng};

    fn do_update_op<R: CryptoRng>(
        group1: &mut GroupState,
        group2: &mut GroupState,
        rng: &mut R,
    ) -> (ApplicationKeyChain, ApplicationKeyChain) {
        let new_path_secret = test_utils::random_path_secret(&group1, rng);
        // This mutates group1
        let (handshake, keychain1) =
            group1.create_and_apply_update_handshake(new_path_secret, rng).unwrap();

        // Process the handshake and update group2
        let (new_group2, keychain2) = group2.process_handshake(&handshake).unwrap();
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
        let mut rng = rand::rngs::StdRng::seed_from_u64(rng_seed);

        // Make a starting group
        let (mut group_state1, identity_keys) = test_utils::random_full_group_state(&mut rng);
        let index1 = group_state1.roster_index.unwrap();

        // Make a copy of this group, but from another perspective. That is, we want the same group
        // but with a different roster index
        let index2 = test_utils::random_roster_index_with_exception(
            group_state1.roster.len(),
            group_state1.roster_index.unwrap() as usize,
            &mut rng,
        );
        let mut group_state2 = test_utils::change_self_index(&group_state1, &identity_keys, index2);

        // Process any kind of Handshake, just so that we get a keychain out of it. We'll make an
        // Update operation starting at group_state1.
        let (app_key_chain1, app_key_chain2) =
            do_update_op(&mut group_state1, &mut group_state2, &mut rng);

        // Group 1 will encrypt a message
        let orig_msg = b"hello world";
        let mut ciphertext = {
            // Make room for the tag
            let mut plaintext = orig_msg.to_vec();
            plaintext.extend(vec![0u8; group_state1.cs.aead_impl.tag_size()]);

            let (key, nonce, _) = app_key_chain1.get_key_nonce_gen(index1 as usize).unwrap();
            group_state1.cs.aead_impl.seal(&key, nonce, &mut plaintext).unwrap();
            plaintext
        };

        // Group 2 will decrypt it
        let plaintext = {
            let (key, nonce, _) = app_key_chain2.get_key_nonce_gen(index1 as usize).unwrap();
            group_state2.cs.aead_impl.open(&key, nonce, &mut ciphertext).unwrap()
        };

        // Make sure they agree
        assert_eq!(plaintext, orig_msg);
    }

    //
    // Everything after this is non-standard
    //

    #[quickcheck]
    fn application_message_correctness(rng_seed: u64) {
        fn encrypt_decrypt_test(
            orig_msg: &[u8],
            group1: &GroupState,
            app_key_chain1: &mut ApplicationKeyChain,
            group2: &GroupState,
            app_key_chain2: &mut ApplicationKeyChain,
        ) {
            // Group 1 will encrypt a message
            let app_message =
                encrypt_application_message(orig_msg.to_vec(), group1, app_key_chain1).unwrap();

            // Group 2 will decrypt it
            let plaintext =
                decrypt_application_message(app_message, group2, app_key_chain2).unwrap();

            // Make sure it's the same after a round trip
            assert_eq!(plaintext.as_slice(), orig_msg);
        }

        let mut rng = rand::rngs::StdRng::seed_from_u64(rng_seed);

        // Make a starting group
        let (mut group_state1, identity_keys) = test_utils::random_full_group_state(&mut rng);

        // Make a copy of this group, but from another perspective. That is, we want the same group
        // but with a different roster index
        let new_roster_idx = test_utils::random_roster_index_with_exception(
            group_state1.roster.len(),
            group_state1.roster_index.unwrap() as usize,
            &mut rng,
        );
        let mut group_state2 =
            test_utils::change_self_index(&group_state1, &identity_keys, new_roster_idx);

        // Process any kind of Handshake, just so that we get a keychain out of it. We'll make an
        // Update operation starting at group_state1.
        let (mut app_key_chain1_epoch1, mut app_key_chain2_epoch1) =
            do_update_op(&mut group_state1, &mut group_state2, &mut rng);

        // This is the plaintext we'll be encrypting and decrypting
        let orig_msg = b"I'm gonna go over the Berlin wall";

        //
        // Epoch 1
        //

        // 1 --> 2
        encrypt_decrypt_test(
            orig_msg,
            &group_state1,
            &mut app_key_chain1_epoch1,
            &group_state2,
            &mut app_key_chain2_epoch1,
        );
        // 2 --> 1
        encrypt_decrypt_test(
            orig_msg,
            &group_state2,
            &mut app_key_chain2_epoch1,
            &group_state1,
            &mut app_key_chain1_epoch1,
        );

        //
        // Update
        //

        let (mut app_key_chain1_epoch2, mut app_key_chain2_epoch2) =
            do_update_op(&mut group_state1, &mut group_state2, &mut rng);

        //
        // Epoch 2
        //

        // 1 --> 2
        encrypt_decrypt_test(
            orig_msg,
            &group_state1,
            &mut app_key_chain1_epoch2,
            &group_state2,
            &mut app_key_chain2_epoch2,
        );
        // 2 --> 1
        encrypt_decrypt_test(
            orig_msg,
            &group_state2,
            &mut app_key_chain2_epoch2,
            &group_state1,
            &mut app_key_chain1_epoch2,
        );

        //
        // Back to Epoch 1
        //

        // 1 --> 2
        encrypt_decrypt_test(
            orig_msg,
            &group_state1,
            &mut app_key_chain1_epoch1,
            &group_state2,
            &mut app_key_chain2_epoch1,
        );
        // 2 --> 1
        encrypt_decrypt_test(
            orig_msg,
            &group_state2,
            &mut app_key_chain2_epoch1,
            &group_state1,
            &mut app_key_chain1_epoch1,
        );
    }

    // A cursory test that our validation checks and ratcheting mechanism is working sufficiently
    // well to prevent misuse
    #[quickcheck]
    fn application_message_soundness(rng_seed: u64) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(rng_seed);

        // Make two perspectives of the same group
        let (mut group_state1, identity_keys) = test_utils::random_full_group_state(&mut rng);
        let new_roster_idx = test_utils::random_roster_index_with_exception(
            group_state1.roster.len(),
            group_state1.roster_index.unwrap() as usize,
            &mut rng,
        );
        let mut group_state2 =
            test_utils::change_self_index(&group_state1, &identity_keys, new_roster_idx);

        // Process any kind of Handshake, just so that we get a keychain out of it. We'll make an
        // Update operation starting at group_state1.
        let (mut app_key_chain1, mut app_key_chain2) =
            do_update_op(&mut group_state1, &mut group_state2, &mut rng);

        // Group 1 encrypts a message
        let orig_msg = b"I want to be anarchy".to_vec();
        let app_message =
            encrypt_application_message(orig_msg, &group_state1, &mut app_key_chain1).unwrap();

        // Group 1 tries to decrypt it. This should error, since the generations don't match up.
        assert!(decrypt_application_message(
            app_message.clone(),
            &group_state1,
            &mut app_key_chain1
        )
        .is_err());

        // Group 2 tries to decrypt it with Group 1's keychain. This should error, since the
        // generations don't match up
        assert!(decrypt_application_message(
            app_message.clone(),
            &group_state2,
            &mut app_key_chain1
        )
        .is_err());

        // Some rando group tries to decrypt it with Group2's keychain. This should error, since
        // this new group's ID won't match the key chain's
        let (rando_group, _) = test_utils::random_full_group_state(&mut rng);
        assert!(decrypt_application_message(
            app_message.clone(),
            &rando_group,
            &mut app_key_chain2
        )
        .is_err());
    }
}
