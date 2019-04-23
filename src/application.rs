//! This module contains the data structures for the application key schedule as well as
//! application-level messages

use crate::{
    crypto::{
        aead::{AeadKey, AeadNonce},
        ciphersuite::CipherSuite,
        hkdf::{self, hkdf_expand_label},
    },
    error::Error,
    group_state::ApplicationSecret,
    tls_ser,
};

use clear_on_drop::ClearOnDrop;

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
pub(crate) struct ApplicationKeyChain {
    cs: &'static CipherSuite,
    write_secrets: Vec<WriteSecret>,
}

impl ApplicationKeyChain {
    /// Creates an `ApplicationKeyChain` object from the given application secret and size of the
    /// current group (really, the size of the current roster, including blanks)
    pub(crate) fn from_application_secret(
        cs: &'static CipherSuite,
        app_secret: ApplicationSecret,
        roster_size: usize,
    ) -> ApplicationKeyChain {
        // Make a write secret for every roster entry
        let write_secrets = (0..roster_size)
            .map(|roster_idx| {
                // write_secret_[sender] =
                //     HKDF-Expand-Label(application_secret, "app sender", sender, Hash.length)
                //  where sender is serialized as usual
                let secret = hkdf::prk_from_bytes(cs.hash_alg, &app_secret.0);
                let mut buf = vec![0u8; cs.hash_alg.output_len];
                let serialized_roster_idx = tls_ser::serialize_to_bytes(&roster_idx).unwrap();
                hkdf_expand_label(
                    &secret,
                    b"app sender",
                    &serialized_roster_idx,
                    buf.as_mut_slice(),
                );

                WriteSecret::new(buf)
            })
            .collect();

        ApplicationKeyChain {
            cs,
            write_secrets,
        }
    }

    /// Retrieves `write_secrets_[roster_idx]`, derives a key and nonce from it, and ratchets it
    /// forward as per section 9.1 of the MLS spec
    ///
    /// Returns: `Ok((write_key_[roster_idx]_[gen], write_nonce_[roster_idx]_[gen]))` on sucess,
    /// where `gen` is the current generation of the `WriteSecret` of the member indexed by
    /// `roster_idx`. Returns an `Error` if `roster_idx` is out of bounds or something goes wrong
    /// in the creation of the key/nonce from bytes.
    fn get_and_ratchet(&mut self, roster_idx: usize) -> Result<(AeadKey, AeadNonce), Error> {
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

        // Get a ref to the write secret. We update this in-place at the end.
        let write_secret = self
            .write_secrets
            .get_mut(roster_idx)
            .ok_or(Error::ValidationError("Roster index out of bounds of application key chain"))?;
        let old_secret = write_secret.clone();

        // Derive the key and nonce
        let prk = hkdf::prk_from_bytes(self.cs.hash_alg, &old_secret.0);
        let mut key_buf = vec![0u8; self.cs.aead_impl.key_size()];
        let mut nonce_buf = vec![0u8; self.cs.aead_impl.nonce_size()];
        hkdf_expand_label(&prk, b"key", b"", key_buf.as_mut_slice());
        hkdf_expand_label(&prk, b"nonce", b"", nonce_buf.as_mut_slice());

        // Now ratchet our copy of the write_secret
        let serialized_roster_idx = tls_ser::serialize_to_bytes(&roster_idx).unwrap();
        hkdf_expand_label(&prk, b"app sender", &serialized_roster_idx, &mut *write_secret.0);

        Ok((
            self.cs.aead_impl.key_from_bytes(&key_buf)?,
            self.cs.aead_impl.nonce_from_bytes(&nonce_buf)?,
        ))
    }
}

#[cfg(test)]
mod test {
    use crate::utils::test_utils;

    use quickcheck_macros::quickcheck;
    use rand::{self, SeedableRng};

    // Check that ApplicationKeyChain operations are consistent with a naive test encrypt/decrypt
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
        let group_state2 = test_utils::change_self_index(&group_state1, &identity_keys, index2);

        // Process any kind of Handshake, just so that we get a keychain out of it. We'll make an
        // Update operation starting at group_state1.
        let new_path_secret = test_utils::random_path_secret(&group_state1, &mut rng);
        let (update_op, mut app_key_chain1, conf_key) =
            group_state1.create_and_apply_update_op(new_path_secret, &mut rng).unwrap();
        let handshake = group_state1.create_handshake(update_op, conf_key).unwrap();

        // Apply the update to the second group
        let (group_state2, mut app_key_chain2) =
            group_state2.process_handshake(&handshake).unwrap();

        // Group 1 will encrypt a message
        let orig_msg = b"hello world";
        let mut ciphertext = {
            // Make room for the tag
            let mut plaintext = orig_msg.to_vec();
            plaintext.extend(vec![0u8; group_state1.cs.aead_impl.tag_size()]);

            let (key, nonce) = app_key_chain1.get_and_ratchet(index1 as usize).unwrap();
            group_state1.cs.aead_impl.seal(&key, nonce, &mut plaintext).unwrap();
            plaintext
        };

        // Group 2 will decrypt it
        let plaintext = {
            let (key, nonce) = app_key_chain2.get_and_ratchet(index1 as usize).unwrap();
            group_state2.cs.aead_impl.open(&key, nonce, &mut ciphertext).unwrap()
        };

        // Make sure they agree
        assert_eq!(plaintext, orig_msg);
    }
}
