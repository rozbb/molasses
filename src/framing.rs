use crate::{
    application::ApplicationKeyChain,
    crypto::{
        aead::{AeadKey, AeadNonce},
        ciphersuite::CipherSuite,
        hkdf,
        hmac::HmacKey,
        rng::CryptoRng,
        sig::{SigPublicKey, Signature, SignatureScheme},
    },
    error::Error,
    group_ctx::{GroupContext, GroupId, HandshakeSecret, SenderDataSecret},
    handshake::Handshake,
    ratchet_tree::MemberIdx,
    tls_de::TlsDeserializer,
    tls_ser,
};

use serde::de::Deserialize;
use subtle::ConstantTimeEq;

/// Encodes the type of payload in an `MlsPlaintext`. This is called `ContentType` in the spec.
#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename = "MlsPlaintextContentKind__enum_u8")]
enum MlsPlaintextContentKind {
    Invalid,
    Handshake,
    Application,
}

/// The payload of an `MlsPlaintext`
#[derive(Deserialize, Serialize)]
pub enum MlsPlaintextContent {
    Invalid,

    /// A Handshake operation
    Handshake(Handshake),

    /// An encrypted application message. This is turned into an `ApplicationMessage` by `Framer`.
    Application(Vec<u8>),
}

impl MlsPlaintextContent {
    /// Returns the variant of this enum
    fn kind(&self) -> MlsPlaintextContentKind {
        match self {
            MlsPlaintextContent::Invalid => MlsPlaintextContentKind::Invalid,
            MlsPlaintextContent::Handshake {
                ..
            } => MlsPlaintextContentKind::Handshake,
            MlsPlaintextContent::Application {
                ..
            } => MlsPlaintextContentKind::Application,
        }
    }
}

/// This is the content that we compute `MlsPlaintext::signature` over
#[derive(Serialize)]
struct MlsPlaintextSigData<'a> {
    group_id: &'a GroupId,
    epoch: u32,
    sender: MemberIdx,
    content: &'a MlsPlaintextContent,
}

/// The container object for any plaintext message sent in MLS
#[derive(Deserialize, Serialize)]
struct MlsPlaintext {
    /// The group ID of the group this plaintext pertains to
    group_id: GroupId,

    /// The epoch of the group this ciphertext pertains to
    epoch: u32,

    /// The sender of this message
    sender: MemberIdx,

    /// The plaintext's payload. This is a handshake message or an application message
    content: MlsPlaintextContent,

    /// Signature over all the prior fields in this struct
    signature: Signature,
}

impl MlsPlaintext {
    /// Create a new `MlsPlaintext` from its constituent components
    ///
    /// Panics: If the given `group_ctx` is in a preliminary state, i.e., it's between a `Welcome`
    /// and `Add` operation
    ///
    /// Returns: `Ok(mls_pt)` on success. If something goes wrong in serializing the underlying
    /// `MlsPlaintextSigData`, returns an `Error::SerdeError`.
    pub(crate) fn new(
        ss: &SignatureScheme,
        group_ctx: &GroupContext,
        content: MlsPlaintextContent,
    ) -> Result<MlsPlaintext, Error> {
        let group_id = group_ctx.group_id.clone();
        let epoch = group_ctx.epoch;
        let sender = group_ctx
            .member_index
            .expect("cannot make an MlsPlaintext from a preliminary group context");

        // This is the data we will calculate the signature of
        let sig_data = MlsPlaintextSigData {
            group_id: &group_id,
            epoch,
            sender: sender,
            content: &content,
        };
        // Serialize the signature data and sign it. This is the final field in MlsPlaintext
        let signature = ss.sign_serializable(&group_ctx.identity_key, &sig_data)?;

        Ok(MlsPlaintext {
            group_id,
            epoch,
            sender,
            content,
            signature,
        })
    }

    /// Verifies `self.signature` against the rest of the `MlsPlaintext` fields
    ///
    /// Returns: `Ok(())` on successful verification. Returns an `Error::SerdeError` if the
    /// non-signature `MlsPlaintext` fields fail to serialize. Returns an `Error::SignatureError`
    /// if signature verification fails.
    fn verify_signature(
        &self,
        ss: &SignatureScheme,
        public_key: &SigPublicKey,
    ) -> Result<(), Error> {
        // MlsPlaintext::signature is computed over everything else in MlsPlaintext
        let sig_data = MlsPlaintextSigData {
            group_id: &self.group_id,
            epoch: self.epoch,
            sender: self.sender,
            content: &self.content,
        };
        ss.verify_serializable(public_key, &sig_data, &self.signature)
    }

    /// Checks that this `MlsPlaintext`'s metadata agrees with the given metadata
    ///
    /// Returns: `Ok(())` if everything matches. Otherwise returns an `Error::ValidationError`.
    fn validate_metadata(
        &self,
        content_type: MlsPlaintextContentKind,
        group_id: &GroupId,
        sender_data: &MlsSenderData,
        epoch: u32,
    ) -> Result<(), Error> {
        // Check type
        if self.content.kind() != content_type {
            return Err(Error::ValidationError(
                "MLSPlaintext's content type does not match the encapsulating MLSCiphertext's",
            ));
        }

        // Check ownership
        let group_ids_match: bool = self.group_id.ct_eq(group_id).into();
        if !group_ids_match {
            return Err(Error::ValidationError(
                "MLSPlaintext's group ID does not match the encapsulating MLSCiphertext's",
            ));
        }

        // Check perspective
        if self.sender != sender_data.sender {
            return Err(Error::ValidationError(
                "MLSPlaintext's sender index does not match the encapsulating MLSCiphertext's",
            ));
        }

        // Check sequence
        if self.epoch != epoch {
            return Err(Error::ValidationError(
                "MLSPlaintext's epoch does not match the encapsulating MLSCiphertext's",
            ));
        }

        Ok(())
    }
}

/// Data about the sender of an `MlsCiphertext`
#[derive(Clone, Copy, Deserialize, Serialize)]
struct MlsSenderData {
    /// The member index of the sender
    sender: MemberIdx,

    /// The generation of the encryption key (default 0 for handshake keys)
    generation: u32,
}

/// The additional authenticated data that goes along with the encryption of `MlsSenderData`
#[derive(Serialize)]
struct MlsCiphertextSenderDataAad<'a> {
    group_id: &'a GroupId,
    epoch: u32,
    content_type: MlsPlaintextContentKind,
    sender_data_nonce: &'a AeadNonce,
}

// TODO: This is a false equivalence. Figure out how to parse zero-padded structs
/// The object that gets encrypted into `MlsCiphertext::ciphertext`
type MlsCiphertextContent = MlsPlaintext;

/// The additional authenticated data that goes along with the encryption of `MlsCiphertextContent`
#[derive(Serialize)]
struct MlsCiphertextContentAad<'a> {
    group_id: &'a GroupId,
    epoch: u32,
    content_type: MlsPlaintextContentKind,
    sender_data_nonce: &'a AeadNonce,
    #[serde(rename = "encrypted_sender_data__bound_u8")]
    encrypted_sender_data: &'a [u8],
}

/// The container object for any ciphertext message sent in MLS
#[derive(Deserialize, Serialize)]
pub struct MlsCiphertext {
    /// The group ID of the group this ciphertext pertains to
    group_id: GroupId,

    /// The epoch of the group this ciphertext pertains to
    epoch: u32,

    /// Encodes whether the contents of this encryped message is a handshake message or an
    /// application message
    content_type: MlsPlaintextContentKind,

    /// Nonce used to decrypt this ciphertext. The key should be derivable from the current group
    /// context.
    sender_data_nonce: AeadNonce,

    /// An encrypted `MlsSenderData`
    #[serde(rename = "encrypted_sender_data__bound_u8")]
    encrypted_sender_data: Vec<u8>,

    /// The payload of this ciphertext. This is an encrypted `MlsCiphertextContent` object
    #[serde(rename = "ciphertext__bound_u32")]
    ciphertext: Vec<u8>,
}

/// This struct is responsible for all framing/unframing operations. A new such object is created
/// for every group epoch.
pub struct Framer {
    // We could theoretically generate all the handshake key/nonce pairs in the constructor and
    // throw away the HandshakeSecret, but that doesn't buy us much additional security. If the
    // HandshakeSecret is compromised, then an attacker can decrypt a Handshake from any sender. If
    // the vector of key/nonce pairs is compromised, the same thing happens. This is different from
    // ApplicationKeyChain because in that case there are keys that need to be ratcheted forward,
    // i.e., forgotton once used. Here, every key can be forgotton once one of them is used, which
    // is equivalent to forgetting the HandshakeSecret after we use it once.
    /// The secret used to derive the key/nonce used to encrypt `Handshake` messages
    handshake_secret: HandshakeSecret,

    /// The key used to encrypt `MlsSenderData`
    sender_data_key: AeadKey,

    /// The creating group's ID
    group_id: GroupId,

    /// The creating group's epoch at the time of creation. This is important for making the
    /// `Framer` work independently from the creating `GroupContext`.
    group_epoch_at_creation: u32,

    /// The member index of this user in the creating group
    my_member_idx: MemberIdx,
}

impl Framer {
    /// Makes a new `Framer` from the given `GroupContext` and some of  the secrets produced from
    /// its last epoch secrets update
    pub(crate) fn new(
        group_ctx: &GroupContext,
        handshake_secret: HandshakeSecret,
        sender_data_secret: SenderDataSecret,
    ) -> Framer {
        let cs = group_ctx.cs;

        // This should never error. Framers can only be made after a group is out of preliminary
        // mode anyway
        let my_member_idx =
            group_ctx.member_index.expect("cannot make a Framer from a preliminary group");

        // sender_data_key = HKDF-Expand-Label(sender_data_secret, "sd key", "", key_length)
        let sender_data_key = {
            let mut key_buf = vec![0u8; cs.aead_impl.key_size()];
            // SenderDataSecrets are just HmacKeys
            let prk: &HmacKey = (&sender_data_secret).into();
            hkdf::expand_label(cs.hash_impl, prk, b"sd key", b"", &mut key_buf);
            // I can't think of a single way this could fail
            AeadKey::new_from_bytes(cs.aead_impl, &key_buf).expect("couldn't make sender_data_key")
        };

        Framer {
            handshake_secret,
            sender_data_key,
            group_id: group_ctx.group_id.clone(),
            group_epoch_at_creation: group_ctx.epoch,
            my_member_idx,
        }
    }

    /// Validates that this `Framer` was created from the given `GroupContext` and has sane values
    fn validate_against_group_ctx(&self, group_ctx: &GroupContext) -> Result<(), Error> {
        // Check ownership
        let group_ids_match: bool = group_ctx.group_id.ct_eq(&self.group_id).into();
        if !group_ids_match {
            return Err(Error::ValidationError("Framer does not belong to this GroupContext"));
        }

        // Check perspective
        if group_ctx.member_index != Some(self.my_member_idx) {
            return Err(Error::ValidationError(
                "Framer's member index is not the same as this GroupContext's",
            ));
        }

        // Check sequence
        if group_ctx.epoch != self.group_epoch_at_creation {
            return Err(Error::ValidationError(
                "Framer's epoch does not equal this GroupContext's",
            ));
        }

        Ok(())
    }

    /// Derives `handshake_key_[sender]` and `handshake_nonce_[sender]` from `handshake_secret`
    ///
    /// Returns `Ok((key, nonce))` on success. If there is an issue creating a new key or nonce,
    /// returns some sort of `Error::CryptoError`.
    fn derive_handshake_key_nonce(
        &self,
        sender: MemberIdx,
        cs: &CipherSuite,
    ) -> Result<(AeadKey, AeadNonce), Error> {
        // Get the sender's member index as a byte string. This cannot fail
        let serialized_sender = tls_ser::serialize_to_bytes(&sender).unwrap();

        // handshake_key_[sender] =
        //     HKDF-Expand-Label(handshake_secret, "hs key", [sender], key_length)
        let key = {
            let mut key_buf = vec![0u8; cs.aead_impl.key_size()];
            hkdf::expand_label(
                cs.hash_impl,
                (&self.handshake_secret).into(),
                b"hs key",
                &serialized_sender,
                &mut key_buf,
            );
            AeadKey::new_from_bytes(cs.aead_impl, &key_buf)?
        };

        // handshake_nonce_[sender] =
        //     HKDF-Expand-Label(handshake_secret, "hs nonce", [sender], nonce_length)
        let nonce = {
            let mut nonce_buf = vec![0u8; cs.aead_impl.nonce_size()];
            hkdf::expand_label(
                cs.hash_impl,
                (&self.handshake_secret).into(),
                b"hs nonce",
                &serialized_sender,
                &mut nonce_buf,
            );
            AeadNonce::new_from_bytes(cs.aead_impl, &nonce_buf)?
        };

        Ok((key, nonce))
    }

    /// Frames an `MlsPlaintextContent` into a `MlsCiphertext` ready for sending. Takes the
    /// relevant `GroupContext`, the content itself, the encryption key/nonce (either a
    /// `handshake_key` or an application `write_key`), the generation of the key (0 if
    /// `Handshake`), and a CSPRNG.
    ///
    /// Returns: `Ok(mls_ciphertext)` if all goes well. If one of myriad things goes wrong, returns
    /// some sort of `Error`.
    pub(crate) fn frame_content<R: CryptoRng>(
        &self,
        group_ctx: &GroupContext,
        content: MlsPlaintextContent,
        content_encryption_key: AeadKey,
        content_encryption_nonce: AeadNonce,
        key_generation: u32,
        csprng: &mut R,
    ) -> Result<MlsCiphertext, Error> {
        // First sanity check the group_ctx we got
        self.validate_against_group_ctx(group_ctx)?;

        // Establish all the context we need to encrypt, authenticate, and sign
        let cs = group_ctx.cs;
        let ss = group_ctx.get_my_signature_scheme();
        let group_id = &group_ctx.group_id;
        let epoch = self.group_epoch_at_creation;
        let content_type = content.kind();

        // This is the unencrypted payload of the message
        let mls_plaintext = MlsPlaintext::new(ss, group_ctx, content)?;

        // Make a random nonce. We need to copies of it: one to encrypt the sender data and one to
        // send along with the ciphertext.
        let (sender_data_nonce1, sender_data_nonce2) =
            AeadNonce::new_pair_from_random(cs.aead_impl, csprng);

        // Encrypt the sender data
        // encrypted_sender_data =
        //     AEAD.Seal(sender_data_key, sender_data_nonce, sender_data_aad, sender_data)
        let encrypted_sender_data = {
            // Package the sender data for encryption
            let sender_data = MlsSenderData {
                sender: mls_plaintext.sender,
                generation: key_generation,
            };
            let mut serialized_sender_data = tls_ser::serialize_to_bytes(&sender_data)?;

            // This is the additional authenticated data that goes along with the sender data
            let sender_data_aad = MlsCiphertextSenderDataAad {
                group_id,
                epoch,
                content_type,
                sender_data_nonce: &sender_data_nonce1,
            };
            let serialized_sender_data_aad = tls_ser::serialize_to_bytes(&sender_data_aad)?;

            // Pad out the plaintext to make room for the tag
            serialized_sender_data.extend(vec![0u8; cs.aead_impl.tag_size()]);
            // In-place seal serialized_sender_data
            cs.aead_impl.seal(
                &self.sender_data_key,
                sender_data_nonce1,
                &serialized_sender_data_aad,
                &mut serialized_sender_data,
            )?;

            // All done
            serialized_sender_data
        };

        // This is the encrypted MlsCiphertextContent which serves as the payload of the
        // MlsCiphertext
        let encrypted_payload = {
            // Serialize the plaintext so we can encrypt it
            let mut serialized_content = tls_ser::serialize_to_bytes(&mls_plaintext)?;

            // This is the additional authenticated data that goes along with the content
            let content_aad = MlsCiphertextContentAad {
                group_id,
                epoch,
                content_type,
                sender_data_nonce: &sender_data_nonce2,
                encrypted_sender_data: &encrypted_sender_data,
            };
            let serialized_content_aad = tls_ser::serialize_to_bytes(&content_aad)?;

            // In-place seal serialized_content
            cs.aead_impl.seal(
                &content_encryption_key,
                content_encryption_nonce,
                &serialized_content_aad,
                &mut serialized_content,
            )?;

            // All done
            serialized_content
        };

        // Put it all together
        Ok(MlsCiphertext {
            group_id: group_id.clone(),
            epoch,
            content_type,
            sender_data_nonce: sender_data_nonce2,
            encrypted_sender_data,
            ciphertext: encrypted_payload,
        })
    }

    /// Unframes a received `MlsCiphertext` into an `MlsPlaintext` fit for reading. Takes the
    /// relevant `GroupContext` and the `MlsCiphertext` itself.
    ///
    /// Returns: `Ok(mls_plaintext)` if all goes well. If one of myriad things goes wrong, returns
    /// some sort of `Error`.
    pub fn unframe_ciphertext(
        &self,
        group_ctx: &GroupContext,
        mls_ciphertext: MlsCiphertext,
    ) -> Result<MlsPlaintextContent, Error> {
        // First sanity check the group_ctx we got
        self.validate_against_group_ctx(group_ctx)?;

        // Verify that the group ID of the incoming ciphertext is mine The reason we insist on
        // using constant-time comparison on GroupIDs is because Framer::unframe_content checks
        // this value before validating anything else about an incoming MLSCiphertext. In theory, a
        // attacker who can inject traffic onto the wire could enumerate the groups a member is in
        // based on how long it takes for them to reject an MLSCiphertext with a bogus group ID
        // (the longer it takes the more bytes of the group ID were guessed correctly). This is a
        // ridiculous scenario, but eh who cares.
        let group_ids_match: bool = self.group_id.ct_eq(&mls_ciphertext.group_id).into();
        if !group_ids_match {
            return Err(Error::ValidationError(
                "Malformed ciphertext: group ID does not match the Framer's",
            ));
        }

        // Verify that the epoch of the incoming ciphertext is the same as mine
        if self.group_epoch_at_creation != mls_ciphertext.epoch {
            return Err(Error::ValidationError(
                "Malformed ciphertext: group epoch does not match the Framer's",
            ));
        }

        // Establish all the context we need to encrypt, authenticate, and verify
        let cs = group_ctx.cs;
        let ss = group_ctx.get_my_signature_scheme();
        let group_id = &group_ctx.group_id;
        let epoch = self.group_epoch_at_creation;

        // This is the additional authenticated data that goes along with the content. We need to
        // construct and serialize this first because the sender_data_nonce gets consumed when
        // decrypting sender_data.
        let serialized_content_aad = {
            let content_aad = MlsCiphertextContentAad {
                group_id,
                epoch,
                content_type: mls_ciphertext.content_type,
                sender_data_nonce: &mls_ciphertext.sender_data_nonce,
                encrypted_sender_data: &mls_ciphertext.encrypted_sender_data,
            };
            tls_ser::serialize_to_bytes(&content_aad)?
        };

        // Unpack the MLSCiphertext so we can decrypt the sender data and keep the rest for
        // decrypting afterwards
        let MlsCiphertext {
            mut encrypted_sender_data,
            sender_data_nonce,
            ciphertext,
            content_type,
            ..
        } = mls_ciphertext;

        // Decrypt the sender data
        // sender_data =
        //     AEAD.Open(sender_data_key, sender_data_nonce, sender_data_aad, encrypted_sender_data)
        let sender_data = {
            // This is the additional authenticated data that goes along with the sender data
            let sender_data_aad = MlsCiphertextSenderDataAad {
                group_id,
                epoch,
                content_type,
                sender_data_nonce: &sender_data_nonce,
            };
            let serialized_sender_data_aad = tls_ser::serialize_to_bytes(&sender_data_aad)?;

            // In-place open the encrypted_sender_data
            let serialized_sender_data = cs.aead_impl.open(
                &self.sender_data_key,
                sender_data_nonce,
                &serialized_sender_data_aad,
                &mut encrypted_sender_data,
            )?;

            // Deserialize the sender data
            let mut cursor = &*serialized_sender_data;
            let mut deserializer = TlsDeserializer::from_reader(&mut cursor);
            MlsSenderData::deserialize(&mut deserializer)?
        };

        // Decrypt the message with the appropriate keys and get the MLSPlaintext out
        let mls_plaintext = match content_type {
            MlsPlaintextContentKind::Handshake => {
                self.decrypt_handshake(cs, ciphertext, sender_data, serialized_content_aad)?
            }
            MlsPlaintextContentKind::Application => {
                unimplemented!()
                //self.unframe_app_msg(group_ctx, mls_ciphertext, sender_data, serialized_content_aad)
            }
            MlsPlaintextContentKind::Invalid => unimplemented!(),
        };

        // Check the MlsPlaintext signature
        let sender_member_info = group_ctx
            .tree
            .get_member_info(sender_data.sender)
            .map_err(|_| Error::ValidationError("Invalid sender index in MLSCiphertext"))?
            .ok_or(Error::ValidationError("Alleged sender of MLSCiphertext is Blank"))?;
        let sender_sig_pubkey = sender_member_info.credential.get_public_key();
        mls_plaintext.verify_signature(ss, sender_sig_pubkey)?;

        // The last step is to validate that all the metadata inside the plaintext agrees with the
        // data in the ciphertext
        mls_plaintext.validate_metadata(
            content_type,
            &group_id,
            &sender_data,
            self.group_epoch_at_creation,
        )?;

        // Ugh finally
        Ok(mls_plaintext.content)
    }

    /// Generates `handshake_key` and `handshake_nonce` and uses them to decrypt an encrypted
    /// `MlsCiphertextContent` that contains a `Handshake`
    fn decrypt_handshake(
        &self,
        cs: &CipherSuite,
        mut ciphertext_payload: Vec<u8>,
        sender_data: MlsSenderData,
        serialized_content_aad: Vec<u8>,
    ) -> Result<MlsCiphertextContent, Error> {
        // Generation is only meaningful for application messages. It should be 0 in the case of
        // handshake messages.
        if sender_data.generation != 0 {
            return Err(Error::ValidationError(
                "Handshakes must have generation = 0 in MLSCiphertext",
            ));
        }

        // Get the appropriate key and nonce for the Handshake from the given sender
        let (handshake_key, handshake_nonce) =
            self.derive_handshake_key_nonce(sender_data.sender, cs)?;

        // We now have everything we need to decrypt MLSCiphertext::ciphertext. Do the decryption
        // in-place
        let serialized_mls_plaintext = cs.aead_impl.open(
            &handshake_key,
            handshake_nonce,
            &serialized_content_aad,
            &mut ciphertext_payload,
        )?;

        // Deserialize the ciphertext content
        let mut cursor = &*serialized_mls_plaintext;
        let mut deserializer = TlsDeserializer::from_reader(&mut cursor);
        MlsCiphertextContent::deserialize(&mut deserializer)
    }

    /// Frames a `Handshake` operation under the given `GroupContext`. The given `GroupContext` is
    /// supposed to be the state the preceeds the application of the given `Handshake`. In other
    /// words, if you modify the group context like `ctx1 ----group op----> ctx2`, then you should
    /// pass `ctx1` into this function.
    ///
    /// Returns: `Ok(mls_ciphertext)` if all goes well. If one of myriad things goes wrong, returns
    /// some sort of `Error`.
    pub fn frame_handshake<R: CryptoRng>(
        &self,
        group_ctx: &GroupContext,
        handshake: Handshake,
        csprng: &mut R,
    ) -> Result<MlsCiphertext, Error> {
        // First sanity check the group_ctx we got
        self.validate_against_group_ctx(group_ctx)?;

        // When we're framing an ApplicationMessage, the "generation" refers to the key generation.
        // When we're framing a Handshake, the "generation" doesn't really refer to anything, and
        // it defaults to 0.
        let generation = 0u32;

        // Get the appropriate key and nonce for a Handshake that I created
        let (key, nonce) = self.derive_handshake_key_nonce(self.my_member_idx, group_ctx.cs)?;

        // Pass to the method that does the heavy lifting
        self.frame_content(
            group_ctx,
            MlsPlaintextContent::Handshake(handshake),
            key,
            nonce,
            generation,
            csprng,
        )
    }

    /// Convenience method: Encrypts the given application message with the latest generation of
    /// write secrets of the `ApplicationKeyChain`, then ratchets the secrets forward.
    ///
    /// Returns: `Ok(mls_ciphertext)` if all goes well. If one of myriad things goes wrong, returns
    /// some sort of `Error`.
    pub fn frame_app_message<R: CryptoRng>(
        &self,
        group_ctx: &GroupContext,
        app_msg: Vec<u8>,
        app_key_chain: &mut ApplicationKeyChain,
        csprng: &mut R,
    ) -> Result<MlsCiphertext, Error> {
        // When we're framing an ApplicationMessage, the "generation" refers to the key generation.
        // When we're framing a Handshake, the "generation" doesn't really refer to anything, and
        // it defaults to 0.
        let (key, nonce, generation) = app_key_chain.get_key_nonce_gen(self.my_member_idx)?;

        // Pass through to frame_content
        let mls_ciphertext = self.frame_content(
            group_ctx,
            MlsPlaintextContent::Application(app_msg),
            key,
            nonce,
            generation.into(),
            csprng,
        )?;

        // If all went well, ratchet the secrets
        app_key_chain.ratchet(self.my_member_idx)?;

        Ok(mls_ciphertext)
    }
}
