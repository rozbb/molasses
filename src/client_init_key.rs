use crate::{
    credential::Credential,
    crypto::{
        ciphersuite::CipherSuite,
        dh::{DhPrivateKey, DhPublicKey},
        rng::CryptoRng,
        sig::{SigSecretKey, Signature},
    },
    error::Error,
    tls_ser,
};

/// Represents a version of the MLS protocol
// uint8 ProtocolVersion;
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProtocolVersion(u8);

/// A dummy protocol version
// TODO: Remove this before going into production. Final last words, amirite
pub const MLS_DUMMY_VERSION: ProtocolVersion = ProtocolVersion(0xba);

/// This is used in lieu of negotiating public keys when a member is added. This has a bunch of
/// published ephemeral keys that can be used to initiated communication with a previously
/// uncontacted member.
#[derive(Clone, Deserialize, Serialize)]
#[cfg_attr(test, derive(Debug))]
pub struct ClientInitKey {
    // opaque client_init_key_id<0..255>
    /// An identifier for this init key. This MUST be unique among the `ClientInitKey` generated by
    /// the client
    #[serde(rename = "client_init_key_id__bound_u8")]
    pub(crate) client_init_key_id: Vec<u8>,

    // ProtocolVersion supported_versions<0..255>;
    /// The protocol versions supported by the member. Each entry is the supported protocol version
    /// of the entry in `init_keys` of the same index. This MUST have the same length as
    /// `init_keys`.
    #[serde(rename = "supported_versions__bound_u8")]
    supported_versions: Vec<ProtocolVersion>,

    // CipherSuite cipher_suites<0..255>
    /// The cipher suites supported by the member. Each cipher suite here corresponds uniquely to a
    /// DH public key in `init_keys`. As such, this MUST have the same length as `init_keys`.
    #[serde(rename = "cipher_suites__bound_u8")]
    pub(crate) cipher_suites: Vec<&'static CipherSuite>,

    // HPKEPublicKey init_keys<1..2^16-1>
    /// The DH public keys owned by the member. Each public key corresponds uniquely to a cipher
    /// suite in `cipher_suites`. As such, this MUST have the same length as `cipher_suites`.
    #[serde(rename = "init_keys__bound_u16")]
    pub(crate) init_keys: Vec<DhPublicKey>,

    /// The DH private keys owned by the member. This is only `Some` if this member is the creator
    /// of this `ClientInitKey`. Each private key corresponds uniquely to a public key in
    /// `init_keys`. As such, this MUST have the same length as `init_keys`.
    #[serde(skip)]
    pub(crate) private_keys: Option<Vec<DhPrivateKey>>,

    /// The identity information of the member
    pub(crate) credential: Credential,

    /// Contains the signature of all the other fields of this struct, under the identity key of
    /// the client.
    pub(crate) signature: Signature,
}

// This struct is everything but the last field in ClientInitKey. We use the serialized form
// of this as the message that the signature is computed over
#[derive(Serialize)]
struct PartialClientInitKey<'a> {
    #[serde(rename = "client_init_key_id__bound_u8")]
    client_init_key_id: &'a [u8],
    #[serde(rename = "supported_versions__bound_u8")]
    supported_versions: &'a [ProtocolVersion],
    #[serde(rename = "cipher_suites__bound_u8")]
    cipher_suites: &'a [&'static CipherSuite],
    #[serde(rename = "init_keys__bound_u16")]
    init_keys: &'a [DhPublicKey],
    credential: &'a Credential,
}

impl ClientInitKey {
    /// Generates a new `ClientInitKey` with the key ID, credential, ciphersuites, and supported
    /// versions. The identity key is needed to sign the resulting structure.
    pub fn new_from_random<R>(
        identity_key: &SigSecretKey,
        client_init_key_id: Vec<u8>,
        credential: Credential,
        mut cipher_suites: Vec<&'static CipherSuite>,
        supported_versions: Vec<ProtocolVersion>,
        csprng: &mut R,
    ) -> Result<ClientInitKey, Error>
    where
        R: CryptoRng,
    {
        // Check the ciphersuite list for duplicates. We don't like this
        let old_cipher_suite_len = cipher_suites.len();
        cipher_suites.dedup();
        if cipher_suites.len() != old_cipher_suite_len {
            return Err(Error::ValidationError(
                "Cannot make a ClientInitKey with duplicate ciphersuites",
            ));
        }
        // Check that the ciphersuite and supported version vectors are the same length
        if cipher_suites.len() != supported_versions.len() {
            return Err(Error::ValidationError(
                "Supported ciphersuites and supported version vectors differ in length",
            ));
        }

        let mut init_keys = Vec::new();
        let mut private_keys = Vec::new();

        // Collect a keypair for every ciphersuite in the given vector
        for cs in cipher_suites.iter() {
            let scalar = DhPrivateKey::new_from_random(cs.dh_impl, csprng)?;
            let public_key = DhPublicKey::new_from_private_key(cs.dh_impl, &scalar);

            init_keys.push(public_key);
            private_keys.push(scalar);
        }
        // The ClientInitKey has this as an Option
        let private_keys = Some(private_keys);

        // Now to compute the signature: Make the partial structure, serialize it, sign that
        let partial = PartialClientInitKey {
            client_init_key_id: client_init_key_id.as_slice(),
            supported_versions: supported_versions.as_slice(),
            cipher_suites: cipher_suites.as_slice(),
            init_keys: init_keys.as_slice(),
            credential: &credential,
        };

        let serialized_cik = tls_ser::serialize_to_bytes(&partial)?;
        let sig_scheme = credential.get_signature_scheme();
        let signature = sig_scheme.sign(identity_key, &serialized_cik);

        Ok(ClientInitKey {
            client_init_key_id,
            supported_versions,
            cipher_suites,
            init_keys,
            private_keys,
            credential,
            signature,
        })
    }

    /// Verifies this `ClientInitKey` under the identity key specified in the `credential` field
    ///
    /// Returns: `Ok(())` on success, `Error::SignatureError` on verification failure, and
    /// `Error::SerdeError` on some serialization failure.
    pub(crate) fn verify_sig(&self) -> Result<(), Error> {
        let partial = PartialClientInitKey {
            client_init_key_id: self.client_init_key_id.as_slice(),
            supported_versions: self.supported_versions.as_slice(),
            cipher_suites: self.cipher_suites.as_slice(),
            init_keys: self.init_keys.as_slice(),
            credential: &self.credential,
        };
        let serialized_cik = tls_ser::serialize_to_bytes(&partial)?;

        let sig_scheme = self.credential.get_signature_scheme();
        let public_key = self.credential.get_public_key();

        sig_scheme.verify(public_key, &serialized_cik, &self.signature)
    }

    // TODO: URGENT Figure out how to implement the mandatory check specified in section 7:
    // "ClientInitKeys also contain an identifier chosen by the client, which the client MUST
    // assure uniquely identifies a given ClientInitKey object among the set of ClientInitKeys
    // created by this client."

    /// Validates the invariants that `ClientInitKey` must satisfy, as in section 7 of the MLS spec
    pub(crate) fn validate(&self) -> Result<(), Error> {
        // All three of supported_versions, cipher_suites, and init_keys MUST have the same length.
        // And if private_keys is non-null, it must have the same length as the other three.
        if self.supported_versions.len() != self.cipher_suites.len() {
            return Err(Error::ValidationError(
                "ClientInitKey::supported_verions.len() != ClientInitKey::cipher_suites.len()",
            ));
        }
        if self.init_keys.len() != self.cipher_suites.len() {
            return Err(Error::ValidationError(
                "ClientInitKey::init_keys.len() != ClientInitKey::cipher_suites.len()",
            ));
        }
        if let Some(ref ks) = self.private_keys {
            if ks.len() != self.cipher_suites.len() {
                return Err(Error::ValidationError(
                    "ClientInitKey::private_keys.len() != ClientInitKey::cipher_suites.len()",
                ));
            }
        }

        // The elements of cipher_suites MUST be unique. Sort them, dedup them, and see if the
        // number has decreased.
        let mut cipher_suites = self.cipher_suites.clone();
        let original_len = cipher_suites.len();
        cipher_suites.sort_by_key(|c| c.name);
        cipher_suites.dedup_by_key(|c| c.name);
        if cipher_suites.len() != original_len {
            return Err(Error::ValidationError(
                "ClientInitKey has init keys with duplicate ciphersuites",
            ));
        }

        Ok(())
    }

    /// Retrieves the public key in this `ClientInitKey` corresponding to the given cipher suite
    ///
    /// Returns: `Ok(Some(pubkey))` on success. Returns `Ok(None)` iff there is no public key
    /// corresponding to the given cipher suite. Returns `Err(Error::ValidationError)` iff
    /// validation (via `ClientInitKey::validate()`) failed.
    pub(crate) fn get_public_key<'a>(
        &'a self,
        cs_to_find: &'static CipherSuite,
    ) -> Result<Option<&'a DhPublicKey>, Error> {
        // First validate. If this were not valid, then the output of this function might be
        // dependent on the order of occurrence of cipher suites, and that is undesirable
        self.validate()?;

        let cipher_suites = &self.cipher_suites;
        let init_keys = &self.init_keys;

        // Look for the ciphersuite in lock-step with the public key. If we find the ciphersuite at
        // index i, then the pubkey we want is also at index i These two lists are the same length,
        // because this property is checked in validate() above. Furthermore, all ciphersuites in
        // cipher_suites are unique, because this property is also checked in validate() above.
        for (cs, key) in cipher_suites.iter().zip(init_keys.iter()) {
            if cs == &cs_to_find {
                return Ok(Some(key));
            }
        }

        // No such public key was found
        Ok(None)
    }

    /// Retrieves the private key in this `ClientInitKey` corresponding to the given cipher suite.
    /// The private key is only known if this member is the creator of this `ClientInitKey`.
    ///
    /// Returns: `Ok(Some(privkey))` on success. Returns `Ok(None)` if the private key is not known
    /// or there is no private key corresponding to the given cipher suite. Returns
    /// `Err(Error::ValidationError)` iff validation (via `ClientInitKey::validate()`) failed.
    pub(crate) fn get_private_key<'a>(
        &'a self,
        cs_to_find: &'static CipherSuite,
    ) -> Result<Option<&'a DhPrivateKey>, Error> {
        // First validate. If this were not valid, then the output of this function might be
        // dependent on the order of occurrence of cipher suites, and that is undesirable
        self.validate()?;

        let cipher_suites = &self.cipher_suites;
        // If we are the creator, we have a chance of finding the private key
        if let Some(ref private_keys) = self.private_keys {
            // Look for the ciphersuite in lock-step with the private key. If we find the
            // ciphersuite at index i, then the privkey we want is also at index i These two lists
            // are the same length, because this property is checked in validate() above.
            // Furthermore, all ciphersuites in cipher_suites are unique, because this property is
            // also checked in validate() above.
            for (cs, key) in cipher_suites.iter().zip(private_keys.iter()) {
                if cs == &cs_to_find {
                    return Ok(Some(key));
                }
            }
        }

        // No such private key was found (or we aren't the creator of this ClientInitKey)
        Ok(None)
    }

    /// Retrieves the supported protocol version in this `ClientInitKey` that corresponds to the
    /// given cipher suite
    ///
    /// Returns: `Ok(Some(supported_version))` on success. Returns `Ok(None)` iff there is no
    /// supported version corresponding to the given ciphersuite Returns
    /// `Err(Error::ValidationError)` iff validation (via `ClientInitKey::validate()`) failed.
    pub(crate) fn get_supported_version(
        &self,
        cs_to_find: &'static CipherSuite,
    ) -> Result<Option<ProtocolVersion>, Error> {
        // First validate. If this were not valid, then the output of this function might be
        // dependent on the order of occurrence of cipher suites, and that is undesirable
        self.validate()?;

        let cipher_suites = &self.cipher_suites;
        let supported_versions = &self.supported_versions;

        // Look for the ciphersuite in lock-step with the public key. If we find the ciphersuite at
        // index i, then the pubkey we want is also at index i These two lists are the same length,
        // because this property is checked in validate() above. Furthermore, all ciphersuites in
        // cipher_suites are unique, because this property is also checked in validate() above.
        for (cs, version) in cipher_suites.iter().zip(supported_versions.iter()) {
            if cs == &cs_to_find {
                return Ok(Some(*version));
            }
        }

        // No such version was found
        Ok(None)
    }
}