use crate::crypto::sig::{SigPublicKey, SignatureScheme};
use crate::error::Error;

// TODO: Decide whether we check the size on the lower end while (de)serializing

/// A `Roster`, as it appears in a `GroupState`, is a list of optional `Credential`s
// Invariant: Rosters can never be empty
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roster(pub(crate) Vec<Option<Credential>>);

impl Roster {
    /// Truncates the roster to the last non-blank entry
    ///
    /// Requires: That there is at least one nonblank entry in the roster
    ///
    /// Returns: `Ok(())` on success. If the above requirement is not met, returns an `Error`.
    #[must_use]
    pub(crate) fn truncate_to_last_nonblank(&mut self) -> Result<(), Error> {
        // Find the last non-None credential
        let mut last_nonempty_roster_entry = None;
        for (i, entry) in self.0.iter().enumerate().rev() {
            if entry.is_some() {
                last_nonempty_roster_entry = Some(i);
                break;
            }
        }

        // Truncate the roster so that the above entry is the last element in the vector
        if let Some(i) = last_nonempty_roster_entry {
            // This can't fail, because i is an index
            let num_elements_to_retain = i + 1;
            self.0.truncate(num_elements_to_retain);
            // All done
            Ok(())
        } else {
            // If there are no nonempty entries in the roster, throw an error, then this isn't
            // well-defined. Error out
            Err(Error::ValidationError(
                "Cannot truncate an empty roster to the last nonblank entry",
            ))
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns an iterator of the non-empty entries in the roster
    pub fn credential_iter<'a>(&'a self) -> impl Iterator<Item = &'a Credential> {
        self.0.iter().filter(|x| x.is_some()).map(|x| x.as_ref().unwrap())
    }
}

// opaque cert_data<1..2^24-1>;
/// A bunch of bytes representing an X.509 certificate. This currently doesn't do anything.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename = "X509CertData__bound_u24")]
pub struct X509CertData(Vec<u8>);

// opaque identity<0..2^16-1>;
/// A bytestring that should uniquely identify the user in the Group
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename = "Identity__bound_u16")]
pub struct Identity(pub(crate) Vec<u8>);

impl Identity {
    /// Makes an `Identity` from the given bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Identity {
        Identity(bytes)
    }

    /// Returns a reference to the identity information
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

/// Defines a simple user credential
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BasicCredential {
    /// This is a user ID
    pub(crate) identity: Identity,

    /// The member's preferred signature scheme
    pub(crate) signature_scheme: &'static dyn SignatureScheme,

    /// The member's public key under said signature scheme
    pub(crate) public_key: SigPublicKey,
}

impl BasicCredential {
    /// Makes a new credential with the given information
    pub fn new(
        identity: Identity,
        signature_scheme: &'static dyn SignatureScheme,
        public_key: SigPublicKey,
    ) -> BasicCredential {
        BasicCredential {
            identity,
            signature_scheme,
            public_key,
        }
    }
}

/// A user credential, as defined in section 5.6 of the MLS spec
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename = "Credential__enum_u8")]
pub enum Credential {
    Basic(BasicCredential),
    X509(X509CertData),
}

impl Credential {
    pub(crate) fn get_public_key(&self) -> &SigPublicKey {
        match self {
            Credential::Basic(ref basic) => &basic.public_key,
            Credential::X509(_) => unimplemented!(),
        }
    }

    pub(crate) fn get_signature_scheme(&self) -> &'static dyn SignatureScheme {
        match self {
            Credential::Basic(ref basic) => basic.signature_scheme,
            Credential::X509(_) => unimplemented!(),
        }
    }

    pub fn get_identity(&self) -> &Identity {
        match self {
            Credential::Basic(ref basic) => &basic.identity,
            Credential::X509(_) => unimplemented!(),
        }
    }
}
