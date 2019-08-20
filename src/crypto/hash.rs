use crate::{error::Error, tls_ser};

use serde::ser::Serialize;

/// The SHA-256 hash algorithm
pub(crate) static SHA256_IMPL: HashFunction = HashFunction {
    hash_alg: &ring::digest::SHA256,
    name: "SHA256",
};

/// The digest size of the SHA256 hash algorithm
pub(crate) const SHA256_DIGEST_SIZE: usize = 32;

// This isn't ring::digest::Digest because you can't deserialize those (there's no constructor)
/// An enum of possible types for a hash digest, depending on the underlying algorithm
#[derive(Clone)]
#[cfg_attr(test, derive(Debug))]
pub(crate) enum Digest {
    /// A SHA256 digest
    Sha256([u8; SHA256_DIGEST_SIZE]),

    /// An undifferentiated variant used for (de)serialization
    Raw(DigestRaw),
}

// From opaque Add::welcome_info_hash<0..255>
/// The form that all `Digest`s take when being sent or received over the wire
#[derive(Clone, Deserialize, Serialize)]
#[cfg_attr(test, derive(Debug))]
#[serde(rename = "DigestRaw__bound_u8")]
pub(crate) struct DigestRaw(pub(crate) Vec<u8>);

impl Digest {
    /// Wraps the given bytes in a `Digest` struct
    pub(crate) fn new_from_bytes(hash_impl: &HashFunction, bytes: &[u8]) -> Digest {
        match hash_impl.name {
            "SHA256" => {
                // Make sure the input is exactly the right length
                assert_eq!(
                    bytes.len(),
                    SHA256_DIGEST_SIZE,
                    "SHA256 digest isn't {} bytes",
                    SHA256_DIGEST_SIZE
                );

                // Copy it in
                let mut buf = [0u8; SHA256_DIGEST_SIZE];
                buf.copy_from_slice(bytes);
                Digest::Sha256(buf)
            }
            h => panic!("unknown hash algorithm {}", h),
        }
    }

    /// Returns the digest in byte form
    pub(crate) fn as_bytes(&self) -> &[u8] {
        match self {
            Digest::Sha256(ref d) => &d[..],
            Digest::Raw(ref v) => v.0.as_slice(),
        }
    }

    /// Creates a digest of all zeros
    pub(crate) fn new_from_zeros(hash_impl: &HashFunction) -> Digest {
        match hash_impl.name {
            "SHA256" => Digest::Sha256([0u8; SHA256_DIGEST_SIZE]),
            h => panic!("unknown hash algorithm {}", h),
        }
    }
}

// ring::digest::Digest --> Digest by copying the buffers in
impl From<ring::digest::Digest> for Digest {
    fn from(d: ring::digest::Digest) -> Digest {
        // Try to match the incoming digest's associated algorithm
        if d.algorithm() == &ring::digest::SHA256 {
            // Copy the bytes in
            let mut buf = [0u8; SHA256_DIGEST_SIZE];
            buf.copy_from_slice(d.as_ref());
            Digest::Sha256(buf)
        } else {
            // We only cover the algorithms explicitly checked above
            panic!("tried to convert a digest from an unknown algorithm {:?}", d.algorithm());
        }
    }
}

// This is used for comparing Add::welcome_info_hash to the hash of the received WelcomeInfo
// This needs to check that the variants and bytes are the same, without leaking anything.
impl subtle::ConstantTimeEq for Digest {
    fn ct_eq(&self, other: &Digest) -> subtle::Choice {
        // Are the variants the same? I'm aware that this branch will actually short-circuit, but
        // we don't actually care if we leak the variant of the digest. It's teh bytes we care more
        // about.
        let variants_match = match (self, other) {
            (Digest::Sha256(_), Digest::Sha256(_)) => subtle::Choice::from(1),
            (Digest::Raw(_), Digest::Raw(_)) => subtle::Choice::from(1),
            _ => subtle::Choice::from(0),
        };

        // Are the bytes the same? Record this and don't short circuit
        let bytes_match = self.as_bytes().ct_eq(other.as_bytes());

        variants_match & bytes_match
    }
}

/// Represents a hash algorithm
#[derive(Debug)]
pub struct HashFunction {
    /// `ring`'s representation of a hash algorithm
    pub(crate) hash_alg: &'static ring::digest::Algorithm,

    /// The name of the algorithm
    pub(crate) name: &'static str,
}

impl HashFunction {
    /// Serializes the given value and returns the digest of the resulting bytes
    ///
    /// Returns: `Ok(digest)` on success. Returns an `Error::SerdeError` if something went wrong
    /// while serializing.
    pub(crate) fn hash_serializable<S: Serialize>(&self, msg: &S) -> Result<Digest, Error> {
        let mut ctx = self.new_context();
        ctx.feed_serializable(msg)?;
        Ok(ctx.finalize())
    }

    /// Computes the hash of the given bytes and returns the digest
    pub(crate) fn hash_bytes(&self, bytes: &[u8]) -> Digest {
        let mut ctx = self.new_context();
        ctx.feed_bytes(bytes);
        ctx.finalize()
    }

    /// Creates a new `HashContext` object with `self` as the underlying algorithm
    pub(crate) fn new_context(&self) -> HashContext {
        HashContext {
            ctx: ring::digest::Context::new(self.hash_alg),
        }
    }

    /// Returns the digest size of this hash algorithm
    pub(crate) fn digest_size(&self) -> usize {
        self.hash_alg.output_len
    }
}

/// Represents a hash algorithm context. Used for computing hashes sequentially without having all
/// the input in a single buffer.
pub(crate) struct HashContext {
    ctx: ring::digest::Context,
}

impl HashContext {
    // TODO: There's no need to allocate a Vec for this. Figure out how to make a Context Writeable
    // so that we can pass it as the TlsSerializer internal buffer
    /// Serializes the input and feeds the resulting bytes into the hash context
    ///
    /// Returns: `Ok(())` on success, updating the internal context. Returns an `Error::SerdeError`
    /// if something went wrong while serializing.
    pub(crate) fn feed_serializable<S: Serialize>(&mut self, msg: &S) -> Result<(), Error> {
        let bytes = tls_ser::serialize_to_bytes(msg)?;
        self.feed_bytes(&bytes);
        Ok(())
    }

    /// Feeds the input bytes into the hash context
    pub(crate) fn feed_bytes(&mut self, bytes: &[u8]) {
        self.ctx.update(&bytes);
    }

    /// Finalizes the hash context and returns the resulting digest
    pub(crate) fn finalize(self) -> Digest {
        self.ctx.finish().into()
    }
}
