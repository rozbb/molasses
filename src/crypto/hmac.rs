use crate::{
    crypto::{
        hash::{HashFunction, SHA256_DIGEST_SIZE},
        rng::CryptoRng,
    },
    error::Error,
};

// A helper trait for converting ring::digest::Algorithm to the associated ring::hmac::Algorithm
impl<'a> From<&'a HashFunction> for ring::hmac::Algorithm {
    fn from(hash_impl: &'a HashFunction) -> ring::hmac::Algorithm {
        match hash_impl.name {
            "SHA256" => ring::hmac::HMAC_SHA256,
            h => panic!("unknown hash algorithm {}", h),
        }
    }
}

// TODO: Make these newtypes ArrayVecs

/// A wrapper around the bytes of an HMAC key. The number of bytes depends on the hash function in
/// use. The only HMAC key in MLS is `confirmation_key`, which has the length `Hash.length`.
#[derive(Clone)]
#[cfg_attr(test, derive(Debug, Eq, PartialEq))]
pub(crate) enum HmacKey {
    Sha256([u8; SHA256_DIGEST_SIZE]),
}

impl HmacKey {
    /// Wraps the given bytes in an `HmacKey` struct
    pub(crate) fn new_from_bytes(hash_impl: &HashFunction, bytes: &[u8]) -> HmacKey {
        match hash_impl.name {
            "SHA256" => {
                // Make sure the input bytes are precisely the same length as a SHA256 digest
                assert_eq!(bytes.len(), SHA256_DIGEST_SIZE, "HKDF-SHA256 salt isn't 32 bytes");
                // Fill a buffer with a copy
                let mut buf = [0u8; SHA256_DIGEST_SIZE];
                buf.copy_from_slice(bytes);
                HmacKey::Sha256(buf)
            }
            h => panic!("unknown hash algorithm {}", h),
        }
    }

    /// Makes a new all-zero HMAC key of the appropriate length
    pub(crate) fn new_from_zeros(hash_impl: &HashFunction) -> HmacKey {
        match hash_impl.name {
            "SHA256" => HmacKey::Sha256([0u8; SHA256_DIGEST_SIZE]),
            h => panic!("unknown hash algorithm {}", h),
        }
    }

    pub fn new_from_random<R>(hash_impl: &HashFunction, csprng: &mut R) -> HmacKey
    where
        R: CryptoRng,
    {
        // Make a zero key of the appropriate length
        let mut key = HmacKey::new_from_zeros(hash_impl);
        // Fill it with randomness
        csprng.fill_bytes(key.as_mut_bytes());

        key
    }

    /// Exposes the underlying bytes of the key
    fn as_mut_bytes(&mut self) -> &mut [u8] {
        match self {
            HmacKey::Sha256(ref mut buf) => buf,
        }
    }

    /// Reveals the underlying bytes of the key
    fn as_bytes(&self) -> &[u8] {
        match self {
            HmacKey::Sha256(ref buf) => buf,
        }
    }
}

// From opaque Handshake::confirmation<0..255>
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename = "Mac__bound_u8")]
pub(crate) struct Mac(Vec<u8>);

// ring::Tag --> Mac by converting to bytes
impl From<ring::hmac::Tag> for Mac {
    fn from(sig: ring::hmac::Tag) -> Mac {
        Mac(sig.as_ref().to_vec())
    }
}

/// Computes the HMAC of the given message under the given key and hash function
pub(crate) fn sign(hash_impl: &HashFunction, key: &HmacKey, msg: &[u8]) -> Mac {
    let mut ctx = new_signing_context(hash_impl, key);
    ctx.feed_bytes(msg);
    ctx.finalize()
}

/// Verifies a MAC against the given message under the given key and hash function
pub(crate) fn verify(
    hash_impl: &HashFunction,
    key: &HmacKey,
    msg: &[u8],
    mac: &Mac,
) -> Result<(), Error> {
    // Make a key to use with ring
    let key = ring::hmac::Key::new(hash_impl.into(), key.as_bytes());

    // This runs in constant time
    ring::hmac::verify(&key, msg, &mac.0)
        .map_err(|_| Error::SignatureError("MAC verification failed"))
}

/// Creates a new context with which we can MAC sequential data
pub(crate) fn new_signing_context(hash_impl: &HashFunction, key: &HmacKey) -> HmacSigningContext {
    // Make a key to use with ring
    let key = ring::hmac::Key::new(hash_impl.into(), key.as_bytes());

    HmacSigningContext {
        ctx: ring::hmac::Context::with_key(&key),
    }
}

/// A context object allowing the MACing of sequential data without having to have all the data in
/// a single buffer
pub(crate) struct HmacSigningContext {
    ctx: ring::hmac::Context,
}

impl HmacSigningContext {
    /// Feed bytes in to the MAC. This has the property that the operation `ctx.feed_bytes(a || b)`
    /// leaves `ctx` the same end state as `ctx.feed_bytes(a); ctx.feed_bytes(b)`.
    pub(crate) fn feed_bytes(&mut self, bytes: &[u8]) {
        self.ctx.update(bytes)
    }

    /// Finalizes the context and returns the MAC over all the inputs. This has the property that
    /// `ctx = new_signing_context(alg, key); ctx.feed_bytes(a); ctx.finalize()` has the same
    /// output as `sign(alg, key, a)`.
    pub(crate) fn finalize(self) -> Mac {
        self.ctx.sign().into()
    }
}

#[cfg(test)]
mod test {
    use crate::crypto::{
        hash::SHA256_IMPL,
        hmac::{self, HmacKey},
    };

    use quickcheck_macros::quickcheck;
    use rand::SeedableRng;

    // Test that the streaming API is equivalent to doing a MAC over the concatenation of messages
    #[quickcheck]
    fn mac_streaming(rng_seed: u64, msg1: Vec<u8>, msg2: Vec<u8>) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(rng_seed);

        let hash_impl = &SHA256_IMPL;
        let key = HmacKey::new_from_random(hash_impl, &mut rng);
        let concatted_msgs: Vec<u8> = [msg1.as_slice(), msg2.as_slice()].concat();

        // Compute HMAC_k over msg1 and then msg2, separately
        let streaming_mac = {
            let mut ctx = hmac::new_signing_context(hash_impl, &key);
            ctx.feed_bytes(&msg1);
            ctx.feed_bytes(&msg2);
            ctx.finalize()
        };

        // Test that the above is the same as computing HMAC_k(msg1 || msg2)
        hmac::verify(hash_impl, &key, &concatted_msgs, &streaming_mac).unwrap();
    }
}
