use crate::{
    crypto::{hash::HashFunction, rng::CryptoRng},
    error::Error,
};

// TODO: Make these newtypes ArrayVecs

/// An HMAC signing/verification key
#[derive(Clone, Deserialize, Serialize)]
#[cfg_attr(test, derive(Debug, Eq, PartialEq))]
// This is opaque <0..255> because WelcomeInfo::init_secret is
#[serde(rename = "HmacKey__bound_u8")]
pub(crate) struct HmacKey(pub(crate) Vec<u8>);

impl HmacKey {
    pub(crate) fn new_from_bytes(bytes: &[u8]) -> HmacKey {
        HmacKey(bytes.to_vec())
    }

    pub fn new_from_random<R>(hash_impl: &HashFunction, csprng: &mut R) -> HmacKey
    where
        R: CryptoRng,
    {
        let mut buf = vec![0u8; hash_impl.digest_size()];
        csprng.fill_bytes(&mut buf);
        HmacKey(buf)
    }

    pub(crate) fn new_from_zeros(hash_impl: &HashFunction) -> HmacKey {
        let buf = vec![0u8; hash_impl.digest_size()];
        HmacKey(buf)
    }
}

// This is <0..255> since the only signature in MLS is
// Handshake::confirmation<0..255>
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename = "Mac__bound_u8")]
pub(crate) struct Mac(Vec<u8>);

impl Mac {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl From<ring::hmac::Tag> for Mac {
    fn from(sig: ring::hmac::Tag) -> Mac {
        Mac(sig.as_ref().to_vec())
    }
}

pub(crate) fn sign(hash_impl: &HashFunction, key: &HmacKey, msg: &[u8]) -> Mac {
    let mut ctx = new_signing_context(hash_impl, key);
    ctx.feed_bytes(msg);
    ctx.finalize()
}

pub(crate) fn verify(
    hash_impl: &HashFunction,
    key: &HmacKey,
    msg: &[u8],
    sig: &Mac,
) -> Result<(), Error> {
    let verification_key: ring::hmac::Key =
        ring::hmac::Key::new(hash_impl.hmac_algorithm(), &key.0);

    // It's okay to reveal that the MAC is incorrect, because the ring::hmac::verify runs in
    // constant time
    ring::hmac::verify(&verification_key, msg, &sig.0)
        .map_err(|_| Error::SignatureError("MAC verification failed"))
}

pub(crate) fn new_signing_context(hash_impl: &HashFunction, key: &HmacKey) -> HmacSigningContext {
    let signing_key: ring::hmac::Key =
        ring::hmac::Key::new(hash_impl.hmac_algorithm(), &key.0);

    HmacSigningContext {
        ctx: ring::hmac::Context::with_key(&signing_key),
    }
}

pub(crate) struct HmacSigningContext {
    ctx: ring::hmac::Context,
}

impl HmacSigningContext {
    pub(crate) fn feed_bytes(&mut self, bytes: &[u8]) {
        self.ctx.update(bytes)
    }

    pub(crate) fn finalize(self) -> Mac {
        self.ctx.sign().into()
    }
}
