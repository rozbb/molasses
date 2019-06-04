use crate::{error::Error, tls_ser};

use serde::ser::Serialize;

pub(crate) const SHA256_IMPL: HashFunction = HashFunction {
    hash_alg: &ring::digest::SHA256,
};

// This isn't ring::digest::Digest because you can't deserialize those (there's no constructor).
// TODO: We could be more efficient by making this an ArrayVec internally.
/// A message digest of a hash function
#[derive(Clone, Deserialize, Serialize)]
#[cfg_attr(test, derive(Debug))]
#[serde(rename = "Digest__bound_u8")]
pub(crate) struct Digest(Vec<u8>);

impl Digest {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    pub(crate) fn new_from_zeros(hash_impl: &HashFunction) -> Digest {
        Digest(vec![0u8; hash_impl.digest_size()])
    }
}

impl From<ring::digest::Digest> for Digest {
    fn from(d: ring::digest::Digest) -> Digest {
        Digest(d.as_ref().to_vec())
    }
}

impl subtle::ConstantTimeEq for Digest {
    fn ct_eq(&self, other: &Digest) -> subtle::Choice {
        self.as_bytes().ct_eq(other.as_bytes())
    }
}

#[derive(Debug)]
pub(crate) struct HashFunction {
    pub(crate) hash_alg: &'static ring::digest::Algorithm,
}

impl HashFunction {
    pub(crate) fn hash_serializable<S: Serialize>(&self, msg: &S) -> Result<Digest, Error> {
        let mut ctx = self.new_context();
        ctx.feed_serializable(msg)?;
        Ok(ctx.finalize())
    }

    pub(crate) fn hash_bytes(&self, bytes: &[u8]) -> Digest {
        let mut ctx = self.new_context();
        ctx.feed_bytes(bytes);
        ctx.finalize()
    }

    pub(crate) fn new_context(&self) -> HashContext {
        HashContext {
            ctx: ring::digest::Context::new(self.hash_alg),
        }
    }

    pub(crate) fn digest_size(&self) -> usize {
        self.hash_alg.output_len
    }
}

pub(crate) struct HashContext {
    ctx: ring::digest::Context,
}

impl HashContext {
    // TODO: There's no need to allocate a Vec for this. Figure out how to make a Context Writeable
    // so that we can pass it as the TlsSerializer internal buffer
    pub(crate) fn feed_serializable<S: Serialize>(&mut self, msg: &S) -> Result<(), Error> {
        let bytes = tls_ser::serialize_to_bytes(msg)?;
        self.feed_bytes(&bytes);
        Ok(())
    }

    pub(crate) fn feed_bytes(&mut self, bytes: &[u8]) {
        self.ctx.update(&bytes);
    }

    pub(crate) fn finalize(self) -> Digest {
        self.ctx.finish().into()
    }
}
