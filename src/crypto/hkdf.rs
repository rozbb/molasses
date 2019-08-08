use crate::{
    crypto::hash::HashFunction,
    crypto::hmac::{self, HmacKey},
    error::Error,
};

use serde::ser::Serialize;

const MLS_PREFIX: &[u8] = b"mls10 ";

// This struct is only used in `hkdf::expand_label`
#[derive(Serialize)]
struct HkdfLabel<'a> {
    // uint16 length = Length;
    length: u16,

    // opaque label<6..255> = "mls10 " + Label;
    #[serde(rename = "label__bound_u8")]
    label: &'a [u8],

    // opaque context<0..2^32-1>
    #[serde(rename = "context__bound_u32")]
    context: &'a [u8],
}

/// An implementation of HKDF-Extract. Code mostly copied from `ring::hkdf::extract`.
pub(crate) fn extract(hash_impl: &HashFunction, salt: &HmacKey, secret: &[u8]) -> HmacKey {
    // We can't just use `ring::hkdf::extract` because it returns a `SigningKey` which we can't get
    // any key bytes from. So we just reimplement it here. The below comment is copied from ring.

    // The spec says that if no salt is provided then a key of `digest_alg.output_len` bytes of
    // zeros is used. But, HMAC keys are already zero-padded to the block length, which is larger
    // than the output length of the extract step (the length of the digest). Consequently, the
    // `SigningKey` constructor will automatically do the right thing for a zero-length string.
    let prk = hmac::sign(hash_impl, salt, secret);
    HmacKey::new_from_bytes(prk.as_bytes())
}

/// An implementation of HKDF-Extract. Passes through to `ring::hkdf::expand`.
pub(crate) fn expand<S: Serialize>(
    hash_impl: &HashFunction,
    salt: &HmacKey,
    info: &S,
    out_buf: &mut [u8],
) -> Result<(), Error> {
    let serialized_info = crate::tls_ser::serialize_to_bytes(info)?;

    // Pass to ring
    let prk = ring::hkdf::Prk::new_less_safe(hash_impl.hkdf_alg, &salt.0);

    struct Len(usize);
    impl ring::hkdf::KeyType for Len {
        fn len(&self) -> usize { self.0 }
    }
    prk.expand(&[&serialized_info], Len(out_buf.len()))
        .and_then(|okm| okm.fill(out_buf))
        .unwrap();

    Ok(())
}

// HKDF-Expand-Label(Secret, Label, Context, Length) = HKDF-Expand(Secret, HkdfLabel, Length)
//
// Where HkdfLabel is specified as:
//
// struct {
//     uint16 length = Length;
//     opaque label<7..255> = "mls10 " + Label;
//     opaque context<0..2^32-1> = Context;
// } HkdfLabel;
/// Computes the `HKDF-Expand-Label` function defined in the "Key Schedule" section of the spec
///
/// Requires: `label_info.len() <= 255 - MLS_PREFIX.len() = 249
///
/// Panics: Iff the above requirement is not met
pub(crate) fn expand_label(
    hash_impl: &HashFunction,
    secret: &HmacKey,
    label_info: &[u8],
    context: &[u8],
    out_buf: &mut [u8],
) {
    // The label size is supposed to be at most 255 bytes after being prefixed with "mls10 "
    assert!(label_info.len() <= 255 - MLS_PREFIX.len());
    // The output length is also supposed to be representable by a u16
    assert!(out_buf.len() <= std::u16::MAX as usize);

    // full_label_info_slice = "mls10 " + Label
    let mut full_label_info = [0u8; 255];
    full_label_info[0..MLS_PREFIX.len()].copy_from_slice(MLS_PREFIX);
    full_label_info[MLS_PREFIX.len()..MLS_PREFIX.len() + label_info.len()]
        .copy_from_slice(label_info);
    let full_label_info_slice = &full_label_info[0..MLS_PREFIX.len() + label_info.len()];

    // We're gonna used the serialized label as the `info` parameter to HKDF-Expand
    let label = HkdfLabel {
        length: out_buf.len() as u16,
        // Recall the def: opaque label<6..255> = "mls10 " + Label;
        label: &full_label_info_slice,
        context,
    };

    // Finally, do the HKDF-Expand operation with built-in serialization. This can't fail, since we
    // check that the label isn't oversized with the assert above.
    expand(hash_impl, secret, &label, out_buf).unwrap();
}

/// This is the `Derive-Secret` function defined in the "Key Schedule" section of the spec. It's
/// used as a helper function for `update_epoch_secrets`
///
/// Returns: `Ok(hmac_key)` on success. If an error occurred with serialization, returns an
/// `Error::SerdeError`.
pub(crate) fn derive_secret<S: Serialize>(
    hash_impl: &HashFunction,
    secret: &HmacKey,
    label_info: &[u8],
    context: &S,
) -> Result<HmacKey, Error> {
    // Derive-Secret(Secret, Label, Context) =
    //     HKDF-Expand-Label(Secret, Label, Hash(Context), Hash.length)
    let key = {
        let hashed_ctx = hash_impl.hash_serializable(context)?;
        let mut key_buf = vec![0u8; hash_impl.digest_size()];
        expand_label(hash_impl, secret, label_info, hashed_ctx.as_bytes(), key_buf.as_mut_slice());
        HmacKey::new_from_bytes(&key_buf)
    };
    Ok(key)
}

#[cfg(test)]
mod test {
    use crate::crypto::{
        hash::SHA256_IMPL,
        hkdf,
        hmac::{self, HmacKey},
    };

    use quickcheck_macros::quickcheck;

    // Check that our implementation of hkdf::extract matches ring's implementation
    #[quickcheck]
    fn hkdf_extract_kat(salt_bytes: Vec<u8>, secret_bytes: Vec<u8>) {
        let hash_impl = &SHA256_IMPL;

        // Wrap the salt bytes in a signing key
        let ring_salt = ring::hkdf::Salt::new(hash_impl.hkdf_alg, &salt_bytes);
        let my_salt = HmacKey::new_from_bytes(&salt_bytes);

        // prk = HKDF-Extract(salt, ikm=secret)
        let ring_prk = ring_salt.extract(&secret_bytes);
        // let my_prk = hkdf::extract(hash_impl, &my_salt, &secret_bytes);

        // Now make sure the prk's agree. We can't check them directly, since there's no way of
        // turning a ring::hkdf::Prk into bytes. So instead, just MAC a random message and
        // see if they turn out the same.

        // TODO: rewrite this.

        //let msg = b"now I got a reason to be waiting";
        //let ring_sig = ring::hmac::sign(&ring_prk, msg);
        //let my_sig = hmac::sign(hash_impl, &my_prk, msg);
        //
        //assert_eq!(ring_sig.as_ref(), my_sig.as_bytes());
    }
}
