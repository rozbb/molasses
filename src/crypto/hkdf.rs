use crate::{
    crypto::{
        ciphersuite::CipherSuite,
        hash::{HashFunction, SHA256_DIGEST_SIZE, SHA256_IMPL},
        okm_util::FromHkdfExpand,
        rng::CryptoRng,
    },
    error::Error,
};

use core::convert::TryFrom;

use ring::hkdf::KeyType;
use serde::ser::Serialize;

/// The prefix used in `HkdfLabel::label` when computing `expand_label`
const MLS_PREFIX: &[u8] = b"mls10 ";

// A helper trait for converting ring::digest::Algorithm to the associated ring::hkdf::Algorithm
impl<'a> From<&'a HashFunction> for ring::hkdf::Algorithm {
    fn from(hash_impl: &'a HashFunction) -> ring::hkdf::Algorithm {
        match hash_impl.name {
            "SHA256" => ring::hkdf::HKDF_SHA256,
            h => panic!("unrecognized hash algorithm {}", h),
        }
    }
}

/// A pseudorandom key that can be expanded with `hkdf::expand`
#[derive(Clone)]
pub(crate) enum HkdfPrk {
    /// A PRK to be used with HKDF-Expand over SHA256
    Sha256([u8; SHA256_DIGEST_SIZE]),

    /// A PRK variant that we cannot represent as bytes. This is basically just `epoch_secret`.
    Opaque(ring::hkdf::Prk),
}

// HkdfPrk --> ring::hkdf::Prk by rewrapping the bytes or just unwrapping `Opaque`
impl<'a> From<&'a HkdfPrk> for ring::hkdf::Prk {
    fn from(prk: &'a HkdfPrk) -> ring::hkdf::Prk {
        match prk {
            HkdfPrk::Sha256(ref bytes) => {
                // Make a `ring` PRK out of the underlying bytes
                ring::hkdf::Prk::new_less_safe((&SHA256_IMPL).into(), bytes)
            }
            // Opaque is just a wrapper around a `ring` PRK
            HkdfPrk::Opaque(ref p) => p.clone(),
        }
    }
}

// Ensures that the secret value of an `HkdfPrk` isn't accidentally logged
impl core::fmt::Debug for HkdfPrk {
    // Outputs the variant of the key, but not the contents
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let variant = match self {
            HkdfPrk::Sha256(_) => "Sha256",
            HkdfPrk::Opaque(_) => "Opaque",
        };

        write!(f, "HkdfPrk::{}", variant)
    }
}

// This impl is for comparing app_secret in group_ctx::test::official_key_schedule_kat() and
// crypto::test::official_crypto_kat()
#[cfg(test)]
impl PartialEq for HkdfPrk {
    fn eq(&self, other: &HkdfPrk) -> bool {
        // This will panic if self or other are of the HkdfPrk::Opaque variant, since there's no
        // way to convert those to bytes
        self.as_bytes() == other.as_bytes()
    }
}

// This impl is for comparing app_secret in group_ctx::test::official_key_schedule_kat() and
// crypto::test::official_crypto_kat()
#[cfg(test)]
impl Eq for HkdfPrk {}

impl HkdfPrk {
    /// Creates a PRK from bytes
    pub(crate) fn new_from_bytes(hash_impl: &HashFunction, bytes: &[u8]) -> HkdfPrk {
        match hash_impl.name {
            "SHA256" => {
                // Make sure the input length is exactly the digest length of SHA256
                assert_eq!(bytes.len(), SHA256_DIGEST_SIZE, "HKDF-SHA256 PRK isn't 32 bytes");
                // Copy the bytes in
                let mut buf = [0u8; SHA256_DIGEST_SIZE];
                buf.copy_from_slice(bytes);
                HkdfPrk::Sha256(buf)
            }
            h => panic!("unknown hash algorithm {}", h),
        }
    }

    /// Creates a new PRK with the size equal to the given `HashFunction`'s digest size
    pub(crate) fn new_from_random<R>(hash_impl: &HashFunction, csprng: &mut R) -> HkdfPrk
    where
        R: CryptoRng,
    {
        match hash_impl.name {
            "SHA256" => {
                // Fill a buffer of appropriate length
                let mut buf = [0u8; SHA256_DIGEST_SIZE];
                csprng.fill_bytes(&mut buf);
                HkdfPrk::Sha256(buf)
            }
            h => panic!("unknown hash algorithm {}", h),
        }
    }

    /// Returns the bytes of this PRK. This MUST only be called by `PathSecret::as_bytes`.
    ///
    /// Panics: If the variant of `self` is `Opaque`. This should never happen.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        match self {
            HkdfPrk::Sha256(ref b) => b,
            HkdfPrk::Opaque(_) => panic!("cannot convert HkdfPrk::Opaque to bytes"),
        }
    }
}

/// A wrapper around the bytes of a "salt" to be used with `hkdf::extract`
#[derive(Clone)]
#[cfg_attr(test, derive(Debug, Eq, PartialEq))]
pub(crate) enum HkdfSalt {
    /// A PRK to be used with HKDF-Expand over SHA256
    Sha256([u8; SHA256_DIGEST_SIZE]),

    /// An undifferentiated variant used for (de)serialization
    Raw(HkdfSaltRaw),
}

// opaque WelcomeInfo::init_secret <0..255>
/// The form that all `HkdfSalt`s take when being sent or received over the wire
#[derive(Clone, Deserialize, Serialize)]
#[cfg_attr(test, derive(Debug, Eq, PartialEq))]
#[serde(rename = "HkdfSaltRaw__bound_u8")]
pub(crate) struct HkdfSaltRaw(pub(crate) Vec<u8>);

impl HkdfSalt {
    /// Wraps the given bytes in an `HkdfSalt` struct
    pub(crate) fn new_from_bytes(hash_impl: &HashFunction, bytes: &[u8]) -> HkdfSalt {
        match hash_impl.name {
            "SHA256" => {
                assert_eq!(bytes.len(), SHA256_DIGEST_SIZE, "HKDF-SHA256 salt isn't 32 bytes");
                let mut buf = [0u8; SHA256_DIGEST_SIZE];
                buf.copy_from_slice(bytes);
                HkdfSalt::Sha256(buf)
            }
            h => panic!("unknown hash algorithm {}", h),
        }
    }

    /// Makes a new all-zero `HkdfSalt` with length equal to the given hash function's digest
    /// length
    pub(crate) fn new_from_zeros(hash_impl: &HashFunction) -> HkdfSalt {
        match hash_impl.name {
            "SHA256" => HkdfSalt::Sha256([0u8; SHA256_DIGEST_SIZE]),
            h => panic!("unknown hash algorithm {}", h),
        }
    }

    /// Reveals the underlying bytes of the salt
    pub(crate) fn as_bytes(&self) -> &[u8] {
        match self {
            HkdfSalt::Sha256(ref buf) => buf,
            HkdfSalt::Raw(ref v) => v.0.as_slice(),
        }
    }

    /// Makes a new random `HkdfSalt` with length equal to the given hash function's digest
    /// length. This is only used for testing purposes.
    #[cfg(test)]
    pub(crate) fn new_from_random<R>(hash_impl: &HashFunction, csprng: &mut R) -> HkdfSalt
    where
        R: CryptoRng,
    {
        match hash_impl.name {
            "SHA256" => {
                let mut buf = [0u8; SHA256_DIGEST_SIZE];
                csprng.fill_bytes(&mut buf);
                HkdfSalt::Sha256(buf)
            }
            h => panic!("unknown hash algorithm {}", h),
        }
    }
}

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

/// Computes `HKDF-Extract(salt=salt, ikm=secret)` and outputs the resulting PRK
pub(crate) fn extract(hash_impl: &HashFunction, salt: &HkdfSalt, secret: &[u8]) -> HkdfPrk {
    let salt = ring::hkdf::Salt::new(hash_impl.into(), salt.as_bytes());
    HkdfPrk::Opaque(salt.extract(secret))
}

/// Serializes `info`, computes `HKDF-Expand(prk, info)`, and outputs the resulting output key
/// material (OKM). The output type has to know how many bytes it needs and how to convert those
/// bytes into key material. This is reflected in the `K: FromHkdfExpand` trait.
///
/// Returns: `Ok(okm)` on success. Returns an `Error::SerdeError` if something goes wrong while
/// serializing `info`
pub(crate) fn expand<S, K>(cs: &'static CipherSuite, prk: &HkdfPrk, info: &S) -> Result<K, Error>
where
    S: Serialize,
    K: FromHkdfExpand,
{
    let serialized_info = crate::tls_ser::serialize_to_bytes(info)?;

    // The length of the output key material in bytes
    let secret_len = K::get_secret_len(cs);
    // The buffer for the output key material
    let mut out_buf = vec![0u8; secret_len.len()];

    // Convert our PRK to a ring-compatible one
    let prk: ring::hkdf::Prk = prk.into();

    // Pass the values off to ring. This can only fail if secret_len is > 255 times the digest size
    // of the underlying hash function's digest. This never happens.
    let info_slice = &[serialized_info.as_slice()];
    let okm = prk.expand(info_slice, secret_len).unwrap();

    // This can only fail if the argument to fill() does not have length equal to secret_len. This
    // never happens.
    okm.fill(out_buf.as_mut_slice()).unwrap();

    // Use the bytes to make the new value
    K::new_from_bytes(cs, &out_buf)
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
/// Returns: `Ok(okm)` on success, where `okm` is the desired output keying material. Returns some
/// sort of `Error` otherwise (this should really never happen).
///
/// Panics: Iff the above requirement is not met
pub(crate) fn expand_label<K>(
    cs: &'static CipherSuite,
    prk: &HkdfPrk,
    label_info: &[u8],
    context: &[u8],
) -> Result<K, Error>
where
    K: FromHkdfExpand,
{
    // Get the length of the desired output
    let secret_len = K::get_secret_len(cs);

    // The label size is supposed to be at most 255 bytes after being prefixed with "mls10 "
    assert!(
        label_info.len() <= 255 - MLS_PREFIX.len(),
        "HKDF-Expand-Label label info cannot exceed 249 bytes"
    );
    // The output length is also supposed to be representable by a u16
    assert!(
        secret_len.len() <= std::u16::MAX as usize,
        "cannot run HKDF-Expand-Label on inputs whose size exceeds 2^16-1 bytes"
    );

    // full_label_info_slice = "mls10 " + Label
    let mut full_label_info = [0u8; 255];
    full_label_info[0..MLS_PREFIX.len()].copy_from_slice(MLS_PREFIX);
    full_label_info[MLS_PREFIX.len()..MLS_PREFIX.len() + label_info.len()]
        .copy_from_slice(label_info);
    let full_label_info_slice = &full_label_info[0..MLS_PREFIX.len() + label_info.len()];

    // We're gonna used the serialized label as the `info` parameter to HKDF-Expand. The length u16
    // conversion cannot fail because we checked that at the beginning
    let label = HkdfLabel {
        length: u16::try_from(secret_len.len()).unwrap(),
        // Recall the def: opaque label<6..255> = "mls10 " + Label;
        label: &full_label_info_slice,
        context,
    };

    // Finally, do the HKDF-Expand operation with built-in serialization
    expand(cs, prk, &label)
}

/// This is the `Derive-Secret` function defined in the "Key Schedule" section of the spec. It's
/// used as a helper function for `update_epoch_secrets`
///
/// Returns: `Ok(hmac_key)` on success. If an error occurred with serialization, returns an
/// `Error::SerdeError`.
pub(crate) fn derive_secret<S, K>(
    cs: &'static CipherSuite,
    prk: &HkdfPrk,
    label_info: &[u8],
    context: &S,
) -> Result<K, Error>
where
    S: Serialize,
    K: FromHkdfExpand,
{
    // Derive-Secret(Secret, Label, Context) =
    //     HKDF-Expand-Label(Secret, Label, Hash(Context), Hash.length)
    let hashed_ctx = cs.hash_impl.hash_serializable(context)?;
    expand_label(cs, prk, label_info, hashed_ctx.as_bytes())
}

#[cfg(test)]
mod test {
    use crate::crypto::{
        ciphersuite::X25519_SHA256_AES128GCM,
        hkdf::{self, FromHkdfExpand, HkdfSalt},
    };

    use quickcheck_macros::quickcheck;

    // Check that our implementation of hkdf::extract matches ring's implementation
    #[quickcheck]
    fn hkdf_extract_kat(salt_bytes: Vec<u8>, secret_bytes: Vec<u8>) {
        let cs = &X25519_SHA256_AES128GCM;

        // Wrap the salt bytes in a signing key
        let ring_salt = ring::hkdf::Salt::new(cs.hash_impl.into(), &salt_bytes);
        let my_salt = HkdfSalt::new_from_bytes(cs.hash_impl, &salt_bytes);

        // prk = HKDF-Extract(salt, ikm=secret)
        let ring_prk = ring_salt.extract(&secret_bytes);
        let my_prk = hkdf::extract(cs.hash_impl, &my_salt, &secret_bytes);

        // Constants we use as info strings
        let msg = b"now I got a reason to be waiting";
        let info = &[&msg[..], &msg[..]];

        // Now make sure the prk's agree. We can't check them directly, since there's no way of
        // turning a ring::hmac::SigningKey into bytes. So instead, just MAC a random message and
        // see if they turn out the same.
        let my_salt: HkdfSalt = hkdf::expand(cs, &my_prk, info).unwrap();
        let ring_okm = ring_prk.expand(info, HkdfSalt::get_secret_len(cs)).unwrap();

        // Our derived salt value
        let my_salt_bytes = my_salt.as_bytes();
        // ring's derived salt value
        let ring_salt_bytes = {
            let mut buf = vec![0u8; my_salt_bytes.len()];
            ring_okm.fill(buf.as_mut_slice()).unwrap();
            buf
        };

        // Make sure the salt values agree
        assert_eq!(my_salt_bytes, ring_salt_bytes.as_slice());
    }
}
