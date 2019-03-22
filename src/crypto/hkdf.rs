type Prk = ring::hmac::SigningKey;

const MLS_PREFIX: &'static [u8] = b"mls10 ";

// This struct is only used for `hkdf_expand_label` calculations
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

pub(crate) fn prk_from_bytes(hash_alg: &'static ring::digest::Algorithm, secret: &[u8]) -> Prk {
    ring::hmac::SigningKey::new(hash_alg, secret)
}

pub(crate) fn hkdf_extract(salt: &Prk, secret: &[u8]) -> Prk {
    ring::hkdf::extract(salt, secret)
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
pub(crate) fn hkdf_expand_label(
    secret: &Prk,
    label_info: &[u8],
    context: &[u8],
    out_buf: &mut [u8],
) {
    // The label size is supposed to be at most 255 bytes after being prefixed with "mls10 "
    assert!(label_info.len() <= 255 - MLS_PREFIX.len());
    // The output length is also supposed to be representable by a u16
    assert!(out_buf.len() <= std::u16::MAX as usize);

    // label = "mls10 " + Label
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
        context: context,
    };
    // Serialize the label
    let serialized_label =
        crate::tls_ser::serialize_to_bytes(&label).expect("couldn't serialize HKDF label");

    // Finally, do the HKDF-Expand operation
    ring::hkdf::expand(&secret, &serialized_label, out_buf);
}

// Derive-Secret(Secret, Label, Context) =
//     HKDF-Expand-Label(Secret, Label, Hash(Context), Hash.length)
/// This is the `Derive-Secret` function defined in section 5.9 of the spec. It's used as a
/// helper function for `update_epoch_secrets`
pub(crate) fn derive_secret(secret: &Prk, label_info: &[u8], context: &[u8]) -> Vec<u8> {
    let hash_alg = secret.digest_algorithm();
    let hashed_ctx = ring::digest::digest(hash_alg, context);
    let mut out_buf = vec![0u8; hash_alg.output_len];
    hkdf_expand_label(secret, label_info, hashed_ctx.as_ref(), out_buf.as_mut_slice());

    out_buf
}
