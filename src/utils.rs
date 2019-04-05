/// Unwraps an enum into an expected variant. Panics if the supplied value is not of the expected
/// variant. This macro is used to succinctly ensure that ciphersuite values are kept consistent
/// throughout the library.
#[macro_export]
macro_rules! enum_variant {
    ($val:expr, $variant:path) => {
        match $val {
            $variant(x) => x,
            _ => panic!("Got wrong enum variant. Was expecting {}", stringify!($variant)),
        }
    };
}

// This was taken and modified from https://serde.rs/enum-number.html
/// This takes a definition of an enum of only unit variants and makes it serializable and
/// deserializable according to its discriminant values
#[macro_export]
macro_rules! make_enum_u8_discriminant {
    ($name:ident { $($variant:ident = $value:expr, )* }) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub enum $name {
            $($variant = $value,)*
        }

        impl serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                // Make sure the discriminant isn't too high
                if (*self as usize) > std::u8::MAX as usize {
                    panic!("variant discriminant out of range")
                }

                // Serialize the enum as a u8.
                let disc = *self as u8;
                serializer.serialize_u8(disc)
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct Visitor;

                impl<'de> serde::de::Visitor<'de> for Visitor {
                    type Value = $name;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                        formatter.write_str("a single byte")
                    }

                    fn visit_u8<E>(self, value: u8) -> Result<$name, E>
                    where
                        E: serde::de::Error,
                    {
                        // Rust does not come with a simple way of converting a number to an enum,
                        // so use a big `match`.
                        match value {
                            $( $value => Ok($name::$variant), )*
                            _ => Err(
                                     E::custom(
                                         format!(
                                             "unexpected discriminant for {}: {}",
                                             stringify!($name),
                                             value
                                         )))
                        }
                    }
                }

                // Deserialize the enum from a u8.
                deserializer.deserialize_u8(Visitor)
            }
        }
    }
}

#[cfg(test)]
pub(crate) use test_utils::*;

#[cfg(test)]
mod test_utils {
    use crate::{
        credential::Credential, crypto::ciphersuite::X25519_SHA256_AES128GCM, error::Error,
        group_state::GroupState, ratchet_tree::RatchetTree,
    };

    // This is all the serializable bits of a GroupState. We have this separate because GroupState
    // is only ever meant to be serialized. The fields in it that are for us and not for
    // serialization require a Default instance in order for GroupState to impl Deserialize. Since
    // I don't think that's a good idea, I'll just initialize all those things to 0 myself. See
    // group_from_test_group.
    #[derive(Debug, Deserialize)]
    pub(crate) struct TestGroupState {
        #[serde(rename = "group_id__bound_u8")]
        group_id: Vec<u8>,
        epoch: u32,
        #[serde(rename = "roster__bound_u32")]
        roster: Vec<Option<Credential>>,
        tree: RatchetTree,
        #[serde(rename = "transcript_hash__bound_u8")]
        pub(crate) transcript_hash: Vec<u8>,
    }

    impl crate::upcast::CryptoUpcast for TestGroupState {
        fn upcast_crypto_values(&mut self, ctx: &crate::upcast::CryptoCtx) -> Result<(), Error> {
            self.roster.upcast_crypto_values(ctx)
        }
    }

    // Makes a mostly empty GroupState from a recently-deserialized TestGroupState
    pub(crate) fn group_from_test_group(tgs: TestGroupState) -> GroupState {
        let cs = &X25519_SHA256_AES128GCM;
        GroupState {
            cs: cs,
            protocol_version: 0,
            identity_key: cs.sig_impl.secret_key_from_bytes(&[0u8; 32]).unwrap(),
            group_id: tgs.group_id,
            epoch: tgs.epoch,
            roster: tgs.roster,
            tree: tgs.tree,
            transcript_hash: tgs.transcript_hash,
            roster_index: 0,
            init_secret: Vec::new(),
        }
    }
}
