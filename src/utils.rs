#[macro_export]
macro_rules! enum_variant {
    ($val:expr, $variant:path) => {
        match $val {
            $variant(x) => x,
            _ => panic!(
                "Got wrong enum variant. Was expecting {}",
                stringify!($variant)
            ),
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
                // Make a Visitor type that just does
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
