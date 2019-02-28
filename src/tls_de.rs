use crate::error::Error;

use std::io::Read;

use byteorder::{BigEndian, ReadBytesExt};
use serde::de::{Deserializer, IntoDeserializer, Visitor};

// TODO: Make this parser more conservative in what it accepts. Currently, it will happily return
// incomplete vectors (i.e., it'll read a length, get to the end of a buffer that's too short, and
// then return what it has instead of blocking or erroring).
// TODO: Consider the blocking behavior of this deserializer. Can we provide non-blocking options?

/// Makes an `error::Error::SerdeError(std::io::Error)` given some formattable input
fn make_custom_error<T: core::fmt::Display>(msg: T) -> Error {
    <Error as serde::de::Error>::custom(msg)
}

/// Given a reader and the name of a field or unit struct, find the length of the upcoming data.
/// This only makes sense for variable-length data types. So for example if we were parsing the `v`
/// field of
/// ```
/// # use serde::Deserialize;
/// #[derive(Deserialize)]
/// struct Foo {
///     #[serde(rename = "v__bound_u8")]
///     v: Vec<u8>
/// }
/// ```
/// we would have `field == "v__bound_u8"` and look for a single byte representing the length of
/// `v`. Similarly for newtype structs,
/// ```
/// # use serde::Deserialize;
/// #[derive(Deserialize)]
/// #[serde(rename = "Foo__bound_u8")]
/// struct Foo(Vec<u8>);
/// ```
/// we would have `field == "Foo__bound_u8` and look for a single byte representing the length of
/// the contained vector.
fn get_field_len<'b, R>(field: &'static str, reader: &mut R) -> Result<Option<u64>, Error>
where
    R: std::io::Read,
{
    let res = if field.ends_with("__bound_u8") {
        Some(reader.read_u8()? as u64)
    } else if field.ends_with("__bound_u16") {
        Some(reader.read_u16::<BigEndian>()? as u64)
    } else if field.ends_with("__bound_u24") {
        Some(reader.read_u24::<BigEndian>()? as u64)
    } else if field.ends_with("__bound_u32") {
        Some(reader.read_u32::<BigEndian>()? as u64)
    } else if field.ends_with("__bound_u64") {
        Some(reader.read_u64::<BigEndian>()?)
    } else {
        None
    };

    Ok(res)
}

/// This implements some subset of the TLS wire format. I still don't have a good source on the
/// format, but it seems as though the idea is "concat everything, and specify length in the
/// prefix".
pub(crate) struct TlsDeserializer<'a, R: std::io::Read> {
    reader: &'a mut R,
}

impl<'a, R: std::io::Read> TlsDeserializer<'a, R> {
    /// Makes a new `TlsDeserializer` from the given byte reader
    pub(crate) fn from_reader(reader: &'a mut R) -> TlsDeserializer<R> {
        TlsDeserializer { reader: reader }
    }
}

impl<'de, 'a, 'b, R: std::io::Read> Deserializer<'de> for &'b mut TlsDeserializer<'a, R> {
    type Error = Error;

    //
    // Implemented stuff
    //

    /// Hint that the `Deserialize` type is expecting a `u8` value.
    fn deserialize_u8<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_u8(self.reader.read_u8()?)
    }

    /// Hint that the `Deserialize` type is expecting a `u16` value.
    fn deserialize_u16<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_u16(self.reader.read_u16::<BigEndian>()?)
    }

    /// Hint that the `Deserialize` type is expecting a `u32` value.
    fn deserialize_u32<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_u32(self.reader.read_u32::<BigEndian>()?)
    }

    /// Hint that the `Deserialize` type is expecting a `u64` value.
    fn deserialize_u64<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_u64(self.reader.read_u64::<BigEndian>()?)
    }

    /// Hint that the `Deserialize` type is expecting an `Option` value. This reads a single byte
    /// that's a 0 or 1, then reads nothing or the contents of the `Some` variant, respectively.
    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        let value: u8 = serde::de::Deserialize::deserialize(&mut *self)?;
        match value {
            0 => visitor.visit_none(),
            1 => visitor.visit_some(&mut *self),
            _ => Err(make_custom_error("expected binary tag for Option type")),
        }
    }

    /// Hint that the `Deserialize` type is expecting a newtype struct with a particular name. This
    /// will use our hacky naming scheme to find the length of the inner type (if it is a
    /// variable-length type) and deserialize the contents normally.
    fn deserialize_newtype_struct<V>(
        self,
        name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        // If the inner type is variable-length, this will return the length of the inner type in
        // bytes
        let field_len = get_field_len(name, &mut self.reader)?;

        // Make a sub-reader that only reads the number of bytes specified by the length tag. Then
        // deserialize the contents normally. It will finish when it runs out of things to read.
        // This is guaranteed by the logic in TlsVecSeq.
        if let Some(len) = field_len {
            // Make a new deserializer with a sub-buffer
            let mut sub_reader = self.reader.take(len);
            let mut sub_deserializer = TlsDeserializer::from_reader(&mut sub_reader);

            // Deserialize the contents normally
            visitor.visit_newtype_struct(&mut sub_deserializer)
        } else {
            // Otherwise, if the inner type is not variable-length, deserialize the contents
            // normally
            visitor.visit_newtype_struct(self)
        }
    }

    /// Hint that the `Deserialize` type is expecting a sequence of values. This will make a new
    /// `TlsVecSeq` object and run `Visitor::visit_seq` on that.
    fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let s = TlsVecSeq::new(self);
        visitor.visit_seq(s)
    }

    fn deserialize_enum<V>(
        self,
        name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        if name.ends_with("__enum_u8") {
            let s = TlsEnumU8::new(self);
            visitor.visit_enum(s)
        } else {
            Err(make_custom_error(
                format_args!(
                    "don't know how to deserialize non-__enum_u8 enums: {}",
                    name
                )
            ))
        }
    }

    fn deserialize_tuple<V>(self, len: usize, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let s = TlsTupleSeq::new(self, len);
        visitor.visit_seq(s)
    }

    /// Hint that the `Deserialize` type is expecting a struct with a particular name and fields.
    /// This will make a new `TlsStructSeq` object with the given fields and run
    /// `Visitor::visit_seq` on that.
    fn deserialize_struct<V>(
        self,
        _name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let s = TlsStructSeq::new(self, fields);
        visitor.visit_seq(s)
    }

    /// I don't care who you are. This is not a human-readable format.
    #[inline]
    fn is_human_readable(&self) -> bool {
        false
    }

    //
    // Unimplemented stuff
    //

    fn deserialize_any<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Self::Error> {
        unimplemented!()
    }
    fn deserialize_bool<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Self::Error> {
        unimplemented!()
    }
    fn deserialize_i8<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Self::Error> {
        unimplemented!()
    }
    fn deserialize_i16<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Self::Error> {
        unimplemented!()
    }
    fn deserialize_i32<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Self::Error> {
        unimplemented!()
    }
    fn deserialize_i64<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Self::Error> {
        unimplemented!()
    }
    fn deserialize_i128<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Self::Error> {
        unimplemented!()
    }
    fn deserialize_u128<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Self::Error> {
        unimplemented!()
    }
    fn deserialize_f32<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Self::Error> {
        unimplemented!()
    }
    fn deserialize_f64<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Self::Error> {
        unimplemented!()
    }
    fn deserialize_char<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Self::Error> {
        unimplemented!()
    }
    fn deserialize_str<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Self::Error> {
        unimplemented!()
    }
    fn deserialize_string<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Self::Error> {
        unimplemented!()
    }
    fn deserialize_bytes<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Self::Error> {
        unimplemented!()
    }
    fn deserialize_byte_buf<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Self::Error> {
        unimplemented!()
    }
    fn deserialize_unit<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Self::Error> {
        unimplemented!()
    }
    fn deserialize_unit_struct<V>(
        self,
        _name: &'static str,
        _visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }
    fn deserialize_tuple_struct<V>(
        self,
        _name: &'static str,
        _len: usize,
        _visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }
    fn deserialize_map<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Self::Error> {
        unimplemented!()
    }
    fn deserialize_identifier<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Self::Error> {
        unimplemented!()
    }
    fn deserialize_ignored_any<V: Visitor<'de>>(
        self,
        _visitor: V,
    ) -> Result<V::Value, Self::Error> {
        unimplemented!()
    }
}

/// This deals with the logic of deserializing structs. This is just a sequence of fields. If the
/// field name has a length tag size, this is handled appropriately.
struct TlsStructSeq<'a, 'b, R: std::io::Read> {
    /// A reference to the deserializer that called us
    de: &'a mut TlsDeserializer<'b, R>,
    /// The fields of this struct
    fields: &'static [&'static str],
    /// An index to which field is currently being deserialized
    field_idx: usize,
}

impl<'a, 'b, R: std::io::Read> TlsStructSeq<'a, 'b, R> {
    /// Returns a new `TlsStructSeq` with the given deserializer, the given fields, and starting
    /// index 0
    fn new(
        de: &'a mut TlsDeserializer<'b, R>,
        fields: &'static [&'static str],
    ) -> TlsStructSeq<'a, 'b, R> {
        TlsStructSeq {
            de: de,
            fields: fields,
            field_idx: 0,
        }
    }
}

/// This deals with the logic of deserializing tuples. It's just a fixed-length sequence of items
struct TlsTupleSeq<'a, 'b, R: std::io::Read> {
    /// A reference to the deserializer that called us
    de: &'a mut TlsDeserializer<'b, R>,
    /// The number of elements in the tuple
    len: usize,
    /// Our current position in the tuple
    idx: usize,
}

impl<'a, 'b, R: std::io::Read> TlsTupleSeq<'a, 'b, R> {
    /// Returns a new `TlsTupleSeq` with the given deserializer and length, and sets the starting
    /// index to 0
    fn new(de: &'a mut TlsDeserializer<'b, R>, len: usize) -> TlsTupleSeq<'a, 'b, R> {
        TlsTupleSeq {
            de: de,
            len: len,
            idx: 0,
        }
    }
}

impl<'de, 'a, 'b, R: std::io::Read> serde::de::SeqAccess<'de> for TlsTupleSeq<'a, 'b, R> {
    type Error = Error;

    /// Deserializes the next field in the tuple
    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, Error>
    where
        T: serde::de::DeserializeSeed<'de>,
    {
        // If we're done, return None. Otherwise increment the counter and deserialize the next
        // thing
        if self.idx >= self.len {
            Ok(None)
        } else {
            self.idx += 1;
            seed.deserialize(&mut *self.de).map(Some)
        }
    }
}

impl<'de, 'a, 'b, R: std::io::Read> serde::de::SeqAccess<'de> for TlsStructSeq<'a, 'b, R> {
    type Error = Error;

    /// Deserializes the next field in the struct
    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, Error>
    where
        T: serde::de::DeserializeSeed<'de>,
    {
        // This function will not be called more times than there are fields in the struct. If it
        // is, we will panic
        let field = self
            .fields
            .get(self.field_idx)
            .expect("in unknown field while deserializing a struct");
        self.field_idx += 1;

        // If this is a variable-length field, read off the length
        let field_len = get_field_len(field, &mut self.de.reader)?;

        // As in TlsDeserializer::deserialize_newtype_struct, make a sub-reader that only reads the
        // number of bytes specified by the length tag. Then deserialize the contents normally. It
        // will finish when it runs out of things to read. This is guaranteed by the logic in
        // TlsVecSeq.
        if let Some(len) = field_len {
            // Make a sub-buffer to read from
            let mut sub_reader = self.de.reader.take(len);
            let mut sub_deserializer = TlsDeserializer::from_reader(&mut sub_reader);

            // Deserialize from it normally
            seed.deserialize(&mut sub_deserializer).map(Some)
        } else {
            // If no length is specified, do the natural thing
            seed.deserialize(&mut *self.de).map(Some)
        }
    }
}

/// This deals with the logic of deserializing sequences (mostly `Vec`s). The logic is simple: keep
/// deserializing items until you run out of buffer space. The reader that this is given is limited
/// to the total number of bytes we're supposed to read, so there's no fear of overrun.
struct TlsVecSeq<'a, 'b, R: std::io::Read> {
    de: &'a mut TlsDeserializer<'b, R>,
}

impl<'a, 'b, R: std::io::Read> TlsVecSeq<'a, 'b, R> {
    /// Makes a new `TlsVecSeq` object from the given deserializer
    fn new(de: &'a mut TlsDeserializer<'b, R>) -> TlsVecSeq<'a, 'b, R> {
        TlsVecSeq { de: de }
    }
}

impl<'de, 'a, 'b, R: std::io::Read> serde::de::SeqAccess<'de> for TlsVecSeq<'a, 'b, R> {
    type Error = Error;

    /// Deserializes the next item in the list
    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, Error>
    where
        T: serde::de::DeserializeSeed<'de>,
    {
        // Try to deserialize the next item
        match seed.deserialize(&mut *self.de) {
            // If it's all good, return it
            Ok(a) => Ok(Some(a)),
            Err(Error::SerdeError(io_err)) => {
                if io_err.kind() == std::io::ErrorKind::UnexpectedEof {
                    // If we've reached the end of the buffer, that means we're done reading into
                    // this list
                    Ok(None)
                } else {
                    // Otherwise, it's some other error. Return it
                    Err(Error::SerdeError(io_err))
                }
            }
            // We can't receive a non-serde error from a deserialize method
            _ => unreachable!(),
        }
    }
}

/// This deals with the logic of deserializing enums with variant indices of size u8
struct TlsEnumU8<'a, 'b, R: std::io::Read> {
    de: &'a mut TlsDeserializer<'b, R>,
}

impl<'a, 'b, R: std::io::Read> TlsEnumU8<'a, 'b, R> {
    /// Makes a new `TlsEnumU8` object from the given deserializer
    fn new(de: &'a mut TlsDeserializer<'b, R>) -> TlsEnumU8<'a, 'b, R> {
        TlsEnumU8 { de: de }
    }
}

impl<'de, 'a, 'b, R: std::io::Read> serde::de::EnumAccess<'de> for TlsEnumU8<'a, 'b, R> {
    type Error = Error;
    type Variant = Self;

    /// Deserializes an enum variant
    fn variant_seed<V>(self, seed: V) -> Result<(V::Value, Self::Variant), Error>
    where
        V: serde::de::DeserializeSeed<'de>,
    {
        // The variant index is a u8. Serde lets us turn that number into a deserializer which we
        // can then use to get find correct variant.
        let idx: u8 = serde::de::Deserialize::deserialize(&mut *self.de)?;
        let variant_de: serde::de::value::U8Deserializer<Error> = idx.into_deserializer();
        // Now that we have the variant index, deserialize the contents (if there are any)
        let val = seed.deserialize(variant_de)?;
        Ok((val, self))
    }
}

impl<'de, 'a, 'b, R> serde::de::VariantAccess<'de> for TlsEnumU8<'a, 'b, R>
where
    R: std::io::Read,
{
    type Error = Error;

    fn unit_variant(self) -> Result<(), Error> {
        Ok(())
    }

    // For newtypes, just deserialize the insides
    fn newtype_variant_seed<T>(self, seed: T) -> Result<T::Value, Error>
    where
        T: serde::de::DeserializeSeed<'de>,
    {
        seed.deserialize(&mut *self.de)
    }

    // For tuples, deserialize the insides as a tuple
    fn tuple_variant<V>(self, len: usize, visitor: V) -> Result<V::Value, Error>
    where
        V: serde::de::Visitor<'de>,
    {
        self.de.deserialize_tuple(len, visitor)
    }

    // For structs, deserialize the insides as a tuple
    fn struct_variant<V>(
        self,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error>
    where
        V: serde::de::Visitor<'de>,
    {
        self.de.deserialize_tuple(fields.len(), visitor)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    // Use the test vectors from the serialization code
    use crate::tls_ser::test::{make_biff, Biff, BIFF_BYTES};

    use serde::de::Deserialize;

    // Make a byte sequence by hand whose Biff-deserialization we know, then test that it is what
    // we expect. This uses some stupidly named structs.
    #[test]
    fn deserialization_kat() {
        let mut buf = BIFF_BYTES;
        let mut deserializer = TlsDeserializer::from_reader(&mut buf);
        let expected_biff = make_biff();
        let deserialized_biff = Biff::deserialize(&mut deserializer).unwrap();

        assert_eq!(deserialized_biff, expected_biff);
    }
}
