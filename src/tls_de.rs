use crate::error::Error;

use std::io::Read;

use byteorder::{BigEndian, ReadBytesExt};
use serde::de::{Deserializer, Visitor};

// TODO: Make this parser more conservative in what it accepts. Currently, it will happily return
// incomplete vectors (i.e., it'll read a length, get to the end of a buffer that's too short, and
// then return what it has instead of blocking or erroring).

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

/// This implements some subset of the Tls wire format. I still don't have a good source on the
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
    fn deserialize_option<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Self::Error> {
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
    fn deserialize_enum<V>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        _visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }
    fn deserialize_tuple<V>(self, _len: usize, _visitor: V) -> Result<V::Value, Self::Error>
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

#[cfg(test)]
mod test {
    use super::*;

    use serde::de::Deserialize;

    // I'm bad at naming things. These are just structs that I'm using to test deserialization
    // though, so whatever

    make_enum_u8_discriminant!(Eek {
        Draxx = 0x05,
        Them = 0xff,
        Sklounst = 0x32,
    });

    #[derive(Debug, Deserialize, Eq, PartialEq)]
    struct Ripp(u16);

    #[derive(Debug, Deserialize, Eq, PartialEq)]
    #[serde(rename = "Biff__bound_u16")]
    struct Shake(Vec<u16>);

    #[derive(Debug, Deserialize, Eq, PartialEq)]
    struct Fan {
        #[serde(rename = "v__bound_u8")]
        fv: Vec<u32>,
        fp: Ripp,
        fs: Shake,
        fe: Eek,
    }

    #[derive(Debug, Deserialize, Eq, PartialEq)]
    struct Biff {
        a: u32,
        b: u32,
        c: u8,
        #[serde(rename = "d__bound_u16")]
        d: Vec<Fan>,
        e: u32,
    }

    // Make a byte sequence by hand whose deserialization we know, then test the result against
    // what we expect. This uses the above stupidly named structs.
    #[test]
    fn deserialization_kat() {
        #[rustfmt::skip]
        let mut bar_bytes = [
            0x01, 0x00, 0x00, 0x00,          // u32
            0x00, 0x00, 0x00, 0x01,          // u32
            0xff,                            // u8
            0x00, 0x20,                      // 32 bytes of Vec<Fan>
                0x0c,                        //   12 bytes of Vec<u32>
                    0xff, 0xff, 0xff, 0x00,  //     u32
                    0x00, 0x00, 0x00, 0xff,  //     u32
                    0x00, 0xff, 0x00, 0xff,  //     u32
                0x09, 0x08,                  //   Ripp
                0x00, 0x00,                  //   0 bytes of Shake
                                             //     [nothing]
                0x05,                        //   Eek::Draxx
                0x04,                        //   4 bytes of Vec<u32>
                    0x10, 0x10, 0x10, 0x10,  //     u32
                0x07, 0x06,                  //   Ripp
                0x00, 0x04,                  //   4 bytes of Shake
                    0xaa, 0xbb,              //     u16
                    0xcc, 0xdd,              //     u16
                0x32,                        //   Eek::Sklounst
            0x00, 0x00, 0x00, 0x02,          // u32
        ];

        let mut buf = &bar_bytes[..];
        let mut deserializer = TlsDeserializer::from_reader(&mut buf);
        let biff = Biff::deserialize(&mut deserializer).unwrap();

        let expected = Biff {
            a: 0x01000000,
            b: 0x00000001,
            c: 0xff,
            d: vec![
                Fan {
                    fv: vec![0xffffff00, 0x000000ff, 0x00ff00ff],
                    fp: Ripp(0x0908),
                    fs: Shake(Vec::new()),
                    fe: Eek::Draxx,
                },
                Fan {
                    fv: vec![0x10101010],
                    fp: Ripp(0x0706),
                    fs: Shake(vec![0xaabb, 0xccdd]),
                    fe: Eek::Sklounst,
                },
            ],
            e: 0x00000002,
        };

        assert_eq!(biff, expected);
    }
}
