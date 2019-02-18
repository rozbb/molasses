use crate::error::Error;

use byteorder::{BigEndian, WriteBytesExt};
use doc_comment::doc_comment;
use serde::ser::{Serialize, SerializeSeq, Serializer};

/// Uses `TlsSerializer` to serialize the input to a vector of bytes
pub(crate) fn serialize_to_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    let mut serializer = TlsSerializer::new();
    value.serialize(&mut serializer)?;
    Ok(serializer.buf.into_inner())
}

// This macro gives us a way of serializing things with Tls notation like <1..2^16-1>. Here's how
// it works: we're given some serializable value: &T and we want to encode it so that we can
// specify its length in bytes as a prefix. So we first write 0 to the serialization buffer (that's
// TlsSerializer.buf), then serialize the whole value out. Once it's serialized, we now know how
// many bytes its serialization takes, so we seek back to the prefix location, and put that in as
// the length. One downside of this: we have to serialize the whole thing before we can reject it
// as too long. But this is nice and simple and I don't think it'll backfire unless the local
// participant is actively trying to take up a ton of memory.
macro_rules! serialize_with_bound {
    ($t:ty, $ti:ident, $fn_name:ident, $write_fn:ident, $endianness:ty ) => {
        doc_comment! {
            concat!(
                "Serializes an object with a length in bytes that must be representable by `",
                stringify!($t),
                "`",
            ),
            pub(crate) fn $fn_name<'a, T: Serialize + ?Sized>(
                value: &T,
                serializer: &mut &'a mut TlsSerializer,
            ) -> Result<
                <&'a mut TlsSerializer as Serializer>::Ok,
                <&'a mut TlsSerializer as Serializer>::Error,
            > {
                // Starting position
                let len_pos = serializer.buf.position();
                // Write a dummy zero here, then serialize everything we get, then rewrite the
                // correct length in the position of the dummy zero.
                serializer.buf.$write_fn::<$endianness>(0)?;
                value.serialize(&mut **serializer)?;
                // End position - start position - size of length tag = length of serialized output
                let len: u64 =
                    serializer.buf.position() - len_pos - (std::mem::size_of::<$t>() as u64);

                if len > (std::$ti::MAX as u64) {
                    let err = <Error as serde::ser::Error>::custom(
                        format_args!(
                            "tried to serialize a {}-bounded object that was too long",
                            stringify!($t)
                        )
                    );
                    return Err(err)
                }

                // If we haven't errored out yet, we're within the bound
                let len: $t = len as $t;
                // Save the position at the end of the buffer, seek to the length tag, write, the
                // length, then seek back to the end.
                let curr_pos = serializer.buf.position();
                serializer.buf.set_position(len_pos);
                serializer.buf.$write_fn::<$endianness>(len)?;
                serializer.buf.set_position(curr_pos);

                Ok(())
            }
        }
    };
}

serialize_with_bound!(u16, u16, serialize_with_bound_u16, write_u16, BigEndian);
serialize_with_bound!(u32, u32, serialize_with_bound_u32, write_u32, BigEndian);
serialize_with_bound!(u64, u64, serialize_with_bound_u64, write_u64, BigEndian);

// We need some custom instances for u8 and u24, since byteorder's write_u8 isn't parametric over
// any type, and u24 is not a type.

/// Serializes an object with a length in bytes that must be representable by `u8`
pub(crate) fn serialize_with_bound_u8<'a, T: Serialize + ?Sized>(
    value: &T,
    serializer: &mut &'a mut TlsSerializer,
) -> Result<<&'a mut TlsSerializer as Serializer>::Ok, <&'a mut TlsSerializer as Serializer>::Error>
{
    // Starting position
    let len_pos = serializer.buf.position();
    // Write a dummy zero here, then serialize everything we get, then rewrite the correct
    // length in the position of the dummy zero.
    serializer.buf.write_u8(0)?;
    value.serialize(&mut **serializer)?;
    // End position - start position - size of length tag = length of serialized output
    let len: u64 = serializer.buf.position() - len_pos - 1;

    if len > (std::u8::MAX as u64) {
        let err = <Error as serde::ser::Error>::custom(
            "tried to serialize a u8-bounded object that was too long",
        );
        return Err(err);
    }

    // If we haven't errored out yet, we're within the bound
    let len: u8 = len as u8;
    // Save the position at the end of the buffer, seek to the length tag, write, the
    // length, then seek back to the end.
    let curr_pos = serializer.buf.position();
    serializer.buf.set_position(len_pos);
    serializer.buf.write_u8(len)?;
    serializer.buf.set_position(curr_pos);

    Ok(())
}

/// Serializes an object with a length in bytes that must be representable by `u24` (i.e. 3 bytes)
pub(crate) fn serialize_with_bound_u24<'a, T: Serialize + ?Sized>(
    value: &T,
    serializer: &mut &'a mut TlsSerializer,
) -> Result<<&'a mut TlsSerializer as Serializer>::Ok, <&'a mut TlsSerializer as Serializer>::Error>
{
    // Starting position
    let len_pos = serializer.buf.position();
    // Write a dummy zero here, then serialize everything we get, then rewrite the correct
    // length in the position of the dummy zero.
    serializer.buf.write_u24::<BigEndian>(0)?;
    value.serialize(&mut **serializer)?;
    // End position - start position - size of length tag = length of serialized output
    let len: u64 = serializer.buf.position() - len_pos - 3;

    if len >= (1u64 << 24) {
        let err = <Error as serde::ser::Error>::custom(
            "tried to serialize a u24-bounded object that was too long",
        );
        return Err(err);
    }

    // If we haven't errored out yet, we're within the bound
    let len: u32 = len as u32;
    // Save the position at the end of the buffer, seek to the length tag, write, the
    // length, then seek back to the end.
    let curr_pos = serializer.buf.position();
    serializer.buf.set_position(len_pos);
    serializer.buf.write_u24::<BigEndian>(len)?;
    serializer.buf.set_position(curr_pos);

    Ok(())
}

pub(crate) fn serialize_with_optional_bound<'a, T>(
    field: &'static str,
    value: &T,
    serializer: &mut &'a mut TlsSerializer,
) -> Result<<&'a mut TlsSerializer as Serializer>::Ok, <&'a mut TlsSerializer as Serializer>::Error>
where
    T: Serialize + ?Sized,
{
    if field.ends_with("__bound_u8") {
        serialize_with_bound_u8(value, serializer)
    } else if field.ends_with("__bound_u16") {
        serialize_with_bound_u16(value, serializer)
    } else if field.ends_with("__bound_u24") {
        serialize_with_bound_u24(value, serializer)
    } else if field.ends_with("__bound_u32") {
        serialize_with_bound_u32(value, serializer)
    } else if field.ends_with("__bound_u64") {
        serialize_with_bound_u64(value, serializer)
    } else {
        value.serialize(&mut **serializer)
    }
}

/// This implements some subset of the Tls wire format. I still don't have a good source on the
/// format, but it seems as though the idea is "concat everything, and specify length in the
/// prefix". The output of this is verified against known serializations.
pub(crate) struct TlsSerializer {
    buf: std::io::Cursor<Vec<u8>>,
}

impl TlsSerializer {
    /// Makes a new empty `TlsSerializer` object
    pub(crate) fn new() -> TlsSerializer {
        TlsSerializer {
            buf: std::io::Cursor::new(Vec::new()),
        }
    }

    /// Returns this objects internal buffer
    pub(crate) fn into_vec(self) -> Vec<u8> {
        self.buf.into_inner()
    }
}

// Alright here's the big stuff. A Serializer needs to implement a _lot_ of methods. Fortunately
// for us, we don't actually need that much functionality out of our serializer. So we're going to
// leave most things unimplemented, and then implement them if we ever end up needing them.

impl<'a> Serializer for &'a mut TlsSerializer {
    type Ok = ();
    type Error = crate::error::Error;

    type SerializeSeq = Self;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;
    type SerializeMap = Self;
    type SerializeStruct = Self;
    type SerializeStructVariant = Self;

    //
    // Implemented stuff
    //

    fn serialize_u8(self, v: u8) -> Result<Self::Ok, Self::Error> {
        self.buf.write_u8(v)?;
        Ok(())
    }

    fn serialize_u16(self, v: u16) -> Result<Self::Ok, Self::Error> {
        self.buf.write_u16::<BigEndian>(v)?;
        Ok(())
    }

    fn serialize_u32(self, v: u32) -> Result<Self::Ok, Self::Error> {
        self.buf.write_u32::<BigEndian>(v)?;
        Ok(())
    }

    fn serialize_u64(self, v: u64) -> Result<Self::Ok, Self::Error> {
        self.buf.write_u64::<BigEndian>(v)?;
        Ok(())
    }

    /// Serializes a newtype struct. This is a bit of a hack: if the name of the struct ends with
    /// `__bound_uX` where X = 8, 16, 24, 32, or 64, then we prefix the serialized inner type with
    /// its length in bytes. This length tag will be the width of the specified X.
    fn serialize_newtype_struct<T>(
        mut self,
        name: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + Serialize,
    {
        serialize_with_optional_bound(name, value, &mut self)
    }

    /// This just forwards to `serialize_seq`
    fn serialize_bytes(self, v: &[u8]) -> Result<Self::Ok, Self::Error> {
        let mut seq = self.serialize_seq(Some(v.len()))?;
        for b in v {
            seq.serialize_element(b)?;
        }
        seq.end()
    }

    /// `TlsSerializer` is also a `SerializeSeq` (see impl below)
    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        Ok(self)
    }

    /// `TlsSerializer` is also a `SerializeStruct` (see impl below)
    fn serialize_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        Ok(self)
    }

    /// To serialize unit types, just write the variant down as a number
    fn serialize_unit_variant(
        self,
        name: &'static str,
        variant_index: u32,
        _variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        if name.ends_with("__enum_u8") {
            // Make sure the variant index isn't out of our range
            assert!(
                variant_index <= core::u8::MAX as u32,
                "enum variant index out of bounds"
            );
            self.serialize_u8(variant_index as u8)
        } else {
            let err = <Error as serde::ser::Error>::custom(
                "don't know how to serialize a non-__enum_u8 enum"
            );
            return Err(err);
        }
    }

    /// To serialize newtypes, we serialize it like a unit type, and then serialize the contents.
    fn serialize_newtype_variant<T>(
        self,
        name: &'static str,
        variant_index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + Serialize,
    {
        self.serialize_unit_variant(name, variant_index, variant)?;
        value.serialize(self)
    }

    /// Same thing as newtype variant. Serialize a struct variant by treating it as a unit variant,
    /// then serializing the struct it contains. `TlsSerializer` is also a `SerializeStructVariant`
    fn serialize_struct_variant(
        self,
        name: &'static str,
        variant_index: u32,
        variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        // Serialize the variant and then return myself as a SerializeStructVariant
        self.serialize_unit_variant(name, variant_index, variant)?;
        Ok(self)
    }

    //
    // Unimplemented stuff
    //

    fn serialize_bool(self, _v: bool) -> Result<Self::Ok, Self::Error> {
        unimplemented!()
    }
    fn serialize_i8(self, _v: i8) -> Result<Self::Ok, Self::Error> {
        unimplemented!()
    }
    fn serialize_i16(self, _v: i16) -> Result<Self::Ok, Self::Error> {
        unimplemented!()
    }
    fn serialize_i32(self, _v: i32) -> Result<Self::Ok, Self::Error> {
        unimplemented!()
    }
    fn serialize_i64(self, _v: i64) -> Result<Self::Ok, Self::Error> {
        unimplemented!()
    }
    fn serialize_f32(self, _v: f32) -> Result<Self::Ok, Self::Error> {
        unimplemented!()
    }
    fn serialize_f64(self, _v: f64) -> Result<Self::Ok, Self::Error> {
        unimplemented!()
    }
    fn serialize_char(self, _v: char) -> Result<Self::Ok, Self::Error> {
        unimplemented!()
    }
    fn serialize_str(self, _v: &str) -> Result<Self::Ok, Self::Error> {
        unimplemented!()
    }
    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        unimplemented!()
    }
    fn serialize_some<T: ?Sized + Serialize>(self, _v: &T) -> Result<Self::Ok, Self::Error> {
        unimplemented!()
    }
    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        unimplemented!()
    }
    fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok, Self::Error> {
        unimplemented!()
    }
    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        unimplemented!()
    }
    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        unimplemented!()
    }
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        unimplemented!()
    }
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        unimplemented!()
    }
}

/// Serializes slices, vecs, etc.
impl<'a> serde::ser::SerializeSeq for &'a mut TlsSerializer {
    type Ok = ();
    type Error = Error;

    /// Sequences (slices, vecs, etc.) get serialized in the naive way: sequentially serialize all
    /// the elements
    fn serialize_element<T>(&mut self, value: &T) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

/// Serializes structs. This does the same thing as `TlsSerializer as SerializeSeq`
impl<'a> serde::ser::SerializeStruct for &'a mut TlsSerializer {
    type Ok = ();
    type Error = crate::error::Error;

    /// Structs are serialized sequentially as well, without any delimiters between fields, since
    /// variable-sized fields are length-prefixed
    fn serialize_field<T>(&mut self, key: &'static str, value: &T) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + Serialize,
    {
        serialize_with_optional_bound(key, value, self)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

//
// More unimplemented stuff
//

impl<'a> serde::ser::SerializeTuple for &'a mut TlsSerializer {
    type Ok = ();
    type Error = Error;

    fn serialize_element<T>(&mut self, _value: &T) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + Serialize,
    {
        unimplemented!();
    }
    fn end(self) -> Result<Self::Ok, Self::Error> {
        unimplemented!();
    }
}

impl<'a> serde::ser::SerializeTupleStruct for &'a mut TlsSerializer {
    type Ok = ();
    type Error = crate::error::Error;

    fn serialize_field<T>(&mut self, _value: &T) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + Serialize,
    {
        unimplemented!();
    }
    fn end(self) -> Result<Self::Ok, Self::Error> {
        unimplemented!();
    }
}

impl<'a> serde::ser::SerializeTupleVariant for &'a mut TlsSerializer {
    type Ok = ();
    type Error = crate::error::Error;

    fn serialize_field<T>(&mut self, _value: &T) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + Serialize,
    {
        unimplemented!();
    }
    fn end(self) -> Result<Self::Ok, Self::Error> {
        unimplemented!();
    }
}

impl<'a> serde::ser::SerializeMap for &'a mut TlsSerializer {
    type Ok = ();
    type Error = crate::error::Error;

    fn serialize_key<T>(&mut self, _key: &T) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + Serialize,
    {
        unimplemented!()
    }
    fn serialize_value<T>(&mut self, _value: &T) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + Serialize,
    {
        unimplemented!()
    }
    fn end(self) -> Result<Self::Ok, Self::Error> {
        unimplemented!()
    }
}

impl<'a> serde::ser::SerializeStructVariant for &'a mut TlsSerializer {
    type Ok = ();
    type Error = crate::error::Error;

    fn serialize_field<T>(&mut self, key: &'static str, value: &T) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + Serialize,
    {
        serialize_with_optional_bound(key, value, self)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;

    use serde::de::Deserialize;

    // I'm bad at naming things. These are just structs that I'm using to test (de)serialization
    // though, so whatever.
    // We're making some of these pub(crate), because tls_de will use these data structures for
    // testing deserialization

    make_enum_u8_discriminant!(Eek {
        Draxx = 0x05,
        Them = 0xff,
        Sklounst = 0x32,
    });

    #[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct Ripp(u16);

    #[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
    #[serde(rename = "Biff__bound_u16")]
    struct Shake(Vec<u16>);

    #[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct Fan {
        #[serde(rename = "fv__bound_u8")]
        fv: Vec<u32>,
        fp: Ripp,
        fs: Shake,
        fe: Eek,
    }

    #[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
    #[serde(rename = "Hacc__enum_u8")]
    enum Hacc {
        Nothing,
        Something { sa: u16, sb: u32 },
    }

    #[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub(crate) struct Biff {
        a: u32,
        b: u32,
        c: u8,
        #[serde(rename = "d__bound_u16")]
        d: Vec<Fan>,
        e: u32,
        f: Hacc,
        g: Hacc,
    }

    // This represents the known Biff data structure that's returned by make_biff()
    #[rustfmt::skip]
    pub(crate) const biff_bytes: &'static [u8] = &[
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
        0x00,                            // Hacc::Nothing
        0x01,                            // Hacc::Something
            0x33, 0x44,                  //   u16
            0x55, 0x66, 0x77, 0x88,      //   u32
    ];

    // This is the Biff whose serialization is biff_bytes
    pub(crate) fn make_biff() -> Biff {
        Biff {
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
            f: Hacc::Nothing,
            g: Hacc::Something {
                sa: 0x3344,
                sb: 0x55667788,
            },
        }
    }

    // Make a Biff whose serialization we know, then make sure the serialization is correct. This
    // uses the above stupidly named structs.
    #[test]
    fn serialization_kat() {
        let biff = make_biff();
        let serialized = serialize_to_bytes(&biff).unwrap();
        let expected_bytes = biff_bytes;

        assert_eq!(serialized.as_slice(), expected_bytes);
    }
}
