use crate::error::Error;

use byteorder::{BigEndian, WriteBytesExt};
use doc_comment::doc_comment;
use serde::ser::{Serialize, SerializeSeq, Serializer};

// TODO: Add more helpful panic messages

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
                v: &T,
                s: &mut &'a mut TlsSerializer,
            ) -> Result<
                <&'a mut TlsSerializer as Serializer>::Ok,
                <&'a mut TlsSerializer as Serializer>::Error,
            > {
                // Starting position
                let len_pos = s.buf.position();
                // Write a dummy zero here, then serialize everything we get, then rewrite the
                // correct length in the position of the dummy zero.
                s.buf.$write_fn::<$endianness>(0)?;
                v.serialize(&mut **s)?;
                // End position - start position - size of length tag = length of serialized output
                let len: u64 = s.buf.position() - len_pos - (std::mem::size_of::<$t>() as u64);

                if len > (std::$ti::MAX as u64) {
                    panic!(
                        "tried to serialize a {}-bounded object that was too long",
                        stringify!($t),
                    )
                }

                // If we haven't panicked yet, we're within the bound
                let len: $t = len as $t;
                s.buf.set_position(len_pos);
                s.buf.$write_fn::<$endianness>(len)?;

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
    v: &T,
    s: &mut &'a mut TlsSerializer,
) -> Result<<&'a mut TlsSerializer as Serializer>::Ok, <&'a mut TlsSerializer as Serializer>::Error>
{
    // Starting position
    let len_pos = s.buf.position();
    // Write a dummy zero here, then serialize everything we get, then rewrite the correct
    // length in the position of the dummy zero.
    s.buf.write_u8(0)?;
    v.serialize(&mut **s)?;
    // End position - start position - size of length tag = length of serialized output
    let len: u64 = s.buf.position() - len_pos - 1;

    if len > (std::u8::MAX as u64) {
        panic!("tried to serialize a u8-bounded object that was too long")
    }

    // If we haven't panicked yet, we're within the bound
    let len: u8 = len as u8;
    s.buf.set_position(len_pos);
    s.buf.write_u8(len)?;

    Ok(())
}

/// Serializes an object with a length in bytes that must be representable by `u24` (i.e. 3 bytes)
pub(crate) fn serialize_with_bound_u24<'a, T: Serialize + ?Sized>(
    v: &T,
    s: &mut &'a mut TlsSerializer,
) -> Result<<&'a mut TlsSerializer as Serializer>::Ok, <&'a mut TlsSerializer as Serializer>::Error>
{
    // Starting position
    let len_pos = s.buf.position();
    // Write a dummy zero here, then serialize everything we get, then rewrite the correct
    // length in the position of the dummy zero.
    s.buf.write_u24::<BigEndian>(0)?;
    v.serialize(&mut **s)?;
    // End position - start position - size of length tag = length of serialized output
    let len: u64 = s.buf.position() - len_pos - 3;

    if len >= (1u64 << 24) {
        panic!("tried to serialize a u24-bounded object that was too long")
    }

    // If we haven't panicked yet, we're within the bound
    let len: u32 = len as u32;
    s.buf.set_position(len_pos);
    s.buf.write_u24::<BigEndian>(len)?;

    Ok(())
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
        if name.ends_with("__bound_u8") {
            serialize_with_bound_u8(value, &mut self)
        } else if name.ends_with("__bound_u16") {
            serialize_with_bound_u16(value, &mut self)
        } else if name.ends_with("__bound_u24") {
            serialize_with_bound_u24(value, &mut self)
        } else if name.ends_with("__bound_u32") {
            serialize_with_bound_u32(value, &mut self)
        } else if name.ends_with("__bound_u64") {
            serialize_with_bound_u64(value, &mut self)
        } else {
            value.serialize(self)
        }
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
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        unimplemented!()
    }
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        unimplemented!()
    }
    fn serialize_newtype_variant<T>(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _value: &T,
    ) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + Serialize,
    {
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
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
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
    fn serialize_field<T>(&mut self, _key: &'static str, value: &T) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(&mut **self)
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

    fn serialize_field<T>(
        &mut self,
        _key: &'static str,
        _value: &T,
    ) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + Serialize,
    {
        unimplemented!()
    }
    fn end(self) -> Result<Self::Ok, Self::Error> {
        unimplemented!()
    }
}
