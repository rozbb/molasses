use crate::crypto::rng::CryptoRng;
use crate::error::Error;

/// A type representing the X25519 DH scheme
pub(crate) const X25519_IMPL: DhScheme = DhScheme(&X25519);

pub(crate) const P256_IMPL: DhScheme = DhScheme(&DummyP256);

const X25519_POINT_SIZE: usize = 32;
const X25519_SCALAR_SIZE: usize = 32;

/// An enum of possible types for a private DH value, depending on the underlying algorithm. In EC
/// terminology, this is a scalar in the base field. In finite-field terminology, this is an
/// exponent.
#[derive(Clone)]
pub(crate) enum DhPrivateKey {
    /// A scalar value in Curve25519
    X25519PrivateKey(x25519_dalek::StaticSecret),
}

impl DhPrivateKey {
    // This just passes through to DhSchemeInterface::private_key_from_bytes
    /// Makes a `DhPrivateKey` from the given bytes
    ///
    /// Requires: `bytes.len() == scheme.private_key_size()`
    ///
    /// Returns: `Ok(private_key)` on success. Otherwise, if `bytes.len() !=
    /// scheme.private_key_size()`, returns `Error::DhError`.
    pub(crate) fn new_from_bytes(scheme: &DhScheme, bytes: &[u8]) -> Result<DhPrivateKey, Error> {
        scheme.0.private_key_from_bytes(bytes)
    }

    // This just passes through to DhSchemeInterface::private_key_from_random
    /// Generates a random private key
    ///
    /// Returns: `Ok(private_key)` on success. Otherwise, if something goes wrong with the RNG, it
    /// returns `Error::OutOfEntropy`.
    pub(crate) fn new_from_random<R>(
        scheme: &DhScheme,
        csprng: &mut R,
    ) -> Result<DhPrivateKey, Error>
    where
        R: CryptoRng,
    {
        scheme.0.private_key_from_random(csprng)
    }
}

impl core::fmt::Debug for DhPrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str("DhPrivateKey: CONTENTS OMITTED")
    }
}

/// An enum of possible types for a DH shared secret, depending on the underlying algorithm. This
/// is mathematically the same as a point, but it is a secret value, not a public key, so we make
/// the same distinction that `dalek` makes
pub(crate) enum DhSharedSecret {
    /// A Curve25519 shared secret
    X25519SharedSecret(x25519_dalek::SharedSecret),
}

impl DhSharedSecret {
    /// Outputs the internal byte representation of a shared secret
    pub(crate) fn as_bytes(&self) -> &[u8] {
        match self {
            DhSharedSecret::X25519SharedSecret(p) => p.as_bytes(),
        }
    }
}

// opaque HPKEPublicKey<1..2^16-1>
/// This is the form that all `DhPublicKey`s take when being sent or received over the wire
#[derive(Clone, Deserialize, Serialize)]
#[cfg_attr(test, derive(Debug))]
#[serde(rename = "DhPublicKeyRaw__bound_u16")]
pub(crate) struct DhPublicKeyRaw(pub(crate) Vec<u8>);

/// An enum of possible types for a public DH value, depending on the underlying algorithm. In EC
/// terminology, this is a point on the curve. In finite-field terminology, this is a field
/// element. The `Raw` variant only gets instantiated at the serialization/deserialization
/// boundary, and should never be dealt with directly. The `CryptoUpcast` trait should take care of
/// this.
#[derive(Clone)]
#[cfg_attr(test, derive(Debug))]
pub(crate) enum DhPublicKey {
    /// A curve point in Curve25519
    X25519PublicKey(x25519_dalek::PublicKey),
    Raw(DhPublicKeyRaw),
}

impl DhPublicKey {
    // You may ask why this function isn't implemented as part of a serialization function for
    // DhPublicKey. That's because the byte representation of this here point is independent of the
    // wire format we choose. This representation is used in the calculation of ECIES ciphertexts,
    // which are computed independently of wire format.
    /// Outputs the internal byte representation of a given point
    pub(crate) fn as_bytes(&self) -> &[u8] {
        match self {
            DhPublicKey::X25519PublicKey(p) => p.as_bytes(),
            DhPublicKey::Raw(p) => p.0.as_slice(),
        }
    }

    // This just passes through to DhSchemeInterface::public_key_from_bytes
    /// Makes a `DhPublicKey` from the given bytes
    ///
    /// Requires: `bytes.len() == scheme.public_key_size()`
    ///
    /// Returns: `Ok(public_key)` on success. Otherwise, if the above requirement is not
    /// met,returns `Error::DhError`.
    pub(crate) fn new_from_bytes(scheme: &DhScheme, bytes: &[u8]) -> Result<DhPublicKey, Error> {
        scheme.0.public_key_from_bytes(bytes)
    }

    // This just passes through to DhSchemeInterface::public_key_from_private_key
    /// Derives a public key from the given private key
    pub(crate) fn new_from_private_key(
        scheme: &DhScheme,
        private_key: &DhPrivateKey,
    ) -> DhPublicKey {
        scheme.0.public_key_from_private_key(private_key)
    }
}

// This is probably not necessary, but why not
impl subtle::ConstantTimeEq for DhPublicKey {
    fn ct_eq(&self, other: &DhPublicKey) -> subtle::Choice {
        self.as_bytes().ct_eq(other.as_bytes())
    }
}

// Why do we do this? Firstly, it's a pain to write &'static dyn DhSchemeInterface everywhere.
// Secondly, I would like to support methods like AeadKey::new_from_bytes which would take in an
// DhSchemeInterface, but this leaves two ways of instantiating a DhPublicKey: either with
// new_from_bytes or with DhSchemeInterface::public_key_from_bytes. I think there should only be
// one way of doing this, so we'll wrap the trait object and not export the trait. Thirdly, this is
// in keeping with the design of SignatureScheme. Reasoning for that mess can be found in sig.rs.
pub(crate) struct DhScheme(&'static dyn DhSchemeInterface);

impl DhScheme {
    // This just passes through to DhSchemeInterface::diffie_hellman
    /// Computes `privkey * Pubkey` where `privkey` is your local secret (a scalar) and `Pubkey` is
    /// someone's public key (a curve point)
    ///
    /// Returns: `Ok(shared_secret)` on success. If the computed shared secret is all zeros,
    /// returns an `Error::DhError`, as required by the spec
    pub(crate) fn diffie_hellman(
        &self,
        privkey: &DhPrivateKey,
        pubkey: &DhPublicKey,
    ) -> Result<DhSharedSecret, Error> {
        self.0.diffie_hellman(privkey, pubkey)
    }
}

/// A trait representing any DH-like key-agreement algorithm. The notation it uses in documentation
/// is that of elliptic curves, but these concepts should generalize to finite-fields, SIDH, CSIDH,
/// etc.
trait DhSchemeInterface : Sync {
    fn public_key_size(&self) -> usize;

    fn private_key_size(&self) -> usize;

    fn public_key_from_bytes(&self, bytes: &[u8]) -> Result<DhPublicKey, Error>;

    fn public_key_from_private_key(&self, scalar: &DhPrivateKey) -> DhPublicKey;

    fn private_key_from_bytes(&self, bytes: &[u8]) -> Result<DhPrivateKey, Error>;

    // This has to take a dyn CryptoRng because DiffieHellman is itself a trait object inside a
    // CipherSuite. Trait objects can't have associated types, associated constants, or generic
    // methods.
    fn private_key_from_random(&self, csprng: &mut dyn CryptoRng) -> Result<DhPrivateKey, Error>;

    fn diffie_hellman(
        &self,
        privkey: &DhPrivateKey,
        pubkey: &DhPublicKey,
    ) -> Result<DhSharedSecret, Error>;
}

/// This represents the X25519 Diffie-Hellman key agreement protocol. Notably, it implements
/// `DiffieHellman`.
pub(crate) struct X25519;

impl DhSchemeInterface for X25519 {
    /// Returns the size of a point
    fn public_key_size(&self) -> usize {
        X25519_POINT_SIZE
    }

    /// Returns the size of a scalar
    fn private_key_size(&self) -> usize {
        X25519_SCALAR_SIZE
    }

    /// Makes a `DhPublicKey` from the given bytes
    ///
    /// Requires: `bytes.len() == X25519_POINT_SIZE == 32`
    ///
    /// Returns: `Ok(public_key)` on success. Otherwise, if `bytes.len() != 32`, returns
    /// `Error::DhError`.
    fn public_key_from_bytes(&self, bytes: &[u8]) -> Result<DhPublicKey, Error> {
        // This has to be the right length
        if bytes.len() != X25519_POINT_SIZE {
            Err(Error::DhError("Wrong public key size"))
        } else {
            let public_key = {
                let mut buf = [0u8; X25519_POINT_SIZE];
                buf.copy_from_slice(bytes);
                buf.into()
            };
            Ok(DhPublicKey::X25519PublicKey(public_key))
        }
    }

    /// Calculates `scalar * P`, where `P` is the standard X25519 basepoint. This function is used
    /// for creating public keys for DHE.
    fn public_key_from_private_key(&self, scalar: &DhPrivateKey) -> DhPublicKey {
        let scalar = enum_variant!(scalar, DhPrivateKey::X25519PrivateKey);
        let public_key: x25519_dalek::PublicKey = scalar.into();
        DhPublicKey::X25519PublicKey(public_key)
    }

    /// Uses the given bytes as a scalar in GF(2^255 - 19)
    ///
    /// Requires: `bytes.len() == 32`
    ///
    /// Returns: `Ok(private_key)` on success. Otherwise, if `bytes.len() != 32`, returns
    /// `Error::DhError`.
    fn private_key_from_bytes(&self, bytes: &[u8]) -> Result<DhPrivateKey, Error> {
        if bytes.len() != X25519_SCALAR_SIZE {
            Err(Error::DhError("Wrong scalar size"))
        } else {
            let mut buf = [0u8; X25519_SCALAR_SIZE];
            buf.copy_from_slice(bytes);
            Ok(DhPrivateKey::X25519PrivateKey(buf.into()))
        }
    }

    /// Generates a random private key
    ///
    /// Returns: `Ok(private_key)` on success. Otherwise, if something goes wrong with the RNG, it
    /// returns `Error::OutOfEntropy`.
    fn private_key_from_random(&self, csprng: &mut dyn CryptoRng) -> Result<DhPrivateKey, Error> {
        let mut box_rng = Box::new(csprng);
        Ok(DhPrivateKey::X25519PrivateKey(x25519_dalek::StaticSecret::new(&mut box_rng)))
    }

    /// Computes `privkey * Pubkey` where `privkey` is your local secret (a scalar) and `Pubkey` is
    /// someone's public key (a curve point)
    ///
    /// Returns: `Ok(shared_secret)` on success. If the computed shared secret is all zeros,
    /// returns an `Error::DhError`, as required by the spec
    fn diffie_hellman(
        &self,
        privkey: &DhPrivateKey,
        pubkey: &DhPublicKey,
    ) -> Result<DhSharedSecret, Error> {
        let privkey = enum_variant!(privkey, DhPrivateKey::X25519PrivateKey);
        let pubkey = enum_variant!(pubkey, DhPublicKey::X25519PublicKey);

        let ss = privkey.diffie_hellman(&pubkey);

        // Make sure we don't get all zeros
        if ss.as_bytes() == &[0u8; 32] {
            Err(Error::DhError("DH resulted in shared secret of all zeros"))
        } else {
            // We're good
            Ok(DhSharedSecret::X25519SharedSecret(ss))
        }
    }
}

pub(crate) struct DummyP256;

impl DhSchemeInterface for DummyP256 {
    fn public_key_size(&self) -> usize {
        65
    }

    fn private_key_size(&self) -> usize {
        32
    }

    fn public_key_from_bytes(&self, bytes: &[u8]) -> Result<DhPublicKey, Error> {
        if bytes.len() != 65 {
            Err(Error::DhError("P256 DH public key isn't 65 bytes long"))
        } else {
            let raw = DhPublicKeyRaw(bytes.to_vec());
            Ok(DhPublicKey::Raw(raw))
        }
    }

    fn public_key_from_private_key(&self, _scalar: &DhPrivateKey) -> DhPublicKey {
        unimplemented!()
    }

    fn private_key_from_bytes(&self, _bytes: &[u8]) -> Result<DhPrivateKey, Error> {
        unimplemented!()
    }

    // This has to take a dyn CryptoRng because DhSchemeInterface is used as a trait object inside
    // DhScheme. Trait objects can't have associated types, associated constants, or generic
    // methods.
    fn private_key_from_random(&self, _csprng: &mut dyn CryptoRng) -> Result<DhPrivateKey, Error> {
        unimplemented!()
    }

    fn diffie_hellman(
        &self,
        _privkey: &DhPrivateKey,
        _pubkey: &DhPublicKey,
    ) -> Result<DhSharedSecret, Error> {
        unimplemented!()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use quickcheck_macros::quickcheck;
    use rand::{RngCore, SeedableRng};

    // Diffie Hellman test vectors from https://tools.ietf.org/html/rfc7748#section-6.1
    #[test]
    fn x25519_kat() {
        // We're only working with x25519
        let scheme: &'static DhScheme = &X25519_IMPL;

        let alice_scalar = {
            let hex_str = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
            let bytes = hex::decode(hex_str).unwrap();
            DhPrivateKey::new_from_bytes(scheme, &bytes).expect("couldn't make scalar from bytes")
        };
        let bob_scalar = {
            let hex_str = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
            let bytes = hex::decode(hex_str).unwrap();
            DhPrivateKey::new_from_bytes(scheme, &bytes).expect("couldn't make scalar from bytes")
        };

        // Compute aP and bP where a is Alice's scalar, and b is Bob's
        let alice_pubkey = DhPublicKey::new_from_private_key(scheme, &alice_scalar);
        let bob_pubkey = DhPublicKey::new_from_private_key(scheme, &bob_scalar);

        // Compute b(aP) and a(bP) and make sure they are the same
        let shared_secret_a = scheme.diffie_hellman(&alice_scalar, &bob_pubkey).unwrap();
        let shared_secret_b = scheme.diffie_hellman(&bob_scalar, &alice_pubkey).unwrap();

        // Known-answer for aP
        assert_eq!(
            hex::encode(alice_pubkey.as_bytes()),
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        );
        // Known-answer for bP
        assert_eq!(
            hex::encode(bob_pubkey.as_bytes()),
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
        );
        // Test b(aP) == a(bP)
        assert_eq!(shared_secret_a.as_bytes(), shared_secret_b.as_bytes());
        // Known-answer for abP
        assert_eq!(
            hex::encode(shared_secret_a.as_bytes()),
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        );
    }

    #[quickcheck]
    fn x25519_correctness(secret_seed: u64) {
        // We're only working with x25519
        let scheme: &'static DhScheme = &X25519_IMPL;

        // Make a secret key seeded with the above seed. This is so that this function is
        // deterministic.
        let (scalar1, scalar2) = {
            let mut rng = rand::rngs::StdRng::seed_from_u64(secret_seed);
            let mut buf1 = [0u8; 32];
            let mut buf2 = [0u8; 32];
            rng.fill_bytes(&mut buf1);
            rng.fill_bytes(&mut buf2);
            (
                DhPrivateKey::new_from_bytes(scheme, &buf1).unwrap(),
                DhPrivateKey::new_from_bytes(scheme, &buf2).unwrap(),
            )
        };

        let (point1, point2) = (
            DhPublicKey::new_from_private_key(scheme, &scalar1),
            DhPublicKey::new_from_private_key(scheme, &scalar2),
        );
        let (shared1, shared2) = (
            X25519_IMPL.diffie_hellman(&scalar1, &point2).unwrap(),
            X25519_IMPL.diffie_hellman(&scalar2, &point1).unwrap(),
        );

        assert_eq!(shared1.as_bytes(), shared2.as_bytes());
    }

    // This comes from
    // https://github.com/mlswg/mls-implementations/blob/master/test_vectors/treesnodes.md
    #[test]
    fn node_key_derivation_kat() {
        // We're only working with x25519
        let scheme: &'static DhScheme = &X25519_IMPL;

        let scalar = {
            let hex_str = "e029fbe9de859e7bd6aea95ac258ae743a9eabccde9358420d8c975365938714";
            let bytes = hex::decode(hex_str).unwrap();
            DhPrivateKey::new_from_bytes(scheme, &bytes).expect("couldn't make scalar from bytes")
        };

        let pubkey = DhPublicKey::new_from_private_key(scheme, &scalar);

        assert_eq!(
            hex::encode(pubkey.as_bytes()),
            "6667b1715a0ad45b0510e850322a8d471d4485ebcbfcc0f3bcce7bcae7b44f7f"
        );
    }
}
