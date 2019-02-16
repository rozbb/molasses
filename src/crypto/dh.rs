use crate::crypto::rng::CryptoRng;
use crate::error::Error;

use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

/// A singleton object representing the X25519 DH scheme
pub(crate) const X25519_IMPL: X25519 = X25519;

const X25519_POINT_SIZE: usize = 32;
const X25519_SCALAR_SIZE: usize = 32;

// We do not use the x25519_dalek DH API because the EphemeralSecret does not expose its internals.
// The MLS spec requires that we be able to create secrets from arbitrary bytestrings, and we can
// only do that if we can touch the buffer inside EphemeralSecret. So, we re-implement a small
// portion of the API here, without doing any actual crypto.
//
// NOTE: Although X25519Scalar can be initialized with arbitrary bytestrings, all scalars are
// clamped by x25519_dalek::x25519() before they are used. This is the only way in which scalars
// are used, and the structs do not implement Eq, so there's no fear of accidentally assuming
// unique representation of scalars.

/// An enum of possible types for a private DH value, depending on the underlying algorithm. In EC
/// terminology, this is a point on the curve. In finite-field terminology, this is an element of
/// the field.
pub(crate) enum DhScalar {
    /// A scalar value in Curve25519
    X25519Scalar([u8; X25519_SCALAR_SIZE]),
}

// opaque DHPublicKey<1..2^16-1>
/// Because these are untagged during serialization and deserialization, we can only represent
/// curve points as bytes, without any variant tag (such as X25519Scalar). So we use this type for
/// all DH stuff. I know, this sucks.
#[derive(Deserialize, Serialize)]
#[serde(rename = "DhPoint__bound_u16")]
pub(crate) struct DhPoint(Vec<u8>);

/// A trait representing any DH-like key-agreement algorithm. The notation it uses in documentation
/// is that of elliptic curves, but these concepts should generalize to finite-fields, SIDH, CSIDH,
/// etc.
pub(crate) trait DiffieHellman {
    // You may ask why this function isn't implemented as part of a serialization function for
    // DhPoint. That's because the byte representation of this here point is independent of the
    // wire format we choose. This representation is used in the calculation of ECIES ciphertexts,
    // which are computed independently of wire format.
    fn point_as_bytes(&self, point: DhPoint) -> Vec<u8>;

    fn point_from_bytes(&self, bytes: Vec<u8>) -> DhPoint;

    fn scalar_from_bytes(&self, bytes: &[u8]) -> Result<DhScalar, Error>;

    // This has to take a dyn CryptoRng because DiffieHellman is itself a trait object inside a
    // CipherSuite. Trait objects can't have associated types, associated constants, or generic
    // methods.
    fn scalar_from_random(&self, csprng: &mut dyn CryptoRng) -> Result<DhScalar, Error>;

    fn multiply_basepoint(&self, scalar: &DhScalar) -> DhPoint;

    fn diffie_hellman(&self, privkey: &DhScalar, pubkey: &DhPoint) -> DhPoint;
}

/// This represents the X25519 Diffie-Hellman key agreement protocol. Notably, it implements
/// `DiffieHellman`.
pub(crate) struct X25519;

// TODO: Urgent: Do the zero checks that the specification requires

impl DiffieHellman for X25519 {
    /// Outputs the internal byte representation of a given point
    fn point_as_bytes(&self, point: DhPoint) -> Vec<u8> {
        point.0
    }

    /// Makes a `DhPoint` from the given bytes
    ///
    /// Requires: `bytes.len() == X25519_POINT_SIZE == 32`
    fn point_from_bytes(&self, bytes: Vec<u8>) -> DhPoint {
        // This has to be the right length
        assert_eq!(bytes.len(), X25519_POINT_SIZE);
        DhPoint(bytes)
    }

    /// Uses the given bytes as a scalar in GF(2^(255) - 19)
    ///
    /// Requires: `bytes.len() == 32`
    ///
    /// Returns: `Ok(scalar)` on success. Otherwise, if `bytes.len() != 32`, returns
    /// `Error::DhError`.
    fn scalar_from_bytes(&self, bytes: &[u8]) -> Result<DhScalar, Error> {
        if bytes.len() != X25519_SCALAR_SIZE {
            return Err(Error::DhError("Wrong key size"));
        } else {
            let mut buf = [0u8; X25519_SCALAR_SIZE];
            buf.copy_from_slice(bytes);
            Ok(DhScalar::X25519Scalar(buf))
        }
    }

    /// Generates a random scalar value
    ///
    /// Returns: `Ok(scalar)` on success. Otherwise, if something goes wrong with the RNG, it
    /// returns `Error::OutOfEntropy`.
    fn scalar_from_random(&self, csprng: &mut dyn CryptoRng) -> Result<DhScalar, Error> {
        let mut buf = [0u8; X25519_SCALAR_SIZE];
        csprng
            .try_fill_bytes(&mut buf)
            .map_err(|_| Error::OutOfEntropy)?;
        Ok(DhScalar::X25519Scalar(buf))
    }

    /// Calculates `scalar * P`, where `P` is the standard X25519 basepoint. This function is used
    /// for creating public keys for DHE.
    fn multiply_basepoint(&self, scalar: &DhScalar) -> DhPoint {
        let scalar = enum_variant!(scalar, DhScalar::X25519Scalar);

        let point_bytes = x25519(*scalar, X25519_BASEPOINT_BYTES);
        self.point_from_bytes(point_bytes.to_vec())
    }

    /// Computes `privkey * Pubkey` where `privkey` is your local secret (a scalar) and `Pubkey` is
    /// someone's public key (a curve point)
    fn diffie_hellman(&self, privkey: &DhScalar, pubkey: &DhPoint) -> DhPoint {
        let privkey = enum_variant!(privkey, DhScalar::X25519Scalar);
        let pubkey = {
            let mut buf = [0u8; X25519_POINT_SIZE];
            buf.copy_from_slice(&pubkey.0);
            buf
        };

        let shared_secret = x25519(*privkey, pubkey);
        DhPoint(shared_secret.to_vec())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use quickcheck_macros::quickcheck;
    use rand_core::{RngCore, SeedableRng};

    // Diffie Hellman test vectors from https://tools.ietf.org/html/rfc7748#section-6.1
    #[test]
    fn x25519_kat() {
        let alice_scalar = {
            let hex_str = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
            let bytes = hex::decode(hex_str).unwrap();
            X25519_IMPL
                .scalar_from_bytes(&bytes)
                .expect("couldn't make scalar from bytes")
        };
        let bob_scalar = {
            let hex_str = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
            let bytes = hex::decode(hex_str).unwrap();
            X25519_IMPL
                .scalar_from_bytes(&bytes)
                .expect("couldn't make scalar from bytes")
        };

        // Compute aP and bP where a is Alice's scalar, and b is Bob's
        let alice_pubkey = X25519_IMPL.multiply_basepoint(&alice_scalar);
        let bob_pubkey = X25519_IMPL.multiply_basepoint(&bob_scalar);

        // Compute b(aP) and a(bP) and make sure they are the same
        let shared_secret_a = {
            let point = X25519_IMPL.diffie_hellman(&alice_scalar, &bob_pubkey);
            enum_variant!(point, DhPoint::X25519Point)
        };
        let shared_secret_b = {
            let point = X25519_IMPL.diffie_hellman(&bob_scalar, &alice_pubkey);
            enum_variant!(point, DhPoint::X25519Point)
        };

        let alice_pubkey = enum_variant!(alice_pubkey, DhPoint::X25519Point);
        let bob_pubkey = enum_variant!(bob_pubkey, DhPoint::X25519Point);

        // Known-answer for aP
        assert_eq!(
            hex::encode(&alice_pubkey),
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        );
        // Known-answer for bP
        assert_eq!(
            hex::encode(&bob_pubkey),
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
        );
        // Test b(aP) == a(bP)
        assert_eq!(shared_secret_a, shared_secret_b);
        // Known-answer for abP
        assert_eq!(
            hex::encode(shared_secret_a),
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        );
    }

    #[quickcheck]
    fn x25519_correctness(secret_seed: u64) {
        // Make a secret key seeded with the above seed. This is so that this function is
        // deterministic.
        let (scalar1, scalar2) = {
            let mut rng = rand::rngs::StdRng::seed_from_u64(secret_seed);
            let mut buf1 = [0u8; 32];
            let mut buf2 = [0u8; 32];
            rng.fill_bytes(&mut buf1);
            rng.fill_bytes(&mut buf2);
            (
                X25519_IMPL.scalar_from_bytes(&buf1).unwrap(),
                X25519_IMPL.scalar_from_bytes(&buf2).unwrap(),
            )
        };

        let (point1, point2) = (
            X25519_IMPL.multiply_basepoint(&scalar1),
            X25519_IMPL.multiply_basepoint(&scalar2),
        );
        let (shared1, shared2) = (
            X25519_IMPL.diffie_hellman(&scalar1, &point2),
            X25519_IMPL.diffie_hellman(&scalar2, &point1),
        );

        let shared1 = enum_variant!(shared1, DhPoint::X25519Point);
        let shared2 = enum_variant!(shared2, DhPoint::X25519Point);

        assert_eq!(shared1, shared2)
    }

    // This comes from
    // https://github.com/mlswg/mls-implementations/blob/master/test_vectors/treesnodes.md
    #[test]
    fn node_key_derivation_kat() {
        let scalar = {
            let hex_str = "e029fbe9de859e7bd6aea95ac258ae743a9eabccde9358420d8c975365938714";
            let bytes = hex::decode(hex_str).unwrap();
            X25519_IMPL
                .scalar_from_bytes(&bytes)
                .expect("couldn't make scalar from bytes")
        };

        let pubkey = X25519_IMPL.multiply_basepoint(&scalar);
        let pubkey = enum_variant!(pubkey, DhPoint::X25519Point);

        assert_eq!(
            hex::encode(&pubkey),
            "6667b1715a0ad45b0510e850322a8d471d4485ebcbfcc0f3bcce7bcae7b44f7f"
        );
    }
}
