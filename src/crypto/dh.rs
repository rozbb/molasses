use crate::error::Error;

use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

const X25519_POINT_SIZE: usize = 32;
const X25519_SCALAR_SIZE: usize = 32;

/// A trait representing any DH-like key-agreement algorithm. The notation it uses in documentation
/// is that of elliptic curves, but these concepts should generalize to finite-fields, SIDH, CSIDH,
/// etc.
pub(crate) trait DiffieHellman {
    /// The type of a public value. In EC terminology, this is a scalar in the base field. In
    /// finite-field terminology, this is an exponent.
    type Scalar;
    /// The type of a private value. In EC terminology, this is a point on the curve. In
    /// finite-field terminology, this is an element of the field.
    type Point;

    // TODO: Once it's possible to do so, I want to return [u8; Self::POINT_SIZE]. This is
    // blocked on https://github.com/rust-lang/rust/issues/39211

    // You may ask why this function isn't implemented as part of a serialization function for
    // Self::Point. That's because the byte representation of this here point is independent of the
    // wire format we choose. This representation is used in the calculation of ECIES ciphertexts,
    // which are computed independently of wire format.
    fn point_as_bytes(point: &Self::Point) -> Vec<u8>;

    fn scalar_from_bytes(bytes: &[u8]) -> Result<Self::Scalar, Error>;

    fn scalar_from_random<T>(csprng: &mut T) -> Result<Self::Scalar, Error>
    where
        T: rand::Rng + rand::CryptoRng;

    fn multiply_basepoint(scalar: &Self::Scalar) -> Self::Point;

    fn diffie_hellman(privkey: &Self::Scalar, pubkey: &Self::Point) -> Self::Point;
}

// We do not use the x25519_dalek DH API because the EphemeralSecret does not expose its internals.
// The MLS spec requires that we be able to create secrets from arbitrary bytestrings, and we can
// only do that if we can touch the buffer inside EphemeralSecret. So, we re-implement a small
// portion of the API here, without doing any actual crypto.
//
// NOTE: Although X25519Scalar can be initiated with arbitrary bytestrings, all scalars are clamped
// by x25519_dalek::x25519() before they are used. This is the only way in which scalars are used,
// and the structs do not implement Eq, so there's no fear of accidentally assuming unique
// representation of scalars.

/// This represents the X25519 Diffie-Hellman key agreement protocol. Notably, it implements
/// `DiffieHellman`.
pub(crate) struct X25519;
/// A scalar value in Curve25519
pub(crate) struct X25519Scalar([u8; X25519_SCALAR_SIZE]);
/// A curve point in Curve25519
pub(crate) struct X25519Point([u8; X25519_POINT_SIZE]);

// TODO: Urgent: Do the zero checks that the specification requires

impl DiffieHellman for X25519 {
    type Scalar = X25519Scalar;
    type Point = X25519Point;

    /// Outputs the internal byte representation of a given point
    fn point_as_bytes(point: &Self::Point) -> Vec<u8> {
        point.0.to_vec()
    }

    /// Uses the given bytes as a scalar in GF(2^(255) - 19)
    ///
    /// Requires: `bytes.len() == 32`
    ///
    /// Returns: `Ok(scalar)` on success. Otherwise, if `bytes.len() != 32`, returns
    /// `Error::DHError`.
    fn scalar_from_bytes(bytes: &[u8]) -> Result<X25519Scalar, Error> {
        if bytes.len() != X25519_SCALAR_SIZE {
            return Err(Error::DHError("Wrong key size"));
        } else {
            let mut buf = [0u8; X25519_SCALAR_SIZE];
            buf.copy_from_slice(bytes);
            Ok(X25519Scalar(buf))
        }
    }

    /// Generates a random scalar value
    ///
    /// Returns: `Ok(scalar)` on success. Otherwise, if something goes wrong with the RNG, it
    /// returns `Error::OutOfEntropy`.
    fn scalar_from_random<T>(csprng: &mut T) -> Result<Self::Scalar, Error>
    where
        T: rand::Rng + rand::CryptoRng,
    {
        let mut buf = [0u8; X25519_SCALAR_SIZE];
        csprng.try_fill(&mut buf).map_err(|_| Error::OutOfEntropy)?;
        Ok(X25519Scalar(buf))
    }

    /// Calculates `scalar * P`, where `P` is the standard X25519 basepoint. This function is used
    /// for creating public keys for DHE.
    fn multiply_basepoint(scalar: &X25519Scalar) -> X25519Point {
        let point_bytes = x25519(scalar.0, X25519_BASEPOINT_BYTES);
        X25519Point(point_bytes)
    }

    /// Computes `privkey * Pubkey` where `privkey` is your local secret (a scalar) and `Pubkey` is
    /// someone's public key (a curve point)
    fn diffie_hellman(privkey: &X25519Scalar, pubkey: &X25519Point) -> X25519Point {
        let shared_secret = x25519(privkey.0, pubkey.0);
        X25519Point(shared_secret)
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
            X25519::scalar_from_bytes(&bytes).expect("couldn't make scalar from bytes")
        };
        let bob_scalar = {
            let hex_str = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
            let bytes = hex::decode(hex_str).unwrap();
            X25519::scalar_from_bytes(&bytes).expect("couldn't make scalar from bytes")
        };

        // Compute aP and bP where a is Alice's scalar, and b is Bob's
        let alice_pubkey = X25519::multiply_basepoint(&alice_scalar);
        let bob_pubkey = X25519::multiply_basepoint(&bob_scalar);

        // Compute b(aP) and a(bP) and make sure they are the same
        let shared_secret_a = X25519::diffie_hellman(&alice_scalar, &bob_pubkey);
        let shared_secret_b = X25519::diffie_hellman(&bob_scalar, &alice_pubkey);

        // Known-answer for aP
        assert_eq!(
            hex::encode(&alice_pubkey.0),
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        );
        // Known-answer for bP
        assert_eq!(
            hex::encode(&bob_pubkey.0),
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
        );
        // Test b(aP) == a(bP)
        assert_eq!(shared_secret_a.0, shared_secret_b.0);
        // Known-answer for abP
        assert_eq!(
            hex::encode(shared_secret_a.0),
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
                X25519::scalar_from_bytes(&buf1).unwrap(),
                X25519::scalar_from_bytes(&buf2).unwrap(),
            )
        };

        let (point1, point2) = (
            X25519::multiply_basepoint(&scalar1),
            X25519::multiply_basepoint(&scalar2),
        );
        let (shared1, shared2) = (
            X25519::diffie_hellman(&scalar1, &point2),
            X25519::diffie_hellman(&scalar2, &point1),
        );

        assert_eq!(&shared1.0, &shared2.0)
    }

    // This comes from
    // https://github.com/mlswg/mls-implementations/blob/master/test_vectors/treesnodes.md
    #[test]
    fn node_key_derivation_kat() {
        let scalar = {
            let hex_str = "e029fbe9de859e7bd6aea95ac258ae743a9eabccde9358420d8c975365938714";
            let bytes = hex::decode(hex_str).unwrap();
            X25519::scalar_from_bytes(&bytes).expect("couldn't make scalar from bytes")
        };

        let pubkey = X25519::multiply_basepoint(&scalar);

        assert_eq!(
            hex::encode(pubkey.0),
            "6667b1715a0ad45b0510e850322a8d471d4485ebcbfcc0f3bcce7bcae7b44f7f"
        );
    }
}
