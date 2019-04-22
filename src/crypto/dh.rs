use crate::crypto::rng::CryptoRng;
use crate::error::Error;

/// A singleton object representing the X25519 DH scheme
pub(crate) const X25519_IMPL: X25519 = X25519;

pub(crate) const P256_IMPL: DummyP256 = DummyP256;

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
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename = "DhPublicKeyRaw__bound_u16")]
pub(crate) struct DhPublicKeyRaw(pub(crate) Vec<u8>);

/// An enum of possible types for a public DH value, depending on the underlying algorithm. In EC
/// terminology, this is a point on the curve. In finite-field terminology, this is a field
/// element. The `Raw` variant only gets instantiated at the serialization/deserialization
/// boundary, and should never be dealt with directly. The `CryptoUpcast` trait should take care of
/// this.
#[derive(Clone, Debug)]
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
}

/// A trait representing any DH-like key-agreement algorithm. The notation it uses in documentation
/// is that of elliptic curves, but these concepts should generalize to finite-fields, SIDH, CSIDH,
/// etc.
pub(crate) trait DiffieHellman {
    fn public_key_from_bytes(&self, bytes: &[u8]) -> Result<DhPublicKey, Error>;

    fn private_key_from_bytes(&self, bytes: &[u8]) -> Result<DhPrivateKey, Error>;

    // This has to take a dyn CryptoRng because DiffieHellman is itself a trait object inside a
    // CipherSuite. Trait objects can't have associated types, associated constants, or generic
    // methods.
    fn scalar_from_random(&self, csprng: &mut dyn CryptoRng) -> Result<DhPrivateKey, Error>;

    fn derive_public_key(&self, scalar: &DhPrivateKey) -> DhPublicKey;

    fn diffie_hellman(&self, privkey: &DhPrivateKey, pubkey: &DhPublicKey) -> DhSharedSecret;
}

/// This represents the X25519 Diffie-Hellman key agreement protocol. Notably, it implements
/// `DiffieHellman`.
pub(crate) struct X25519;

// TODO: Urgent: Do the zero checks that the specification requires
// TODO: Change "point" to "public key" and "scalar" to "private key"

impl DiffieHellman for X25519 {
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

    /// Uses the given bytes as a scalar in GF(2^255 - 19)
    ///
    /// Requires: `bytes.len() == 32`
    ///
    /// Returns: `Ok(scalar)` on success. Otherwise, if `bytes.len() != 32`, returns
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

    /// Generates a random scalar value
    ///
    /// Returns: `Ok(scalar)` on success. Otherwise, if something goes wrong with the RNG, it
    /// returns `Error::OutOfEntropy`.
    fn scalar_from_random(&self, csprng: &mut dyn CryptoRng) -> Result<DhPrivateKey, Error> {
        let mut box_rng = Box::new(csprng);
        Ok(DhPrivateKey::X25519PrivateKey(x25519_dalek::StaticSecret::new(&mut box_rng)))
    }

    /// Calculates `scalar * P`, where `P` is the standard X25519 basepoint. This function is used
    /// for creating public keys for DHE.
    fn derive_public_key(&self, scalar: &DhPrivateKey) -> DhPublicKey {
        let scalar = enum_variant!(scalar, DhPrivateKey::X25519PrivateKey);
        let public_key: x25519_dalek::PublicKey = scalar.into();
        DhPublicKey::X25519PublicKey(public_key)
    }

    /// Computes `privkey * Pubkey` where `privkey` is your local secret (a scalar) and `Pubkey` is
    /// someone's public key (a curve point)
    fn diffie_hellman(&self, privkey: &DhPrivateKey, pubkey: &DhPublicKey) -> DhSharedSecret {
        let privkey = enum_variant!(privkey, DhPrivateKey::X25519PrivateKey);
        let pubkey = enum_variant!(pubkey, DhPublicKey::X25519PublicKey);

        let ss = privkey.diffie_hellman(&pubkey);
        DhSharedSecret::X25519SharedSecret(ss)
    }
}

pub(crate) struct DummyP256;

impl DiffieHellman for DummyP256 {
    fn public_key_from_bytes(&self, bytes: &[u8]) -> Result<DhPublicKey, Error> {
        if bytes.len() != 65 {
            Err(Error::DhError("P256 DH public key isn't 65 bytes long"))
        } else {
            let raw = DhPublicKeyRaw(bytes.to_vec());
            Ok(DhPublicKey::Raw(raw))
        }
    }

    fn private_key_from_bytes(&self, _bytes: &[u8]) -> Result<DhPrivateKey, Error> {
        unimplemented!()
    }

    // This has to take a dyn CryptoRng because DiffieHellman is itself a trait object inside a
    // CipherSuite. Trait objects can't have associated types, associated constants, or generic
    // methods.
    fn scalar_from_random(&self, _csprng: &mut dyn CryptoRng) -> Result<DhPrivateKey, Error> {
        unimplemented!()
    }

    fn derive_public_key(&self, _scalar: &DhPrivateKey) -> DhPublicKey {
        unimplemented!()
    }

    fn diffie_hellman(&self, _privkey: &DhPrivateKey, _pubkey: &DhPublicKey) -> DhSharedSecret {
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
        let alice_scalar = {
            let hex_str = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
            let bytes = hex::decode(hex_str).unwrap();
            X25519_IMPL.private_key_from_bytes(&bytes).expect("couldn't make scalar from bytes")
        };
        let bob_scalar = {
            let hex_str = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
            let bytes = hex::decode(hex_str).unwrap();
            X25519_IMPL.private_key_from_bytes(&bytes).expect("couldn't make scalar from bytes")
        };

        // Compute aP and bP where a is Alice's scalar, and b is Bob's
        let alice_pubkey = X25519_IMPL.derive_public_key(&alice_scalar);
        let bob_pubkey = X25519_IMPL.derive_public_key(&bob_scalar);

        // Compute b(aP) and a(bP) and make sure they are the same
        let shared_secret_a = X25519_IMPL.diffie_hellman(&alice_scalar, &bob_pubkey);
        let shared_secret_b = X25519_IMPL.diffie_hellman(&bob_scalar, &alice_pubkey);

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
        // Make a secret key seeded with the above seed. This is so that this function is
        // deterministic.
        let (scalar1, scalar2) = {
            let mut rng = rand::rngs::StdRng::seed_from_u64(secret_seed);
            let mut buf1 = [0u8; 32];
            let mut buf2 = [0u8; 32];
            rng.fill_bytes(&mut buf1);
            rng.fill_bytes(&mut buf2);
            (
                X25519_IMPL.private_key_from_bytes(&buf1).unwrap(),
                X25519_IMPL.private_key_from_bytes(&buf2).unwrap(),
            )
        };

        let (point1, point2) =
            (X25519_IMPL.derive_public_key(&scalar1), X25519_IMPL.derive_public_key(&scalar2));
        let (shared1, shared2) = (
            X25519_IMPL.diffie_hellman(&scalar1, &point2),
            X25519_IMPL.diffie_hellman(&scalar2, &point1),
        );

        assert_eq!(shared1.as_bytes(), shared2.as_bytes());
    }

    // This comes from
    // https://github.com/mlswg/mls-implementations/blob/master/test_vectors/treesnodes.md
    #[test]
    fn node_key_derivation_kat() {
        let scalar = {
            let hex_str = "e029fbe9de859e7bd6aea95ac258ae743a9eabccde9358420d8c975365938714";
            let bytes = hex::decode(hex_str).unwrap();
            X25519_IMPL.private_key_from_bytes(&bytes).expect("couldn't make scalar from bytes")
        };

        let pubkey = X25519_IMPL.derive_public_key(&scalar);

        assert_eq!(
            hex::encode(pubkey.as_bytes()),
            "6667b1715a0ad45b0510e850322a8d471d4485ebcbfcc0f3bcce7bcae7b44f7f"
        );
    }
}
