// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: BSD-3-Clause-Clear

pub mod direct_product;

use core::fmt::Debug;
use core::iter;
use core::ops::{Add, AddAssign, Neg, Sub, SubAssign};

use crypto_bigint::{rand_core::CryptoRngCore, Uint};
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// An error in group element instantiation [`GroupElement::new()`]
#[derive(thiserror::Error, Clone, Debug, PartialEq)]
pub enum Error {
    #[error("unsupported public parameters: the implementation doesn't support the public parameters, whether or not it identifies a valid group.")]
    UnsupportedPublicParameters,

    #[error(
        "invalid public parameters: no valid group can be identified by the public parameters."
    )]
    InvalidPublicParameters,

    #[error("invalid group element: the value does not belong to the group identified by the public parameters.")]
    InvalidGroupElement,
}

/// The Result of the `new()` operation of types implementing the `GroupElement` trait
pub type Result<T> = std::result::Result<T, Error>;

/// An element of an abelian group, in additive notation.
///
/// Group operations are only valid between elements within the group (otherwise the result is
/// undefined.)
///
/// All group operations are guaranteed to be constant time
pub trait GroupElement:
    Neg<Output = Self>
    + Add<Self, Output = Self>
    + for<'r> Add<&'r Self, Output = Self>
    + Sub<Self, Output = Self>
    + for<'r> Sub<&'r Self, Output = Self>
    + AddAssign<Self>
    + for<'r> AddAssign<&'r Self>
    + SubAssign<Self>
    + for<'r> SubAssign<&'r Self>
    + Into<Self::Value>
    + Into<Self::PublicParameters>
    + Debug
    + PartialEq
    + Eq
    + Clone
{
    /// The actual value of the group point used for encoding/decoding.
    ///
    /// For some groups (e.g. `group::secp256k1::Secp256k1GroupElement`) the group parameters and
    /// equations are statically hard-coded into the code, and then they would have `Self::Value
    /// = Self`.
    ///
    /// However, other groups (e.g. `group::paillier::PaillierCiphertextGroupElement`) rely on
    /// dynamic values to determine group operations in runtime (like the Paillier modulus
    /// $N^2$).
    ///
    /// In those cases, it is both ineffecient communication-wise to serialize these statements
    /// as they are known by the deserializing side, and even worse it is a security risk as
    /// malicious actors could try and craft groups in which they can break security assumptions
    /// in order to e.g. bypass zk-proof verification and have the verifier use those groups.
    ///
    /// In order to mitigate these risks and save on communication, we separate the value of the
    /// point from the group parameters.
    type Value: Serialize
        + for<'r> Deserialize<'r>
        + Clone
        + Debug
        + PartialEq
        + Eq
        + ConstantTimeEq
        + ConditionallySelectable
        + Copy;

    /// Returns the value of this group element
    fn value(&self) -> Self::Value {
        self.clone().into()
    }

    /// The public parameters of the group, used for group operations.
    ///
    /// These include both dynamic information for runtime calculations
    /// (that provides the required context for `Self::new()` alongside the `Self::Value` to
    /// instantiate a `GroupElement`), as well as static information hardcoded into the code
    /// (that, together with the dynamic information, uniquely identifies a group and will be used
    /// for Fiat-Shamir Transcripts).
    type PublicParameters: Serialize + for<'r> Deserialize<'r> + Clone + PartialEq + Debug;

    /// Returns the public parameters of this group element
    fn public_parameters(&self) -> Self::PublicParameters {
        self.clone().into()
    }

    /// Instantiate the group element from its value and the caller supplied parameters.
    ///
    /// *** NOTICE ***: `Self::new()` must check that the
    /// `value` belongs to the group identified by `params` and return an error otherwise!
    ///
    /// Even for static groups where `Self::Value = Self`, it must be assured the value is an
    /// element of the group either here or in deserialization.
    fn new(value: Self::Value, public_parameters: &Self::PublicParameters) -> Result<Self>;

    /// Returns the additive identity, also known as the "neutral element".
    fn neutral(&self) -> Self;

    /// Determines if this point is the identity in constant-time.
    fn is_neutral(&self) -> Choice {
        self.value().ct_eq(&self.neutral().value())
    }

    /// Constant-time Multiplication by (any bounded) natural number (scalar)
    fn scalar_mul<const LIMBS: usize>(&self, scalar: &Uint<LIMBS>) -> Self;

    /// Constant-time Multiplication by (any bounded) natural number (scalar),     
    /// with `scalar_bits` representing the number of (least significant) bits
    /// to take into account for the scalar.
    ///
    /// NOTE: `scalar_bits` may be leaked in the time pattern.
    fn scalar_mul_bounded<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        scalar_bits: usize,
    ) -> Self {
        // A bench implementation for groups whose underlying implementation does not expose a
        // bounded multiplication function, and operates in constant-time. This implementation
        // simply assures that the only the required bits out of the multiplied value is taken; this
        // is a correctness adaptation and not a performance one.

        // First take only the `scalar_bits` least significant bits
        let mask = (Uint::<LIMBS>::ONE << scalar_bits).wrapping_sub(&Uint::<LIMBS>::ONE);
        let scalar = scalar & mask;

        // Call the underlying scalar mul function, which now only use the `scalar_bits` least
        // significant bits, but will still take the same time to compute due to
        // constant-timeness.
        self.scalar_mul(&scalar)
    }

    /// Double this point in constant-time.
    #[must_use]
    fn double(&self) -> Self;
}

pub type Value<G> = <G as GroupElement>::Value;

pub type PublicParameters<G> = <G as GroupElement>::PublicParameters;

/// A marker-trait for  element of an abelian group of bounded (by `Uint<SCALAR_LIMBS>::MAX`) order,
/// in additive notation.
pub trait BoundedGroupElement<const SCALAR_LIMBS: usize>: GroupElement {}

pub trait Samplable: GroupElement {
    /// Uniformly sample a random element.
    fn sample(
        public_parameters: &Self::PublicParameters,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self>;

    /// Uniformly sample a batch of random elements.
    fn sample_batch(
        public_parameters: &Self::PublicParameters,
        batch_size: usize,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<Self>> {
        iter::repeat_with(|| Self::sample(public_parameters, rng))
            .take(batch_size)
            .collect()
    }
}
