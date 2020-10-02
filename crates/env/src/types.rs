// Copyright 2018-2020 Parity Technologies (UK) Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Types for the default environment.
//!
//! These are simple mirrored types from the default substrate FRAME configuration.
//! Their interfaces and functionality might not be complete.
//!
//! Users are required to provide their own type definitions and `EnvTypes`
//! implementations in order to write ink! contracts for other chain configurations.
//!
//! # Note
//!
//! When authoring a contract, the concrete `EnvTypes` are available via aliases
//! generated by the `lang` macro. Therefore all functionality of the concrete
//! types is accessible in the contract, not constrained by the required trait
//! bounds.
//!
//! Outside of the contract and its tests (e.g. in the offchain environment), where
//! there is no knowledge of the concrete types, the functionality is restricted to
//! the trait bounds on the `EnvTypes` trait types.

use super::arithmetic::AtLeast32BitUnsigned;
use core::{
    array::TryFromSliceError,
    convert::TryFrom,
};
use derive_more::From;
use scale::{
    Decode,
    Encode,
};
#[cfg(feature = "std")]
use scale_info::TypeInfo;

/// The environmental types usable by contracts defined with ink!.
pub trait EnvTypes {
    /// The maximum number of supported event topics provided by the runtime.
    ///
    /// The value must match the maximum number of supported event topics of the used runtime.
    const MAX_EVENT_TOPICS: usize;

    /// The type of an address.
    type AccountId: 'static + scale::Codec + Clone + PartialEq + Eq + Ord;

    /// The type of balances.
    type Balance: 'static
        + scale::Codec
        + Copy
        + Clone
        + PartialEq
        + Eq
        + AtLeast32BitUnsigned;

    /// The type of hash.
    type Hash: 'static
        + scale::Codec
        + Copy
        + Clone
        + Clear
        + PartialEq
        + Eq
        + Ord
        + AsRef<[u8]>
        + AsMut<[u8]>;

    /// The type of timestamps.
    type Timestamp: 'static
        + scale::Codec
        + Copy
        + Clone
        + PartialEq
        + Eq
        + AtLeast32BitUnsigned;

    /// The type of block number.
    type BlockNumber: 'static
        + scale::Codec
        + Copy
        + Clone
        + PartialEq
        + Eq
        + AtLeast32BitUnsigned;
}

/// Implemented by event types to communicate their topic hashes.
pub trait Topics<T>
where
    T: EnvTypes,
{
    /// Returns the topic hashes of `self`.
    ///
    /// The length of the slice must be less than or equal to `<T as EvnTypes>::MAX_EVENT_TOPICS`.
    fn topics(&self) -> &'static [<T as EnvTypes>::Hash];
}

/// The fundamental types of the default configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(TypeInfo))]
pub enum DefaultEnvTypes {}

impl EnvTypes for DefaultEnvTypes {
    const MAX_EVENT_TOPICS: usize = 4;

    type AccountId = AccountId;
    type Balance = Balance;
    type Hash = Hash;
    type Timestamp = Timestamp;
    type BlockNumber = BlockNumber;
}

/// The default balance type.
pub type Balance = u128;

/// The default timestamp type.
pub type Timestamp = u64;

/// The default block number type.
pub type BlockNumber = u64;

/// The default environment `AccountId` type.
///
/// # Note
///
/// This is a mirror of the `AccountId` type used in the default configuration
/// of PALLET contracts.
#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    Ord,
    PartialOrd,
    Hash,
    Encode,
    Decode,
    From,
    Default,
)]
#[cfg_attr(feature = "std", derive(TypeInfo))]
pub struct AccountId([u8; 32]);

impl<'a> TryFrom<&'a [u8]> for AccountId {
    type Error = TryFromSliceError;

    fn try_from(bytes: &'a [u8]) -> Result<Self, TryFromSliceError> {
        let address = <[u8; 32]>::try_from(bytes)?;
        Ok(Self(address))
    }
}

/// The default environment `Hash` type.
///
/// # Note
///
/// This is a mirror of the `Hash` type used in the default configuration
/// of PALLET contracts.
#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    Ord,
    PartialOrd,
    Hash,
    Encode,
    Decode,
    From,
    Default,
)]
#[cfg_attr(feature = "std", derive(TypeInfo))]
pub struct Hash([u8; 32]);

impl<'a> TryFrom<&'a [u8]> for Hash {
    type Error = TryFromSliceError;

    fn try_from(bytes: &'a [u8]) -> Result<Self, TryFromSliceError> {
        let address = <[u8; 32]>::try_from(bytes)?;
        Ok(Self(address))
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl AsMut<[u8]> for Hash {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0[..]
    }
}

/// The equivalent of `Zero` for hashes.
///
/// A hash that consists only of 0 bits is clear.
pub trait Clear {
    /// Returns `true` if the hash is clear.
    fn is_clear(&self) -> bool;

    /// Returns a clear hash.
    fn clear() -> Self;
}

impl Clear for [u8; 32] {
    fn is_clear(&self) -> bool {
        self.as_ref().iter().all(|&byte| byte == 0x00)
    }

    fn clear() -> Self {
        [0x00; 32]
    }
}

impl Clear for Hash {
    fn is_clear(&self) -> bool {
        self.as_ref().iter().all(|&byte| byte == 0x00)
    }

    fn clear() -> Self {
        Self([0x00; 32])
    }
}
