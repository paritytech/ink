// Copyright 2018-2022 Parity Technologies (UK) Ltd.
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

//! Utilities in use by ink!.
//!
//! These are kept separate from ink! core utilities to allow for more dynamic inter-crate dependencies.
//! The main problem is that today Cargo manages crate features on a per-crate basis instead of
//! a per-crate-target basis thus making dependencies from `ink` (or others) to `ink_env` or `ink_storage` impossible.
//!
//! By introducing `ink_primitives` we have a way to share utility components between `ink_env` or `ink_storage` and
//! other parts of the framework, like `ink`.

#![doc(
    html_logo_url = "https://use.ink/img/crate-docs/logo.png",
    html_favicon_url = "https://use.ink/crate-docs/favicon.png"
)]
#![cfg_attr(not(feature = "std"), no_std)]

mod key;
mod types;

pub use self::{
    key::{
        Key,
        KeyComposer,
    },
    types::{
        AccountId,
        Clear,
        Hash,
    },
};

/// An error emitted by the smart contracting language.
///
/// This is different than errors from:
/// - Errors from the contract, which are programmer defined
/// - Errors from the underlying execution environment (e.g `pallet-contracts`)
#[non_exhaustive]
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, ::scale::Encode, ::scale::Decode)]
#[cfg_attr(feature = "std", derive(::scale_info::TypeInfo))]
pub enum LangError {
    /// Failed to read execution input for the dispatchable.
    CouldNotReadInput = 1u32,
}

/// The `Result` type for ink! messages.
#[doc(hidden)]
pub type MessageResult<T> = ::core::result::Result<T, LangError>;
