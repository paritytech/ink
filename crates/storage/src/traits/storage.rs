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

use core::{
    fmt::Debug,
    marker::PhantomData,
};
use ink_primitives::StorageKey;

/// Returns storage key for the type
pub trait StorageKeyHolder {
    /// Storage key
    const KEY: StorageKey;
}

/// `AtomicGuard<true>` is automatically implemented for all primitive types and atomic structures.
/// It can be used to add requirement for the generic to be atomic.
///
/// `AtomicGuard<false>` is useless bound because every type can implements it without any restriction.
pub trait AtomicGuard<const IS_ATOMIC: bool> {}

/// Returns the type that should be used for storing the value
pub trait StorageType<Salt: StorageKeyHolder> {
    /// Type with storage key inside
    type Type;
}

/// That key type means that the storage key should be calculated automatically.
#[derive(Default, Copy, Clone, PartialEq, PartialOrd, Debug)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub struct AutoKey;

impl StorageKeyHolder for AutoKey {
    const KEY: StorageKey = 0;
}

/// That key type specifies the storage key.
#[derive(Default, Copy, Clone, PartialEq, PartialOrd, Debug)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub struct ManualKey<const KEY: StorageKey, Salt: StorageKeyHolder = ()>(
    PhantomData<fn() -> Salt>,
);

impl<const KEY: StorageKey, Salt: StorageKeyHolder> StorageKeyHolder
    for ManualKey<KEY, Salt>
{
    // TODO: Use XoR here or better to calculate const hash during compilation?
    const KEY: StorageKey = KEY ^ Salt::KEY;
}
