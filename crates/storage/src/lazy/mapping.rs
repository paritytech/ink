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

//! A simple mapping to contract storage.
//!
//! # Note
//!
//! This mapping doesn't actually "own" any data.
//! Instead it is just a simple wrapper around the contract storage facilities.

use crate::traits::{
    AtomicGuard,
    AutoKey,
    StorageKeyHolder,
    StorageType,
};
use core::marker::PhantomData;
use ink_env::hash::{
    Blake2x256,
    HashOutput,
};
use ink_primitives::{
    Key,
    StorageKey,
};
use scale::{
    Decode,
    Encode,
    Error,
    Input,
    Output,
};

/// A mapping of key-value pairs directly into contract storage.
///
/// # Important
///
/// The mapping requires its own pre-defined storage key where to store values. By default,
/// it is [`AutoKey`](crate::traits::AutoKey) and during compilation is calculated based on
/// the name of the structure and the field. But anyone can specify its storage key
/// via [`ManualKey`](crate::traits::ManualKey).
///
/// This is an example of how you can do this:
/// ```rust
/// # use ink_lang as ink;
/// # use ink_env::{
/// #     Environment,
/// #     DefaultEnvironment,
/// # };
/// # type AccountId = <DefaultEnvironment as Environment>::AccountId;
///
/// # #[ink::contract]
/// # mod my_module {
/// use ink_storage::{traits::ManualKey, Mapping};
///
/// #[ink(storage)]
/// #[derive(Default)]
/// pub struct MyContract {
///     balances: Mapping<AccountId, Balance>,
///     allowance: Mapping<AccountId, Balance, ManualKey<123>>,
/// }
///
/// impl MyContract {
///     #[ink(constructor)]
///     pub fn new() -> Self {
///         let mut instance = Self::default();
///         instance.new_init();
///         instance
///     }
///
///     /// Default initializes the contract.
///     fn new_init(&mut self) {
///         let caller = Self::env().caller();
///         let value: Balance = Default::default();
///         self.balances.insert(&caller, &value);
///     }
///
/// #   #[ink(message)]
/// #   pub fn my_message(&self) { }
/// }
/// # }
/// ```
///
/// More usage examples can be found [in the ink! examples](https://github.com/paritytech/ink/tree/master/examples).
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub struct Mapping<K, V: AtomicGuard<true>, KeyType: StorageKeyHolder = AutoKey> {
    #[allow(clippy::type_complexity)]
    _marker: PhantomData<fn() -> (K, V, KeyType)>,
}

/// We implement this manually because the derived implementation adds trait bounds.
impl<K, V, KeyType> Default for Mapping<K, V, KeyType>
where
    V: AtomicGuard<true>,
    KeyType: StorageKeyHolder,
{
    fn default() -> Self {
        Self {
            _marker: Default::default(),
        }
    }
}

impl<K, V, KeyType> Mapping<K, V, KeyType>
where
    V: AtomicGuard<true>,
    KeyType: StorageKeyHolder,
{
    /// Creates a new empty `Mapping`.
    pub fn new() -> Self {
        Self {
            _marker: Default::default(),
        }
    }
}

impl<K, V, KeyType> ::core::fmt::Debug for Mapping<K, V, KeyType>
where
    V: AtomicGuard<true>,
    KeyType: StorageKeyHolder,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("Mapping")
            .field("storage_key", &KeyType::KEY)
            .finish()
    }
}

impl<K, V, KeyType> Mapping<K, V, KeyType>
where
    K: Encode,
    V: AtomicGuard<true> + Encode + Decode,
    KeyType: StorageKeyHolder,
{
    /// Insert the given `value` to the contract storage.
    #[inline]
    pub fn insert<Q, R>(&mut self, key: Q, value: &R)
    where
        Q: scale::EncodeLike<K>,
        R: scale::EncodeLike<V>,
    {
        ink_env::set_contract_storage(&self.storage_key(&key), value);
    }

    /// Insert the given `value` to the contract storage.
    ///
    /// Returns the size of the pre-existing value at the specified key if any.
    #[inline]
    pub fn insert_return_size<Q, R>(&mut self, key: Q, value: &R) -> Option<u32>
    where
        Q: scale::EncodeLike<K>,
        R: scale::EncodeLike<V>,
    {
        ink_env::set_contract_storage(&self.storage_key(&key), value)
    }

    /// Get the `value` at `key` from the contract storage.
    ///
    /// Returns `None` if no `value` exists at the given `key`.
    #[inline]
    pub fn get<Q>(&self, key: Q) -> Option<V>
    where
        Q: scale::EncodeLike<K>,
    {
        let root_key = self.storage_key(&key);
        ink_env::get_contract_storage::<V>(&root_key).unwrap_or_else(|error| {
            panic!(
                "failed to get packed from root key {}: {:?}",
                root_key, error
            )
        })
    }

    /// Get the size of a value stored at `key` in the contract storage.
    ///
    /// Returns `None` if no `value` exists at the given `key`.
    #[inline]
    pub fn size<Q>(&self, key: Q) -> Option<u32>
    where
        Q: scale::EncodeLike<K>,
    {
        ink_env::contract_storage_contains(&self.storage_key(&key))
    }

    /// Checks if a value is stored at the given `key` in the contract storage.
    ///
    /// Returns `None` if no `value` exists at the given `key`.
    #[inline]
    pub fn contains<Q>(&self, key: Q) -> bool
    where
        Q: scale::EncodeLike<K>,
    {
        ink_env::contract_storage_contains(&self.storage_key(&key)).is_some()
    }

    /// Clears the value at `key` from storage.
    pub fn remove<Q>(&self, key: Q)
    where
        Q: scale::EncodeLike<K>,
    {
        ink_env::clear_contract_storage(&self.storage_key(&key));
    }

    /// Returns a `Key` pointer used internally by the storage API.
    ///
    /// This key is a combination of the `Mapping`'s internal `offset_key`
    /// and the user provided `key`.
    fn storage_key<Q>(&self, key: &Q) -> Key
    where
        Q: scale::EncodeLike<K>,
    {
        let encodedable_key = (key, &KeyType::KEY);
        let mut output = <Blake2x256 as HashOutput>::Type::default();
        ink_env::hash_encoded::<Blake2x256, _>(&encodedable_key, &mut output);
        output.into()
    }
}

impl<K, V, Salt, InnerSalt> StorageType<Salt> for Mapping<K, V, InnerSalt>
where
    V: AtomicGuard<true>,
    Salt: StorageKeyHolder,
    InnerSalt: StorageKeyHolder,
{
    type Type = Mapping<K, V, Salt>;
    type PreferredKey = InnerSalt;
}

impl<K, V, KeyType> Encode for Mapping<K, V, KeyType>
where
    V: AtomicGuard<true>,
    KeyType: StorageKeyHolder,
{
    fn encode_to<T: Output + ?Sized>(&self, _dest: &mut T) {}
}

impl<K, V, KeyType> Decode for Mapping<K, V, KeyType>
where
    V: AtomicGuard<true>,
    KeyType: StorageKeyHolder,
{
    fn decode<I: Input>(_input: &mut I) -> Result<Self, Error> {
        Ok(Default::default())
    }
}

impl<K, V, KeyType> StorageKeyHolder for Mapping<K, V, KeyType>
where
    V: AtomicGuard<true>,
    KeyType: StorageKeyHolder,
{
    const KEY: StorageKey = KeyType::KEY;
}

#[cfg(feature = "std")]
const _: () = {
    use crate::traits::StorageLayout;
    use ink_metadata::layout::{
        Layout,
        LayoutKey,
        RootLayout,
    };

    impl<K, V, KeyType> StorageLayout for Mapping<K, V, KeyType>
    where
        K: scale_info::TypeInfo + 'static,
        V: AtomicGuard<true> + StorageLayout + scale_info::TypeInfo + 'static,
        KeyType: StorageKeyHolder + scale_info::TypeInfo + 'static,
    {
        fn layout(_: &StorageKey) -> Layout {
            Layout::Root(RootLayout::new(
                LayoutKey::from(&KeyType::KEY),
                <V as StorageLayout>::layout(&KeyType::KEY),
            ))
        }
    }
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_get_work() {
        ink_env::test::run_test::<ink_env::DefaultEnvironment, _>(|_| {
            let mut mapping: Mapping<u8, _> = Mapping::new();
            mapping.insert(&1, &2);
            assert_eq!(mapping.get(&1), Some(2));

            Ok(())
        })
        .unwrap()
    }

    #[test]
    fn gets_default_if_no_key_set() {
        ink_env::test::run_test::<ink_env::DefaultEnvironment, _>(|_| {
            let mapping: Mapping<u8, u8> = Mapping::new();
            assert_eq!(mapping.get(&1), None);

            Ok(())
        })
        .unwrap()
    }

    #[test]
    fn can_clear_entries() {
        ink_env::test::run_test::<ink_env::DefaultEnvironment, _>(|_| {
            // Given
            let mut mapping: Mapping<u8, u8> = Mapping::new();

            mapping.insert(&1, &2);
            assert_eq!(mapping.get(&1), Some(2));

            // When
            mapping.remove(&1);

            // Then
            assert_eq!(mapping.get(&1), None);

            Ok(())
        })
        .unwrap()
    }

    #[test]
    fn can_clear_unexistent_entries() {
        ink_env::test::run_test::<ink_env::DefaultEnvironment, _>(|_| {
            // Given
            let mapping: Mapping<u8, u8> = Mapping::new();

            // When
            mapping.remove(&1);

            // Then
            assert_eq!(mapping.get(&1), None);

            Ok(())
        })
        .unwrap()
    }
}
