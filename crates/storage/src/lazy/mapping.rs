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
use ink_primitives::Key;
use scale::{
    Decode,
    Encode,
    Error,
    Input,
    Output,
};

/// TODO: Add comment
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub struct Mapping<K, V: AtomicGuard<true>, KeyType: StorageKeyHolder = AutoKey> {
    _marker: PhantomData<fn() -> (K, V, KeyType)>,
}

/// We implement this manually because the derived implementation adds trait bounds.
impl<K, V: AtomicGuard<true>, KeyType: StorageKeyHolder> Default
    for Mapping<K, V, KeyType>
{
    fn default() -> Self {
        Self {
            _marker: Default::default(),
        }
    }
}

impl<K, V: AtomicGuard<true>, KeyType: StorageKeyHolder> Mapping<K, V, KeyType> {
    /// TODO: Add comment
    pub fn new() -> Self {
        Self {
            _marker: Default::default(),
        }
    }
}

impl<K, V: AtomicGuard<true>, KeyType: StorageKeyHolder> core::fmt::Debug
    for Mapping<K, V, KeyType>
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
    pub fn contains<Q>(&self, key: Q) -> Option<u32>
    where
        Q: scale::EncodeLike<K>,
    {
        ink_env::contract_storage_contains(&self.storage_key(&key))
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

impl<K, V: AtomicGuard<true>, KeyType: StorageKeyHolder> Encode
    for Mapping<K, V, KeyType>
{
    fn encode_to<T: Output + ?Sized>(&self, _dest: &mut T) {}
}

impl<K, V: AtomicGuard<true>, KeyType: StorageKeyHolder> Decode
    for Mapping<K, V, KeyType>
{
    fn decode<I: Input>(_input: &mut I) -> Result<Self, Error> {
        Ok(Default::default())
    }
}

#[cfg(feature = "std")]
const _: () = {
    use crate::traits::StorageLayout;
    use ink_metadata::layout::{
        CellLayout,
        Layout,
        LayoutKey,
    };
    use ink_primitives::StorageKey;

    impl<K, V: AtomicGuard<true>, KeyType: StorageKeyHolder> StorageLayout
        for Mapping<K, V, KeyType>
    where
        K: scale_info::TypeInfo + 'static,
        V: scale_info::TypeInfo + 'static,
        KeyType: scale_info::TypeInfo + 'static,
    {
        fn layout(_key: &StorageKey) -> Layout {
            Layout::Cell(CellLayout::new::<Self>(LayoutKey::from(&KeyType::KEY)))
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
