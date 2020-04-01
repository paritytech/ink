// Copyright 2019-2020 Parity Technologies (UK) Ltd.
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

use super::ValueEntry;
use crate::{
    hash::hasher::Hasher,
    storage2 as storage,
    storage2::{
        collections::stash::Iter as StashIter,
        LazyHashMap,
        Pack,
        PullForward,
        StorageFootprint,
    },
};
use ink_primitives::Key;

/// An iterator over shared references to the elements of a storage hash map.
#[derive(Clone, Copy)]
pub struct Iter<'a, K, V, H> {
    /// The iterator over the map's keys.
    keys_iter: StashIter<'a, K>,
    /// The lazy hash map to query the values.
    values: &'a LazyHashMap<K, Pack<ValueEntry<V>>, H>,
}

impl<'a, K, V, H> Iter<'a, K, V, H> {
    /// Creates a new iterator for the given storage hash map.
    pub(crate) fn new(hash_map: &'a storage::HashMap<K, V, H>) -> Self
    where
        H: Hasher,
    {
        Self {
            keys_iter: hash_map.keys.iter(),
            values: &hash_map.values,
        }
    }
}

impl<'a, K, V, H> Iter<'a, K, V, H>
where
    K: Ord + Eq + Clone + StorageFootprint + PullForward + scale::Codec,
    V: scale::Decode,
    H: Hasher,
    Key: From<H::Output>,
{
    /// Queries the value for the given key and returns the key/value pair.
    ///
    /// # Panics
    ///
    /// If the key refers to an invalid element.
    fn query_value(&self, key: &'a K) -> <Self as Iterator>::Item {
        let entry = self
            .values
            .get(key)
            .map(Pack::as_inner)
            .expect("a key must always refer to an existing entry");
        (key, &entry.value)
    }
}

impl<'a, K, V, H> Iterator for Iter<'a, K, V, H>
where
    K: Ord + Eq + Clone + StorageFootprint + PullForward + scale::Codec,
    V: scale::Decode,
    H: Hasher,
    Key: From<H::Output>,
{
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        let key = self.keys_iter.next()?;
        Some(self.query_value(key))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.keys_iter.size_hint()
    }
}

impl<'a, K, V, H> ExactSizeIterator for Iter<'a, K, V, H>
where
    K: Ord + Eq + Clone + StorageFootprint + PullForward + scale::Codec,
    V: scale::Decode,
    H: Hasher,
    Key: From<H::Output>,
{
}

impl<'a, K, V, H> DoubleEndedIterator for Iter<'a, K, V, H>
where
    K: Ord + Eq + Clone + StorageFootprint + PullForward + scale::Codec,
    V: scale::Decode,
    H: Hasher,
    Key: From<H::Output>,
{
    fn next_back(&mut self) -> Option<Self::Item> {
        let key = self.keys_iter.next_back()?;
        Some(self.query_value(key))
    }
}
