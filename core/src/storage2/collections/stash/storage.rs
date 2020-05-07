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

//! Implementation of ink! storage traits.

use super::{
    Entry,
    Header,
    Stash as StorageStash,
};
use crate::storage2::{
    lazy::LazyIndexMap,
    traits::{
        forward_clear_packed,
        forward_pull_packed,
        forward_push_packed,
        KeyPtr,
        PackedLayout,
        SpreadLayout,
    },
};
use ink_primitives::Key;

impl SpreadLayout for Header {
    const FOOTPRINT: u64 = 1;

    fn pull_spread(ptr: &mut KeyPtr) -> Self {
        forward_pull_packed::<Self>(ptr)
    }

    fn push_spread(&self, ptr: &mut KeyPtr) {
        forward_push_packed::<Self>(self, ptr)
    }

    fn clear_spread(&self, ptr: &mut KeyPtr) {
        forward_clear_packed::<Self>(self, ptr)
    }
}

impl PackedLayout for Header {
    fn pull_packed(&mut self, _at: &Key) {}
    fn push_packed(&self, _at: &Key) {}
    fn clear_packed(&self, _at: &Key) {}
}

impl<T> SpreadLayout for Entry<T>
where
    T: PackedLayout,
{
    const FOOTPRINT: u64 = 1;

    fn pull_spread(ptr: &mut KeyPtr) -> Self {
        forward_pull_packed::<Self>(ptr)
    }

    fn push_spread(&self, ptr: &mut KeyPtr) {
        forward_push_packed::<Self>(self, ptr)
    }

    fn clear_spread(&self, ptr: &mut KeyPtr) {
        forward_clear_packed::<Self>(self, ptr)
    }
}

impl<T> PackedLayout for Entry<T>
where
    T: PackedLayout,
{
    fn pull_packed(&mut self, at: &Key) {
        if let Entry::Occupied(value) = self {
            <T as PackedLayout>::pull_packed(value, at)
        }
    }

    fn push_packed(&self, at: &Key) {
        if let Entry::Occupied(value) = self {
            <T as PackedLayout>::push_packed(value, at)
        }
    }

    fn clear_packed(&self, at: &Key) {
        if let Entry::Occupied(value) = self {
            <T as PackedLayout>::clear_packed(value, at)
        }
    }
}

impl<T> SpreadLayout for StorageStash<T>
where
    T: PackedLayout,
{
    const FOOTPRINT: u64 = 1 + <LazyIndexMap<T> as SpreadLayout>::FOOTPRINT;

    fn pull_spread(ptr: &mut KeyPtr) -> Self {
        Self {
            header: SpreadLayout::pull_spread(ptr),
            entries: SpreadLayout::pull_spread(ptr),
        }
    }

    fn push_spread(&self, ptr: &mut KeyPtr) {
        SpreadLayout::push_spread(&self.header, ptr);
        SpreadLayout::push_spread(&self.entries, ptr);
    }

    fn clear_spread(&self, ptr: &mut KeyPtr) {
        self.clear_cells();
        SpreadLayout::clear_spread(&self.header, ptr);
        SpreadLayout::clear_spread(&self.entries, ptr);
    }
}
