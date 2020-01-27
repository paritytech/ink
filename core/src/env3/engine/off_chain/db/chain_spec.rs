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

use super::{
    super::Result,
    OffBalance,
};
use crate::env3::EnvTypes;

/// The chain specification.
pub struct ChainSpec {
    /// The current gas price.
    gas_price: OffBalance,
    /// The minimum value an account of the chain may have.
    minimum_balance: OffBalance,
    /// The tombstone deposit.
    tombstone_deposit: OffBalance,
}

impl ChainSpec {
    /// Creates a new uninitialized chain specification.
    pub fn uninitialized() -> Self {
        Self {
            gas_price: OffBalance::uninitialized(),
            minimum_balance: OffBalance::uninitialized(),
            tombstone_deposit: OffBalance::uninitialized(),
        }
    }

    /// Returns the gas price for the chain.
    pub fn gas_price<T>(&self) -> Result<T::Balance>
    where
        T: EnvTypes,
    {
        self.gas_price.decode().map_err(Into::into)
    }

    /// Returns the minimum balance for an account on the chain.
    pub fn minimum_balance<T>(&self) -> Result<T::Balance>
    where
        T: EnvTypes,
    {
        self.minimum_balance.decode().map_err(Into::into)
    }

    /// Returns the tombstone deposit for the chain.
    pub fn tombstone_deposit<T>(&self) -> Result<T::Balance>
    where
        T: EnvTypes,
    {
        self.tombstone_deposit.decode().map_err(Into::into)
    }
}
