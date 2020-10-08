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

use super::{
    hashing,
    Account,
    EnvInstance,
};
use crate::{
    call::{
        utils::ReturnType,
        CallParams,
        CreateParams,
    },
    hash::{
        Blake2x128,
        Blake2x256,
        CryptoHash,
        HashOutput,
        Keccak256,
        Sha2x256,
    },
    topics::Topics,
    EnvBackend,
    Error,
    Environment,
    Result,
    ReturnFlags,
    TypedEnvBackend,
};
use core::convert::TryInto;
use ink_primitives::Key;
use num_traits::Bounded;

impl EnvInstance {
    /// Returns the callee account.
    fn callee_account(&self) -> &Account {
        let callee = self
            .exec_context()
            .expect("uninitialized execution context")
            .callee
            .clone();
        self.accounts
            .get_account_off(&callee)
            .expect("callee account does not exist")
    }

    /// Returns the callee account as mutable reference.
    fn callee_account_mut(&mut self) -> &mut Account {
        let callee = self
            .exec_context()
            .expect("uninitialized execution context")
            .callee
            .clone();
        self.accounts
            .get_account_off_mut(&callee)
            .expect("callee account does not exist")
    }
}

impl CryptoHash for Blake2x128 {
    fn hash(input: &[u8], output: &mut <Self as HashOutput>::Type) {
        type OutputType = [u8; 16];
        static_assertions::assert_type_eq_all!(
            <Blake2x128 as HashOutput>::Type,
            OutputType
        );
        let output: &mut OutputType = arrayref::array_mut_ref!(output, 0, 16);
        hashing::blake2b_128(input, output);
    }
}

impl CryptoHash for Blake2x256 {
    fn hash(input: &[u8], output: &mut <Self as HashOutput>::Type) {
        type OutputType = [u8; 32];
        static_assertions::assert_type_eq_all!(
            <Blake2x256 as HashOutput>::Type,
            OutputType
        );
        let output: &mut OutputType = arrayref::array_mut_ref!(output, 0, 32);
        hashing::blake2b_256(input, output);
    }
}

impl CryptoHash for Sha2x256 {
    fn hash(input: &[u8], output: &mut <Self as HashOutput>::Type) {
        type OutputType = [u8; 32];
        static_assertions::assert_type_eq_all!(
            <Sha2x256 as HashOutput>::Type,
            OutputType
        );
        let output: &mut OutputType = arrayref::array_mut_ref!(output, 0, 32);
        hashing::sha2_256(input, output);
    }
}

impl CryptoHash for Keccak256 {
    fn hash(input: &[u8], output: &mut <Self as HashOutput>::Type) {
        type OutputType = [u8; 32];
        static_assertions::assert_type_eq_all!(
            <Keccak256 as HashOutput>::Type,
            OutputType
        );
        let output: &mut OutputType = arrayref::array_mut_ref!(output, 0, 32);
        hashing::keccak_256(input, output);
    }
}

impl EnvBackend for EnvInstance {
    fn set_contract_storage<V>(&mut self, key: &Key, value: &V)
    where
        V: scale::Encode,
    {
        self.callee_account_mut()
            .set_storage(*key, value)
            .expect("callee account is not a smart contract");
    }

    fn get_contract_storage<R>(&mut self, key: &Key) -> Result<Option<R>>
    where
        R: scale::Decode,
    {
        self.callee_account()
            .get_storage::<R>(*key)
            .map_err(Into::into)
    }

    fn clear_contract_storage(&mut self, key: &Key) {
        self.callee_account_mut()
            .clear_storage(*key)
            .expect("callee account is not a smart contract");
    }

    fn decode_input<T>(&mut self) -> Result<T>
    where
        T: scale::Decode,
    {
        self.exec_context()
            .map(|exec_ctx| &exec_ctx.call_data)
            .map(|call_data| scale::Encode::encode(call_data))
            .map_err(Into::into)
            .and_then(|encoded| {
                <T as scale::Decode>::decode(&mut &encoded[..])
                    .map_err(|_| scale::Error::from("could not decode input call data"))
                    .map_err(Into::into)
            })
    }

    fn return_value<R>(&mut self, flags: ReturnFlags, return_value: &R) -> !
    where
        R: scale::Encode,
    {
        let ctx = self
            .exec_context_mut()
            .expect("uninitialized execution context");
        ctx.output = Some(return_value.encode());
        std::process::exit(flags.into_u32() as i32)
    }

    fn println(&mut self, content: &str) {
        self.console.println(content)
    }

    fn hash_bytes<H>(&mut self, input: &[u8], output: &mut <H as HashOutput>::Type)
    where
        H: CryptoHash,
    {
        <H as CryptoHash>::hash(input, output)
    }

    fn hash_encoded<H, T>(&mut self, input: &T, output: &mut <H as HashOutput>::Type)
    where
        H: CryptoHash,
        T: scale::Encode,
    {
        let encoded = input.encode();
        self.hash_bytes::<H>(&encoded[..], output)
    }

    #[cfg(feature = "ink-unstable-chain-extensions")]
    fn call_chain_extension<I, O>(&mut self, func_id: u32, input: &I) -> Result<O>
    where
        I: scale::Codec + 'static,
        O: scale::Codec + 'static,
    {
        self.chain_extension_handler.eval(func_id, input)
    }
}

impl EnvInstance {
    fn transfer_impl<T>(
        &mut self,
        destination: T::AccountId,
        value: T::Balance,
    ) -> Result<()>
    where
        T: Environment,
    {
        let src_id = self.account_id::<T>()?;
        let src_value = self
            .accounts
            .get_account::<T>(&src_id)
            .expect("account of executed contract must exist")
            .balance::<T>()?;
        if src_value < value {
            return Err(Error::TransferFailed)
        }
        let dst_value = self
            .accounts
            .get_or_create_account::<T>(&destination)
            .balance::<T>()?;
        self.accounts
            .get_account_mut::<T>(&src_id)
            .expect("account of executed contract must exist")
            .set_balance::<T>(src_value - value)?;
        self.accounts
            .get_account_mut::<T>(&destination)
            .expect("the account must exist already or has just been created")
            .set_balance::<T>(dst_value + value)?;
        Ok(())
    }
}

impl TypedEnvBackend for EnvInstance {
    fn caller<T: Environment>(&mut self) -> Result<T::AccountId> {
        self.exec_context()
            .expect("uninitialized execution context")
            .caller::<T>()
            .map_err(|_| scale::Error::from("could not decode caller"))
            .map_err(Into::into)
    }

    fn transferred_balance<T: Environment>(&mut self) -> Result<T::Balance> {
        self.exec_context()
            .expect("uninitialized execution context")
            .transferred_value::<T>()
            .map_err(|_| scale::Error::from("could not decode transferred balance"))
            .map_err(Into::into)
    }

    /// Emulates gas price calculation
    fn weight_to_fee<T: Environment>(&mut self, gas: u64) -> Result<T::Balance> {
        use crate::arithmetic::Saturating as _;

        let gas_price = self
            .chain_spec
            .gas_price::<T>()
            .map_err(|_| scale::Error::from("could not decode gas price"))?;

        Ok(gas_price
            .saturating_mul(gas.try_into().unwrap_or_else(|_| Bounded::max_value())))
    }

    fn gas_left<T: Environment>(&mut self) -> Result<T::Balance> {
        self.exec_context()
            .expect("uninitialized execution context")
            .gas::<T>()
            .map_err(|_| scale::Error::from("could not decode gas left"))
            .map_err(Into::into)
    }

    fn block_timestamp<T: Environment>(&mut self) -> Result<T::Timestamp> {
        self.current_block()
            .expect("uninitialized execution context")
            .timestamp::<T>()
            .map_err(|_| scale::Error::from("could not decode block time"))
            .map_err(Into::into)
    }

    fn account_id<T: Environment>(&mut self) -> Result<T::AccountId> {
        self.exec_context()
            .expect("uninitialized execution context")
            .callee::<T>()
            .map_err(|_| scale::Error::from("could not decode callee"))
            .map_err(Into::into)
    }

    fn balance<T: Environment>(&mut self) -> Result<T::Balance> {
        self.callee_account()
            .balance::<T>()
            .map_err(|_| scale::Error::from("could not decode callee balance"))
            .map_err(Into::into)
    }

    fn rent_allowance<T: Environment>(&mut self) -> Result<T::Balance> {
        self.callee_account()
            .rent_allowance::<T>()
            .map_err(|_| scale::Error::from("could not decode callee rent allowance"))
            .map_err(Into::into)
    }

    fn block_number<T: Environment>(&mut self) -> Result<T::BlockNumber> {
        self.current_block()
            .expect("uninitialized execution context")
            .number::<T>()
            .map_err(|_| scale::Error::from("could not decode block number"))
            .map_err(Into::into)
    }

    fn minimum_balance<T: Environment>(&mut self) -> Result<T::Balance> {
        self.chain_spec
            .minimum_balance::<T>()
            .map_err(|_| scale::Error::from("could not decode minimum balance"))
            .map_err(Into::into)
    }

    fn tombstone_deposit<T: Environment>(&mut self) -> Result<T::Balance> {
        self.chain_spec
            .tombstone_deposit::<T>()
            .map_err(|_| scale::Error::from("could not decode tombstone deposit"))
            .map_err(Into::into)
    }

    fn emit_event<T, Event>(&mut self, new_event: Event)
    where
        T: Environment,
        Event: Topics + scale::Encode,
    {
        self.emitted_events.record::<T, Event>(new_event)
    }

    fn set_rent_allowance<T>(&mut self, new_rent_allowance: T::Balance)
    where
        T: Environment,
    {
        self.callee_account_mut()
            .set_rent_allowance::<T>(new_rent_allowance)
            .expect("could not encode rent allowance")
    }

    fn invoke_contract<T, Args>(
        &mut self,
        _call_params: &CallParams<T, Args, ()>,
    ) -> Result<()>
    where
        T: Environment,
        Args: scale::Encode,
    {
        unimplemented!("off-chain environment does not support contract invokation")
    }

    fn eval_contract<T, Args, R>(
        &mut self,
        _call_params: &CallParams<T, Args, ReturnType<R>>,
    ) -> Result<R>
    where
        T: Environment,
        Args: scale::Encode,
        R: scale::Decode,
    {
        unimplemented!("off-chain environment does not support contract evaluation")
    }

    fn instantiate_contract<T, Args, C>(
        &mut self,
        _params: &CreateParams<T, Args, C>,
    ) -> Result<T::AccountId>
    where
        T: Environment,
        Args: scale::Encode,
    {
        unimplemented!("off-chain environment does not support contract instantiation")
    }

    fn terminate_contract<T>(&mut self, _beneficiary: T::AccountId) -> !
    where
        T: Environment,
    {
        unimplemented!("off-chain environment does not support contract termination")
    }

    fn restore_contract<T>(
        &mut self,
        _account_id: T::AccountId,
        _code_hash: T::Hash,
        _rent_allowance: T::Balance,
        _filtered_keys: &[Key],
    ) where
        T: Environment,
    {
        unimplemented!("off-chain environment does not support contract restoration")
    }

    fn transfer<T>(&mut self, destination: T::AccountId, value: T::Balance) -> Result<()>
    where
        T: Environment,
    {
        self.transfer_impl::<T>(destination, value)
    }

    fn random<T>(&mut self, subject: &[u8]) -> Result<T::Hash>
    where
        T: Environment,
    {
        self.current_block()
            .expect("uninitialized execution context")
            .random::<T>(subject)
            .map_err(Into::into)
    }
}
