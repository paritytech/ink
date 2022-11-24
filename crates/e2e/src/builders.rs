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

use ink::codegen::TraitCallBuilder;
use ink_env::{
    call::{
        utils::{
            ReturnType,
            Set,
            Unset,
        },
        Call,
        CallBuilder,
        CreateBuilder,
        ExecutionInput,
        FromAccountId,
    },
    Environment,
};
use scale::Encode;

/// The type returned from `ContractRef` constructors, partially initialized with the execution
/// input arguments.
type CreateBuilderPartial<E, Args, R> = CreateBuilder<
    E,
    Unset<<E as Environment>::Hash>,
    Unset<u64>,
    Unset<<E as Environment>::Balance>,
    Set<ExecutionInput<Args>>,
    Unset<ink_env::call::state::Salt>,
    R,
>;

/// Shim onto the `CreateBuilder` to allow access to the `ExecutionInput` args.
pub struct ConstructorBuilder<E: Environment, Args: Encode, R> {
    inner: CreateBuilderPartial<E, Args, R>,
}

impl<E: Environment, Args: Encode, R> From<CreateBuilderPartial<E, Args, R>>
    for ConstructorBuilder<E, Args, R>
{
    fn from(inner: CreateBuilderPartial<E, Args, R>) -> Self {
        Self { inner }
    }
}

impl<E: Environment, Args: Encode, R> ConstructorBuilder<E, Args, R> {
    /// Returns encoded constructor args.
    pub fn exec_input(self) -> Vec<u8> {
        // set all the other properties to default values, we only require the `exec_input`.
        self.inner
            .endowment(0u32.into())
            .code_hash(ink_primitives::Clear::clear())
            .salt_bytes(Vec::new())
            .params()
            .exec_input()
            .encode()
    }
}

#[derive(Debug, Clone)]
pub struct Message<E: Environment, RetType> {
    account_id: E::AccountId,
    exec_input: Vec<u8>,
    marker: std::marker::PhantomData<RetType>,
}

impl<E, RetType> Message<E, RetType>
where
    E: Environment,
{
    pub fn build<F, Ref, Args>(
        account_id: E::AccountId,
        message: F,
    ) -> Message<E, RetType>
    where
        E: Environment,
        Ref: TraitCallBuilder + FromAccountId<E>,
        Args: scale::Encode,
        F: FnOnce(
            &<Ref as TraitCallBuilder>::Builder,
        ) -> CallBuilder<
            E,
            Set<Call<E>>,
            Set<ExecutionInput<Args>>,
            Set<ReturnType<RetType>>,
        >,
        RetType: scale::Decode,
    {
        let contract_ref = <Ref as FromAccountId<E>>::from_account_id(account_id.clone());
        let call_builder = <Ref as TraitCallBuilder>::call(&contract_ref);
        let builder = message(&call_builder);
        let exec_input = builder.params().exec_input().encode();
        Message {
            account_id,
            exec_input,
            marker: Default::default(),
        }
    }

    pub fn account_id(&self) -> &E::AccountId {
        &self.account_id
    }

    pub fn exec_input(&self) -> &[u8] {
        &self.exec_input
    }
}

/// Convenience method for building messages for the default environment
pub fn build_message<Ref>(
    account_id: <ink_env::DefaultEnvironment as Environment>::AccountId,
) -> MessageBuilder<ink_env::DefaultEnvironment, Ref>
where
    Ref: TraitCallBuilder + FromAccountId<ink_env::DefaultEnvironment>,
{
    MessageBuilder::from_account_id(account_id)
}

/// Build messages using a contract ref.
pub struct MessageBuilder<E: Environment, Ref> {
    account_id: E::AccountId,
    contract_ref: Ref,
}

impl<E, Ref> MessageBuilder<E, Ref>
where
    E: Environment,
    Ref: TraitCallBuilder + FromAccountId<E>,
{
    pub fn from_account_id(account_id: E::AccountId) -> Self {
        let contract_ref = <Ref as FromAccountId<E>>::from_account_id(account_id.clone());
        Self {
            account_id,
            contract_ref,
        }
    }

    pub fn account_id(&self) -> &E::AccountId {
        &self.account_id
    }

    pub fn call<F, Args, RetType>(mut self, mut message: F) -> Message<E, RetType>
    where
        F: FnMut(
            &mut <Ref as TraitCallBuilder>::Builder,
        ) -> CallBuilder<
            E,
            Set<Call<E>>,
            Set<ExecutionInput<Args>>,
            Set<ReturnType<RetType>>,
        >,
        Args: scale::Encode,
        RetType: scale::Decode,
    {
        let call_builder = <Ref as TraitCallBuilder>::call_mut(&mut self.contract_ref);
        let builder = message(call_builder);
        let exec_input = builder.params().exec_input().encode();
        Message {
            account_id: self.account_id.clone(),
            exec_input,
            marker: Default::default(),
        }
    }
}
