use ink_env::Environment;
use pallet_contracts_primitives::ContractInstantiateResult;
use scale::{
    Decode,
    Encode,
};
use sp_weights::Weight;

use crate::{
    builders::CreateBuilderPartial,
    CallBuilderFinal,
    CallDryRunResult,
    CallResult,
    ContractsBackend,
    InstantiationResult,
};

use super::Keypair;

pub struct CallBuilder<'a, E, Args, RetType, CB>
where
    E: Environment,
    Args: Encode + Clone,
    RetType: Send + Decode,

    CB: ContractsBackend<E>,
{
    client: &'a mut CB,
    caller: &'a Keypair,
    message: &'a CallBuilderFinal<E, Args, RetType>,
    value: E::Balance,
    extra_gas_portion: Option<u64>,
    storage_deposit_limit: Option<E::Balance>,
}

impl<'a, E, Args, RetType, CB> CallBuilder<'a, E, Args, RetType, CB>
where
    E: Environment,
    Args: Sync + Encode + Clone,
    RetType: Send + Decode,
    E::Balance: Clone,

    CB: ContractsBackend<E>,
{
    /// Initialize a call builder with essential values.
    pub fn new(
        client: &'a mut CB,
        caller: &'a Keypair,
        message: &'a CallBuilderFinal<E, Args, RetType>,
    ) -> CallBuilder<'a, E, Args, RetType, CB>
    where
        E::Balance: From<u32>,
    {
        Self {
            client,
            caller,
            message,
            value: 0u32.into(),
            extra_gas_portion: None,
            storage_deposit_limit: None,
        }
    }

    /// Provide value with a call
    pub fn value(&mut self, value: E::Balance) {
        self.value = value;
    }

    /// Increases the gas limit marginally by a specified percent.
    /// Useful when the message's gas usage depends on the runtime state
    /// and the dry run does not produce an accurate gas estimate.
    ///
    /// # Example
    ///
    /// With dry run gas estimate of `100` units and `5`% extra gas portion specified,
    /// the set gas limit becomes `105` units
    pub fn extra_gas_portion(&mut self, per_cent: u64) {
        if per_cent == 0 {
            self.extra_gas_portion = None
        } else {
            self.extra_gas_portion = Some(per_cent)
        }
    }

    /// Specify the max amount of funds that can be charged for storage.
    pub fn storage_deposit_limit(&mut self, storage_deposit_limit: E::Balance) {
        if storage_deposit_limit == 0u32.into() {
            self.storage_deposit_limit = None
        } else {
            self.storage_deposit_limit = Some(storage_deposit_limit)
        }
    }

    /// Submit the call for the on-chain execution.
    pub async fn submit(
        &mut self,
    ) -> Result<CallResult<E, RetType, CB::EventLog>, CB::Error>
    where
        CallBuilderFinal<E, Args, RetType>: Clone,
    {
        let dry_run = CB::bare_call_dry_run(
            self.client,
            self.caller,
            self.message,
            self.value,
            self.storage_deposit_limit,
        )
        .await;
        let gas_required: Weight =
            self.extra_gas_portion
                .map_or(dry_run.exec_result.gas_required, |margin| {
                    let gas = dry_run.exec_result.gas_required;
                    gas + (gas / 100 * margin)
                });
        let call_result = CB::bare_call(
            self.client,
            self.caller,
            self.message,
            self.value,
            gas_required,
            self.storage_deposit_limit,
        )
        .await?;
        Ok(CallResult {
            dry_run,
            events: call_result,
        })
    }

    /// Dry run the call.
    pub async fn submit_dry_run(&mut self) -> CallDryRunResult<E, RetType>
    where
        CallBuilderFinal<E, Args, RetType>: Clone,
    {
        CB::bare_call_dry_run(
            self.client,
            self.caller,
            self.message,
            self.value,
            self.storage_deposit_limit,
        )
        .await
    }
}

pub struct InstantiateBuilder<'a, E, Contract, Args, R, C>
where
    E: Environment,
    Args: Encode + Clone,

    C: ContractsBackend<E>,
{
    client: &'a mut C,
    caller: &'a Keypair,
    contract_name: &'a str,
    constructor: CreateBuilderPartial<E, Contract, Args, R>,
    value: E::Balance,
    extra_gas_portion: Option<u64>,
    storage_deposit_limit: Option<E::Balance>,
}

impl<'a, E, Contract, Args, R, C> InstantiateBuilder<'a, E, Contract, Args, R, C>
where
    E: Environment,
    Args: Encode + Clone + Send + Sync,

    C: ContractsBackend<E>,
{
    /// Initialize a call builder with essential values.
    pub fn new(
        client: &'a mut C,
        caller: &'a Keypair,
        contract_name: &'a str,
        constructor: CreateBuilderPartial<E, Contract, Args, R>,
    ) -> InstantiateBuilder<'a, E, Contract, Args, R, C>
    where
        E::Balance: From<u32>,
    {
        Self {
            client,
            caller,
            contract_name,
            constructor,
            value: 0u32.into(),
            extra_gas_portion: None,
            storage_deposit_limit: None,
        }
    }

    /// Provide value with a call
    pub fn value(&mut self, value: E::Balance) {
        self.value = value;
    }

    /// Increases the gas limit marginally by a specified percent.
    /// Useful when the message's gas usage depends on the runtime state
    /// and the dry run does not produce an accurate gas estimate.
    ///
    /// # Example
    ///
    /// With dry run gas estimate of `100` units and `5`% extra gas portion specified,
    /// the set gas limit becomes `105` units
    pub fn extra_gas_portion(&mut self, per_cent: u64) {
        if per_cent == 0 {
            self.extra_gas_portion = None
        } else {
            self.extra_gas_portion = Some(per_cent)
        }
    }

    /// Specify the max amount of funds that can be charged for storage.
    pub fn storage_deposit_limit(&mut self, storage_deposit_limit: E::Balance) {
        if storage_deposit_limit == 0u32.into() {
            self.storage_deposit_limit = None
        } else {
            self.storage_deposit_limit = Some(storage_deposit_limit)
        }
    }

    /// Submit the instantiate call for the on-chain execution.
    pub async fn submit(self) -> Result<InstantiationResult<E, C::EventLog>, C::Error> {
        C::instantiate_with_gas_margin(
            self.client,
            self.contract_name,
            self.caller,
            self.constructor,
            self.value,
            self.extra_gas_portion,
            self.storage_deposit_limit,
        )
        .await
    }

    /// Dry run the instantiate call.
    pub async fn submit_dry_run(
        self,
    ) -> ContractInstantiateResult<E::AccountId, E::Balance, ()> {
        C::bare_instantiate_dry_run(
            self.client,
            self.contract_name,
            self.caller,
            self.constructor,
            self.value,
            self.storage_deposit_limit,
        )
        .await
    }
}
