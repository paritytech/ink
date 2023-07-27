use crate::builders::CreateBuilderPartial;
use crate::InstantiationResult;
use ink_env::Environment;
use jsonrpsee::core::async_trait;
use pallet_contracts_primitives::ContractInstantiateResult;
use subxt::dynamic::Value;

/// Full E2E testing backend: combines general chain API and contract-specific operations.
#[async_trait]
pub trait E2EBackend<E: Environment>: ChainBackend + ContractsBackend<E> {}

/// General chain operations useful in contract testing.
#[async_trait]
pub trait ChainBackend {
    /// Abstract type representing the entity that interacts with the chain.
    type Actor: Send;
    /// Identifier type for an actor.
    type ActorId;
    /// Balance type.
    type Balance: Send;
    /// Error type.
    type Error;
    /// Event log type.
    type EventLog;

    /// Generate a new actor's credentials and fund it with the given amount from the
    /// `sender` actor.
    async fn create_and_fund_account(
        &mut self,
        origin: &Self::Actor,
        amount: Self::Balance,
    ) -> Self::Actor;

    /// Returns the balance of `actor`.
    async fn balance(&self, actor: Self::ActorId) -> Result<Self::Balance, Self::Error>;

    /// Executes a runtime call `call_name` for the `pallet_name`.
    /// The `call_data` is a `Vec<Value>`.
    ///
    /// Note:
    /// - `pallet_name` must be in camel case, for example `Balances`.
    /// - `call_name` must be snake case, for example `force_transfer`.
    /// - `call_data` is a `Vec<subxt::dynamic::Value>` that holds a representation of
    ///   some value.
    ///
    /// Returns when the transaction is included in a block. The return value contains all
    /// events that are associated with this transaction.
    async fn runtime_call<'a>(
        &mut self,
        actor: &Self::Actor,
        pallet_name: &'a str,
        call_name: &'a str,
        call_data: Vec<Value>,
    ) -> Result<Self::EventLog, Self::Error>;
}

/// Contract-specific operations.
#[async_trait]
pub trait ContractsBackend<E: Environment> {
    /// Abstract type representing the entity that interacts with the chain.
    type Actor;
    /// Error type.
    type Error;
    /// Event log type.
    type EventLog;

    /// The function subsequently uploads and instantiates an instance of the contract.
    ///
    /// This function extracts the metadata of the contract at the file path
    /// `target/ink/$contract_name.contract`.
    ///
    /// Calling this function multiple times should be idempotent, the contract is
    /// newly instantiated each time using a unique salt. No existing contract
    /// instance is reused!
    async fn instantiate<Contract, Args: Send + scale::Encode, R>(
        &mut self,
        contract_name: &str,
        caller: &Self::Actor,
        constructor: CreateBuilderPartial<E, Contract, Args, R>,
        value: E::Balance,
        storage_deposit_limit: Option<E::Balance>,
    ) -> Result<InstantiationResult<E, Self::EventLog>, Self::Error>;

    /// Dry run contract instantiation.
    async fn instantiate_dry_run<Contract, Args: Send + scale::Encode, R>(
        &mut self,
        contract_name: &str,
        caller: &Self::Actor,
        constructor: CreateBuilderPartial<E, Contract, Args, R>,
        value: E::Balance,
        storage_deposit_limit: Option<E::Balance>,
    ) -> ContractInstantiateResult<E::AccountId, E::Balance, ()>;
}
