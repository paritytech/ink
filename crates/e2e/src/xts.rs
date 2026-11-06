// Copyright (C) Use Ink (UK) Ltd.
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

use super::{log_info, sr25519, ContractExecResult, ContractInstantiateResult, Keypair};
use ink_env::Environment;

use crate::H256;
use core::marker::PhantomData;
use pallet_contracts::CodeUploadResult;
use subxt::{
    config::{
        DefaultExtrinsicParams, DefaultExtrinsicParamsBuilder, TransactionExtensions,
    },
    ext::scale_encode,
    extrinsics::ExtrinsicEvents,
    metadata::ArcMetadata,
    rpcs::{methods::legacy::LegacyRpcMethods, RpcClient},
    tx::{Signer, TransactionStatus},
    utils::MultiAddress,
    OnlineClient,
};

/// Copied from `sp_weight` to additionally implement `scale_encode::EncodeAsType`.
#[derive(
    Copy,
    Clone,
    Eq,
    PartialEq,
    Debug,
    Default,
    scale::Encode,
    scale::Decode,
    scale::MaxEncodedLen,
    scale_encode::EncodeAsType,
    serde::Serialize,
    serde::Deserialize,
)]
#[encode_as_type(crate_path = "subxt::ext::scale_encode")]
pub struct Weight {
    #[codec(compact)]
    /// The weight of computational time used based on some reference hardware.
    ref_time: u64,
    #[codec(compact)]
    /// The weight of storage space used by proof of validity.
    proof_size: u64,
}

impl From<sp_weights::Weight> for Weight {
    fn from(weight: sp_weights::Weight) -> Self {
        Self {
            ref_time: weight.ref_time(),
            proof_size: weight.proof_size(),
        }
    }
}

impl From<Weight> for sp_weights::Weight {
    fn from(weight: Weight) -> Self {
        sp_weights::Weight::from_parts(weight.ref_time, weight.proof_size)
    }
}

/// A raw call to `pallet-contracts`'s `instantiate_with_code`.
#[derive(Debug, scale::Encode, scale::Decode, scale_encode::EncodeAsType)]
#[encode_as_type(trait_bounds = "", crate_path = "subxt::ext::scale_encode")]
pub struct InstantiateWithCode<E: Environment> {
    #[codec(compact)]
    value: E::Balance,
    gas_limit: Weight,
    storage_deposit_limit: Option<E::Balance>,
    code: Vec<u8>,
    data: Vec<u8>,
    salt: Vec<u8>,
}

/// A raw call to `pallet-contracts`'s `call`.
#[derive(Debug, scale::Decode, scale::Encode, scale_encode::EncodeAsType)]
#[encode_as_type(trait_bounds = "", crate_path = "subxt::ext::scale_encode")]
pub struct Call<E: Environment> {
    dest: MultiAddress<E::AccountId, ()>,
    #[codec(compact)]
    value: E::Balance,
    gas_limit: Weight,
    storage_deposit_limit: Option<E::Balance>,
    data: Vec<u8>,
}

/// A raw call to `pallet-contracts`'s `call`.
#[derive(Debug, scale::Decode, scale::Encode, scale_encode::EncodeAsType)]
#[encode_as_type(trait_bounds = "", crate_path = "subxt::ext::scale_encode")]
pub struct Transfer<E: Environment, C: subxt::Config> {
    dest: C::Address,
    #[codec(compact)]
    value: E::Balance,
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    serde::Serialize,
    scale::Decode,
    scale::Encode,
    scale_encode::EncodeAsType,
)]
#[encode_as_type(crate_path = "subxt::ext::scale_encode")]
pub enum Determinism {
    /// The execution should be deterministic and hence no indeterministic instructions
    /// are allowed.
    ///
    /// Dispatchables always use this mode in order to make on-chain execution
    /// deterministic.
    Enforced,
    /// Allow calling or uploading an indeterministic code.
    ///
    /// This is only possible when calling into `pallet-contracts` directly via
    /// [`crate::Pallet::bare_call`].
    ///
    /// # Note
    ///
    /// **Never** use this mode for on-chain execution.
    Relaxed,
}

/// A raw call to `pallet-contracts`'s `remove_code`.
#[derive(Debug, scale::Encode, scale::Decode, scale_encode::EncodeAsType)]
#[encode_as_type(trait_bounds = "", crate_path = "subxt::ext::scale_encode")]
pub struct RemoveCode<E: Environment> {
    code_hash: E::Hash,
}

/// A raw call to `pallet-contracts`'s `upload`.
#[derive(Debug, scale::Encode, scale::Decode, scale_encode::EncodeAsType)]
#[encode_as_type(trait_bounds = "", crate_path = "subxt::ext::scale_encode")]
pub struct UploadCode<E: Environment> {
    code: Vec<u8>,
    storage_deposit_limit: Option<E::Balance>,
    determinism: Determinism,
}

/// A struct that encodes RPC parameters required to instantiate a new smart contract.
#[derive(serde::Serialize, scale::Encode)]
#[serde(rename_all = "camelCase")]
struct RpcInstantiateRequest<C: subxt::Config, E: Environment> {
    origin: C::AccountId,
    value: E::Balance,
    gas_limit: Option<Weight>,
    storage_deposit_limit: Option<E::Balance>,
    code: Code,
    data: Vec<u8>,
    salt: Vec<u8>,
}

/// A struct that encodes RPC parameters required to upload a new smart contract.
#[derive(serde::Serialize, scale::Encode)]
#[serde(rename_all = "camelCase")]
struct RpcCodeUploadRequest<C: subxt::Config, E: Environment>
where
    E::Balance: serde::Serialize,
{
    origin: C::AccountId,
    code: Vec<u8>,
    storage_deposit_limit: Option<E::Balance>,
    determinism: Determinism,
}

/// A struct that encodes RPC parameters required for a call to a smart contract.
///
/// Copied from [`pallet-contracts-rpc`].
#[derive(serde::Serialize, scale::Encode)]
#[serde(rename_all = "camelCase")]
struct RpcCallRequest<C: subxt::Config, E: Environment> {
    origin: C::AccountId,
    dest: E::AccountId,
    value: E::Balance,
    gas_limit: Option<Weight>,
    storage_deposit_limit: Option<E::Balance>,
    input_data: Vec<u8>,
}

/// Reference to an existing code hash or a new Wasm module.
#[derive(serde::Serialize, scale::Encode)]
#[serde(rename_all = "camelCase")]
enum Code {
    /// A Wasm module as raw bytes.
    Upload(Vec<u8>),
    #[allow(unused)]
    /// The code hash of an on-chain Wasm blob.
    Existing(H256),
}

/// Provides functions for interacting with the `pallet-contracts` API.
pub struct ContractsApi<C: subxt::Config, E: Environment> {
    pub rpc: LegacyRpcMethods<subxt::config::RpcConfigFor<C>>,
    pub client: OnlineClient<C>,
    _phantom: PhantomData<fn() -> (C, E)>,
}

impl<C, E> ContractsApi<C, E>
where
    C: subxt::Config,
    C::AccountId: From<sr25519::PublicKey> + serde::de::DeserializeOwned + scale::Codec,
    C::Address: From<sr25519::PublicKey>,
    C::Signature: From<sr25519::Signature>,
    <C::TransactionExtensions as TransactionExtensions<C>>::Params:
        From<DefaultExtrinsicParams<C>>,

    E: Environment,
    E::Balance: scale::HasCompact + serde::Serialize,
{
    /// Creates a new [`ContractsApi`] instance.
    pub async fn new(rpc: RpcClient) -> Result<Self, subxt::Error>
    where
        C: Default,
    {
        let client = OnlineClient::<C>::from_rpc_client(rpc.clone()).await?;
        let rpc = LegacyRpcMethods::new(rpc);
        Ok(Self {
            rpc,
            client,
            _phantom: Default::default(),
        })
    }

    /// Uses one block for the dry run and the metadata needed to decode its errors.
    async fn dry_run<R: scale::Decode>(
        &self,
        function: &str,
        params: Vec<u8>,
    ) -> (R, ArcMetadata) {
        let block = self.best_block().await;
        let at_block = self
            .client
            .at_block(subxt::backend::BlockRef::from_hash(block))
            .await
            .expect("failed to load dry-run block");
        let bytes = self
            .rpc
            .state_call(function, Some(&params), Some(block))
            .await
            .unwrap_or_else(|err| panic!("error calling {function}: {err:?}"));
        let result = scale::Decode::decode(&mut bytes.as_ref())
            .unwrap_or_else(|err| panic!("decoding {function} result failed: {err}"));
        (result, at_block.metadata())
    }

    /// Attempt to transfer the `value` from `origin` to `dest`.
    ///
    /// Returns `Ok` on success, and a [`subxt::Error`] if the extrinsic is
    /// invalid (e.g. out of date nonce)
    pub async fn try_transfer_balance(
        &self,
        origin: &Keypair,
        dest: C::AccountId,
        value: E::Balance,
    ) -> Result<(), subxt::Error> {
        let call = subxt::tx::StaticPayload::new(
            "Balances",
            "transfer_allow_death",
            Transfer::<E, C> {
                dest: dest.into(),
                value,
            },
        )
        .unvalidated();

        let _ = self.submit_extrinsic(&call, origin).await;

        Ok(())
    }

    /// Dry runs the instantiation of the given `code`.
    pub async fn instantiate_with_code_dry_run(
        &self,
        value: E::Balance,
        storage_deposit_limit: Option<E::Balance>,
        code: Vec<u8>,
        data: Vec<u8>,
        salt: Vec<u8>,
        signer: &Keypair,
    ) -> (
        ContractInstantiateResult<E::AccountId, E::Balance, ()>,
        ArcMetadata,
    ) {
        let code = Code::Upload(code);
        let call_request = RpcInstantiateRequest::<C, E> {
            origin: Signer::<C>::account_id(signer),
            value,
            gas_limit: None,
            storage_deposit_limit,
            code,
            data,
            salt,
        };
        self.dry_run(
            "ContractsApi_instantiate",
            scale::Encode::encode(&call_request),
        )
        .await
    }

    /// Sign and submit an extrinsic with the given call payload.
    pub async fn submit_extrinsic<Call>(
        &self,
        call: &Call,
        signer: &Keypair,
    ) -> (ExtrinsicEvents<C>, ArcMetadata)
    where
        Call: subxt::tx::Payload,
    {
        let account_id = <Keypair as Signer<C>>::account_id(signer);
        let at_block = self
            .client
            .at_block(subxt::backend::BlockRef::from_hash(self.best_block().await))
            .await
            .expect("failed to load best block");
        let transactions = at_block.transactions();
        let account_nonce = transactions
            .account_nonce(&account_id)
            .await
            .unwrap_or_else(|err| panic!("error fetching account nonce: {err:?}"));
        let params = DefaultExtrinsicParamsBuilder::new()
            .nonce(account_nonce)
            .build();
        let signed = transactions
            .create_signable_offline(call, params.into())
            .unwrap_or_else(|err| panic!("error creating transaction: {err:?}"))
            .sign(signer)
            .unwrap_or_else(|err| panic!("error signing transaction: {err:?}"));
        let mut tx = signed
            .submit_and_watch()
            .await
            .inspect(|tx_progress| {
                log_info(&format!(
                    "signed and submitted tx with hash {:?}",
                    tx_progress.extrinsic_hash()
                ));
            })
            .unwrap_or_else(|err| {
                panic!("error on call `submit_and_watch`: {err:?}");
            });

        // Below we use the low level API to replicate the `wait_for_in_block` behaviour
        // which was removed in subxt 0.33.0. See https://github.com/paritytech/subxt/pull/1237.
        //
        // We require this because we use `substrate-contracts-node` as our development
        // node, which does not currently support finality, so we just want to
        // wait until it is included in a block.
        while let Some(status) = tx.next().await {
            match status.unwrap_or_else(|err| {
                panic!("error subscribing to tx status: {err:?}");
            }) {
                TransactionStatus::InBestBlock(tx_in_block)
                | TransactionStatus::InFinalizedBlock(tx_in_block) => {
                    let metadata = tx_in_block
                        .at()
                        .await
                        .expect("failed to load transaction block")
                        .metadata();
                    let events = tx_in_block.fetch_events().await.unwrap_or_else(|err| {
                        panic!("error on call `fetch_events`: {err:?}");
                    });
                    return (events, metadata);
                }
                TransactionStatus::Error { message } => {
                    panic!("TransactionStatus::Error: {message:?}");
                }
                TransactionStatus::Invalid { message } => {
                    panic!("TransactionStatus::Invalid: {message:?}");
                }
                TransactionStatus::Dropped { message } => {
                    panic!("TransactionStatus::Dropped: {message:?}");
                }
                _ => continue,
            }
        }
        panic!("Error waiting for tx status")
    }

    /// Return the hash of the *best* block
    pub async fn best_block(&self) -> subxt::config::HashFor<C> {
        self.rpc
            .chain_get_block_hash(None)
            .await
            .unwrap_or_else(|err| {
                panic!("error on call `chain_get_block_hash`: {err:?}");
            })
            .unwrap_or_else(|| {
                panic!("error on call `chain_get_block_hash`: no best block found");
            })
    }

    /// Submits an extrinsic to instantiate a contract with the given code.
    ///
    /// Returns when the transaction is included in a block. The return value
    /// contains all events that are associated with this transaction.
    #[allow(clippy::too_many_arguments)]
    pub async fn instantiate_with_code(
        &self,
        value: E::Balance,
        gas_limit: Weight,
        storage_deposit_limit: Option<E::Balance>,
        code: Vec<u8>,
        data: Vec<u8>,
        salt: Vec<u8>,
        signer: &Keypair,
    ) -> (ExtrinsicEvents<C>, ArcMetadata) {
        let call = subxt::tx::StaticPayload::new(
            "Contracts",
            "instantiate_with_code",
            InstantiateWithCode::<E> {
                value,
                gas_limit,
                storage_deposit_limit,
                code,
                data,
                salt,
            },
        )
        .unvalidated();

        self.submit_extrinsic(&call, signer).await
    }

    /// Dry runs the upload of the given `code`.
    pub async fn upload_dry_run(
        &self,
        signer: &Keypair,
        code: Vec<u8>,
        storage_deposit_limit: Option<E::Balance>,
    ) -> (CodeUploadResult<E::Hash, E::Balance>, ArcMetadata) {
        let call_request = RpcCodeUploadRequest::<C, E> {
            origin: Signer::<C>::account_id(signer),
            code,
            storage_deposit_limit,
            determinism: Determinism::Enforced,
        };
        self.dry_run(
            "ContractsApi_upload_code",
            scale::Encode::encode(&call_request),
        )
        .await
    }

    /// Submits an extrinsic to upload a given code.
    ///
    /// Returns when the transaction is included in a block. The return value
    /// contains all events that are associated with this transaction.
    pub async fn upload(
        &self,
        signer: &Keypair,
        code: Vec<u8>,
        storage_deposit_limit: Option<E::Balance>,
    ) -> (ExtrinsicEvents<C>, ArcMetadata) {
        let call = subxt::tx::StaticPayload::new(
            "Contracts",
            "upload_code",
            UploadCode::<E> {
                code,
                storage_deposit_limit,
                determinism: Determinism::Enforced,
            },
        )
        .unvalidated();

        self.submit_extrinsic(&call, signer).await
    }

    /// Submits an extrinsic to remove the code at the given hash.
    ///
    /// Returns when the transaction is included in a block. The return value
    /// contains all events that are associated with this transaction.
    pub async fn remove_code(
        &self,
        signer: &Keypair,
        code_hash: E::Hash,
    ) -> (ExtrinsicEvents<C>, ArcMetadata) {
        let call = subxt::tx::StaticPayload::new(
            "Contracts",
            "remove_code",
            RemoveCode::<E> { code_hash },
        )
        .unvalidated();

        self.submit_extrinsic(&call, signer).await
    }

    /// Dry runs a call of the contract at `contract` with the given parameters.
    pub async fn call_dry_run(
        &self,
        origin: C::AccountId,
        dest: E::AccountId,
        input_data: Vec<u8>,
        value: E::Balance,
        storage_deposit_limit: Option<E::Balance>,
    ) -> (ContractExecResult<E::Balance, ()>, ArcMetadata) {
        let call_request = RpcCallRequest::<C, E> {
            origin,
            dest,
            value,
            gas_limit: None,
            storage_deposit_limit,
            input_data,
        };
        self.dry_run("ContractsApi_call", scale::Encode::encode(&call_request))
            .await
    }

    /// Submits an extrinsic to call a contract with the given parameters.
    ///
    /// Returns when the transaction is included in a block. The return value
    /// contains all events that are associated with this transaction.
    pub async fn call(
        &self,
        contract: MultiAddress<E::AccountId, ()>,
        value: E::Balance,
        gas_limit: Weight,
        storage_deposit_limit: Option<E::Balance>,
        data: Vec<u8>,
        signer: &Keypair,
    ) -> (ExtrinsicEvents<C>, ArcMetadata) {
        let call = subxt::tx::StaticPayload::new(
            "Contracts",
            "call",
            Call::<E> {
                dest: contract,
                value,
                gas_limit,
                storage_deposit_limit,
                data,
            },
        )
        .unvalidated();

        self.submit_extrinsic(&call, signer).await
    }

    /// Submit an extrinsic `call_name` for the `pallet_name`.
    /// The `call_data` is a `Vec<subxt::dynamic::Value>` that holds
    /// a representation of some value.
    ///
    /// Returns when the transaction is included in a block. The return value
    /// contains all events that are associated with this transaction.
    pub async fn runtime_call<'a>(
        &self,
        signer: &Keypair,
        pallet_name: &'a str,
        call_name: &'a str,
        call_data: Vec<subxt::dynamic::Value>,
    ) -> (ExtrinsicEvents<C>, ArcMetadata) {
        let call = subxt::dynamic::tx(pallet_name, call_name, call_data);

        self.submit_extrinsic(&call, signer).await
    }
}
