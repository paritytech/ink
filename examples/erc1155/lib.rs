// Copyright 2018-2021 Parity Technologies (UK) Ltd.
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

#![cfg_attr(not(feature = "std"), no_std)]

use ink_env::AccountId;
use ink_lang as ink;
use ink_prelude::vec::Vec;

// This is the "magic" return value that we expect if a smart contract supports receiving ERC-1155
// tokens.
//
// It is calculated with
// `bytes4(keccak256("onERC1155Received(address,address,uint256,uint256,bytes)"))`, and corresponds
// to 0xf23a6e61.
//
// Note that this is Ethereum specific, I don't know how it translates in Ink! land.
const MAGIC_VALUE: [u8; 4] = [242, 58, 110, 97];

type TokenId = u128;
type Balance = <ink_env::DefaultEnvironment as ink_env::Environment>::Balance;

/// The interface for an ERC-1155 compliant contract.
///
/// The interface is defined here: https://eips.ethereum.org/EIPS/eip-1155.
///
/// The goal of ERC-1155 is to allow a single deployed contract to manage a variety of assets.
/// These assets can be fungible, non-fungible, or a combination.
///
/// By tracking multiple assets the ERC-1155 standard is able to support batch transfers, which
/// make it easy to transfer a mix of multiple tokens at once.
#[ink::trait_definition]
pub trait Erc1155 {
    /// Transfer the a `value` amount of `token_id` tokens to the `to` account from the `from`
    /// account.
    ///
    /// Note that the call does not have to originate from the `from` account, and may originate
    /// from any account which is approved to transfer `from`'s tokens.
    #[ink(message)]
    fn safe_transfer_from(
        &mut self,
        from: AccountId,
        to: AccountId,
        token_id: TokenId,
        value: Balance,
        data: Vec<u8>,
    );

    /// Perform a batch transfer of `token_ids` to the `to` account from the `from` account.
    ///
    /// The number of `values` specified to be transfer must match the number of `token_ids`,
    /// otherwise this call will revert.
    ///
    /// Note that the call does not have to originate from the `from` account, and may originate
    /// from any account which is approved to transfer `from`'s tokens.
    #[ink(message)]
    fn safe_batch_transfer_from(
        &mut self,
        from: AccountId,
        to: AccountId,
        token_ids: Vec<TokenId>,
        values: Vec<Balance>,
        data: Vec<u8>,
    );

    /// Query the balance of a specific token for the provided account.
    #[ink(message)]
    fn balance_of(&self, owner: AccountId, token_id: TokenId) -> Balance;

    /// Query the balances for a set of tokens for a set of accounts.
    ///
    /// E.g use this call if you want to query what Alice and Bob's balances are for Tokens ID1 and
    /// ID2.
    ///
    /// This will return all the balances for a given owner before moving on to the next owner. In
    /// the example above this means that the return value should look like:
    ///
    /// [Alice Balance of Token ID1, Alice Balance of Token ID2, Bob Balance of Token ID2, Bob Balance of Token ID2]
    #[ink(message)]
    fn balance_of_batch(
        &self,
        owners: Vec<AccountId>,
        token_ids: Vec<TokenId>,
    ) -> Vec<Balance>;

    /// Enable or disable a third party, known as an `operator`, to control all tokens on behalf of
    /// the caller.
    #[ink(message)]
    fn set_approval_for_all(&mut self, operator: AccountId, approved: bool);

    /// Query if the given `operator` is allowed to control all of `owner`'s tokens.
    #[ink(message)]
    fn is_approved_for_all(&self, owner: AccountId, operator: AccountId) -> bool;
}

/// The interface for an ERC-1155 Token Receiver contract.
///
/// The interface is defined here: https://eips.ethereum.org/EIPS/eip-1155.
///
/// Smart contracts which want to accept token transfers must implement this interface. By default
/// if a contract does not support this interface any transactions originating from an ERC-1155
/// compliant contract which attempt to transfer tokens directly to the contract's address must be
/// reverted.
#[ink::trait_definition]
pub trait Erc1155TokenReceiver {
    /// Handle the receipt of a single ERC-1155 token.
    ///
    /// This should be called by a compliant ERC-1155 contract if the intended recipient is a smart
    /// contract.
    ///
    /// If the smart contract implementing this interface accepts token transfers then it must
    /// return `MAGIC_VALUE` from this function. To reject a transfer it must revert.
    ///
    /// Any callers must revert if they receive anything other than `MAGIC_VALUE` as a return
    /// value.
    #[ink(message)]
    fn on_erc_1155_received(
        &mut self,
        operator: AccountId,
        from: AccountId,
        token_id: TokenId,
        value: Balance,
        data: Vec<u8>,
    ) -> Vec<u8>;

    /// Handle the receipt of multiple ERC-1155 tokens.
    ///
    /// This should be called by a compliant ERC-1155 contract if the intended recipient is a smart
    /// contract.
    ///
    /// If the smart contract implementing this interface accepts token transfers then it must
    /// return `BATCH_MAGIC_VALUE` from this function. To reject a transfer it must revert.
    ///
    /// Any callers must revert if they receive anything other than `BATCH_MAGIC_VALUE` as a return
    /// value.
    #[ink(message)]
    fn on_erc_1155_batch_received(
        &mut self,
        operator: AccountId,
        from: AccountId,
        token_ids: Vec<TokenId>,
        values: Vec<Balance>,
        data: Vec<u8>,
    );
}

#[ink::contract]
mod erc1155 {
    use super::*;

    use ink_env::call::{build_call, utils::ReturnType, ExecutionInput, Selector};
    use ink_prelude::collections::BTreeMap;

    /// Indicate that a token transfer has occured.
    ///
    /// This must be emitted even if a zero value transfer occurs.
    #[ink(event)]
    pub struct TransferSingle {
        operator: AccountId,
        from: AccountId,
        to: AccountId,
        token_id: TokenId,
        value: Balance,
    }

    /// Indicate that an approval event has happened.
    #[ink(event)]
    pub struct ApprovalForAll {
        owner: AccountId,
        operator: AccountId,
        approved: bool,
    }

    /// An ERC-1155 contract.
    #[ink(storage)]
    pub struct Contract {
        /// Tracks the balances of accounts across the different tokens that they might be holding.
        balances: BTreeMap<(AccountId, TokenId), Balance>,

        /// Which accounts (called operators) have been approved to spend funds on behalf of an owner.
        ///
        /// Note that the mapping is Set<(Owner, Operator)>.
        ///
        /// TODO: Figure out why I can't use a Set here...
        approvals: BTreeMap<(AccountId, AccountId), ()>,
    }

    impl Contract {
        #[ink(constructor)]
        pub fn new(balances: BTreeMap<(AccountId, TokenId), Balance>) -> Self {
            Self {
                balances,
                approvals: Default::default(),
            }
        }

        // Helper function for performing single token transfers.
        //
        // Should not be used directly since it's missing certain checks which are important to the
        // ERC-1155 standard (it is expected that the caller has already perfomred these).
        fn perform_transfer(
            &mut self,
            from: AccountId,
            to: AccountId,
            token_id: TokenId,
            value: Balance,
            data: Vec<u8>,
        ) {
            assert!(
                self.balance_of(from, token_id) >= value,
                "Insufficent token balance for transfer."
            );

            if let Some(b) = self.balances.get_mut(&(from, token_id)) {
                *b -= value
            }

            self.balances
                .entry((to, token_id))
                .and_modify(|b| *b += value)
                .or_insert(value);

            self.env().emit_event(TransferSingle {
                operator: self.env().caller(),
                from,
                to,
                token_id,
                value,
            });

            // Quick Haxx, otherwise my tests just panic due to the use of eval_contract()
            #[cfg(not(test))]
            {
                // If our recipient is a smart contract we need to see if they accept or
                // reject this transfer. If they reject it we need to revert the call.
                let params = build_call::<ink_env::DefaultEnvironment>()
                    .callee(to)
                    .gas_limit(5000) // what's the correct amount to use here?
                    .exec_input(
                        // Idk how to get the bytes for the selector
                        ExecutionInput::new(Selector::new([166, 229, 27, 154]))
                        .push_arg(self.env().caller())
                        .push_arg(from)
                        .push_arg(token_id)
                        .push_arg(value)
                        .push_arg(data)
                    )
                    .returns::<ReturnType<Vec<u8>>>()
                    .params();

                match ink_env::eval_contract(&params) {
                    Ok(v) => assert_eq!(
                        v,
                        &MAGIC_VALUE[..],
                        "Recipient contract does not accept token transfers."
                    ),
                    Err(e) => match e {
                        ink_env::Error::CodeNotFound => {
                            // Our recipient wasn't a smart contract, so there's nothing more for
                            // us to do
                        }
                        _ => panic!("{:?}", e),
                    },
                }
            }
        }
    }

    impl super::Erc1155 for Contract {
        #[ink(message)]
        fn safe_transfer_from(
            &mut self,
            from: AccountId,
            to: AccountId,
            token_id: TokenId,
            value: Balance,
            data: Vec<u8>,
        ) {
            // Q: Does the caller change if the function is called from within this smart contract?
            if self.env().caller() != from {
                assert!(
                    self.is_approved_for_all(from, self.env().caller()),
                    "Caller is not allowed to transfer on behalf of {:?}.",
                    from
                );
            }

            // Q: Would a call be reverted if I return an Error vs. just panicking?
            assert!(
                to != AccountId::default(),
                "Cannot send tokens to the zero-address."
            );

            self.perform_transfer(from, to, token_id, value, data);
        }

        #[ink(message)]
        fn safe_batch_transfer_from(
            &mut self,
            from: AccountId,
            to: AccountId,
            token_ids: Vec<TokenId>,
            values: Vec<Balance>,
            data: Vec<u8>,
        ) {
            if self.env().caller() != from {
                assert!(
                    self.is_approved_for_all(from, self.env().caller()),
                    "Caller is not allowed to transfer on behalf of {:?}.",
                    from
                );
            }

            assert!(
                to != AccountId::default(),
                "Cannot send tokens to the zero-address."
            );

            assert_eq!(
                token_ids.len(),
                values.len(),
                "The number of tokens being transferred does
                 not match the number of transfer amounts."
            );

            token_ids.iter().zip(values.iter()).for_each(|(&id, &v)| {
                self.perform_transfer(from, to, id, v, data.clone());
            })
        }

        #[ink(message)]
        fn balance_of(&self, owner: AccountId, token_id: TokenId) -> Balance {
            *self.balances.get(&(owner, token_id)).unwrap_or(&0)
        }

        #[ink(message)]
        fn balance_of_batch(
            &self,
            owners: Vec<AccountId>,
            token_ids: Vec<TokenId>,
        ) -> Vec<Balance> {
            let mut output = Vec::new();
            for o in &owners {
                for t in &token_ids {
                    let amt = self.balance_of(*o, *t);
                    output.push(amt);
                }
            }
            output
        }

        #[ink(message)]
        fn set_approval_for_all(&mut self, operator: AccountId, approved: bool) {
            if approved {
                self.approvals.insert((self.env().caller(), operator), ());
            } else {
                self.approvals.remove(&(self.env().caller(), operator));
            }

            self.env().emit_event(ApprovalForAll {
                owner: self.env().caller(),
                operator,
                approved,
            });
        }

        #[ink(message)]
        fn is_approved_for_all(&self, owner: AccountId, operator: AccountId) -> bool {
            self.approvals.get(&(owner, operator)).is_some()
        }
    }

    impl super::Erc1155TokenReceiver for Contract {
        #[ink(message)]
        fn on_erc_1155_received(
            &mut self,
            _operator: AccountId,
            _from: AccountId,
            _token_id: TokenId,
            _value: Balance,
            _data: Vec<u8>,
        ) -> Vec<u8> {
            unimplemented!("This smart contract does not accept token transfer.")
        }

        #[ink(message)]
        fn on_erc_1155_batch_received(
            &mut self,
            _operator: AccountId,
            _from: AccountId,
            _token_ids: Vec<TokenId>,
            _values: Vec<Balance>,
            _data: Vec<u8>,
        ) {
            unimplemented!("This smart contract does not accept batch token transfers.")
        }
    }

    /// Unit tests.
    #[cfg(not(feature = "ink-experimental-engine"))]
    #[cfg(test)]
    mod tests {
        /// Imports all the definitions from the outer scope so we can use them here.
        use super::*;
        use crate::Erc1155;

        use ink_lang as ink;

        fn set_sender(sender: AccountId) {
            const WALLET: [u8; 32] = [7; 32];
            ink_env::test::push_execution_context::<Environment>(
                sender,
                WALLET.into(),
                1000000,
                1000000,
                ink_env::test::CallData::new(ink_env::call::Selector::new([0x00; 4])), // dummy
            );
        }

        fn default_accounts(
        ) -> ink_env::test::DefaultAccounts<ink_env::DefaultEnvironment> {
            ink_env::test::default_accounts::<ink_env::DefaultEnvironment>()
                .expect("off-chain environment should have been initialized already")
        }

        fn alice() -> AccountId {
            default_accounts().alice
        }

        fn bob() -> AccountId {
            default_accounts().bob
        }

        fn charlie() -> AccountId {
            default_accounts().charlie
        }

        fn init_contract() -> Contract {
            let mut balances = BTreeMap::new();
            balances.insert((alice(), 1), 10);
            balances.insert((alice(), 2), 20);
            balances.insert((bob(), 1), 10);

            Contract::new(balances)
        }

        #[ink::test]
        fn can_get_correct_balance_of() {
            let erc = init_contract();

            assert_eq!(erc.balance_of(alice(), 1), 10);
            assert_eq!(erc.balance_of(alice(), 2), 20);
            assert_eq!(erc.balance_of(alice(), 3), 0);
            assert_eq!(erc.balance_of(bob(), 2), 0);
        }

        #[ink::test]
        fn can_get_correct_batch_balance_of() {
            let erc = init_contract();

            assert_eq!(
                erc.balance_of_batch(vec![alice()], vec![1, 2, 3]),
                vec![10, 20, 0]
            );
            assert_eq!(
                erc.balance_of_batch(vec![alice(), bob()], vec![1]),
                vec![10, 10]
            );

            assert_eq!(
                erc.balance_of_batch(vec![alice(), bob(), charlie()], vec![1, 2]),
                vec![10, 20, 10, 0, 0, 0]
            );
        }

        #[ink::test]
        fn can_send_tokens_between_accounts() {
            let mut erc = init_contract();

            erc.safe_transfer_from(alice(), bob(), 1, 5, vec![]);
            assert_eq!(erc.balance_of(alice(), 1), 5);
            assert_eq!(erc.balance_of(bob(), 1), 15);

            erc.safe_transfer_from(alice(), bob(), 2, 5, vec![]);
            assert_eq!(erc.balance_of(alice(), 2), 15);
            assert_eq!(erc.balance_of(bob(), 2), 5);
        }

        #[ink::test]
        #[should_panic]
        fn sending_too_many_tokens_fails() {
            let mut erc = init_contract();
            erc.safe_transfer_from(alice(), bob(), 1, 99, vec![]);
        }

        #[ink::test]
        #[should_panic]
        fn sending_tokens_to_zero_address_fails() {
            let burn: AccountId = [0; 32].into();

            let mut erc = init_contract();
            erc.safe_transfer_from(alice(), burn, 1, 10, vec![]);
        }

        #[ink::test]
        fn can_send_batch_tokens() {
            let mut erc = init_contract();
            erc.safe_batch_transfer_from(alice(), bob(), vec![1, 2], vec![5, 10], vec![]);

            let balances = erc.balance_of_batch(vec![alice(), bob()], vec![1, 2]);
            assert_eq!(balances, vec![5, 10, 15, 10])
        }

        #[ink::test]
        #[should_panic]
        fn rejects_batch_if_lengths_dont_match() {
            let mut erc = init_contract();
            erc.safe_batch_transfer_from(alice(), bob(), vec![1, 2, 3], vec![5], vec![]);
        }

        #[ink::test]
        fn operator_can_send_tokens() {
            let mut erc = init_contract();

            let owner = alice();
            let operator = bob();

            set_sender(owner);
            erc.set_approval_for_all(operator, true);

            set_sender(operator);
            erc.safe_transfer_from(owner, charlie(), 1, 5, vec![]);
            assert_eq!(erc.balance_of(alice(), 1), 5);
            assert_eq!(erc.balance_of(charlie(), 1), 5);
        }

        #[ink::test]
        fn approvals_work() {
            let mut erc = init_contract();
            let owner = alice();
            let operator = bob();
            let another_operator = charlie();

            // Note: All of these tests are from the context of the owner who is either allowing or
            // disallowing an operator to control their funds.
            set_sender(owner);
            assert!(erc.is_approved_for_all(owner, operator) == false);

            erc.set_approval_for_all(operator, true);
            assert!(erc.is_approved_for_all(owner, operator));

            erc.set_approval_for_all(another_operator, true);
            assert!(erc.is_approved_for_all(owner, another_operator));

            erc.set_approval_for_all(operator, false);
            assert!(erc.is_approved_for_all(owner, operator) == false);
        }
    }
}
