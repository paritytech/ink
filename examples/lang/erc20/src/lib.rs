// Copyright 2018-2019 Parity Technologies (UK) Ltd.
// This file is part of ink!.
//
// ink! is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// ink! is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with ink!.  If not, see <http://www.gnu.org/licenses/>.

#![cfg_attr(not(any(test, feature = "test-env")), no_std)]

use ink_core::{
    env::{
        self,
        AccountId,
        Balance,
    },
    memory::format,
    storage,
};
use ink_lang::contract;

contract! {
    /// The storage items for a typical ERC20 token implementation.
    struct Erc20 {
        /// All peeps done by all users.
        balances: storage::HashMap<AccountId, Balance>,
        /// Balances that are spendable by non-owners.
        ///
        /// # Note
        ///
        /// Mapping: (from, to) -> allowed
        allowances: storage::HashMap<(AccountId, AccountId), Balance>,
        /// The total supply.
        total_supply: storage::Value<Balance>,
    }

    event Approval { owner: AccountId, spender: AccountId, value: Balance }
    event Transfer { from: Option<AccountId>, to: Option<AccountId>, value: Balance }

    impl Deploy for Erc20 {
        fn deploy(&mut self, init_value: Balance) {
            // We have to set total supply to `0` in order to initialize it.
            // Otherwise accesses to total supply will panic.
            env.println(&format!("Erc20::deploy(caller = {:?}, init_value = {:?})", env.caller(), init_value));
            self.total_supply.set(init_value);
            self.balances.insert(env.caller(), init_value);
            env.emit(Transfer{ from: None, to: Some(env.caller()), value: init_value });
        }
    }

    impl Erc20 {
        /// Returns the total number of tokens in existence.
        pub(external) fn total_supply(&self) -> Balance {
            let total_supply = *self.total_supply;
            env.println(&format!("Erc20::total_supply = {:?}", total_supply));
            total_supply
        }

        /// Returns the balance of the given address.
        pub(external) fn balance_of(&self, owner: AccountId) -> Balance {
            let balance = self.balance_of_or_zero(&owner);
            env.println(&format!("Erc20::balance_of(owner = {:?}) = {:?}", owner, balance));
            balance
        }

        /// Returns the amount of tokens that an owner allowed to a spender.
        pub(external) fn allowance(&self, owner: AccountId, spender: AccountId) -> Balance {
            self.allowance_or_zero(&owner, &spender)
        }

        /// Transfers token from the sender to the `to` address.
        pub(external) fn transfer(&mut self, to: AccountId, value: Balance) -> bool {
            env.println(&format!(
                "Erc20::transfer(to = {:?}, value = {:?})",
                to, value
            ));
            self.transfer_impl(env, env.caller(), to, value)
        }

        /// Approve the passed address to spend the specified amount of tokens
        /// on the behalf of the message's sender.
        pub(external) fn approve(&mut self, spender: AccountId, value: Balance) -> bool {
            env.println(&format!(
                "Erc20::approve(spender = {:?}, value = {:?})",
                spender, value
            ));
            let owner = env.caller();
            self.allowances.insert((owner, spender), value);
            env.emit(Approval{ owner, spender, value });
            true
        }

        /// Transfer tokens from one address to another.
        pub(external) fn transfer_from(&mut self, from: AccountId, to: AccountId, value: Balance) -> bool {
            env.println(&format!(
                "Erc20::transfer_from(from: {:?}, to = {:?}, value = {:?})",
                from, to, value
            ));
            self.transfer_impl(env, from, to, value)
        }
    }

    impl Erc20 {
        /// Decreases the allowance and returns if it was successful.
        fn try_decrease_allowance(&mut self, from: &AccountId, by: Balance) -> bool {
            // The owner of the coins doesn't need an allowance.
            if &env::caller() == from {
                return true
            }
            let allowance = self.allowance_or_zero(from, &env::caller());
            if allowance < by {
                return false
            }
            self.allowances.insert((*from, env::caller()), allowance - by);
            true
        }

        /// Returns the allowance or 0 of there is no allowance.
        fn allowance_or_zero(&self, from: &AccountId, to: &AccountId) -> Balance {
            let allowance = self.allowances.get(&(*from, *to)).unwrap_or(&0);
            env::println(&format!(
                "Erc20::allowance_or_zero(from = {:?}, to = {:?}) = {:?}",
                from, to, allowance
            ));
            *allowance
        }

        /// Returns the balance of the address or 0 if there is no balance.
        fn balance_of_or_zero(&self, of: &AccountId) -> Balance {
            let balance = self.balances.get(of).unwrap_or(&0);
            env::println(&format!(
                "Erc20::balance_of_or_zero(of = {:?}) = {:?}",
                of, balance
            ));
            *balance
        }

        /// Transfers token from a specified address to another address.
        fn transfer_impl(
            &mut self,
            env: &ink_model::EnvHandler,
            from: AccountId,
            to: AccountId,
            value: Balance
        ) -> bool {
            env::println(&format!(
                "Erc20::transfer_impl(from = {:?}, to = {:?}, value = {:?})",
                from, to, value
            ));
            let balance_from = self.balance_of_or_zero(&from);
            let balance_to = self.balance_of_or_zero(&to);
            if balance_from < value {
                return false
            }
            if !self.try_decrease_allowance(&from, value) {
                return false
            }
            self.balances.insert(from, balance_from - value);
            self.balances.insert(to, balance_to + value);
            env.emit(Transfer{ from: Some(from), to: Some(to), value });
            true
        }
    }
}

#[cfg(all(test, feature = "test-env"))]
mod tests {
    use super::*;
    use std::convert::TryFrom;

    #[test]
    fn transfer_works() {
        let mut erc20 = Erc20::deploy_mock(1234);
        let alice = AccountId::try_from([0x0; 32]).unwrap();
        let bob = AccountId::try_from([0x1; 32]).unwrap();

        env::test::set_caller(alice);
        assert_eq!(erc20.total_supply(), 1234);
        assert_eq!(erc20.balance_of(alice), 1234);
        // Alice does not have enough funds for this
        assert_eq!(erc20.transfer(bob, 4321), false);
        // Alice can do this though
        assert_eq!(erc20.transfer(bob, 234), true);
        assert_eq!(erc20.balance_of(alice), 1000);
        assert_eq!(erc20.balance_of(bob), 234);
    }

    #[test]
    fn allowance_works() {
        let mut erc20 = Erc20::deploy_mock(1234);
        let alice = AccountId::try_from([0x0; 32]).unwrap();
        let bob = AccountId::try_from([0x1; 32]).unwrap();
        let charlie = AccountId::try_from([0x2; 32]).unwrap();

        env::test::set_caller(alice);
        // Not allowed, since alice is the caller
        // and she has no approval from bob.
        assert_eq!(erc20.transfer_from(bob, alice, 1), false);
        assert_eq!(erc20.allowance(alice, bob), 0);
        assert_eq!(erc20.approve(bob, 20), true);
        assert_eq!(erc20.allowance(alice, bob), 20);

        // Charlie cannot send on behalf of Bob or Alice
        env::test::set_caller(charlie);
        assert_eq!(erc20.transfer_from(alice, bob, 10), false);
        // Bob cannot transfer more than he is allowed
        env::test::set_caller(bob);
        assert_eq!(erc20.transfer_from(alice, charlie, 25), false);
        // This should work though
        assert_eq!(erc20.transfer_from(alice, charlie, 10), true);
        // Allowance is updated
        assert_eq!(erc20.allowance(alice, bob), 10);
        // Balance transferred to the right person
        assert_eq!(erc20.balance_of(charlie), 10);
    }
}
