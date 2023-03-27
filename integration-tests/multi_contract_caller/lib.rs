#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), no_main)]

#[ink::contract]
mod multi_contract_caller {
    use accumulator::AccumulatorRef;
    use adder::AdderRef;
    use subber::SubberRef;

    /// Specifies the state of the `multi_contract_caller` contract.
    ///
    /// In `Adder` state the `multi_contract_caller` contract will call the `Adder`
    /// contract and in `Subber` state will call to the `Subber` contract.
    ///
    /// The initial state is `Adder`.
    #[derive(Debug, Copy, Clone, PartialEq, Eq, scale::Decode, scale::Encode)]
    #[cfg_attr(
        feature = "std",
        derive(ink::storage::traits::StorageLayout, scale_info::TypeInfo)
    )]
    pub enum Which {
        Adder,
        Subber,
    }

    /// Calls to an `adder` or `subber` contract to mutate a value in an `accumulator`
    /// contract.
    ///
    /// # Note
    ///
    /// In order to instantiate the `multi_contract_caller` smart contract we first
    /// have to manually put the code of the `accumulator`, `adder`
    /// and `subber` smart contracts, receive their code hashes from
    /// the signalled events and put their code hash into our
    /// `multi_contract_caller` smart contract.
    ///
    /// The `AccumulatorRef`, `AdderRef` and `SubberRef` are smart contract
    /// reference types that have been automatically generated by ink!.
    #[ink(storage)]
    pub struct MultiContractCaller {
        /// Says which of `adder` or `subber` is currently in use.
        which: Which,
        /// The `accumulator` smart contract.
        accumulator: AccumulatorRef,
        /// The `adder` smart contract.
        adder: AdderRef,
        /// The `subber` smart contract.
        subber: SubberRef,
    }

    impl MultiContractCaller {
        /// Instantiate a `multi_contract_caller` contract with the given sub-contract
        /// codes.
        #[ink(constructor)]
        pub fn new(
            init_value: i32,
            version: u32,
            accumulator_code_hash: Hash,
            adder_code_hash: Hash,
            subber_code_hash: Hash,
        ) -> Self {
            let total_balance = Self::env().balance();
            let salt = version.to_le_bytes();
            let accumulator = AccumulatorRef::new(init_value)
                .endowment(total_balance / 4)
                .code_hash(accumulator_code_hash)
                .salt_bytes(salt)
                .instantiate();
            let adder = AdderRef::new(accumulator.clone())
                .endowment(total_balance / 4)
                .code_hash(adder_code_hash)
                .salt_bytes(salt)
                .instantiate();
            let subber = SubberRef::new(accumulator.clone())
                .endowment(total_balance / 4)
                .code_hash(subber_code_hash)
                .salt_bytes(salt)
                .instantiate();
            Self {
                which: Which::Adder,
                accumulator,
                adder,
                subber,
            }
        }

        /// Returns the `accumulator` value.
        #[ink(message)]
        pub fn get(&self) -> i32 {
            self.accumulator.get()
        }

        /// Delegates the call to either `Adder` or `Subber`.
        #[ink(message)]
        pub fn change(&mut self, by: i32) {
            match self.which {
                Which::Adder => self.adder.inc(by),
                Which::Subber => self.subber.dec(by),
            }
        }

        /// Switches the `multi_contract_caller` contract.
        #[ink(message)]
        pub fn switch(&mut self) {
            match self.which {
                Which::Adder => {
                    self.which = Which::Subber;
                }
                Which::Subber => {
                    self.which = Which::Adder;
                }
            }
        }
    }

    #[cfg(all(test, feature = "e2e-tests"))]
    mod e2e_tests {
        use super::MultiContractCallerRef;
        use ink_e2e::build_message;

        type E2EResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

        #[ink_e2e::test]
        async fn e2e_multi_contract_caller(
            mut client: ink_e2e::Client<C, E>,
        ) -> E2EResult<()> {
            // given
            let accumulator_hash = client
                .upload("accumulator", &ink_e2e::alice(), None)
                .await
                .expect("uploading `accumulator` failed")
                .code_hash;

            let adder_hash = client
                .upload("adder", &ink_e2e::alice(), None)
                .await
                .expect("uploading `adder` failed")
                .code_hash;

            let subber_hash = client
                .upload("subber", &ink_e2e::alice(), None)
                .await
                .expect("uploading `subber` failed")
                .code_hash;

            let constructor = MultiContractCallerRef::new(
                1234, // initial value
                1337, // salt
                accumulator_hash,
                adder_hash,
                subber_hash,
            );

            let multi_contract_caller_acc_id = client
                .instantiate(
                    "multi_contract_caller",
                    &ink_e2e::alice(),
                    constructor,
                    0,
                    None,
                )
                .await
                .expect("instantiate failed")
                .account_id;

            // when
            let get = build_message::<MultiContractCallerRef>(
                multi_contract_caller_acc_id.clone(),
            )
            .call(|contract| contract.get());
            let value = client
                .call_dry_run(&ink_e2e::bob(), &get, 0, None)
                .await
                .return_value();
            assert_eq!(value, 1234);
            let change = build_message::<MultiContractCallerRef>(
                multi_contract_caller_acc_id.clone(),
            )
            .call(|contract| contract.change(6));
            let _ = client
                .call(&ink_e2e::bob(), change, 0, None)
                .await
                .expect("calling `change` failed");

            // then
            let get = build_message::<MultiContractCallerRef>(
                multi_contract_caller_acc_id.clone(),
            )
            .call(|contract| contract.get());
            let value = client
                .call_dry_run(&ink_e2e::bob(), &get, 0, None)
                .await
                .return_value();
            assert_eq!(value, 1234 + 6);

            // when
            let switch = build_message::<MultiContractCallerRef>(
                multi_contract_caller_acc_id.clone(),
            )
            .call(|contract| contract.switch());
            let _ = client
                .call(&ink_e2e::bob(), switch, 0, None)
                .await
                .expect("calling `switch` failed");
            let change = build_message::<MultiContractCallerRef>(
                multi_contract_caller_acc_id.clone(),
            )
            .call(|contract| contract.change(3));
            let _ = client
                .call(&ink_e2e::bob(), change, 0, None)
                .await
                .expect("calling `change` failed");

            // then
            let get = build_message::<MultiContractCallerRef>(
                multi_contract_caller_acc_id.clone(),
            )
            .call(|contract| contract.get());
            let value = client
                .call_dry_run(&ink_e2e::bob(), &get, 0, None)
                .await
                .return_value();
            assert_eq!(value, 1234 + 6 - 3);

            Ok(())
        }
    }
}
