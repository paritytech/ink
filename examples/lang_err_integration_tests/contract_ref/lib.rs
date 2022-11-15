#![cfg_attr(not(feature = "std"), no_std)]

#[ink::contract]
mod contract_ref {
    use integration_flipper::FlipperRef;

    #[ink(storage)]
    pub struct CrossChainRef {
        flipper: FlipperRef,
    }

    impl CrossChainRef {
        #[ink(constructor)]
        pub fn new(version: u32, flipper_code_hash: Hash) -> Self {
            let salt = version.to_le_bytes();
            let flipper = FlipperRef::default()
                .endowment(0)
                .code_hash(flipper_code_hash)
                .salt_bytes(salt)
                .instantiate()
                .unwrap_or_else(|error| {
                    panic!("failed at instantiating the Flipper contract: {:?}", error)
                });

            Self { flipper }
        }

        #[ink(message)]
        pub fn flip(&mut self) {
            self.flipper.flip();
        }

        #[ink(message)]
        pub fn flip_check(&mut self) {
            self.flipper.flip_checked().unwrap();
        }

        #[ink(message)]
        pub fn get(&mut self) -> bool {
            self.flipper.get()
        }

        #[ink(message)]
        pub fn get_check(&mut self) -> bool {
            self.flipper.get_checked().unwrap()
        }
    }

    #[cfg(all(test, feature = "e2e-tests"))]
    mod e2e_tests {
        type E2EResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

        #[ink_e2e::test(additional_contracts = "../flipper/Cargo.toml")]
        async fn e2e_contract_ref(mut client: ink_e2e::Client<C, E>) -> E2EResult<()> {
            let flipper_hash: ink_e2e::H256 = client
                .upload(&mut ink_e2e::alice(), flipper::CONTRACT_PATH, None)
                .await
                .expect("uploading `flipper` failed")
                .code_hash;
            let flipper_hash = ink_e2e::utils::runtime_hash_to_ink_hash::<
                ink::env::DefaultEnvironment,
            >(&flipper_hash);

            let constructor =
                contract_ref::constructors::new(Default::default(), flipper_hash);
            let contract_acc_id = client
                .instantiate(&mut ink_e2e::alice(), constructor, 0, None)
                .await
                .expect("instantiate failed")
                .account_id;

            let get_call_result = client
                .call(
                    &mut ink_e2e::alice(),
                    contract_acc_id.clone(),
                    contract_ref::messages::get_check(),
                    0,
                    None,
                )
                .await
                .expect("Calling `get_check` failed");
            let initial_value = get_call_result
                .value
                .expect("Input is valid, call must not fail.");

            let flip_call_result = client
                .call(
                    &mut ink_e2e::alice(),
                    contract_acc_id.clone(),
                    contract_ref::messages::flip_check(),
                    0,
                    None,
                )
                .await
                .expect("Calling `flip` failed");
            assert!(
                flip_call_result.value.is_ok(),
                "Messages now return a `Result`, which should be `Ok` here."
            );

            let get_call_result = client
                .call(
                    &mut ink_e2e::alice(),
                    contract_acc_id.clone(),
                    contract_ref::messages::get_check(),
                    0,
                    None,
                )
                .await
                .expect("Calling `get` failed");
            let flipped_value = get_call_result
                .value
                .expect("Input is valid, call must not fail.");
            assert!(flipped_value != initial_value);

            Ok(())
        }
    }
}
