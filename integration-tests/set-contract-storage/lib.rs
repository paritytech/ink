#![cfg_attr(not(feature = "std"), no_std, no_main)]

#[ink::contract]
mod set_contract_storage {
    use ink::env::set_contract_storage;

    const SIZE_LIMIT: usize = (1 << 14) - 4;

    #[ink(storage)]
    pub struct SetContractStorage {}

    impl SetContractStorage {
        /// Creates a new SetContractStorage contract.
        #[ink(constructor)]
        pub fn new() -> Self {
            Self {}
        }

        /// Stores an array that is JUST big enough to be validly allocated.
        #[ink(message)]
        pub fn set_storage_big(&self) {
            set_contract_storage(&42, &[42u8; SIZE_LIMIT]);
        }

        /// Tries to store the smallest array that is too big to be validly
        /// allocated. This function should always fail.
        #[ink(message)]
        pub fn set_storage_very_big(&self) {
            set_contract_storage(&42, &[42u8; SIZE_LIMIT + 1]);
        }
    }

    impl Default for SetContractStorage {
        fn default() -> Self {
            Self::new()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[ink::test]
        fn contract_storage_big() {
            let contract = SetContractStorage::new();

            contract.set_storage_big();

            assert_eq!(0, 0);
        }

        #[ink::test]
        #[should_panic(
            expected = "Value too large to be stored in contract storage, maximum size is 16380 bytes"
        )]
        fn contract_storage_too_big() {
            let contract = SetContractStorage::new();

            contract.set_storage_very_big();
        }
    }

    #[cfg(all(test, feature = "e2e-tests"))]
    mod e2e_tests {
        use ink_e2e::ContractsBackend;

        use super::*;

        type E2EResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

        #[ink_e2e::test]
        async fn contract_storage_big(
            mut client: ink_e2e::Client<C, E>,
        ) -> E2EResult<()> {
            // given
            let constructor = SetContractStorageRef::new();

            let contract = client
                .instantiate(
                    "set-contract-storage",
                    &ink_e2e::alice(),
                    constructor,
                    0,
                    None,
                )
                .await
                .expect("instantiate failed");
            let contract_acc_id = contract.account_id;
            let mut call = contract.call::<SetContractStorage>();

            // when
            let set_storage_big_call = call.set_storage_big();

            client
                .call(&ink_e2e::alice(), &set_storage_big_call, 0, None)
                .await
                .expect("set_storage_big failed");

            Ok(())
        }

        #[ink_e2e::test]
        #[should_panic]
        async fn contract_storage_too_big(mut client: ink_e2e::Client<C, E>) {
            // given
            let constructor = SetContractStorageRef::new();

            let contract = client
                .instantiate(
                    "set-contract-storage",
                    &ink_e2e::bob(),
                    constructor,
                    0,
                    None,
                )
                .await
                .expect("instantiate failed");
            let contract_acc_id = contract.account_id;
            let mut call = contract.call::<SetContractStorage>();

            // when
            let set_storage_very_big_call = call.set_storage_very_big();

            client
                .call(&ink_e2e::bob(), &set_storage_very_big_call, 0, None)
                .await
                .expect("set_storage_very_big failed");
        }
    }
}
