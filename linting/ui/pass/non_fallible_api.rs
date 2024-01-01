#![cfg_attr(not(feature = "std"), no_std, no_main)]

#[ink::contract]
pub mod non_fallible_api {
    use ink::storage::{
        Lazy,
        Mapping,
    };

    #[ink(storage)]
    pub struct NonFallibleAPI {
        map_1: Mapping<AccountId, AccountId>,
        lazy_1: Lazy<AccountId>,
    }

    impl NonFallibleAPI {
        #[ink(constructor)]
        pub fn new() -> Self {
            Self {
                map_1: Mapping::new(),
                lazy_1: Lazy::new(),
            }
        }

        // Don't generate warnings when using the fallible API
        #[ink(message)]
        pub fn fallible(&mut self, a: AccountId, b: AccountId) {
            // Mapping
            let _ = self.map_1.try_insert(a, &b);
            let _ = self.map_1.try_get(a);
            let _ = self.map_1.try_take(a);

            // Lazy
            let _ = self.lazy_1.try_get();
            let _ = self.lazy_1.try_set(&a);
        }

        // Don't raise warnings when using non-fallible API with argument which encoded
        // size is statically known.
        #[ink(message)]
        pub fn non_fallible_statically_known(&mut self, a: AccountId, b: AccountId) {
            // Mapping
            let _ = self.map_1.insert(a, &b);
            let _ = self.map_1.get(a);
            let _ = self.map_1.take(a);

            // Lazy
            let _ = self.lazy_1.get();
            self.lazy_1.set(&a);
        }
    }
}

fn main() {}
