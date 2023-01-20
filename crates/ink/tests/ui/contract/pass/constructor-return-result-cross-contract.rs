#[ink::contract]
mod contract_callee {
    #[ink(storage)]
    pub struct Callee {}

    #[derive(Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(::scale_info::TypeInfo))]
    pub enum Error {
        Foo,
    }

    impl Callee {
        #[ink(constructor)]
        pub fn new_self() -> Self {
            Self { }
        }

        #[ink(constructor)]
        pub fn new_storage_name() -> Callee {
            Callee { }
        }

        #[ink(constructor)]
        pub fn new_result_self() -> Result<Self, Error> {
            Ok(Self { })
        }

        #[ink(constructor)]
        pub fn new_result_storage_name() -> Result<Callee, Error> {
            Ok(Callee { })
        }

        #[ink(message)]
        pub fn message(&self) {}
    }
}

// #[ink::contract]
// mod contract_caller {
//     use super::contract_callee::{CalleeRef, Error};
//
//     #[ink(storage)]
//     pub struct Caller {}
//
//     impl Caller {
//         #[ink(constructor)]
//         pub fn new() -> Self {
//             Self { }
//         }
//
//         #[ink(message)]
//         pub fn invoke_callee_constructors(&self) {
//             let _: Result<CalleeRef, Error> = CalleeRef::new_result_self()
//                 .code_hash(Hash::from([0x42; 32]))
//                 .gas_limit(4000)
//                 .endowment(25)
//                 .salt_bytes([0xDE, 0xAD, 0xBE, 0xEF])
//                 .instantiate()
//                 .unwrap();
//
//             // let _: Result<CalleeRef, Error> = CalleeRef::new_result_storage_name().instantiate();
//             //
//             // let _: CalleeRef = CalleeRef::new_self().instantiate();
//             //
//             // let _: CalleeRef = CalleeRef::new_storage_name().instantiate();
//         }
//     }
// }

fn main() {
    use contract_callee::{CalleeRef, Error};

    // fn new_self() -> Self
    let _: fn() -> CalleeRef = || {
        CalleeRef::new_self()
            .code_hash(ink_primitives::Clear::CLEAR_HASH)
            .gas_limit(4000)
            .endowment(25)
            .salt_bytes([0xDE, 0xAD, 0xBE, 0xEF])
            .instantiate()
            .unwrap()
    };

    // fn new_storage_name() -> Callee
    let _: fn() -> CalleeRef = || {
        CalleeRef::new_storage_name()
            .code_hash(ink_primitives::Clear::CLEAR_HASH)
            .gas_limit(4000)
            .endowment(25)
            .salt_bytes([0xDE, 0xAD, 0xBE, 0xEF])
            .instantiate()
            .unwrap()
    };

    // fn new_result_self() -> Result<Self, Error>
    let _: fn() -> Result<CalleeRef, Error> = || {
        CalleeRef::new_result_self()
            .code_hash(ink_primitives::Clear::CLEAR_HASH)
            .gas_limit(4000)
            .endowment(25)
            .salt_bytes([0xDE, 0xAD, 0xBE, 0xEF])
            .instantiate()
            .unwrap()
    };

    // fn new_result_storage_name() -> Result<Callee, Error>
    let _: fn() -> Result<CalleeRef, Error> = || {
        CalleeRef::new_result_self()
            .code_hash(ink_primitives::Clear::CLEAR_HASH)
            .gas_limit(4000)
            .endowment(25)
            .salt_bytes([0xDE, 0xAD, 0xBE, 0xEF])
            .instantiate()
            .unwrap()
    };
}


