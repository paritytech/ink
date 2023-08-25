#[ink::contract]
mod contract {
    #[ink(storage)]
    pub struct Contract {}

    #[derive(Debug, PartialEq, Eq)]
    #[ink::scale_derive(encode, decode, type_info)]
    pub enum Error {
        Foo,
    }

    impl Contract {
        #[ink(constructor)]
        pub fn constructor() -> Result<Self, Error> {
            Err(Error::Foo)
        }

        #[ink(message)]
        pub fn message(&self) {}
    }
}

fn main() {
    use contract::Contract;
    use std::any::TypeId;

    const ID: u32 = ::ink::selector_id!("constructor");
    assert_eq!(
        <Contract as ::ink::reflect::DispatchableConstructorInfo<ID>>::IS_RESULT,
        true
    );
    assert_eq!(
        TypeId::of::<<Contract as ::ink::reflect::DispatchableConstructorInfo<ID>>::Error>(
        ),
        TypeId::of::<contract::Error>(),
    )
}
