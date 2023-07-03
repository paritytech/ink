#[ink::contract]
pub mod primitive_topic {

    #[ink(event)]
    pub struct Transaction {
        #[ink(topic)]
        src: Option<AccountId>,
        #[ink(topic)]
        dst: Option<AccountId>,
        // Good: no topic annotation
        value_1: Balance,
        // TODO: Good: warning is suppressed
        // value_2: Balance,
    }

    #[ink(storage)]
    pub struct PrimitiveTopic {}

    impl PrimitiveTopic {
        #[ink(constructor)]
        pub fn new() -> Self {
            Self {}
        }
        #[ink(message)]
        pub fn do_nothing(&mut self) {}
    }
}

fn main() {}
