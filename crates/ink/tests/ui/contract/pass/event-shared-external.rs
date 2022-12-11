#[ink::event_definition]
pub enum SharedEvent {
    Event1 {
        arg_1: u8,
        #[ink(topic)]
        arg_2: u16,
    },
}

#[ink::contract]
mod contract {
    #[ink(storage)]
    pub struct Contract {}

    impl Contract {
        #[ink(constructor)]
        pub fn constructor() -> Self {
            Self {}
        }

        #[ink(message)]
        pub fn message(&self) {
            self.env()
                .emit_event(super::SharedEvent::Event1 { arg_1: 1, arg_2: 2 });
        }
    }
}

fn main() {}
