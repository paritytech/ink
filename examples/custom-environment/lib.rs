#![cfg_attr(not(feature = "std"), no_std)]

use ink::env::{
    DefaultEnvironment,
    Environment,
};

/// Our custom environment diverges from the `DefaultEnvironment` in the event topics limit.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub enum EnvironmentWithManyTopics {}

impl Environment for EnvironmentWithManyTopics {
    // We allow for 5 topics in the event, therefore the contract pallet's schedule must allow for
    // 6 of them (to allow the implicit topic for the event signature).
    const MAX_EVENT_TOPICS: usize =
        <DefaultEnvironment as Environment>::MAX_EVENT_TOPICS + 1;

    type AccountId = <DefaultEnvironment as Environment>::AccountId;
    type Balance = <DefaultEnvironment as Environment>::Balance;
    type Hash = <DefaultEnvironment as Environment>::Hash;
    type BlockNumber = <DefaultEnvironment as Environment>::BlockNumber;
    type Timestamp = <DefaultEnvironment as Environment>::Timestamp;

    type ChainExtension = <DefaultEnvironment as Environment>::ChainExtension;
}

#[ink::contract(env = crate::EnvironmentWithManyTopics)]
mod runtime_call {
    /// Trivial contract with a single message that emits an event with many topics.
    #[ink(storage)]
    #[derive(Default)]
    pub struct Topics;

    /// An event that would be forbidden in the default environment, but is completely valid in
    /// our custom one.
    #[ink(event)]
    #[derive(Default)]
    pub struct EventWithTopics {
        #[ink(topic)]
        first_topic: Balance,
        #[ink(topic)]
        second_topic: Balance,
        #[ink(topic)]
        third_topic: Balance,
        #[ink(topic)]
        fourth_topic: Balance,
        #[ink(topic)]
        fifth_topic: Balance,
    }

    impl Topics {
        #[ink(constructor)]
        pub fn new() -> Self {
            Default::default()
        }

        /// Emit an event with many topics.
        #[ink(message)]
        pub fn trigger(&mut self) {
            self.env().emit_event(EventWithTopics::default());
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[ink::test]
        fn emits_event_with_many_topics() {
            let mut contract = Topics::new();
            contract.trigger();

            let emitted_events = ink::env::test::recorded_events().collect::<Vec<_>>();
            assert_eq!(emitted_events.len(), 1);

            let _ = <<Topics as ink::reflect::ContractEventBase>::Type as scale::Decode>::decode(&mut &emitted_events[0].data[..])
                .expect("encountered invalid contract event data buffer");
        }
    }

    #[cfg(all(test, feature = "e2e-tests"))]
    mod e2e_tests {
        use super::*;

        use ink_e2e::MessageBuilder;

        type E2EResult<T> = Result<T, Box<dyn std::error::Error>>;

        #[ink_e2e::test(environment = crate::EnvironmentWithManyTopics)]
        #[ignore = "Requires that the pallet contract is configured with a schedule allowing for \
            more event topics. For example:\
            ```rust
            pub Schedule: pallet_contracts::Schedule<Runtime> = pallet_contracts::Schedule::<Runtime> {
                limits: pallet_contracts::Limits {
                    event_topics: 6,
                    ..Default::default()
                },
                ..Default::default()
            };
            };
            ```"]
        async fn calling_custom_environment_works(
            mut client: Client<C, E>,
        ) -> E2EResult<()> {
            // given
            let constructor = TopicsRef::new();
            let contract_acc_id = client
                .instantiate(
                    "custom-environment",
                    &ink_e2e::alice(),
                    constructor,
                    0,
                    None,
                )
                .await
                .expect("instantiate failed")
                .account_id;

            // when
            let message =
                MessageBuilder::<crate::EnvironmentWithManyTopics, TopicsRef>::from_account_id(
                    contract_acc_id,
                )
                .call(|caller| caller.trigger());

            let call_res = client
                .call(&ink_e2e::alice(), message, 0, None)
                .await
                .expect("call failed");

            // then
            call_res.contains_event("Contracts", "ContractEmitted");

            Ok(())
        }
    }
}