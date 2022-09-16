#![cfg_attr(not(feature = "std"), no_std)]

#[ink::contract]
mod delegator {
    use accumulator::AccumulatorRef;
    use adder::AdderRef;
    use subber::SubberRef;

    /// Specifies the state of the `delegator` contract.
    ///
    /// In `Adder` state the `delegator` contract will delegate to the `Adder` contract
    /// and in `Subber` state will delegate to the `Subber` contract.
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

    /// Delegates calls to an `adder` or `subber` contract to mutate
    /// a value in an `accumulator` contract.
    ///
    /// # Note
    ///
    /// In order to instantiate the `delegator` smart contract we first
    /// have to manually put the code of the `accumulator`, `adder`
    /// and `subber` smart contracts, receive their code hashes from
    /// the signalled events and put their code hash into our
    /// `delegator` smart contract.
    ///
    /// The `AccumulatorRef`, `AdderRef` and `SubberRef` are smart contract
    /// reference types that have been automatically generated by ink!.
    #[ink(storage)]
    pub struct Delegator {
        /// Says which of `adder` or `subber` is currently in use.
        which: Which,
        /// The `accumulator` smart contract.
        accumulator: AccumulatorRef,
        /// The `adder` smart contract.
        adder: AdderRef,
        /// The `subber` smart contract.
        subber: SubberRef,
    }

    impl Delegator {
        /// Instantiate a `delegator` contract with the given sub-contract codes.
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
                .instantiate()
                .unwrap_or_else(|error| {
                    panic!(
                        "failed at instantiating the Accumulator contract: {:?}",
                        error
                    )
                });
            let adder = AdderRef::new(accumulator.clone())
                .endowment(total_balance / 4)
                .code_hash(adder_code_hash)
                .salt_bytes(salt)
                .instantiate()
                .unwrap_or_else(|error| {
                    panic!("failed at instantiating the Adder contract: {:?}", error)
                });
            let subber = SubberRef::new(accumulator.clone())
                .endowment(total_balance / 4)
                .code_hash(subber_code_hash)
                .salt_bytes(salt)
                .instantiate()
                .unwrap_or_else(|error| {
                    panic!("failed at instantiating the Subber contract: {:?}", error)
                });
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

        /// Switches the `delegator` contract.
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
}
