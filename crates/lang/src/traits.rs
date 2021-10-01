// Copyright 2018-2021 Parity Technologies (UK) Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/// The global call builder type for an ink! trait definition.
pub trait TraitCallBuilder {
    /// The call builder type.
    type Builder;

    /// Returns a shared reference to the global call builder type.
    ///
    /// This allows to call `&self` ink! trait messages.
    fn call(&self) -> &Self::Builder;

    /// Returns an exclusive reference to the global call builder type.
    ///
    /// This allows to call any ink! trait message.
    fn call_mut(&mut self) -> &mut Self::Builder;
}

/// Implemented by the global trait info provider.
///
/// This communicates the `u32` number that uniquely identifies
/// the ink! trait definition.
pub trait TraitUniqueId {
    /// The unique trait `u32` identifier.
    const ID: u32;
}

/// Implemented by the global trait info provider.
///
/// It is used to query the global trait call forwarder.
/// There is one global trait call forwarder that implements
/// the call forwarding (short- and long-form) for all calls
/// to this trait in `ink-as-dependency` configuration.
pub trait TraitCallForwarder {
    /// The call forwarder type.
    type Forwarder: TraitCallBuilder;
}

/// Captures the module path of the ink! trait definition.
///
/// This can be used to differentiate between two equally named
/// ink! trait definitions and also for metadata.
pub trait TraitModulePath {
    /// The module path of the ink! trait definition.
    ///
    /// This is equivalent to Rust's builtin `module_path!` macro
    /// invocation at the definition site of the ink! trait.
    const PATH: &'static str;

    /// The name of the ink! trait.
    ///
    /// This is just for convenience.
    const NAME: &'static str;
}

/// Implemented by call builders of smart contracts.
///
/// These might be implementing multiple different ink! traits.
/// The codegen makes them implement this trait once for every
/// ink! trait they have to implement.
///
/// While the trait is not necessary it encapsulates a lot of
/// utility and auxiliary code required for the actual ink! trait
/// implementations.
pub trait TraitCallForwarderFor<const ID: u32> {
    type Forwarder: TraitCallBuilder;

    /// Forwards the `&self` call.
    ///
    /// # Note
    ///
    /// This is used for the short-hand calling syntax.
    fn forward(&self) -> &Self::Forwarder;

    /// Forwards the `&mut self` call.
    ///
    /// # Note
    ///
    /// This is used for the short-hand calling syntax.
    fn forward_mut(&mut self) -> &mut Self::Forwarder;

    /// Builds up the `&self` call.
    ///
    /// # Note
    ///
    /// This is used for the long-hand calling syntax.
    fn build(&self) -> &<Self::Forwarder as TraitCallBuilder>::Builder;

    /// Builds up the `&mut self` call.
    ///
    /// # Note
    ///
    /// This is used for the long-hand calling syntax.
    fn build_mut(&mut self) -> &mut <Self::Forwarder as TraitCallBuilder>::Builder;
}

/// Stores information for every ink! trait message of an ink! trait definition.
///
/// This information includes if the ink! trait message is payable
/// as well as its derived or manually specified selector.
///
/// In the future this info trait might be extended to contain
/// more information about a single ink! trait message.
///
/// The information provided through this trait can be used on the
/// implementer side of an ink! trait to check and guard certain
/// properties on a Rust type system level. This is important since
/// ink! cannot be guaranteed to have both the ink! trait definition
/// and all of its implementers under its scope and radar.
///
/// # Note
///
/// - The `TraitMessageInfo<LOCAL_ID>` is implemented by the
///   automatically generated ink! trait definition information object
///   associated to the ink! trait definition at hand.
/// - For every ink! trait message defined by the ink! trait definition
///   the associated ink! trait definition information object implements
///   this trait given the `TRAIT_LOCAL_MESSAGE_ID` of each ink! trait
///   message respectively.
/// - The local IDs uniquely identifying all the ink! trait messages
///   of the ink! trait definition are computed solely using the Rust
///   identifier of the ink! trait message which can be derived from
///   ink! implementation blocks in order to query the information
///   stored by this ink! trait information object trait implementation.
pub trait TraitMessageInfo<const TRAIT_LOCAL_MESSAGE_ID: u32> {
    /// Is `true` if the ink! trait message has been annotated with `#[ink(payable)]`.
    const PAYABLE: bool;

    /// The unique selector of the ink! trait message.
    ///
    /// This might have been adjusted using `#[ink(selector = N:u32)]` at the
    /// ink! trait definition site.
    const SELECTOR: [u8; 4];
}
