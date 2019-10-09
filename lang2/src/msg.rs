// Copyright 2018-2019 Parity Technologies (UK) Ltd.
// This file is part of ink!.
//
// ink! is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// ink! is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with ink!.  If not, see <http://www.gnu.org/licenses/>.

use core::marker::PhantomData;
use ink_core::env2::call::Selector;

/// Dispatchable functions that have inputs.
pub trait FnInput {
    /// The tuple-type of all inputs.
    type Input: scale::Decode + 'static;
}

/// Dispatchable functions that have an output.
pub trait FnOutput {
    /// The output type.
    type Output: scale::Encode + 'static;
}

/// The selector of dispatchable functions.
pub trait FnSelector {
    /// The selector.
    const SELECTOR: Selector;
}

/// Types implementing this are messages.
pub trait Message: FnInput + FnOutput + FnSelector {
    /// Indicates whether the message has been defined as `&mut self`.
    const IS_MUT: bool;
}

/// Types implementing this are constructors.
pub trait Constructor: FnInput + FnSelector {}

/// A concrete instance of a dispatchable function.
pub struct Dispatchable<S, M> {
    /// Used to make the compiler think that we actually make use of `S` and `M`.
    marker: PhantomData<fn() -> (S, M)>,
}

mod marker {
    /// Indicates messages.
    pub enum MessageMarker {}
    /// Indicates constructors.
    pub enum ConstructorMarker {}
}

/// A concrete message instance.
pub type Msg<S> = Dispatchable<S, marker::MessageMarker>;

/// A concrete constructor instance.
pub type Constr<S> = Dispatchable<S, marker::ConstructorMarker>;

impl<T> FnOutput for T
where
    T: Constructor,
{
    // TODO: decide whether we need this auto-impl
    type Output = ();
}
