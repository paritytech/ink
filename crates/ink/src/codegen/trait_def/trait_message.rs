// Copyright 2018-2022 Parity Technologies (UK) Ltd.
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

/// Used as `payable` property guard for ink! trait messages.
///
/// # Note
///
/// When an ink! trait message is annotated with `#[ink(payable)]`
/// a compile time check is generated by ink! to guard that the
/// payability of the ink! trait message matches the payability of
/// the same ink! message as defined by the ink! trait message.
pub struct TraitMessagePayable<const IS_PAYABLE: bool>;

/// Used as `allow_reentrancy` property guard for ink! trait messages.
///
/// # Note
///
/// When an ink! trait message is annotated with `#[ink(allow_reentrancy)]`
/// a compile time check is generated by ink! to guard that the
/// reentrancy allowance of the ink! trait message matches the reentrancy
/// allowance of the same ink! message as defined by the ink! trait message.
pub struct TraitMessageReentrant<const ALLOW_REENTRANCY: bool>;

/// Used as `selector` property guard for ink! trait messages.
///
/// # Note
///
/// When an ink! trait message is annotated with `#[ink(selector = ..)]`
/// a compile time check is generated by ink! to guard that the
/// selector of the ink! trait message matches the selector of
/// the same ink! message as defined by the ink! trait message.
pub struct TraitMessageSelector<const SELECTOR_ID: u32>;
