// Copyright 2018-2020 Parity Technologies (UK) Ltd.
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

use super::{
    ensure_callable_invariants,
    CallableKind,
    Visibility,
};
use crate::ir2;
use core::convert::TryFrom;
use proc_macro2::Span;
use syn::spanned::Spanned as _;

/// The receiver of an ink! message.
#[derive(Debug, Copy, Clone)]
pub enum Receiver {
    /// The `&self` message receiver.
    Ref,
    /// The `&mut self` message receiver.
    RefMut,
}

impl Receiver {
    /// Returns `true` if the receiver is `&self`.
    pub fn is_ref(self) -> bool {
        matches!(self, Self::Ref)
    }

    /// Returns `true` if the receiver is `&mut self`.
    pub fn is_ref_mut(self) -> bool {
        matches!(self, Self::RefMut)
    }
}

/// An ink! message definition.
#[derive(Debug, PartialEq, Eq)]
pub struct Message {
    /// The underlying Rust method item.
    item: syn::ImplItemMethod,
    /// If the ink! message can receive funds.
    is_payable: bool,
    /// An optional user provided salt.
    salt: Option<ir2::Salt>,
    /// An optional user provided selector.
    selector: Option<ir2::Selector>,
}

impl Message {
    /// Ensures that the given `fn_args` start with `&self` or `&mut self`
    /// receivers.
    ///
    /// If not an appropriate error is returned.
    ///
    /// # Errors
    ///
    /// - If `fn_args` yields no elements.
    /// - If the first yielded element of `fn_args` is not `&self` or `&mut self`.
    fn ensure_receiver_is_self_ref<'a, I>(
        parent_span: Span,
        fn_args: I,
    ) -> Result<(), syn::Error>
    where
        I: IntoIterator<Item = &'a syn::FnArg>,
    {
        let mut fn_args = fn_args.into_iter();
        fn bail(span: Span) -> syn::Error {
            format_err_span!(
                span,
                "ink! messages must have `&self` or `&mut self` receiver",
            )
        }
        match fn_args.next() {
            None => return Err(bail(parent_span)),
            Some(syn::FnArg::Typed(pat_typed)) => return Err(bail(pat_typed.span())),
            Some(syn::FnArg::Receiver(receiver)) => {
                if receiver.reference.is_none() {
                    return Err(bail(receiver.span()))
                }
            }
        }
        Ok(())
    }
}

impl TryFrom<syn::ImplItemMethod> for Message {
    type Error = syn::Error;

    fn try_from(method_item: syn::ImplItemMethod) -> Result<Self, Self::Error> {
        let method_span = method_item.span();
        ensure_callable_invariants(
            &method_item,
            CallableKind::Message,
        )?;
        Self::ensure_receiver_is_self_ref(
            method_item.sig.inputs.span(),
            method_item.sig.inputs.iter(),
        )?;
        let (ink_attrs, other_attrs) = ir2::sanitize_attributes(
            method_span,
            method_item.attrs,
            &ir2::AttributeArgKind::Message,
            |kind| {
                match kind {
                    ir2::AttributeArgKind::Message
                    | ir2::AttributeArgKind::Payable
                    | ir2::AttributeArgKind::Salt(_)
                    | ir2::AttributeArgKind::Selector(_) => false,
                    _ => true,
                }
            },
        )?;
        let is_payable = false; // TODO
        let salt = None; // TODO
        let selector = None; // TODO
        Ok(Self {
            is_payable,
            salt,
            selector,
            item: syn::ImplItemMethod {
                attrs: other_attrs,
                ..method_item
            },
        })
    }
}

impl Message {
    /// Returns the visibility of the message.
    pub fn visibility(&self) -> Visibility {
        match &self.item.vis {
            syn::Visibility::Public(vis_public) => Visibility::Public(vis_public.clone()),
            syn::Visibility::Inherited => Visibility::Inherited,
            _ => unreachable!("encountered invalid visibility for ink! message"),
        }
    }

    /// Returns the `self` receiver of the ink! message.
    pub fn receiver(&self) -> Receiver {
        match self.item.sig.inputs.iter().next() {
            Some(syn::FnArg::Receiver(receiver)) => {
                debug_assert!(receiver.reference.is_some());
                if receiver.mutability.is_some() {
                    Receiver::RefMut
                } else {
                    Receiver::Ref
                }
            }
            _ => unreachable!("encountered invalid receiver argument for ink! message"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn visibility_works() {
        let test_inputs: Vec<(bool, syn::ImplItemMethod)> = vec![
            // &self
            (
                false,
                syn::parse_quote! {
                    #[ink(message)]
                    fn my_message(&self) {}
                },
            ),
            // &self + pub
            (
                true,
                syn::parse_quote! {
                    #[ink(message)]
                    pub fn my_message(&self) {}
                },
            ),
            // &mut self
            (
                false,
                syn::parse_quote! {
                    #[ink(message)]
                    fn my_message(&mut self) {}
                },
            ),
            // &mut self + pub
            (
                true,
                syn::parse_quote! {
                    #[ink(message)]
                    pub fn my_message(&mut self) {}
                },
            ),
        ];
        for (is_pub, item_method) in test_inputs {
            let visibility = <ir2::Message as TryFrom<_>>::try_from(item_method)
                .unwrap()
                .visibility();
            assert_eq!(visibility.is_pub(), is_pub);
            assert_eq!(visibility.is_inherited(), !is_pub);
        }
    }

    #[test]
    fn receiver_works() {
        let test_inputs: Vec<(bool, syn::ImplItemMethod)> = vec![
            // &self
            (
                false,
                syn::parse_quote! {
                    #[ink(message)]
                    fn my_message(&self) {}
                },
            ),
            // &mut self
            (
                true,
                syn::parse_quote! {
                    #[ink(message)]
                    fn my_message(&mut self) {}
                },
            ),
        ];
        for (is_mut, item_method) in test_inputs {
            let receiver = <ir2::Message as TryFrom<_>>::try_from(item_method)
                .unwrap()
                .receiver();
            assert_eq!(receiver.is_ref_mut(), is_mut);
            assert_eq!(receiver.is_ref(), !is_mut);
        }
    }

    #[test]
    fn try_from_works() {
        let item_methods: Vec<syn::ImplItemMethod> = vec![
            // &self
            syn::parse_quote! {
                #[ink(message)]
                fn my_message(&self) {}
            },
            // &self + pub
            syn::parse_quote! {
                #[ink(message)]
                pub fn my_message(&self) {}
            },
            // &mut self
            syn::parse_quote! {
                #[ink(message)]
                fn my_message(&mut self) {}
            },
            // &mut self + pub
            syn::parse_quote! {
                #[ink(message)]
                pub fn my_message(&mut self) {}
            },
            // &self + payable
            syn::parse_quote! {
                #[ink(message, payable)]
                fn my_message(&self) {}
            },
            // &mut self + payable
            syn::parse_quote! {
                #[ink(message, payable)]
                fn my_message(&mut self) {}
            },
            // &self + many inputs + output works
            syn::parse_quote! {
                #[ink(message)]
                fn my_message(&self, input1: i32, input2: i64, input3: u32, input4: u64) -> bool {}
            },
            // &mut self + many inputs + output works
            syn::parse_quote! {
                #[ink(message)]
                fn my_message(&mut self, input1: i32, input2: i64, input3: u32, input4: u64) -> bool {}
            },
        ];
        for item_method in item_methods {
            assert!(<ir2::Message as TryFrom<_>>::try_from(item_method).is_ok());
        }
    }

    fn assert_try_from_fails(item_method: syn::ImplItemMethod, expected_err: &str) {
        assert_eq!(
            <ir2::Message as TryFrom<_>>::try_from(item_method)
                .map_err(|err| err.to_string()),
            Err(expected_err.to_string()),
        );
    }

    #[test]
    fn try_from_generics_fails() {
        let item_methods: Vec<syn::ImplItemMethod> = vec![
            syn::parse_quote! {
                #[ink(message)]
                fn my_message<T>(&self) {}
            },
            syn::parse_quote! {
                #[ink(message)]
                pub fn my_message<T>(&self) {}
            },
            syn::parse_quote! {
                #[ink(message)]
                fn my_message<T>(&mut self) {}
            },
            syn::parse_quote! {
                #[ink(message)]
                pub fn my_message<T>(&mut self) {}
            },
        ];
        for item_method in item_methods {
            assert_try_from_fails(item_method, "ink! messages must not be generic")
        }
    }

    #[test]
    fn try_from_receiver_fails() {
        let item_methods: Vec<syn::ImplItemMethod> = vec![
            syn::parse_quote! {
                #[ink(message)]
                fn my_message() {}
            },
            syn::parse_quote! {
                #[ink(message)]
                fn my_message(self) {}
            },
            syn::parse_quote! {
                #[ink(message)]
                pub fn my_message(mut self) {}
            },
            syn::parse_quote! {
                #[ink(message)]
                fn my_message(this: &Self) {}
            },
            syn::parse_quote! {
                #[ink(message)]
                pub fn my_message(this: &mut Self) {}
            },
        ];
        for item_method in item_methods {
            assert_try_from_fails(
                item_method,
                "ink! messages must have `&self` or `&mut self` receiver",
            )
        }
    }

    #[test]
    fn try_from_const_fails() {
        let item_methods: Vec<syn::ImplItemMethod> = vec![
            // &self
            syn::parse_quote! {
                #[ink(message)]
                const fn my_message(&self) {}
            },
            // &mut self
            syn::parse_quote! {
                #[ink(message)]
                const fn my_message(&mut self) {}
            },
        ];
        for item_method in item_methods {
            assert_try_from_fails(item_method, "ink! messages must not be const")
        }
    }

    #[test]
    fn try_from_async_fails() {
        let item_methods: Vec<syn::ImplItemMethod> = vec![
            // &self
            syn::parse_quote! {
                #[ink(message)]
                async fn my_message(&self) {}
            },
            // &mut self
            syn::parse_quote! {
                #[ink(message)]
                async fn my_message(&mut self) {}
            },
        ];
        for item_method in item_methods {
            assert_try_from_fails(item_method, "ink! messages must not be async")
        }
    }

    #[test]
    fn try_from_unsafe_fails() {
        let item_methods: Vec<syn::ImplItemMethod> = vec![
            // &self
            syn::parse_quote! {
                #[ink(message)]
                unsafe fn my_message(&self) {}
            },
            // &mut self
            syn::parse_quote! {
                #[ink(message)]
                unsafe fn my_message(&mut self) {}
            },
        ];
        for item_method in item_methods {
            assert_try_from_fails(item_method, "ink! messages must not be unsafe")
        }
    }

    #[test]
    fn try_from_explicit_abi_fails() {
        let item_methods: Vec<syn::ImplItemMethod> = vec![
            // &self
            syn::parse_quote! {
                #[ink(message)]
                extern "C" fn my_message(&self) {}
            },
            // &mut self
            syn::parse_quote! {
                #[ink(message)]
                extern "C" fn my_message(&mut self) {}
            },
        ];
        for item_method in item_methods {
            assert_try_from_fails(item_method, "ink! messages must have explicit ABI")
        }
    }

    #[test]
    fn try_from_variadic_fails() {
        let item_methods: Vec<syn::ImplItemMethod> = vec![
            // &self
            syn::parse_quote! {
                #[ink(message)]
                fn my_message(&self, ...) {}
            },
            // &mut self
            syn::parse_quote! {
                #[ink(message)]
                fn my_message(&mut self, ...) {}
            },
        ];
        for item_method in item_methods {
            assert_try_from_fails(item_method, "ink! messages must not be variadic")
        }
    }

    #[test]
    fn try_from_visibility_fails() {
        let item_methods: Vec<syn::ImplItemMethod> = vec![
            // &self + crate visibility
            syn::parse_quote! {
                #[ink(message)]
                crate fn my_message(&self) {}
            },
            // &mut self + crate visibility
            syn::parse_quote! {
                #[ink(message)]
                crate fn my_message(&mut self) {}
            },
            // &self + pub restricted visibility
            syn::parse_quote! {
                #[ink(message)]
                pub(in my::path) fn my_message(&self) {}
            },
            // &mut self + pub restricted visibility
            syn::parse_quote! {
                #[ink(message)]
                pub(in my::path) fn my_message(&mut self) {}
            },
        ];
        for item_method in item_methods {
            assert_try_from_fails(
                item_method,
                "ink! messages must have public or inherited visibility",
            )
        }
    }
}
