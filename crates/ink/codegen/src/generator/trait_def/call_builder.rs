// Copyright (C) Parity Technologies (UK) Ltd.
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

use super::TraitDefinition;
use crate::{
    generator,
    traits::GenerateCode,
};
use derive_more::From;
use proc_macro2::{
    Span,
    TokenStream as TokenStream2,
};
use quote::{
    quote,
    quote_spanned,
};

impl<'a> TraitDefinition<'a> {
    /// Generates code for the global trait call builder for an ink! trait.
    ///
    /// # Note
    ///
    /// - The generated call builder type implements the ink! trait definition and allows
    ///   to build up contract calls that allow for customization by the user to provide
    ///   gas limit, endowment etc.
    /// - The call builder is used directly by the generated call forwarder. There exists
    ///   one global call forwarder and call builder pair for every ink! trait definition.
    pub fn generate_call_builder(&self) -> TokenStream2 {
        CallBuilder::from(*self).generate_code()
    }

    /// The identifier of the ink! trait call builder.
    pub fn call_builder_ident(&self) -> syn::Ident {
        self.append_trait_suffix(CallBuilder::SUFFIX)
    }
}

/// Generates code for the global ink! trait call builder.
#[derive(From)]
struct CallBuilder<'a> {
    trait_def: TraitDefinition<'a>,
}

impl GenerateCode for CallBuilder<'_> {
    fn generate_code(&self) -> TokenStream2 {
        let struct_definition = self.generate_struct_definition();
        let auxiliary_trait_impls = self.generate_auxiliary_trait_impls();
        let ink_trait_impl = self.generate_ink_trait_impl();
        quote! {
            #struct_definition
            #auxiliary_trait_impls
            #ink_trait_impl
        }
    }
}

impl CallBuilder<'_> {
    /// The name suffix for ink! trait call builder.
    const SUFFIX: &'static str = "TraitCallBuilder";

    /// Returns the span of the ink! trait definition.
    fn span(&self) -> Span {
        self.trait_def.span()
    }

    /// Returns the identifier of the ink! trait call builder.
    fn ident(&self) -> syn::Ident {
        self.trait_def.call_builder_ident()
    }

    /// Generates the struct type definition for the account wrapper type.
    ///
    /// This type is going to implement the trait so that invoking its trait
    /// methods will perform contract calls via contract's pallet contract
    /// execution abstraction.
    ///
    /// # Note
    ///
    /// Unlike the layout specific traits it is possible to derive the SCALE
    /// `Encode` and `Decode` traits since they generate trait bounds per field
    /// instead of per generic parameter which is exactly what we need here.
    /// However, it should be noted that this is not Rust default behavior.
    fn generate_struct_definition(&self) -> TokenStream2 {
        let span = self.span();
        let call_builder_ident = self.ident();
        quote_spanned!(span =>
            /// The global call builder type for all trait implementers.
            ///
            /// All calls to types (contracts) implementing the trait will be built by this type.
            #[doc(hidden)]
            #[allow(non_camel_case_types)]
            #[::ink::scale_derive(Encode, Decode)]
            #[repr(transparent)]
            pub struct #call_builder_ident<E> {
                marker: ::core::marker::PhantomData<fn() -> E>,
            }
        )
    }

    /// Generates trait implementations for auxiliary traits.
    ///
    /// # Note
    ///
    /// Auxiliary traits currently include:
    ///
    /// - `Default`: To allow constructing a new instance of the call builder.
    fn generate_auxiliary_trait_impls(&self) -> TokenStream2 {
        let span = self.span();
        let call_builder_ident = self.ident();
        quote_spanned!(span=>
            /// We require this manual implementation since the derive produces incorrect trait bounds.
            impl<E> ::core::default::Default for #call_builder_ident<E>
            where
                E: ::ink::env::Environment,
            {
                fn default() -> Self {
                    Self { marker: ::core::default::Default::default() }
                }
            }
        )
    }


    /// Generates the implementation of the associated ink! trait definition.
    ///
    /// # Note
    ///
    /// The implemented messages call the SEAL host runtime in order to dispatch
    /// the respective ink! trait message calls of the called smart contract
    /// instance.
    /// The way these messages are built-up allows the caller to customize message
    /// parameters such as gas limit and transferred value.
    fn generate_ink_trait_impl(&self) -> TokenStream2 {
        let span = self.trait_def.span();
        let trait_ident = self.trait_def.trait_def.item().ident();
        let trait_info_ident = self.trait_def.trait_info_ident();
        let builder_ident = self.ident();
        let message_impls = self.generate_ink_trait_impl_messages();
        quote_spanned!(span=>
            impl<E> ::ink::env::ContractEnv for #builder_ident<E>
            where
                E: ::ink::env::Environment,
            {
                type Env = E;
            }

            impl<E> #trait_ident for #builder_ident<E>
            where
                E: ::ink::env::Environment,
            {
                #[allow(non_camel_case_types)]
                type __ink_TraitInfo = #trait_info_ident<E>;

                #message_impls
            }
        )
    }

    /// Generate the code for all ink! trait messages implemented by the trait call
    /// builder.
    fn generate_ink_trait_impl_messages(&self) -> TokenStream2 {
        let messages = self.trait_def.trait_def.item().iter_items().filter_map(
            |(item, selector)| {
                item.filter_map_message().map(|message| {
                    self.generate_ink_trait_impl_for_message(&message, selector)
                })
            },
        );
        quote! {
            #( #messages )*
        }
    }

    /// Generate the code for a single ink! trait message implemented by the trait call
    /// builder.
    fn generate_ink_trait_impl_for_message(
        &self,
        message: &ir::InkTraitMessage,
        selector: ir::Selector,
    ) -> TokenStream2 {
        let span = message.span();
        let message_ident = message.ident();
        let attrs = self
            .trait_def
            .trait_def
            .config()
            .whitelisted_attributes()
            .filter_attr(message.attrs());
        let output_ident = generator::output_ident(message_ident);
        let output = message.output();
        let output_type =
            output.map_or_else(|| quote! { () }, |output| quote! { #output });
        let selector_bytes = selector.hex_lits();
        let input_bindings = generator::input_bindings(message.inputs());
        let input_types = generator::input_types(message.inputs());
        let arg_list = generator::generate_argument_list(input_types.iter().cloned());
        let mut_tok = message.mutates().then(|| quote! { mut });
        let cfg_attrs = message.get_cfg_attrs(span);
        quote_spanned!(span =>
            #[allow(clippy::type_complexity)]
            #( #cfg_attrs )*
            type #output_ident = ::ink::env::call::Invoke<
                #arg_list,
                #output_type,
            >;

            #( #attrs )*
            #[inline]
            fn #message_ident(
                & #mut_tok self
                #( , #input_bindings : #input_types )*
            ) -> Self::#output_ident {
                ::ink::env::call::Invoke::new(
                    ::ink::env::call::ExecutionInput::new(
                        ::ink::env::call::Selector::new([ #( #selector_bytes ),* ])
                    )
                    #(
                        .push_arg(#input_bindings)
                    )*
                )
            }
        )
    }
}
