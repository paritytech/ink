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

use crate::GenerateCode;
use derive_more::From;
use ir::HexLiteral;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::spanned::Spanned;

/// Generates code to generate signature topic.
#[derive(From, Copy, Clone)]
pub struct SignatureTopic<'a> {
    /// The event item to generate code for.
    item: &'a ir::SignatureTopic,
}

impl GenerateCode for SignatureTopic<'_> {
    /// Generates ink! signature topic item code.
    fn generate_code(&self) -> TokenStream2 {
        let item = self.item.item();
        let signature_topic = self.generate_signature_topic();
        let cfg_attrs = self.item.get_cfg_attrs(item.span());

        quote::quote! (
            #( #cfg_attrs )*
            #signature_topic
            #item
        )
    }
}

impl SignatureTopic<'_> {
    /// Generates the implementation of `GetSignatureTopic` trait.
    fn generate_signature_topic(&self) -> TokenStream2 {
        let item_ident = &self.item.item().ident;
        let signature_topic = if let Some(bytes) = self.item.signature_topic() {
            let hash_bytes = bytes.map(|b| b.hex_padded_suffixed());
            quote! { ::core::option::Option::Some([ #( #hash_bytes ),* ]) }
        } else {
            let calculated_topic = signature_topic(&self.item.item().fields, item_ident);
            quote! { ::core::option::Option::Some(#calculated_topic) }
        };

        quote! {
            impl ::ink::env::GetSignatureTopic for #item_ident {
                fn signature_topic() -> Option<[u8; 32]> {
                    #signature_topic
                }
            }
        }
    }
}

/// The signature topic of an event variant.
///
/// Calculated with `blake2b("Event(field1_type,field2_type)")`.
fn signature_topic(fields: &syn::Fields, event_ident: &syn::Ident) -> TokenStream2 {
    let fields = fields
        .iter()
        .map(|field| {
            quote::ToTokens::to_token_stream(&field.ty)
                .to_string()
                .replace(' ', "")
        })
        .collect::<Vec<_>>()
        .join(",");
    let topic_str = format!("{}({fields})", event_ident);
    quote!(::ink::blake2x256!(#topic_str))
}