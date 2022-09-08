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

use ink_storage_codegen::DeriveUtils;
use proc_macro2::TokenStream as TokenStream2;
use quote::{
    quote,
    ToTokens,
};

pub fn storage_key_derive(mut s: synstructure::Structure) -> TokenStream2 {
    s.add_bounds(synstructure::AddBounds::None)
        .underscore_const(true);

    let salt = if let Some(param) = s.ast().find_salt() {
        param.ident.to_token_stream()
    } else {
        quote! { () }
    };

    s.gen_impl(quote! {
        gen impl ::ink_storage::traits::StorageKey for @Self {
            const KEY: ::ink_primitives::Key = <#salt as ::ink_storage::traits::StorageKey>::KEY;
        }
    })
}
