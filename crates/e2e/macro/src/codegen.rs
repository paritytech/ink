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

use crate::ir;
use core::cell::RefCell;
use derive_more::From;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use std::{
    collections::HashMap,
    sync::Once,
};

/// We use this to only build the contracts once for all tests, at the
/// time of generating the Rust code for the tests, so at compile time.
static BUILD_ONCE: Once = Once::new();

thread_local! {
    // We save a mapping of `contract_manifest_path` to the built `*.contract` files.
    // This is necessary so that not each individual `#[ink_e2e::test]` starts
    // rebuilding the main contract and possibly specified `additional_contracts` contracts.
    pub static ALREADY_BUILT_CONTRACTS: RefCell<HashMap<String, String>> = RefCell::new(HashMap::new());
}

/// Returns the path to the `*.contract` file of the contract for which a test
/// is currently executed.
pub fn already_built_contracts() -> HashMap<String, String> {
    ALREADY_BUILT_CONTRACTS.with(|already_built| already_built.borrow().clone())
}

/// Sets a new `HashMap` for the already built contracts.
pub fn set_already_built_contracts(hash_map: HashMap<String, String>) {
    ALREADY_BUILT_CONTRACTS.with(|metadata_paths| {
        *metadata_paths.borrow_mut() = hash_map;
    });
}

/// Generates code for the `[ink::e2e_test]` macro.
#[derive(From)]
pub struct InkE2ETest {
    /// The test function to generate code for.
    test: ir::InkE2ETest,
}

impl InkE2ETest {
    /// Generates the code for `#[ink:e2e_test]`.
    pub fn generate_code(&self) -> TokenStream2 {
        #[cfg(clippy)]
        if true {
            return quote! {}
        }

        let item_fn = &self.test.item_fn.item_fn;
        let fn_name = &item_fn.sig.ident;
        let block = &item_fn.block;
        let fn_return_type = &item_fn.sig.output;
        let vis = &item_fn.vis;
        let attrs = &item_fn.attrs;
        let ret = match fn_return_type {
            syn::ReturnType::Default => quote! {},
            syn::ReturnType::Type(rarrow, ret_type) => quote! { #rarrow #ret_type },
        };

        let ws_url = &self.test.config.ws_url();

        let mut additional_contracts: Vec<String> =
            self.test.config.additional_contracts();
        let default_main_contract_manifest_path = String::from("Cargo.toml");
        let mut contracts_to_build_and_import = vec![default_main_contract_manifest_path];
        contracts_to_build_and_import.append(&mut additional_contracts);

        let mut already_built_contracts = already_built_contracts();
        if already_built_contracts.is_empty() {
            // Build all of them for the first time and initialize everything
            BUILD_ONCE.call_once(|| {
                env_logger::init();
                for manifest_path in contracts_to_build_and_import {
                    let dest_metadata = build_contract(&manifest_path);
                    let _ = already_built_contracts.insert(manifest_path, dest_metadata);
                }
                set_already_built_contracts(already_built_contracts.clone());
            });
        } else if !already_built_contracts.is_empty() {
            // Some contracts have already been built and we check if the
            // `additional_contracts` for this particular test contain ones
            // that haven't been build before
            for manifest_path in contracts_to_build_and_import {
                if already_built_contracts.get("Cargo.toml").is_none() {
                    let dest_metadata = build_contract(&manifest_path);
                    let _ = already_built_contracts.insert(manifest_path, dest_metadata);
                }
            }
            set_already_built_contracts(already_built_contracts.clone());
        }

        assert!(
            !already_built_contracts.is_empty(),
            "built contract artifacts must exist here"
        );
        let meta: Vec<TokenStream2> = already_built_contracts
            .iter()
            .map(|(_manifest_path, bundle_path)| {
                let path = syn::LitStr::new(bundle_path, proc_macro2::Span::call_site());
                quote! {
                    // TODO(#1421) `smart-bench_macro` needs to be forked.
                    ::ink_e2e::smart_bench_macro::contract!(#path);
                }
            })
            .collect();

        quote! {
            #( #attrs )*
            #[test]
            #vis fn #fn_name () #ret {
                use ::ink_e2e::log_info;
                ::ink_e2e::LOG_PREFIX.with(|log_prefix| {
                    let str = format!("test: {}", stringify!(#fn_name));
                    *log_prefix.borrow_mut() = String::from(str);
                });
                log_info("setting up e2e test");

                ::ink_e2e::INIT.call_once(|| {
                    ::ink_e2e::env_logger::init();
                });

                #( #meta )*

                log_info("creating new client");

                let run = async {
                    // TODO(#xxx) Make those two generic environments customizable.
                    let mut client = ::ink_e2e::Client::<
                        ::ink_e2e::PolkadotConfig,
                        ink::env::DefaultEnvironment
                    >::new(&#ws_url).await;

                    let __ret = {
                        #block
                    };
                    __ret
                };

                {
                    return ::ink_e2e::tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .expect("Failed building the Runtime")
                        .block_on(run);
                }
            }
        }
    }
}

/// Builds the contract at `manifest_path`, returns the path to the contract
/// bundle build artifact.
fn build_contract(manifest_path: &str) -> String {
    use std::process::{
        Command,
        Stdio,
    };
    let output = Command::new("cargo")
        .args([
            "+stable",
            "contract",
            "build",
            "--output-json",
            &format!("--manifest-path={}", manifest_path),
        ])
        .env("RUST_LOG", "")
        .stderr(Stdio::inherit())
        .output()
        .expect("failed to execute `cargo-contract` build process");

    log::info!("`cargo-contract` returned status: {}", output.status);
    log::info!(
        "`cargo-contract` stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    if !output.status.success() {
        log::error!(
            "`cargo-contract` stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    assert!(
        output.status.success(),
        "contract build for {} failed",
        manifest_path
    );

    let json = String::from_utf8_lossy(&output.stdout);
    let metadata: serde_json::Value =
        serde_json::from_str(&json).expect("cannot convert json to utf8");
    let dest_metadata = metadata["metadata_result"]["dest_bundle"].to_string();
    dest_metadata.trim_matches('"').to_string()
}
