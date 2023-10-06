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
use clippy_utils::match_def_path;
use if_chain::if_chain;
use rustc_hir::{
    ExprKind,
    HirId,
    ItemId,
    ItemKind,
    QPath,
    StmtKind,
    Ty,
    TyKind,
};
use rustc_lint::LateContext;

/// Returns `true` iff the ink storage attribute is defined for the given HIR
fn has_storage_attr(cx: &LateContext, hir: HirId) -> bool {
    const INK_STORAGE: &str = "__ink_dylint_Storage";
    let attrs = format!("{:?}", cx.tcx.hir().attrs(hir));
    attrs.contains(INK_STORAGE)
}

/// Returns `ItemId` of the structure annotated with `#[ink(storage)]`
pub(crate) fn find_storage_struct(
    cx: &LateContext,
    item_ids: &[ItemId],
) -> Option<ItemId> {
    item_ids
        .iter()
        .find(|&item_id| {
            let item = cx.tcx.hir().item(*item_id);
            if_chain! {
                if has_storage_attr(cx, item.hir_id());
                if let ItemKind::Struct(..) = item.kind;
                then { true } else { false }

            }
        })
        .copied()
}

// TODO: Extracted from #1914; reuse this in #1914 when it is merged
/// Returns `ItemId`s defined inside the code block of `const _: () = {}`.
///
/// The Rust code expanded after ink! code generation used these to define different
/// implementations of a contract.
fn items_in_unnamed_const(cx: &LateContext<'_>, id: &ItemId) -> Vec<ItemId> {
    if_chain! {
        if let ItemKind::Const(ty, body_id) = cx.tcx.hir().item(*id).kind;
        if let TyKind::Tup([]) = ty.kind;
        let body = cx.tcx.hir().body(body_id);
        if let ExprKind::Block(block, _) = body.value.kind;
        then {
            block.stmts.iter().fold(Vec::new(), |mut acc, stmt| {
                if let StmtKind::Item(id) = stmt.kind {
                    // We don't call `items_in_unnamed_const` here recursively, because the source
                    // code generated by ink! doesn't have nested `const _: () = {}` expressions.
                    acc.push(id)
                }
                acc
            })
        } else {
            vec![]
        }
    }
}

// TODO: Extracted from #1914; reuse this in #1914 when it is merged
/// Collect all the `ItemId`s in nested `const _: () = {}`
pub(crate) fn expand_unnamed_consts(
    cx: &LateContext<'_>,
    item_ids: &[ItemId],
) -> Vec<ItemId> {
    item_ids.iter().fold(Vec::new(), |mut acc, item_id| {
        acc.push(*item_id);
        acc.append(&mut items_in_unnamed_const(cx, item_id));
        acc
    })
}

// TODO: Extracted from #1914; reuse this in #1914 when it is merged
/// Finds type of the struct that implements a contract with user-defined code
fn find_contract_ty_hir<'tcx>(
    cx: &LateContext<'tcx>,
    item_ids: &[ItemId],
) -> Option<&'tcx Ty<'tcx>> {
    item_ids
        .iter()
        .find_map(|item_id| {
            if_chain! {
                let item = cx.tcx.hir().item(*item_id);
                if let ItemKind::Impl(item_impl) = &item.kind;
                if let Some(trait_ref) = cx.tcx.impl_trait_ref(item.owner_id);
                if match_def_path(
                    cx,
                    trait_ref.skip_binder().def_id,
                    &["ink_env", "contract", "ContractEnv"],
                );
                then { Some(&item_impl.self_ty) } else { None }
            }
        })
        .copied()
}

// TODO: Extracted from #1914; reuse this in #1914 when it is merged
/// Compares types of two user-defined structs
fn eq_hir_struct_tys(lhs: &Ty<'_>, rhs: &Ty<'_>) -> bool {
    match (lhs.kind, rhs.kind) {
        (
            TyKind::Path(QPath::Resolved(_, lhs_path)),
            TyKind::Path(QPath::Resolved(_, rhs_path)),
        ) => lhs_path.res.eq(&rhs_path.res),
        _ => false,
    }
}

// TODO: Extracted from #1914; reuse this in #1914 when it is merged
/// Finds an ID of the implementation of the contract struct containing user-defined code
pub(crate) fn find_contract_impl_id(
    cx: &LateContext<'_>,
    item_ids: Vec<ItemId>,
) -> Option<ItemId> {
    let contract_struct_ty = find_contract_ty_hir(cx, &item_ids)?;
    item_ids
        .iter()
        .find(|item_id| {
            if_chain! {
                let item = cx.tcx.hir().item(**item_id);
                if let ItemKind::Impl(item_impl) = &item.kind;
                if item_impl.of_trait.is_none();
                if eq_hir_struct_tys(contract_struct_ty, item_impl.self_ty);
                then { true } else { false }
            }
        })
        .copied()
}
