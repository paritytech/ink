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
use clippy_utils::{
    diagnostics::span_lint_hir_and_then,
    match_def_path,
    source::snippet_opt,
};
use if_chain::if_chain;
use rustc_errors::Applicability;
use rustc_hir::{
    self as hir,
    def_id::DefId,
    AssocItemKind,
    ExprKind,
    ItemId,
    ItemKind,
    QPath,
    StmtKind,
    Ty,
    TyKind,
};
use rustc_index::bit_set::BitSet;
use rustc_lint::{
    LateContext,
    LateLintPass,
};
use rustc_middle::{
    mir::{
        traversal,
        visit::Visitor,
        BasicBlock,
        BinOp,
        Body,
        Constant,
        HasLocalDecls,
        Local,
        Location,
        Operand,
        Place,
        Rvalue,
        Statement,
        Terminator,
        TerminatorKind,
    },
    ty as mir_ty,
};
use rustc_mir_dataflow::{
    Analysis,
    AnalysisDomain,
    CallReturnPlaces,
    Forward,
};
use rustc_session::{
    declare_lint,
    declare_lint_pass,
};
use rustc_span::{
    source_map::BytePos,
    Span,
};
use std::collections::HashMap;

declare_lint! {
    /// **What it does:** Looks for strict equalities with balance in ink! contracts.
    ///
    /// **Why is this bad?** The problem with strict balance equality is that it is always possible
    /// to forcibly send tokens to a contract, for example, using
    /// [`terminate_contract`](https://paritytech.github.io/ink/ink_env/fn.terminate_contract.html).
    /// In such a case, the condition involving the contract balance will work incorrectly, what
    /// may lead to security issues, including DoS attacks and draining contract's gas.
    ///
    /// **Known problems**: There are many ways to implement comparison between integers in Rust.
    /// This lint is not trying to be exhaustive; instead, it addresses the most common cases that
    /// will occur in almost all real-world contracts.
    ///
    /// **Example:**
    ///
    /// Assume, there is an attacker contract that sends all its funds to the target contract when
    /// terminated:
    /// ```rust
    /// #[ink::contract]
    /// pub mod attacker {
    ///   // ...
    ///   #[ink(message)]
    ///   pub fn attack(&mut self, target: &AccountId) {
    ///       self.env().terminate_contract(target);
    ///   }
    /// }
    /// ```
    ///
    /// If the target contains a condition with strict balance equality, this may be manipulated by
    /// the attacker:
    /// ```rust
    /// #[ink::contract]
    /// pub mod target {
    ///   // ...
    ///   #[ink(message)]
    ///   pub fn do_something(&mut self) {
    ///       if self.env().balance() != 100 { // Bad: Strict balance equality
    ///           // ... some logic
    ///       }
    ///   }
    /// }
    /// ```
    ///
    /// This could be mitigated using non-strict equality operators in the condition with the
    /// balance:
    /// ```rust
    /// #[ink::contract]
    /// pub mod target {
    ///   // ...
    ///   #[ink(message)]
    ///   pub fn do_something(&mut self) {
    ///       if self.env().balance() < 100 { // Good: Non-strict equality
    ///           // ... some logic
    ///       }
    ///   }
    /// }
    /// ```
    pub STRICT_BALANCE_EQUALITY,
    Warn,
    "strict equality with contract's balance"
}

declare_lint_pass!(StrictBalanceEquality => [STRICT_BALANCE_EQUALITY]);

/// The dataflow problem that tracks local variables that are tainted with the return
/// value of `self.env().balance()`. The tainted values could be propagated between
/// function calls.
struct StrictBalanceEqualityAnalysis<'a, 'tcx> {
    cx: &'a LateContext<'tcx>,
    fun_cache: &'a mut VisitedFunctionsCache,
}

/// Holds the results of running the dataflow analysis over a function with the given
/// input parameters.
type VisitedFunctionsCache = HashMap<(FunctionName, TaintsInArguments), AnalysisResults>;
type FunctionName = String;
type TaintsInArguments = Vec<bool>;
type AnalysisResults = BitSet<Local>;

/// TransferFunction is a temporary object used by the implementation of a dataflow
/// transfer function to iterate over MIR statements of a function.
struct TransferFunction<'a, 'tcx> {
    cx: &'a LateContext<'tcx>,
    fun_cache: &'a mut VisitedFunctionsCache,
    state: &'a mut BitSet<Local>,
}

impl<'a, 'tcx> StrictBalanceEqualityAnalysis<'a, 'tcx> {
    pub fn new(
        cx: &'a LateContext<'tcx>,
        fun_cache: &'a mut VisitedFunctionsCache,
    ) -> Self {
        Self { cx, fun_cache }
    }
}

impl<'a, 'tcx> AnalysisDomain<'tcx> for StrictBalanceEqualityAnalysis<'a, 'tcx> {
    /// A lattice that represents program's state. `BitSet` is a powerset over MIR Locals
    /// defined in the analyzed function. Inclusion to the set means that the Local is
    /// tainted with some operation with `self.env().balance()`.
    type Domain = BitSet<Local>;

    const NAME: &'static str = "strict_balance_equality";

    type Direction = Forward;

    fn bottom_value(&self, body: &Body) -> Self::Domain {
        // bottom = no balance taints
        BitSet::new_empty(body.local_decls().len())
    }

    fn initialize_start_block(&self, _body: &Body, _state: &mut Self::Domain) {
        // Source of taints are: locals, contract fields and mutable arguments.
        // TODO: No of these are tainted with balance at the beginning, but we should fix
        // it when working on interprocedural analysis.
    }
}

/// The implementation of the transfer function for the dataflow problem
impl<'a, 'tcx> Analysis<'tcx> for StrictBalanceEqualityAnalysis<'a, 'tcx> {
    fn apply_statement_effect(
        &mut self,
        state: &mut Self::Domain,
        statement: &Statement,
        location: Location,
    ) {
        TransferFunction {
            cx: self.cx,
            fun_cache: self.fun_cache,
            state,
        }
        .visit_statement(statement, location);
    }

    fn apply_terminator_effect(
        &mut self,
        state: &mut Self::Domain,
        terminator: &Terminator,
        location: Location,
    ) {
        TransferFunction {
            cx: self.cx,
            fun_cache: self.fun_cache,
            state,
        }
        .visit_terminator(terminator, location);
    }

    fn apply_call_return_effect(
        &mut self,
        _state: &mut Self::Domain,
        _block: BasicBlock,
        _return_place: CallReturnPlaces,
    ) {
        // Do nothing
    }
}

impl Visitor<'_> for TransferFunction<'_, '_> {
    fn visit_assign(&mut self, place: &Place, rvalue: &Rvalue, _: Location) {
        match rvalue {
            // Result of direct comparison with balance
            Rvalue::BinaryOp(_, box (lhs, rhs))
            | Rvalue::CheckedBinaryOp(_, box (lhs, rhs)) => {
                if tainted_with_balance(self.state, lhs).is_some()
                    || tainted_with_balance(self.state, rhs).is_some()
                {
                    self.state.insert(place.local);
                }
            }
            // Assigments of intermediate locals created by rustc
            Rvalue::Use(Operand::Move(use_place) | Operand::Copy(use_place)) => {
                let use_local = use_place.local;
                if self.state.contains(use_local) {
                    self.state.insert(place.local);
                }
            }
            _ => {}
        }
    }

    fn visit_terminator(&mut self, terminator: &Terminator, _: Location) {
        if let TerminatorKind::Call {
            func,
            args,
            destination,
            ..
        } = &terminator.kind
        {
            if_chain! {
                if let Some((fn_def_id, _)) = func.const_fn_def();
                if match_def_path(self.cx,
                                  fn_def_id,
                                  &["ink", "env_access", "EnvAccess", "balance"]);
                then {
                    // Handle `self.env().balance()` calls
                    self.state.insert(destination.local);
                } else {
                    // Handle other calls
                    if let Operand::Constant(func_op) = func {
                        self.visit_call(func_op, args, destination)
                    }
                }
            };
        }
    }
}

impl<'a> TransferFunction<'_, '_> {
    /// Runs a dataflow analysis over the given function
    fn analyze_function(&mut self, fn_def_id: &DefId) -> Option<AnalysisResults> {
        if !fn_def_id.is_local() {
            return None
        }
        let fn_mir = self.cx.tcx.optimized_mir(fn_def_id);
        let mut taint_results =
            StrictBalanceEqualityAnalysis::new(self.cx, self.fun_cache)
                .into_engine(self.cx.tcx, fn_mir)
                .iterate_to_fixpoint()
                .into_results_cursor(fn_mir);
        if let Some((last, _)) = traversal::reverse_postorder(fn_mir).last() {
            taint_results.seek_to_block_end(last);
            Some(taint_results.get().clone())
        } else {
            None
        }
    }

    /// Returns true iff the returns value is tainted with `self.env().balance()`
    fn is_return_value_tainted(&self, results: &BitSet<Local>) -> bool {
        if results.is_empty() {
            return false
        }
        let return_local = Place::return_place().local;
        results.contains(return_local)
    }

    fn visit_call(&mut self, func: &Constant, args: &[Operand], destination: &Place) {
        let init_taints = args.iter().fold(Vec::new(), |mut acc, arg| {
            if let Operand::Move(place) | Operand::Copy(place) = arg {
                acc.push(self.state.contains(place.local))
            }
            acc
        });

        let fn_def_id = if let mir_ty::TyKind::FnDef(id, _) = func.literal.ty().kind() {
            id
        } else {
            return
        };

        // Run the dataflow analysis if the function hasn't been analyzed yet
        let cache_key = (func.to_string(), init_taints);
        let analysis_results =
            if let Some(cached_results) = self.fun_cache.get(&cache_key) {
                cached_results
            } else {
                // Insert an empty value first to handle recursive calls
                let _ = self
                    .fun_cache
                    .insert(cache_key.clone(), BitSet::new_empty(0));
                let results = self
                    .analyze_function(fn_def_id)
                    .unwrap_or(BitSet::new_empty(0));
                let _ = self.fun_cache.insert(cache_key.clone(), results);
                if let Some(results) = self.fun_cache.get(&cache_key) {
                    results
                } else {
                    return
                }
            };

        if self.is_return_value_tainted(analysis_results) {
            self.state.insert(destination.local);
        }

        // TODO: Check if any of the arguments are tainted (only mutable references?)
    }
}

/// Returns Local if the given operand is tainted with balance in the `state` lattice
fn tainted_with_balance(state: &BitSet<Local>, op: &Operand) -> Option<Local> {
    if_chain! {
        if let Some(place) = op.place();
        if state.contains(place.local);
        then { Some(place.local) } else { None }
    }
}

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
                    // code generated by ink! don't have nested `const _: () = {}` expressions.
                    acc.push(id)
                }
                acc
            })
        } else {
            vec![]
        }
    }
}

/// Collect all the `ItemId`s in nested cosnt _: () = {}``
fn expand_unnamed_consts(cx: &LateContext<'_>, item_ids: &[ItemId]) -> Vec<ItemId> {
    item_ids.iter().fold(Vec::new(), |mut acc, item_id| {
        acc.push(*item_id);
        acc.append(&mut items_in_unnamed_const(cx, item_id));
        acc
    })
}

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

/// Finds an ID of the implementaiton of a contract struct containing user-defined code
fn find_contract_impl_id(cx: &LateContext<'_>, item_ids: Vec<ItemId>) -> Option<ItemId> {
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

impl<'tcx> LateLintPass<'tcx> for StrictBalanceEquality {
    fn check_mod(
        &mut self,
        cx: &LateContext<'tcx>,
        m: &'tcx hir::Mod<'tcx>,
        _: hir::HirId,
    ) {
        if_chain! {
            let all_item_ids = expand_unnamed_consts(cx, m.item_ids);
            if let Some(contract_impl_id) = find_contract_impl_id(cx, all_item_ids);
            let contract_impl = cx.tcx.hir().item(contract_impl_id);
            if let ItemKind::Impl(contract_impl) = contract_impl.kind;
            then {
                let mut fun_cache = VisitedFunctionsCache::new();
                contract_impl.items.iter().for_each(|impl_item| {
                    if let AssocItemKind::Fn { .. } = impl_item.kind {
                        self.check_contract_fun(
                            cx,
                            &mut fun_cache,
                            impl_item.span,
                            impl_item.id.owner_id.to_def_id(),
                        )
                    }
                })
            }
        }
    }
}

impl<'tcx> StrictBalanceEquality {
    /// Checks a function from the contract implementation
    fn check_contract_fun(
        &mut self,
        cx: &LateContext<'tcx>,
        fun_cache: &mut VisitedFunctionsCache,
        fn_span: Span,
        fn_def_id: DefId,
    ) {
        let fn_mir = cx.tcx.optimized_mir(fn_def_id);
        let mut taint_results = StrictBalanceEqualityAnalysis::new(cx, fun_cache)
            .into_engine(cx.tcx, fn_mir)
            .iterate_to_fixpoint()
            .into_results_cursor(fn_mir);
        for (bb, bb_data) in traversal::preorder(fn_mir) {
            taint_results.seek_to_block_end(bb);
            let tainted_locals = taint_results.get();
            if tainted_locals.is_empty() {
                continue
            }
            let terminator = bb_data.terminator();
            if_chain! {
                if let TerminatorKind::SwitchInt { discr, .. } = &terminator.kind;
                if let Some(place) = discr.place();
                if tainted_locals.contains(place.local);
                let span = terminator.source_info.span;
                let scope = terminator.source_info.scope;
                let node = fn_mir.source_scopes[scope]
                    .local_data
                    .as_ref()
                    .assert_crate_local()
                    .lint_root;
                if let Some(snip) = snippet_opt(cx, span);
                if let Some(op) = snip.rfind("==").or(snip.rfind("!="));
                then {
                    let op_pos = span.lo() + BytePos(op as u32);
                    let sugg_span = Span::new(
                        op_pos,
                        op_pos + BytePos("==".len() as u32),
                        // We have to use a span different from `span`, since it is resulted after
                        // macro expansion and therefore cannot be used to emit diagnostics.
                        fn_span.ctxt(),
                        fn_span.parent()
                    );
                    span_lint_hir_and_then(
                        cx,
                        STRICT_BALANCE_EQUALITY,
                        node,
                        sugg_span,
                        "dangerous strict balance equality",
                        |diag| {
                            diag.span_suggestion(
                                sugg_span,
                                "consider using non-strict equality operators instead: `<`, `>`".to_string(),
                                "",
                                Applicability::Unspecified,
                            );
                        },
                    )

                }
            }
        }
    }
}