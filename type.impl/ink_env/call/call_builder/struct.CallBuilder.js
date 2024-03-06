(function() {var type_impls = {
"ink_e2e":[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-CallBuilder%3CE,+CallType,+Args,+RetType%3E\" class=\"impl\"><a href=\"#impl-CallBuilder%3CE,+CallType,+Args,+RetType%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;E, CallType, Args, RetType&gt; CallBuilder&lt;E, CallType, Args, RetType&gt;<span class=\"where fmt-newline\">where\n    E: Environment,</span></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.call_flags\" class=\"method\"><h4 class=\"code-header\">pub fn <a class=\"fn\">call_flags</a>(\n    self,\n    call_flags: CallFlags\n) -&gt; CallBuilder&lt;E, CallType, Args, RetType&gt;</h4></section></summary><div class=\"docblock\"><p>The flags used to change the behavior of the contract call.</p>\n</div></details></div></details>",0,"ink_e2e::subxt_client::CallBuilderFinal"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-CallBuilder%3CE,+Set%3CCall%3CE%3E%3E,+Args,+RetType%3E\" class=\"impl\"><a href=\"#impl-CallBuilder%3CE,+Set%3CCall%3CE%3E%3E,+Args,+RetType%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;E, Args, RetType&gt; CallBuilder&lt;E, Set&lt;Call&lt;E&gt;&gt;, Args, RetType&gt;<span class=\"where fmt-newline\">where\n    E: Environment,</span></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.call_v1\" class=\"method\"><h4 class=\"code-header\">pub fn <a class=\"fn\">call_v1</a>(self) -&gt; CallBuilder&lt;E, Set&lt;CallV1&lt;E&gt;&gt;, Args, RetType&gt;</h4></section></summary><div class=\"docblock\"><p>Switch to the original <code>call</code> host function API, which only allows the <code>gas_limit</code>\nlimit parameter (equivalent to the <code>ref_time_limit</code> in the latest <code>call_v2</code>).</p>\n<p>This method instance is used to allow usage of the generated call builder methods\nfor messages which initialize the builder with the new [<code>Call</code>] type.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.ref_time_limit\" class=\"method\"><h4 class=\"code-header\">pub fn <a class=\"fn\">ref_time_limit</a>(\n    self,\n    ref_time_limit: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.75.0/std/primitive.u64.html\">u64</a>\n) -&gt; CallBuilder&lt;E, Set&lt;Call&lt;E&gt;&gt;, Args, RetType&gt;</h4></section></summary><div class=\"docblock\"><p>Sets the <code>ref_time_limit</code> part of the weight limit for the current cross-contract\ncall.</p>\n<p><code>ref_time</code> refers to the amount of computational time that can be\nused for execution, in picoseconds. You can find more info\n<a href=\"https://use.ink/basics/cross-contract-calling/\">here</a>.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.proof_size_limit\" class=\"method\"><h4 class=\"code-header\">pub fn <a class=\"fn\">proof_size_limit</a>(\n    self,\n    proof_size_limit: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.75.0/std/primitive.u64.html\">u64</a>\n) -&gt; CallBuilder&lt;E, Set&lt;Call&lt;E&gt;&gt;, Args, RetType&gt;</h4></section></summary><div class=\"docblock\"><p>Sets the <code>proof_size_limit</code> part of the weight limit for the current\ncross-contract call.</p>\n<p><code>proof_size</code> refers to the amount of storage in bytes that a transaction\nis allowed to read. You can find more info\n<a href=\"https://use.ink/basics/cross-contract-calling/\">here</a>.</p>\n<p><strong>Note</strong></p>\n<p>This limit is only relevant for parachains, not for standalone chains which do not\nrequire sending a Proof-of-validity to the relay chain.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.storage_deposit_limit\" class=\"method\"><h4 class=\"code-header\">pub fn <a class=\"fn\">storage_deposit_limit</a>(\n    self,\n    storage_deposit_limit: &lt;E as Environment&gt;::Balance\n) -&gt; CallBuilder&lt;E, Set&lt;Call&lt;E&gt;&gt;, Args, RetType&gt;</h4></section></summary><div class=\"docblock\"><p>Sets the <code>storage_deposit_limit</code> for the current cross-contract call.</p>\n<p>The <code>storage_deposit_limit</code> specifies the amount of user funds that\ncan be charged for creating storage. You can find more info\n<a href=\"https://use.ink/basics/cross-contract-calling/\">here</a>.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.transferred_value\" class=\"method\"><h4 class=\"code-header\">pub fn <a class=\"fn\">transferred_value</a>(\n    self,\n    transferred_value: &lt;E as Environment&gt;::Balance\n) -&gt; CallBuilder&lt;E, Set&lt;Call&lt;E&gt;&gt;, Args, RetType&gt;</h4></section></summary><div class=\"docblock\"><p>Sets the <code>transferred_value</code> for the current cross-contract call.</p>\n<p>This value specifies the amount of user funds that are transferred\nto the other contract with this call.</p>\n</div></details></div></details>",0,"ink_e2e::subxt_client::CallBuilderFinal"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-CallBuilder%3CE,+Set%3CCall%3CE%3E%3E,+Set%3CExecutionInput%3CArgs%3E%3E,+Set%3CReturnType%3CRetType%3E%3E%3E\" class=\"impl\"><a href=\"#impl-CallBuilder%3CE,+Set%3CCall%3CE%3E%3E,+Set%3CExecutionInput%3CArgs%3E%3E,+Set%3CReturnType%3CRetType%3E%3E%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;E, Args, RetType&gt; CallBuilder&lt;E, Set&lt;Call&lt;E&gt;&gt;, Set&lt;ExecutionInput&lt;Args&gt;&gt;, Set&lt;ReturnType&lt;RetType&gt;&gt;&gt;<span class=\"where fmt-newline\">where\n    E: Environment,</span></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.params\" class=\"method\"><h4 class=\"code-header\">pub fn <a class=\"fn\">params</a>(self) -&gt; CallParams&lt;E, Call&lt;E&gt;, Args, RetType&gt;</h4></section></summary><div class=\"docblock\"><p>Finalizes the call builder to call a function.</p>\n</div></details></div></details>",0,"ink_e2e::subxt_client::CallBuilderFinal"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-CallBuilder%3CE,+Set%3CCall%3CE%3E%3E,+Set%3CExecutionInput%3CArgs%3E%3E,+Set%3CReturnType%3CR%3E%3E%3E\" class=\"impl\"><a href=\"#impl-CallBuilder%3CE,+Set%3CCall%3CE%3E%3E,+Set%3CExecutionInput%3CArgs%3E%3E,+Set%3CReturnType%3CR%3E%3E%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;E, Args, R&gt; CallBuilder&lt;E, Set&lt;Call&lt;E&gt;&gt;, Set&lt;ExecutionInput&lt;Args&gt;&gt;, Set&lt;ReturnType&lt;R&gt;&gt;&gt;<span class=\"where fmt-newline\">where\n    E: Environment,\n    Args: Encode,\n    R: Decode,</span></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.invoke\" class=\"method\"><h4 class=\"code-header\">pub fn <a class=\"fn\">invoke</a>(self) -&gt; R</h4></section></summary><div class=\"docblock\"><p>Invokes the cross-chain function call and returns the result.</p>\n<h5 id=\"panics\"><a href=\"#panics\">Panics</a></h5>\n<p>This method panics if it encounters an [<code>ink::env::Error</code>][<code>crate::Error</code>] or an\n[<code>ink::primitives::LangError</code>][<code>ink_primitives::LangError</code>]. If you want to handle\nthose use the [<code>try_invoke</code>][<code>CallBuilder::try_invoke</code>] method instead.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.try_invoke\" class=\"method\"><h4 class=\"code-header\">pub fn <a class=\"fn\">try_invoke</a>(self) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.75.0/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;<a class=\"enum\" href=\"https://doc.rust-lang.org/1.75.0/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;R, LangError&gt;, Error&gt;</h4></section></summary><div class=\"docblock\"><p>Invokes the cross-chain function call and returns the result.</p>\n<h5 id=\"note\"><a href=\"#note\">Note</a></h5>\n<p>On failure this returns an outer [<code>ink::env::Error</code>][<code>crate::Error</code>] or inner\n[<code>ink::primitives::LangError</code>][<code>ink_primitives::LangError</code>], both of which can be\nhandled by the caller.</p>\n</div></details></div></details>",0,"ink_e2e::subxt_client::CallBuilderFinal"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Clone-for-CallBuilder%3CE,+CallType,+Args,+RetType%3E\" class=\"impl\"><a href=\"#impl-Clone-for-CallBuilder%3CE,+CallType,+Args,+RetType%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;E, CallType, Args, RetType&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for CallBuilder&lt;E, CallType, Args, RetType&gt;<span class=\"where fmt-newline\">where\n    E: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + Environment,\n    CallType: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>,\n    Args: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>,\n    RetType: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>,</span></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone\" class=\"method trait-impl\"><a href=\"#method.clone\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.75.0/core/clone/trait.Clone.html#tymethod.clone\" class=\"fn\">clone</a>(&amp;self) -&gt; CallBuilder&lt;E, CallType, Args, RetType&gt;</h4></section></summary><div class='docblock'>Returns a copy of the value. <a href=\"https://doc.rust-lang.org/1.75.0/core/clone/trait.Clone.html#tymethod.clone\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone_from\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/1.75.0/src/core/clone.rs.html#169\">source</a></span><a href=\"#method.clone_from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.75.0/core/clone/trait.Clone.html#method.clone_from\" class=\"fn\">clone_from</a>(&amp;mut self, source: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.75.0/std/primitive.reference.html\">&amp;Self</a>)</h4></section></summary><div class='docblock'>Performs copy-assignment from <code>source</code>. <a href=\"https://doc.rust-lang.org/1.75.0/core/clone/trait.Clone.html#method.clone_from\">Read more</a></div></details></div></details>","Clone","ink_e2e::subxt_client::CallBuilderFinal"]]
};if (window.register_type_impls) {window.register_type_impls(type_impls);} else {window.pending_type_impls = type_impls;}})()