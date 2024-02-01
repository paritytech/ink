(function() {var implementors = {
"ink_env":[["impl TypeInfo for <a class=\"enum\" href=\"ink_env/enum.NoChainExtension.html\" title=\"enum ink_env::NoChainExtension\">NoChainExtension</a>"],["impl TypeInfo for <a class=\"enum\" href=\"ink_env/enum.DefaultEnvironment.html\" title=\"enum ink_env::DefaultEnvironment\">DefaultEnvironment</a>"]],
"ink_metadata":[],
"ink_primitives":[["impl TypeInfo for <a class=\"struct\" href=\"ink_primitives/struct.Hash.html\" title=\"struct ink_primitives::Hash\">Hash</a>"],["impl TypeInfo for <a class=\"enum\" href=\"ink_primitives/enum.LangError.html\" title=\"enum ink_primitives::LangError\">LangError</a>"],["impl TypeInfo for <a class=\"struct\" href=\"ink_primitives/struct.AccountId.html\" title=\"struct ink_primitives::AccountId\">AccountId</a>"]],
"ink_storage":[["impl&lt;K, V, KeyType&gt; TypeInfo for <a class=\"struct\" href=\"ink_storage/struct.Mapping.html\" title=\"struct ink_storage::Mapping\">Mapping</a>&lt;K, V, KeyType&gt;<span class=\"where fmt-newline\">where\n    <a class=\"struct\" href=\"https://doc.rust-lang.org/1.75.0/core/marker/struct.PhantomData.html\" title=\"struct core::marker::PhantomData\">PhantomData</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.75.0/std/primitive.fn.html\">fn</a>() -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.75.0/std/primitive.tuple.html\">(K, V, KeyType)</a>&gt;: TypeInfo + 'static,\n    K: TypeInfo + 'static,\n    V: <a class=\"trait\" href=\"ink_storage_traits/storage/trait.Packed.html\" title=\"trait ink_storage_traits::storage::Packed\">Packed</a> + TypeInfo + 'static,\n    KeyType: <a class=\"trait\" href=\"ink_storage_traits/storage/trait.StorageKey.html\" title=\"trait ink_storage_traits::storage::StorageKey\">StorageKey</a> + TypeInfo + 'static,</span>"],["impl&lt;V, KeyType&gt; TypeInfo for <a class=\"struct\" href=\"ink_storage/struct.StorageVec.html\" title=\"struct ink_storage::StorageVec\">StorageVec</a>&lt;V, KeyType&gt;<span class=\"where fmt-newline\">where\n    <a class=\"struct\" href=\"ink_storage/struct.Lazy.html\" title=\"struct ink_storage::Lazy\">Lazy</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.75.0/std/primitive.u32.html\">u32</a>, KeyType&gt;: TypeInfo + 'static,\n    <a class=\"struct\" href=\"ink_storage/struct.Mapping.html\" title=\"struct ink_storage::Mapping\">Mapping</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.75.0/std/primitive.u32.html\">u32</a>, V, KeyType&gt;: TypeInfo + 'static,\n    V: <a class=\"trait\" href=\"ink_storage_traits/storage/trait.Packed.html\" title=\"trait ink_storage_traits::storage::Packed\">Packed</a> + TypeInfo + 'static,\n    KeyType: <a class=\"trait\" href=\"ink_storage_traits/storage/trait.StorageKey.html\" title=\"trait ink_storage_traits::storage::StorageKey\">StorageKey</a> + TypeInfo + 'static,</span>"],["impl&lt;V, KeyType&gt; TypeInfo for <a class=\"struct\" href=\"ink_storage/struct.Lazy.html\" title=\"struct ink_storage::Lazy\">Lazy</a>&lt;V, KeyType&gt;<span class=\"where fmt-newline\">where\n    <a class=\"struct\" href=\"https://doc.rust-lang.org/1.75.0/core/marker/struct.PhantomData.html\" title=\"struct core::marker::PhantomData\">PhantomData</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.75.0/std/primitive.fn.html\">fn</a>() -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.75.0/std/primitive.tuple.html\">(V, KeyType)</a>&gt;: TypeInfo + 'static,\n    V: TypeInfo + 'static,\n    KeyType: <a class=\"trait\" href=\"ink_storage_traits/storage/trait.StorageKey.html\" title=\"trait ink_storage_traits::storage::StorageKey\">StorageKey</a> + TypeInfo + 'static,</span>"]],
"ink_storage_traits":[["impl&lt;L, R&gt; TypeInfo for <a class=\"struct\" href=\"ink_storage_traits/struct.ResolverKey.html\" title=\"struct ink_storage_traits::ResolverKey\">ResolverKey</a>&lt;L, R&gt;<span class=\"where fmt-newline\">where\n    <a class=\"struct\" href=\"https://doc.rust-lang.org/1.75.0/core/marker/struct.PhantomData.html\" title=\"struct core::marker::PhantomData\">PhantomData</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.75.0/std/primitive.fn.html\">fn</a>() -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.75.0/std/primitive.tuple.html\">(L, R)</a>&gt;: TypeInfo + 'static,\n    L: TypeInfo + 'static,\n    R: TypeInfo + 'static,</span>"],["impl TypeInfo for <a class=\"struct\" href=\"ink_storage_traits/struct.AutoKey.html\" title=\"struct ink_storage_traits::AutoKey\">AutoKey</a>"],["impl&lt;const KEY: <a class=\"type\" href=\"ink_primitives/key/type.Key.html\" title=\"type ink_primitives::key::Key\">Key</a>, ParentKey&gt; TypeInfo for <a class=\"struct\" href=\"ink_storage_traits/struct.ManualKey.html\" title=\"struct ink_storage_traits::ManualKey\">ManualKey</a>&lt;KEY, ParentKey&gt;<span class=\"where fmt-newline\">where\n    <a class=\"struct\" href=\"https://doc.rust-lang.org/1.75.0/core/marker/struct.PhantomData.html\" title=\"struct core::marker::PhantomData\">PhantomData</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.75.0/std/primitive.fn.html\">fn</a>() -&gt; ParentKey&gt;: TypeInfo + 'static,\n    ParentKey: <a class=\"trait\" href=\"ink_storage_traits/trait.StorageKey.html\" title=\"trait ink_storage_traits::StorageKey\">StorageKey</a> + TypeInfo + 'static,</span>"]]
};if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()