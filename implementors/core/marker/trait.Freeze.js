(function() {var implementors = {
"ink":[["impl&lt;T&gt; Freeze for <a class=\"struct\" href=\"ink/codegen/struct.DispatchInput.html\" title=\"struct ink::codegen::DispatchInput\">DispatchInput</a>&lt;T&gt;<span class=\"where fmt-newline\">where\n    T: Freeze,</span>",1,["ink::codegen::dispatch::type_check::DispatchInput"]],["impl&lt;T&gt; Freeze for <a class=\"struct\" href=\"ink/codegen/struct.DispatchOutput.html\" title=\"struct ink::codegen::DispatchOutput\">DispatchOutput</a>&lt;T&gt;<span class=\"where fmt-newline\">where\n    T: Freeze,</span>",1,["ink::codegen::dispatch::type_check::DispatchOutput"]],["impl&lt;const IS_PAYABLE: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.74.0/std/primitive.bool.html\">bool</a>&gt; Freeze for <a class=\"struct\" href=\"ink/codegen/struct.TraitMessagePayable.html\" title=\"struct ink::codegen::TraitMessagePayable\">TraitMessagePayable</a>&lt;IS_PAYABLE&gt;",1,["ink::codegen::trait_def::trait_message::TraitMessagePayable"]],["impl&lt;const SELECTOR_ID: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.74.0/std/primitive.u32.html\">u32</a>&gt; Freeze for <a class=\"struct\" href=\"ink/codegen/struct.TraitMessageSelector.html\" title=\"struct ink::codegen::TraitMessageSelector\">TraitMessageSelector</a>&lt;SELECTOR_ID&gt;",1,["ink::codegen::trait_def::trait_message::TraitMessageSelector"]],["impl&lt;T&gt; Freeze for <a class=\"struct\" href=\"ink/codegen/utils/struct.IsSameType.html\" title=\"struct ink::codegen::utils::IsSameType\">IsSameType</a>&lt;T&gt;",1,["ink::codegen::utils::same_type::IsSameType"]],["impl&lt;T&gt; Freeze for <a class=\"struct\" href=\"ink/reflect/struct.ConstructorOutputValue.html\" title=\"struct ink::reflect::ConstructorOutputValue\">ConstructorOutputValue</a>&lt;T&gt;<span class=\"where fmt-newline\">where\n    T: Freeze,</span>",1,["ink::reflect::dispatch::ConstructorOutputValue"]],["impl Freeze for <a class=\"enum\" href=\"ink/reflect/enum.DispatchError.html\" title=\"enum ink::reflect::DispatchError\">DispatchError</a>",1,["ink::reflect::dispatch::DispatchError"]],["impl&lt;E&gt; Freeze for <a class=\"struct\" href=\"ink/reflect/struct.TraitDefinitionRegistry.html\" title=\"struct ink::reflect::TraitDefinitionRegistry\">TraitDefinitionRegistry</a>&lt;E&gt;",1,["ink::reflect::trait_def::registry::TraitDefinitionRegistry"]],["impl Freeze for <a class=\"struct\" href=\"ink/struct.ValueReturned.html\" title=\"struct ink::ValueReturned\">ValueReturned</a>",1,["ink::chain_extension::ValueReturned"]],["impl&lt;'a, E&gt; Freeze for <a class=\"struct\" href=\"ink/struct.EnvAccess.html\" title=\"struct ink::EnvAccess\">EnvAccess</a>&lt;'a, E&gt;",1,["ink::env_access::EnvAccess"]]],
"ink_e2e":[["impl&lt;'a, E, Args, RetType, B&gt; Freeze for <a class=\"struct\" href=\"ink_e2e/struct.CallBuilder.html\" title=\"struct ink_e2e::CallBuilder\">CallBuilder</a>&lt;'a, E, Args, RetType, B&gt;<span class=\"where fmt-newline\">where\n    &lt;E as Environment&gt;::Balance: Freeze,</span>",1,["ink_e2e::backend_calls::CallBuilder"]],["impl&lt;'a, E, Contract, Args, R, B&gt; Freeze for <a class=\"struct\" href=\"ink_e2e/struct.InstantiateBuilder.html\" title=\"struct ink_e2e::InstantiateBuilder\">InstantiateBuilder</a>&lt;'a, E, Contract, Args, R, B&gt;<span class=\"where fmt-newline\">where\n    &lt;E as Environment&gt;::Balance: Freeze,</span>",1,["ink_e2e::backend_calls::InstantiateBuilder"]],["impl&lt;E, EventLog&gt; Freeze for <a class=\"struct\" href=\"ink_e2e/struct.InstantiationResult.html\" title=\"struct ink_e2e::InstantiationResult\">InstantiationResult</a>&lt;E, EventLog&gt;<span class=\"where fmt-newline\">where\n    EventLog: Freeze,\n    &lt;E as Environment&gt;::AccountId: Freeze,\n    &lt;E as Environment&gt;::Balance: Freeze,</span>",1,["ink_e2e::contract_results::InstantiationResult"]],["impl&lt;E, EventLog&gt; Freeze for <a class=\"struct\" href=\"ink_e2e/struct.UploadResult.html\" title=\"struct ink_e2e::UploadResult\">UploadResult</a>&lt;E, EventLog&gt;<span class=\"where fmt-newline\">where\n    EventLog: Freeze,\n    &lt;E as Environment&gt;::Balance: Freeze,\n    &lt;E as Environment&gt;::Hash: Freeze,</span>",1,["ink_e2e::contract_results::UploadResult"]],["impl&lt;E, V, EventLog&gt; Freeze for <a class=\"struct\" href=\"ink_e2e/struct.CallResult.html\" title=\"struct ink_e2e::CallResult\">CallResult</a>&lt;E, V, EventLog&gt;<span class=\"where fmt-newline\">where\n    EventLog: Freeze,\n    &lt;E as Environment&gt;::Balance: Freeze,</span>",1,["ink_e2e::contract_results::CallResult"]],["impl&lt;E, V&gt; Freeze for <a class=\"struct\" href=\"ink_e2e/struct.CallDryRunResult.html\" title=\"struct ink_e2e::CallDryRunResult\">CallDryRunResult</a>&lt;E, V&gt;<span class=\"where fmt-newline\">where\n    &lt;E as Environment&gt;::Balance: Freeze,</span>",1,["ink_e2e::contract_results::CallDryRunResult"]],["impl&lt;E&gt; Freeze for <a class=\"struct\" href=\"ink_e2e/struct.InstantiateDryRunResult.html\" title=\"struct ink_e2e::InstantiateDryRunResult\">InstantiateDryRunResult</a>&lt;E&gt;<span class=\"where fmt-newline\">where\n    &lt;E as Environment&gt;::AccountId: Freeze,\n    &lt;E as Environment&gt;::Balance: Freeze,</span>",1,["ink_e2e::contract_results::InstantiateDryRunResult"]],["impl&lt;AccountId, Hash, Runtime&gt; !Freeze for <a class=\"struct\" href=\"ink_e2e/struct.DrinkClient.html\" title=\"struct ink_e2e::DrinkClient\">Client</a>&lt;AccountId, Hash, Runtime&gt;",1,["ink_e2e::drink_client::Client"]],["impl&lt;E&gt; Freeze for <a class=\"struct\" href=\"ink_e2e/events/struct.ContractInstantiatedEvent.html\" title=\"struct ink_e2e::events::ContractInstantiatedEvent\">ContractInstantiatedEvent</a>&lt;E&gt;<span class=\"where fmt-newline\">where\n    &lt;E as Environment&gt;::AccountId: Freeze,</span>",1,["ink_e2e::events::ContractInstantiatedEvent"]],["impl&lt;E&gt; Freeze for <a class=\"struct\" href=\"ink_e2e/events/struct.CodeStoredEvent.html\" title=\"struct ink_e2e::events::CodeStoredEvent\">CodeStoredEvent</a>&lt;E&gt;<span class=\"where fmt-newline\">where\n    &lt;E as Environment&gt;::Hash: Freeze,</span>",1,["ink_e2e::events::CodeStoredEvent"]],["impl&lt;E&gt; Freeze for <a class=\"struct\" href=\"ink_e2e/events/struct.ContractEmitted.html\" title=\"struct ink_e2e::events::ContractEmitted\">ContractEmitted</a>&lt;E&gt;<span class=\"where fmt-newline\">where\n    &lt;E as Environment&gt;::AccountId: Freeze,</span>",1,["ink_e2e::events::ContractEmitted"]],["impl&lt;T&gt; Freeze for <a class=\"struct\" href=\"ink_e2e/events/struct.EventWithTopics.html\" title=\"struct ink_e2e::events::EventWithTopics\">EventWithTopics</a>&lt;T&gt;<span class=\"where fmt-newline\">where\n    T: Freeze,</span>",1,["ink_e2e::events::EventWithTopics"]],["impl&lt;R&gt; Freeze for <a class=\"struct\" href=\"ink_e2e/struct.TestNodeProcess.html\" title=\"struct ink_e2e::TestNodeProcess\">TestNodeProcess</a>&lt;R&gt;",1,["ink_e2e::node_proc::TestNodeProcess"]],["impl&lt;R&gt; Freeze for <a class=\"struct\" href=\"ink_e2e/struct.TestNodeProcessBuilder.html\" title=\"struct ink_e2e::TestNodeProcessBuilder\">TestNodeProcessBuilder</a>&lt;R&gt;",1,["ink_e2e::node_proc::TestNodeProcessBuilder"]],["impl&lt;C, E&gt; Freeze for <a class=\"struct\" href=\"ink_e2e/struct.Client.html\" title=\"struct ink_e2e::Client\">Client</a>&lt;C, E&gt;",1,["ink_e2e::subxt_client::Client"]]],
"ink_engine":[["impl Freeze for <a class=\"enum\" href=\"ink_engine/ext/enum.Error.html\" title=\"enum ink_engine::ext::Error\">Error</a>",1,["ink_engine::ext::Error"]],["impl Freeze for <a class=\"struct\" href=\"ink_engine/ext/struct.ReturnCode.html\" title=\"struct ink_engine::ext::ReturnCode\">ReturnCode</a>",1,["ink_engine::ext::ReturnCode"]],["impl Freeze for <a class=\"struct\" href=\"ink_engine/ext/struct.Engine.html\" title=\"struct ink_engine::ext::Engine\">Engine</a>",1,["ink_engine::ext::Engine"]],["impl Freeze for <a class=\"struct\" href=\"ink_engine/ext/struct.ChainSpec.html\" title=\"struct ink_engine::ext::ChainSpec\">ChainSpec</a>",1,["ink_engine::ext::ChainSpec"]],["impl Freeze for <a class=\"struct\" href=\"ink_engine/test_api/struct.EmittedEvent.html\" title=\"struct ink_engine::test_api::EmittedEvent\">EmittedEvent</a>",1,["ink_engine::test_api::EmittedEvent"]],["impl Freeze for <a class=\"struct\" href=\"ink_engine/test_api/struct.RecordedDebugMessages.html\" title=\"struct ink_engine::test_api::RecordedDebugMessages\">RecordedDebugMessages</a>",1,["ink_engine::test_api::RecordedDebugMessages"]],["impl Freeze for <a class=\"struct\" href=\"ink_engine/test_api/struct.DebugInfo.html\" title=\"struct ink_engine::test_api::DebugInfo\">DebugInfo</a>",1,["ink_engine::test_api::DebugInfo"]],["impl Freeze for <a class=\"enum\" href=\"ink_engine/enum.AccountError.html\" title=\"enum ink_engine::AccountError\">AccountError</a>",1,["ink_engine::types::AccountError"]],["impl Freeze for <a class=\"enum\" href=\"ink_engine/enum.Error.html\" title=\"enum ink_engine::Error\">Error</a>",1,["ink_engine::Error"]]],
"ink_env":[["impl Freeze for <a class=\"struct\" href=\"ink_env/struct.ReturnFlags.html\" title=\"struct ink_env::ReturnFlags\">ReturnFlags</a>",1,["ink_env::backend::ReturnFlags"]],["impl Freeze for <a class=\"struct\" href=\"ink_env/struct.CallFlags.html\" title=\"struct ink_env::CallFlags\">CallFlags</a>",1,["ink_env::backend::CallFlags"]],["impl&lt;E, CallType, Args, R&gt; Freeze for <a class=\"struct\" href=\"ink_env/call/struct.CallParams.html\" title=\"struct ink_env::call::CallParams\">CallParams</a>&lt;E, CallType, Args, R&gt;<span class=\"where fmt-newline\">where\n    Args: Freeze,\n    CallType: Freeze,</span>",1,["ink_env::call::call_builder::CallParams"]],["impl&lt;E&gt; Freeze for <a class=\"struct\" href=\"ink_env/call/struct.Call.html\" title=\"struct ink_env::call::Call\">Call</a>&lt;E&gt;<span class=\"where fmt-newline\">where\n    &lt;E as <a class=\"trait\" href=\"ink_env/trait.Environment.html\" title=\"trait ink_env::Environment\">Environment</a>&gt;::<a class=\"associatedtype\" href=\"ink_env/trait.Environment.html#associatedtype.AccountId\" title=\"type ink_env::Environment::AccountId\">AccountId</a>: Freeze,\n    &lt;E as <a class=\"trait\" href=\"ink_env/trait.Environment.html\" title=\"trait ink_env::Environment\">Environment</a>&gt;::<a class=\"associatedtype\" href=\"ink_env/trait.Environment.html#associatedtype.Balance\" title=\"type ink_env::Environment::Balance\">Balance</a>: Freeze,</span>",1,["ink_env::call::call_builder::Call"]],["impl&lt;E&gt; Freeze for <a class=\"struct\" href=\"ink_env/call/struct.DelegateCall.html\" title=\"struct ink_env::call::DelegateCall\">DelegateCall</a>&lt;E&gt;<span class=\"where fmt-newline\">where\n    &lt;E as <a class=\"trait\" href=\"ink_env/trait.Environment.html\" title=\"trait ink_env::Environment\">Environment</a>&gt;::<a class=\"associatedtype\" href=\"ink_env/trait.Environment.html#associatedtype.Hash\" title=\"type ink_env::Environment::Hash\">Hash</a>: Freeze,</span>",1,["ink_env::call::call_builder::DelegateCall"]],["impl&lt;E, CallType, Args, RetType&gt; Freeze for <a class=\"struct\" href=\"ink_env/call/struct.CallBuilder.html\" title=\"struct ink_env::call::CallBuilder\">CallBuilder</a>&lt;E, CallType, Args, RetType&gt;<span class=\"where fmt-newline\">where\n    Args: Freeze,\n    CallType: Freeze,\n    RetType: Freeze,</span>",1,["ink_env::call::call_builder::CallBuilder"]],["impl&lt;T&gt; Freeze for <a class=\"struct\" href=\"ink_env/call/utils/struct.ReturnType.html\" title=\"struct ink_env::call::utils::ReturnType\">ReturnType</a>&lt;T&gt;",1,["ink_env::call::common::ReturnType"]],["impl&lt;T&gt; Freeze for <a class=\"struct\" href=\"ink_env/call/utils/struct.Set.html\" title=\"struct ink_env::call::utils::Set\">Set</a>&lt;T&gt;<span class=\"where fmt-newline\">where\n    T: Freeze,</span>",1,["ink_env::call::common::Set"]],["impl&lt;T&gt; Freeze for <a class=\"struct\" href=\"ink_env/call/utils/struct.Unset.html\" title=\"struct ink_env::call::utils::Unset\">Unset</a>&lt;T&gt;",1,["ink_env::call::common::Unset"]],["impl Freeze for <a class=\"enum\" href=\"ink_env/call/state/enum.Salt.html\" title=\"enum ink_env::call::state::Salt\">Salt</a>",1,["ink_env::call::create_builder::state::Salt"]],["impl&lt;E, ContractRef, Args, Salt, R&gt; Freeze for <a class=\"struct\" href=\"ink_env/call/struct.CreateParams.html\" title=\"struct ink_env::call::CreateParams\">CreateParams</a>&lt;E, ContractRef, Args, Salt, R&gt;<span class=\"where fmt-newline\">where\n    Args: Freeze,\n    Salt: Freeze,\n    &lt;E as <a class=\"trait\" href=\"ink_env/trait.Environment.html\" title=\"trait ink_env::Environment\">Environment</a>&gt;::<a class=\"associatedtype\" href=\"ink_env/trait.Environment.html#associatedtype.Balance\" title=\"type ink_env::Environment::Balance\">Balance</a>: Freeze,\n    &lt;E as <a class=\"trait\" href=\"ink_env/trait.Environment.html\" title=\"trait ink_env::Environment\">Environment</a>&gt;::<a class=\"associatedtype\" href=\"ink_env/trait.Environment.html#associatedtype.Hash\" title=\"type ink_env::Environment::Hash\">Hash</a>: Freeze,</span>",1,["ink_env::call::create_builder::CreateParams"]],["impl&lt;E, ContractRef, CodeHash, GasLimit, Endowment, Args, Salt, RetType&gt; Freeze for <a class=\"struct\" href=\"ink_env/call/struct.CreateBuilder.html\" title=\"struct ink_env::call::CreateBuilder\">CreateBuilder</a>&lt;E, ContractRef, CodeHash, GasLimit, Endowment, Args, Salt, RetType&gt;<span class=\"where fmt-newline\">where\n    Args: Freeze,\n    CodeHash: Freeze,\n    Endowment: Freeze,\n    GasLimit: Freeze,\n    RetType: Freeze,\n    Salt: Freeze,</span>",1,["ink_env::call::create_builder::CreateBuilder"]],["impl&lt;Args&gt; Freeze for <a class=\"struct\" href=\"ink_env/call/struct.ExecutionInput.html\" title=\"struct ink_env::call::ExecutionInput\">ExecutionInput</a>&lt;Args&gt;<span class=\"where fmt-newline\">where\n    Args: Freeze,</span>",1,["ink_env::call::execution_input::ExecutionInput"]],["impl&lt;Head, Rest&gt; Freeze for <a class=\"struct\" href=\"ink_env/call/utils/struct.ArgumentList.html\" title=\"struct ink_env::call::utils::ArgumentList\">ArgumentList</a>&lt;Head, Rest&gt;<span class=\"where fmt-newline\">where\n    Head: Freeze,\n    Rest: Freeze,</span>",1,["ink_env::call::execution_input::ArgumentList"]],["impl&lt;T&gt; Freeze for <a class=\"struct\" href=\"ink_env/call/utils/struct.Argument.html\" title=\"struct ink_env::call::utils::Argument\">Argument</a>&lt;T&gt;<span class=\"where fmt-newline\">where\n    T: Freeze,</span>",1,["ink_env::call::execution_input::Argument"]],["impl Freeze for <a class=\"struct\" href=\"ink_env/call/utils/struct.ArgumentListEnd.html\" title=\"struct ink_env::call::utils::ArgumentListEnd\">ArgumentListEnd</a>",1,["ink_env::call::execution_input::ArgumentListEnd"]],["impl Freeze for <a class=\"struct\" href=\"ink_env/call/struct.Selector.html\" title=\"struct ink_env::call::Selector\">Selector</a>",1,["ink_env::call::selector::Selector"]],["impl Freeze for <a class=\"enum\" href=\"ink_env/chain_extension/state/enum.IgnoreErrorCode.html\" title=\"enum ink_env::chain_extension::state::IgnoreErrorCode\">IgnoreErrorCode</a>",1,["ink_env::chain_extension::state::IgnoreErrorCode"]],["impl&lt;T&gt; Freeze for <a class=\"struct\" href=\"ink_env/chain_extension/state/struct.HandleErrorCode.html\" title=\"struct ink_env::chain_extension::state::HandleErrorCode\">HandleErrorCode</a>&lt;T&gt;",1,["ink_env::chain_extension::state::HandleErrorCode"]],["impl&lt;I, O, ErrorCode, const IS_RESULT: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.74.0/std/primitive.bool.html\">bool</a>&gt; Freeze for <a class=\"struct\" href=\"ink_env/chain_extension/struct.ChainExtensionMethod.html\" title=\"struct ink_env::chain_extension::ChainExtensionMethod\">ChainExtensionMethod</a>&lt;I, O, ErrorCode, IS_RESULT&gt;",1,["ink_env::chain_extension::ChainExtensionMethod"]],["impl Freeze for <a class=\"struct\" href=\"ink_env/test/struct.CallData.html\" title=\"struct ink_env::test::CallData\">CallData</a>",1,["ink_env::engine::off_chain::call_data::CallData"]],["impl Freeze for <a class=\"struct\" href=\"ink_env/test/struct.EmittedEvent.html\" title=\"struct ink_env::test::EmittedEvent\">EmittedEvent</a>",1,["ink_env::engine::off_chain::test_api::EmittedEvent"]],["impl&lt;T&gt; Freeze for <a class=\"struct\" href=\"ink_env/test/struct.DefaultAccounts.html\" title=\"struct ink_env::test::DefaultAccounts\">DefaultAccounts</a>&lt;T&gt;<span class=\"where fmt-newline\">where\n    &lt;T as <a class=\"trait\" href=\"ink_env/trait.Environment.html\" title=\"trait ink_env::Environment\">Environment</a>&gt;::<a class=\"associatedtype\" href=\"ink_env/trait.Environment.html#associatedtype.AccountId\" title=\"type ink_env::Environment::AccountId\">AccountId</a>: Freeze,</span>",1,["ink_env::engine::off_chain::test_api::DefaultAccounts"]],["impl Freeze for <a class=\"enum\" href=\"ink_env/enum.Error.html\" title=\"enum ink_env::Error\">Error</a>",1,["ink_env::error::Error"]],["impl Freeze for <a class=\"enum\" href=\"ink_env/hash/enum.Sha2x256.html\" title=\"enum ink_env::hash::Sha2x256\">Sha2x256</a>",1,["ink_env::hash::Sha2x256"]],["impl Freeze for <a class=\"enum\" href=\"ink_env/hash/enum.Keccak256.html\" title=\"enum ink_env::hash::Keccak256\">Keccak256</a>",1,["ink_env::hash::Keccak256"]],["impl Freeze for <a class=\"enum\" href=\"ink_env/hash/enum.Blake2x256.html\" title=\"enum ink_env::hash::Blake2x256\">Blake2x256</a>",1,["ink_env::hash::Blake2x256"]],["impl Freeze for <a class=\"enum\" href=\"ink_env/hash/enum.Blake2x128.html\" title=\"enum ink_env::hash::Blake2x128\">Blake2x128</a>",1,["ink_env::hash::Blake2x128"]],["impl Freeze for <a class=\"enum\" href=\"ink_env/enum.NoChainExtension.html\" title=\"enum ink_env::NoChainExtension\">NoChainExtension</a>",1,["ink_env::types::NoChainExtension"]],["impl Freeze for <a class=\"enum\" href=\"ink_env/enum.DefaultEnvironment.html\" title=\"enum ink_env::DefaultEnvironment\">DefaultEnvironment</a>",1,["ink_env::types::DefaultEnvironment"]]],
"ink_ir":[["impl Freeze for <a class=\"struct\" href=\"ink_ir/ast/struct.AttributeArgs.html\" title=\"struct ink_ir::ast::AttributeArgs\">AttributeArgs</a>",1,["ink_ir::ast::attr_args::AttributeArgs"]],["impl Freeze for <a class=\"enum\" href=\"ink_ir/ast/enum.Meta.html\" title=\"enum ink_ir::ast::Meta\">Meta</a>",1,["ink_ir::ast::meta::Meta"]],["impl Freeze for <a class=\"struct\" href=\"ink_ir/ast/struct.MetaNameValue.html\" title=\"struct ink_ir::ast::MetaNameValue\">MetaNameValue</a>",1,["ink_ir::ast::meta::MetaNameValue"]],["impl Freeze for <a class=\"enum\" href=\"ink_ir/ast/enum.MetaValue.html\" title=\"enum ink_ir::ast::MetaValue\">MetaValue</a>",1,["ink_ir::ast::meta::MetaValue"]],["impl Freeze for <a class=\"enum\" href=\"ink_ir/ast/enum.Symbol.html\" title=\"enum ink_ir::ast::Symbol\">Symbol</a>",1,["ink_ir::ast::meta::Symbol"]],["impl Freeze for <a class=\"struct\" href=\"ink_ir/struct.Namespace.html\" title=\"struct ink_ir::Namespace\">Namespace</a>",1,["ink_ir::ir::attrs::Namespace"]],["impl Freeze for <a class=\"struct\" href=\"ink_ir/struct.Blake2x256Macro.html\" title=\"struct ink_ir::Blake2x256Macro\">Blake2x256Macro</a>",1,["ink_ir::ir::blake2::Blake2x256Macro"]],["impl Freeze for <a class=\"struct\" href=\"ink_ir/struct.ChainExtension.html\" title=\"struct ink_ir::ChainExtension\">ChainExtension</a>",1,["ink_ir::ir::chain_extension::ChainExtension"]],["impl Freeze for <a class=\"struct\" href=\"ink_ir/struct.ChainExtensionMethod.html\" title=\"struct ink_ir::ChainExtensionMethod\">ChainExtensionMethod</a>",1,["ink_ir::ir::chain_extension::ChainExtensionMethod"]],["impl Freeze for <a class=\"struct\" href=\"ink_ir/struct.ExtensionId.html\" title=\"struct ink_ir::ExtensionId\">ExtensionId</a>",1,["ink_ir::ir::chain_extension::ExtensionId"]],["impl Freeze for <a class=\"struct\" href=\"ink_ir/struct.Config.html\" title=\"struct ink_ir::Config\">Config</a>",1,["ink_ir::ir::config::Config"]],["impl Freeze for <a class=\"struct\" href=\"ink_ir/struct.Contract.html\" title=\"struct ink_ir::Contract\">Contract</a>",1,["ink_ir::ir::contract::Contract"]],["impl Freeze for <a class=\"struct\" href=\"ink_ir/struct.SignatureTopicArg.html\" title=\"struct ink_ir::SignatureTopicArg\">SignatureTopicArg</a>",1,["ink_ir::ir::event::signature_topic::SignatureTopicArg"]],["impl Freeze for <a class=\"struct\" href=\"ink_ir/struct.Event.html\" title=\"struct ink_ir::Event\">Event</a>",1,["ink_ir::ir::event::Event"]],["impl Freeze for <a class=\"struct\" href=\"ink_ir/struct.InkTest.html\" title=\"struct ink_ir::InkTest\">InkTest</a>",1,["ink_ir::ir::ink_test::InkTest"]],["impl Freeze for <a class=\"struct\" href=\"ink_ir/struct.Storage.html\" title=\"struct ink_ir::Storage\">Storage</a>",1,["ink_ir::ir::item::storage::Storage"]],["impl Freeze for <a class=\"enum\" href=\"ink_ir/enum.Item.html\" title=\"enum ink_ir::Item\">Item</a>",1,["ink_ir::ir::item::Item"]],["impl Freeze for <a class=\"enum\" href=\"ink_ir/enum.InkItem.html\" title=\"enum ink_ir::InkItem\">InkItem</a>",1,["ink_ir::ir::item::InkItem"]],["impl Freeze for <a class=\"enum\" href=\"ink_ir/enum.CallableKind.html\" title=\"enum ink_ir::CallableKind\">CallableKind</a>",1,["ink_ir::ir::item_impl::callable::CallableKind"]],["impl&lt;'a, C&gt; Freeze for <a class=\"struct\" href=\"ink_ir/struct.CallableWithSelector.html\" title=\"struct ink_ir::CallableWithSelector\">CallableWithSelector</a>&lt;'a, C&gt;",1,["ink_ir::ir::item_impl::callable::CallableWithSelector"]],["impl Freeze for <a class=\"enum\" href=\"ink_ir/enum.Visibility.html\" title=\"enum ink_ir::Visibility\">Visibility</a>",1,["ink_ir::ir::item_impl::callable::Visibility"]],["impl&lt;'a&gt; Freeze for <a class=\"struct\" href=\"ink_ir/struct.InputsIter.html\" title=\"struct ink_ir::InputsIter\">InputsIter</a>&lt;'a&gt;",1,["ink_ir::ir::item_impl::callable::InputsIter"]],["impl Freeze for <a class=\"struct\" href=\"ink_ir/struct.Constructor.html\" title=\"struct ink_ir::Constructor\">Constructor</a>",1,["ink_ir::ir::item_impl::constructor::Constructor"]],["impl Freeze for <a class=\"enum\" href=\"ink_ir/enum.ImplItem.html\" title=\"enum ink_ir::ImplItem\">ImplItem</a>",1,["ink_ir::ir::item_impl::impl_item::ImplItem"]],["impl&lt;'a&gt; Freeze for <a class=\"struct\" href=\"ink_ir/struct.IterConstructors.html\" title=\"struct ink_ir::IterConstructors\">IterConstructors</a>&lt;'a&gt;",1,["ink_ir::ir::item_impl::iter::IterConstructors"]],["impl&lt;'a&gt; Freeze for <a class=\"struct\" href=\"ink_ir/struct.IterMessages.html\" title=\"struct ink_ir::IterMessages\">IterMessages</a>&lt;'a&gt;",1,["ink_ir::ir::item_impl::iter::IterMessages"]],["impl Freeze for <a class=\"enum\" href=\"ink_ir/enum.Receiver.html\" title=\"enum ink_ir::Receiver\">Receiver</a>",1,["ink_ir::ir::item_impl::message::Receiver"]],["impl Freeze for <a class=\"struct\" href=\"ink_ir/struct.Message.html\" title=\"struct ink_ir::Message\">Message</a>",1,["ink_ir::ir::item_impl::message::Message"]],["impl Freeze for <a class=\"struct\" href=\"ink_ir/struct.ItemImpl.html\" title=\"struct ink_ir::ItemImpl\">ItemImpl</a>",1,["ink_ir::ir::item_impl::ItemImpl"]],["impl Freeze for <a class=\"struct\" href=\"ink_ir/struct.ItemMod.html\" title=\"struct ink_ir::ItemMod\">ItemMod</a>",1,["ink_ir::ir::item_mod::ItemMod"]],["impl&lt;'a&gt; Freeze for <a class=\"struct\" href=\"ink_ir/struct.IterEvents.html\" title=\"struct ink_ir::IterEvents\">IterEvents</a>&lt;'a&gt;",1,["ink_ir::ir::item_mod::IterEvents"]],["impl&lt;'a&gt; Freeze for <a class=\"struct\" href=\"ink_ir/struct.IterItemImpls.html\" title=\"struct ink_ir::IterItemImpls\">IterItemImpls</a>&lt;'a&gt;",1,["ink_ir::ir::item_mod::IterItemImpls"]],["impl Freeze for <a class=\"struct\" href=\"ink_ir/struct.Selector.html\" title=\"struct ink_ir::Selector\">Selector</a>",1,["ink_ir::ir::selector::Selector"]],["impl Freeze for <a class=\"enum\" href=\"ink_ir/marker/enum.SelectorId.html\" title=\"enum ink_ir::marker::SelectorId\">SelectorId</a>",1,["ink_ir::ir::selector::SelectorId"]],["impl Freeze for <a class=\"enum\" href=\"ink_ir/marker/enum.SelectorBytes.html\" title=\"enum ink_ir::marker::SelectorBytes\">SelectorBytes</a>",1,["ink_ir::ir::selector::SelectorBytes"]],["impl&lt;T&gt; Freeze for <a class=\"struct\" href=\"ink_ir/struct.SelectorMacro.html\" title=\"struct ink_ir::SelectorMacro\">SelectorMacro</a>&lt;T&gt;",1,["ink_ir::ir::selector::SelectorMacro"]],["impl Freeze for <a class=\"struct\" href=\"ink_ir/struct.StorageItem.html\" title=\"struct ink_ir::StorageItem\">StorageItem</a>",1,["ink_ir::ir::storage_item::StorageItem"]],["impl&lt;'a&gt; Freeze for <a class=\"struct\" href=\"ink_ir/struct.IterInkTraitItems.html\" title=\"struct ink_ir::IterInkTraitItems\">IterInkTraitItems</a>&lt;'a&gt;",1,["ink_ir::ir::trait_def::item::iter::IterInkTraitItems"]],["impl&lt;'a&gt; Freeze for <a class=\"enum\" href=\"ink_ir/enum.InkTraitItem.html\" title=\"enum ink_ir::InkTraitItem\">InkTraitItem</a>&lt;'a&gt;",1,["ink_ir::ir::trait_def::item::trait_item::InkTraitItem"]],["impl&lt;'a&gt; Freeze for <a class=\"struct\" href=\"ink_ir/struct.InkTraitMessage.html\" title=\"struct ink_ir::InkTraitMessage\">InkTraitMessage</a>&lt;'a&gt;",1,["ink_ir::ir::trait_def::item::trait_item::InkTraitMessage"]],["impl Freeze for <a class=\"struct\" href=\"ink_ir/struct.InkItemTrait.html\" title=\"struct ink_ir::InkItemTrait\">InkItemTrait</a>",1,["ink_ir::ir::trait_def::item::InkItemTrait"]],["impl Freeze for <a class=\"struct\" href=\"ink_ir/struct.InkTraitDefinition.html\" title=\"struct ink_ir::InkTraitDefinition\">InkTraitDefinition</a>",1,["ink_ir::ir::trait_def::InkTraitDefinition"]],["impl Freeze for <a class=\"struct\" href=\"ink_ir/utils/struct.WhitelistedAttributes.html\" title=\"struct ink_ir::utils::WhitelistedAttributes\">WhitelistedAttributes</a>",1,["ink_ir::ir::utils::WhitelistedAttributes"]]],
"ink_metadata":[["impl Freeze for <a class=\"struct\" href=\"ink_metadata/layout/struct.ValidateLayout.html\" title=\"struct ink_metadata::layout::ValidateLayout\">ValidateLayout</a>",1,["ink_metadata::layout::validate::ValidateLayout"]],["impl&lt;F&gt; Freeze for <a class=\"enum\" href=\"ink_metadata/layout/enum.Layout.html\" title=\"enum ink_metadata::layout::Layout\">Layout</a>&lt;F&gt;<span class=\"where fmt-newline\">where\n    &lt;F as Form&gt;::String: Freeze,\n    &lt;F as Form&gt;::Type: Freeze,</span>",1,["ink_metadata::layout::Layout"]],["impl Freeze for <a class=\"struct\" href=\"ink_metadata/layout/struct.LayoutKey.html\" title=\"struct ink_metadata::layout::LayoutKey\">LayoutKey</a>",1,["ink_metadata::layout::LayoutKey"]],["impl&lt;F&gt; Freeze for <a class=\"struct\" href=\"ink_metadata/layout/struct.RootLayout.html\" title=\"struct ink_metadata::layout::RootLayout\">RootLayout</a>&lt;F&gt;<span class=\"where fmt-newline\">where\n    &lt;F as Form&gt;::Type: Freeze,</span>",1,["ink_metadata::layout::RootLayout"]],["impl&lt;F&gt; Freeze for <a class=\"struct\" href=\"ink_metadata/layout/struct.LeafLayout.html\" title=\"struct ink_metadata::layout::LeafLayout\">LeafLayout</a>&lt;F&gt;<span class=\"where fmt-newline\">where\n    &lt;F as Form&gt;::Type: Freeze,</span>",1,["ink_metadata::layout::LeafLayout"]],["impl&lt;F&gt; Freeze for <a class=\"struct\" href=\"ink_metadata/layout/struct.HashLayout.html\" title=\"struct ink_metadata::layout::HashLayout\">HashLayout</a>&lt;F&gt;",1,["ink_metadata::layout::HashLayout"]],["impl Freeze for <a class=\"struct\" href=\"ink_metadata/layout/struct.HashingStrategy.html\" title=\"struct ink_metadata::layout::HashingStrategy\">HashingStrategy</a>",1,["ink_metadata::layout::HashingStrategy"]],["impl Freeze for <a class=\"enum\" href=\"ink_metadata/layout/enum.CryptoHasher.html\" title=\"enum ink_metadata::layout::CryptoHasher\">CryptoHasher</a>",1,["ink_metadata::layout::CryptoHasher"]],["impl&lt;F&gt; Freeze for <a class=\"struct\" href=\"ink_metadata/layout/struct.ArrayLayout.html\" title=\"struct ink_metadata::layout::ArrayLayout\">ArrayLayout</a>&lt;F&gt;",1,["ink_metadata::layout::ArrayLayout"]],["impl&lt;F&gt; Freeze for <a class=\"struct\" href=\"ink_metadata/layout/struct.StructLayout.html\" title=\"struct ink_metadata::layout::StructLayout\">StructLayout</a>&lt;F&gt;<span class=\"where fmt-newline\">where\n    &lt;F as Form&gt;::String: Freeze,</span>",1,["ink_metadata::layout::StructLayout"]],["impl&lt;F&gt; Freeze for <a class=\"struct\" href=\"ink_metadata/layout/struct.FieldLayout.html\" title=\"struct ink_metadata::layout::FieldLayout\">FieldLayout</a>&lt;F&gt;<span class=\"where fmt-newline\">where\n    &lt;F as Form&gt;::String: Freeze,\n    &lt;F as Form&gt;::Type: Freeze,</span>",1,["ink_metadata::layout::FieldLayout"]],["impl Freeze for <a class=\"struct\" href=\"ink_metadata/layout/struct.Discriminant.html\" title=\"struct ink_metadata::layout::Discriminant\">Discriminant</a>",1,["ink_metadata::layout::Discriminant"]],["impl&lt;F&gt; Freeze for <a class=\"struct\" href=\"ink_metadata/layout/struct.EnumLayout.html\" title=\"struct ink_metadata::layout::EnumLayout\">EnumLayout</a>&lt;F&gt;<span class=\"where fmt-newline\">where\n    &lt;F as Form&gt;::String: Freeze,</span>",1,["ink_metadata::layout::EnumLayout"]],["impl Freeze for <a class=\"enum\" href=\"ink_metadata/layout/enum.MetadataError.html\" title=\"enum ink_metadata::layout::MetadataError\">MetadataError</a>",1,["ink_metadata::layout::MetadataError"]],["impl&lt;F&gt; Freeze for <a class=\"struct\" href=\"ink_metadata/struct.ContractSpec.html\" title=\"struct ink_metadata::ContractSpec\">ContractSpec</a>&lt;F&gt;<span class=\"where fmt-newline\">where\n    &lt;F as Form&gt;::Type: Freeze,</span>",1,["ink_metadata::specs::ContractSpec"]],["impl&lt;F, S&gt; Freeze for <a class=\"struct\" href=\"ink_metadata/struct.ContractSpecBuilder.html\" title=\"struct ink_metadata::ContractSpecBuilder\">ContractSpecBuilder</a>&lt;F, S&gt;<span class=\"where fmt-newline\">where\n    &lt;F as Form&gt;::Type: Freeze,</span>",1,["ink_metadata::specs::ContractSpecBuilder"]],["impl&lt;F&gt; Freeze for <a class=\"struct\" href=\"ink_metadata/struct.ConstructorSpec.html\" title=\"struct ink_metadata::ConstructorSpec\">ConstructorSpec</a>&lt;F&gt;<span class=\"where fmt-newline\">where\n    &lt;F as Form&gt;::String: Freeze,\n    &lt;F as Form&gt;::Type: Freeze,</span>",1,["ink_metadata::specs::ConstructorSpec"]],["impl&lt;F, Selector, IsPayable, Returns&gt; Freeze for <a class=\"struct\" href=\"ink_metadata/struct.ConstructorSpecBuilder.html\" title=\"struct ink_metadata::ConstructorSpecBuilder\">ConstructorSpecBuilder</a>&lt;F, Selector, IsPayable, Returns&gt;<span class=\"where fmt-newline\">where\n    &lt;F as Form&gt;::String: Freeze,\n    &lt;F as Form&gt;::Type: Freeze,</span>",1,["ink_metadata::specs::ConstructorSpecBuilder"]],["impl&lt;F&gt; Freeze for <a class=\"struct\" href=\"ink_metadata/struct.MessageSpec.html\" title=\"struct ink_metadata::MessageSpec\">MessageSpec</a>&lt;F&gt;<span class=\"where fmt-newline\">where\n    &lt;F as Form&gt;::String: Freeze,\n    &lt;F as Form&gt;::Type: Freeze,</span>",1,["ink_metadata::specs::MessageSpec"]],["impl&lt;F, Selector, Mutates, IsPayable, Returns&gt; Freeze for <a class=\"struct\" href=\"ink_metadata/struct.MessageSpecBuilder.html\" title=\"struct ink_metadata::MessageSpecBuilder\">MessageSpecBuilder</a>&lt;F, Selector, Mutates, IsPayable, Returns&gt;<span class=\"where fmt-newline\">where\n    &lt;F as Form&gt;::String: Freeze,\n    &lt;F as Form&gt;::Type: Freeze,</span>",1,["ink_metadata::specs::MessageSpecBuilder"]],["impl&lt;F&gt; Freeze for <a class=\"struct\" href=\"ink_metadata/struct.EventSpec.html\" title=\"struct ink_metadata::EventSpec\">EventSpec</a>&lt;F&gt;<span class=\"where fmt-newline\">where\n    &lt;F as Form&gt;::String: Freeze,</span>",1,["ink_metadata::specs::EventSpec"]],["impl&lt;F&gt; Freeze for <a class=\"struct\" href=\"ink_metadata/struct.EventSpecBuilder.html\" title=\"struct ink_metadata::EventSpecBuilder\">EventSpecBuilder</a>&lt;F&gt;<span class=\"where fmt-newline\">where\n    &lt;F as Form&gt;::String: Freeze,</span>",1,["ink_metadata::specs::EventSpecBuilder"]],["impl Freeze for <a class=\"struct\" href=\"ink_metadata/struct.Selector.html\" title=\"struct ink_metadata::Selector\">Selector</a>",1,["ink_metadata::specs::Selector"]],["impl&lt;F&gt; Freeze for <a class=\"struct\" href=\"ink_metadata/struct.TypeSpec.html\" title=\"struct ink_metadata::TypeSpec\">TypeSpec</a>&lt;F&gt;<span class=\"where fmt-newline\">where\n    &lt;F as Form&gt;::Type: Freeze,</span>",1,["ink_metadata::specs::TypeSpec"]],["impl&lt;F&gt; Freeze for <a class=\"struct\" href=\"ink_metadata/struct.EventParamSpec.html\" title=\"struct ink_metadata::EventParamSpec\">EventParamSpec</a>&lt;F&gt;<span class=\"where fmt-newline\">where\n    &lt;F as Form&gt;::String: Freeze,\n    &lt;F as Form&gt;::Type: Freeze,</span>",1,["ink_metadata::specs::EventParamSpec"]],["impl&lt;F&gt; Freeze for <a class=\"struct\" href=\"ink_metadata/struct.EventParamSpecBuilder.html\" title=\"struct ink_metadata::EventParamSpecBuilder\">EventParamSpecBuilder</a>&lt;F&gt;<span class=\"where fmt-newline\">where\n    &lt;F as Form&gt;::String: Freeze,\n    &lt;F as Form&gt;::Type: Freeze,</span>",1,["ink_metadata::specs::EventParamSpecBuilder"]],["impl&lt;F&gt; Freeze for <a class=\"struct\" href=\"ink_metadata/struct.ReturnTypeSpec.html\" title=\"struct ink_metadata::ReturnTypeSpec\">ReturnTypeSpec</a>&lt;F&gt;<span class=\"where fmt-newline\">where\n    &lt;F as Form&gt;::Type: Freeze,</span>",1,["ink_metadata::specs::ReturnTypeSpec"]],["impl&lt;F&gt; Freeze for <a class=\"struct\" href=\"ink_metadata/struct.MessageParamSpec.html\" title=\"struct ink_metadata::MessageParamSpec\">MessageParamSpec</a>&lt;F&gt;<span class=\"where fmt-newline\">where\n    &lt;F as Form&gt;::String: Freeze,\n    &lt;F as Form&gt;::Type: Freeze,</span>",1,["ink_metadata::specs::MessageParamSpec"]],["impl&lt;F&gt; Freeze for <a class=\"struct\" href=\"ink_metadata/struct.MessageParamSpecBuilder.html\" title=\"struct ink_metadata::MessageParamSpecBuilder\">MessageParamSpecBuilder</a>&lt;F&gt;<span class=\"where fmt-newline\">where\n    &lt;F as Form&gt;::String: Freeze,\n    &lt;F as Form&gt;::Type: Freeze,</span>",1,["ink_metadata::specs::MessageParamSpecBuilder"]],["impl&lt;F&gt; Freeze for <a class=\"struct\" href=\"ink_metadata/struct.EnvironmentSpec.html\" title=\"struct ink_metadata::EnvironmentSpec\">EnvironmentSpec</a>&lt;F&gt;<span class=\"where fmt-newline\">where\n    &lt;F as Form&gt;::Type: Freeze,</span>",1,["ink_metadata::specs::EnvironmentSpec"]],["impl&lt;F, A, B, H, T, BN, C, M, BS&gt; Freeze for <a class=\"struct\" href=\"ink_metadata/struct.EnvironmentSpecBuilder.html\" title=\"struct ink_metadata::EnvironmentSpecBuilder\">EnvironmentSpecBuilder</a>&lt;F, A, B, H, T, BN, C, M, BS&gt;<span class=\"where fmt-newline\">where\n    &lt;F as Form&gt;::Type: Freeze,</span>",1,["ink_metadata::specs::EnvironmentSpecBuilder"]],["impl Freeze for <a class=\"enum\" href=\"ink_metadata/enum.MetadataVersion.html\" title=\"enum ink_metadata::MetadataVersion\">MetadataVersion</a>",1,["ink_metadata::MetadataVersion"]],["impl Freeze for <a class=\"struct\" href=\"ink_metadata/struct.InkProject.html\" title=\"struct ink_metadata::InkProject\">InkProject</a>",1,["ink_metadata::InkProject"]]],
"ink_primitives":[["impl Freeze for <a class=\"struct\" href=\"ink_primitives/struct.KeyComposer.html\" title=\"struct ink_primitives::KeyComposer\">KeyComposer</a>",1,["ink_primitives::key::KeyComposer"]],["impl Freeze for <a class=\"struct\" href=\"ink_primitives/struct.AccountId.html\" title=\"struct ink_primitives::AccountId\">AccountId</a>",1,["ink_primitives::types::AccountId"]],["impl Freeze for <a class=\"struct\" href=\"ink_primitives/struct.Hash.html\" title=\"struct ink_primitives::Hash\">Hash</a>",1,["ink_primitives::types::Hash"]],["impl Freeze for <a class=\"enum\" href=\"ink_primitives/enum.LangError.html\" title=\"enum ink_primitives::LangError\">LangError</a>",1,["ink_primitives::LangError"]]],
"ink_storage":[["impl&lt;K, V, KeyType&gt; Freeze for <a class=\"struct\" href=\"ink_storage/struct.Mapping.html\" title=\"struct ink_storage::Mapping\">Mapping</a>&lt;K, V, KeyType&gt;",1,["ink_storage::lazy::mapping::Mapping"]],["impl&lt;V, KeyType = <a class=\"struct\" href=\"ink_storage_traits/impls/struct.AutoKey.html\" title=\"struct ink_storage_traits::impls::AutoKey\">AutoKey</a>&gt; !Freeze for <a class=\"struct\" href=\"ink_storage/struct.StorageVec.html\" title=\"struct ink_storage::StorageVec\">StorageVec</a>&lt;V, KeyType&gt;",1,["ink_storage::lazy::vec::StorageVec"]],["impl&lt;V, KeyType&gt; Freeze for <a class=\"struct\" href=\"ink_storage/struct.Lazy.html\" title=\"struct ink_storage::Lazy\">Lazy</a>&lt;V, KeyType&gt;",1,["ink_storage::lazy::Lazy"]]],
"ink_storage_traits":[["impl Freeze for <a class=\"struct\" href=\"ink_storage_traits/struct.AutoKey.html\" title=\"struct ink_storage_traits::AutoKey\">AutoKey</a>",1,["ink_storage_traits::impls::AutoKey"]],["impl&lt;const KEY: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.74.0/std/primitive.u32.html\">u32</a>, ParentKey&gt; Freeze for <a class=\"struct\" href=\"ink_storage_traits/struct.ManualKey.html\" title=\"struct ink_storage_traits::ManualKey\">ManualKey</a>&lt;KEY, ParentKey&gt;",1,["ink_storage_traits::impls::ManualKey"]],["impl&lt;L, R&gt; Freeze for <a class=\"struct\" href=\"ink_storage_traits/struct.ResolverKey.html\" title=\"struct ink_storage_traits::ResolverKey\">ResolverKey</a>&lt;L, R&gt;",1,["ink_storage_traits::impls::ResolverKey"]]]
};if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()