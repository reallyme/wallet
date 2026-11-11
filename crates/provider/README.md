# ReallyMe Wallet Provider

`reallyme-wallet-provider` validates provider descriptors, capabilities,
request correlation, and request/result pairing. Its protobuf backends adapt an
injected `ProviderTransport` to Wallet runtime and key-storage operations.

The crate supplies no concrete store, global provider, callback ABI, or language
binding. Native and asynchronous-host adapters share the same message semantics;
Identity owns their scheduling and foreign-boundary memory rules.

See the [provider contract](../../docs/architecture/WALLET_PROVIDER_CONTRACT.md)
for the exact capability set, response limit, atomicity, and replay requirements.
