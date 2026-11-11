# SDK Composition

ReallyMe Wallet is the Rust policy and state engine composed by ReallyMe
Identity's application SDKs. Wallet owns domain behavior and its protobuf
contract; Identity owns language bindings and final artifacts.

## Ownership

| Component | Responsibility |
| --- | --- |
| Wallet | Domain records, state transitions, canonical schemas, bounded codecs, provider policy, and transport-neutral dispatch |
| Identity | Application APIs, C/FFI, JNI, Swift, Kotlin/Android, TypeScript, Wasm, Connect clients, and final package composition |
| VaultKit | Generic client handles and orchestration |
| VaultWallet | Opaque storage operations and the optional Wallet Store integration |

General Wallet client API definitions and final artifact packaging
remain in `reallyme/identity`. VaultKit and VaultWallet do not take ownership
of credential, consent, lifecycle, or protocol semantics.

## Canonical contract

Bindings use the same generated messages:

- `WalletOperationRequest` and `WalletOperationResponse` for operations;
- `WalletProviderDescriptor`, `WalletProviderRequest`, and
  `WalletProviderResponse` for injected providers; and
- the shared [vectors](../../vectors/README.md) for byte-level parity.

The service declaration is separate from the message schemas. Transport bindings
may wrap this contract without adding parallel DTOs, method numbers, error
codes, or storage semantics. A wire variant's presence does not guarantee it is
executable: the runtime rejects unauthenticated credential writes, status claims,
verifier entitlements, and standalone lifecycle-evidence appends.

## Adapter requirements

Native adapters must validate pointer lengths, ownership, aliasing, and output
capacity before entering Rust. Foreign boundaries need an explicit panic and
error policy consistent with the linked build's panic strategy; a
`panic = "abort"` build cannot recover through unwinding. Wallet's release
profile uses that strategy.

An application loads one composed ReallyMe Rust binary, or one combined Wasm
module. Identity owns the shared Wasm memory and handle space. Wallet supplies
Rust libraries and has no independent platform package or standalone Wasm API.

Adapters must explicitly construct a provider with the full versioned
capability set and preserve correlation, idempotency, revisions, atomicity, and
once-only claim behavior. See the [provider contract](WALLET_PROVIDER_CONTRACT.md).
Unavailable providers and algorithms must return stable typed errors. Sensitive
temporary buffers must be wiped as soon as ownership permits.

## Cross-language verification

Each supported binding must verify request, response, provider, and error parity
against the shared vectors. Negative tests must cover malformed and oversized
input, duplicate and unknown fields, mismatched responses, provider rejection,
and unavailable capabilities. Native packages must verify symbols and
single-binary composition; web packages must verify Wasm imports, exports, and
single-module composition.

The executable ownership contracts are
[`identity-wallet-handoff-v1.json`](../../conformance/features/identity-wallet-handoff-v1.json)
and
[`wallet-client-surface-ownership-v1.json`](../../conformance/features/wallet-client-surface-ownership-v1.json).
They define responsibilities; passing Wallet tests alone does not establish
that a downstream package has met them.
