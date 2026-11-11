# Wallet Provider Contract

`reallyme.wallet.v1.WalletProviderRequest` and `WalletProviderResponse` define
the versioned exchange between Wallet and host-provided persistence. The
[provider schema](../../crates/proto/proto/reallyme/wallet/v1/wallet_provider.proto)
is the canonical contract. The [provider crate](../../crates/provider/README.md)
validates descriptors, correlation, and result pairing and adapts the exchange
to Rust runtime interfaces.

The protobuf contract defines message semantics, not a C ABI or JavaScript API.
Identity owns native callbacks and browser completion. Both invocation modes
must preserve the same atomicity, field numbers, and typed errors.

## Creation contract

Before use, an adapter validates `WalletProviderDescriptor`:

- `contract_version` must be `1`.
- Invocation mode must match the adapter: synchronous native or asynchronous host.
- All 25 required capabilities must occur exactly once. Unknown, unspecified,
  duplicate, and missing capabilities are rejected.
- `max_response_bytes` must equal `MAX_WALLET_PROVIDER_PROTO_MESSAGE_BYTES`
  (2,162,688 bytes). Version 1 does not negotiate a smaller limit.

`REQUIRED_PROVIDER_CAPABILITIES` in the provider crate defines the exact set.
The legacy standalone lifecycle-evidence append capability is excluded because
state and evidence must change together. There is no default provider, ambient
lookup, partial capability set, or production in-memory fallback.

## Request correlation

Each request carries a non-zero, adapter-assigned `executor_id` and a non-zero,
executor-scoped `request_id`. Responses must echo both and the contract version.
Request IDs advance with checked arithmetic. A mismatched response or exhausted
sequence returns a typed error; IDs are correlation values, not credentials or
storage identifiers.

A successful result must match the request variant's protobuf field number.
Provider errors use a known, non-unspecified `WalletProviderErrorReason`.
Transport invocation failures are mapped separately from decoded provider
errors.

Lifecycle, transaction-log, and QTSP-decision calls read the current time
with `ReadTrustedTime`. Lifecycle transitions that need authority are checked
with `VerifyLifecycleAuthority`, which must confirm the exact Wallet Unit,
predecessor state, and event. Binding the evidence to the predecessor stops a
reactivation from being replayed against a later suspension. A Rust host may
attach a `ProviderTrustedClock` or `WalletLifecycleAuthorityVerifier` to the
backend; when attached, it replaces the matching RPC, and the provider is not
asked. The descriptor must still advertise both capabilities, since version 1
has no way to declare them as served locally. Whichever source answers carries the same obligation: the clock must be
one the host trusts for security decisions, and the verifier must not approve
evidence it has not authenticated. A storage host that answers both RPCs
without that checking would authorize its own lifecycle changes. An unavailable
clock or an unverified transition fails closed.

Lifecycle requests must name the Wallet Unit the backend is bound to. A request
for any other unit is refused before any lifecycle record is read or written;
for a mutating request the refusal is still journaled under its key.

## Atomicity and replay

Providers must implement each mutation as one durable transaction:

| Operation | Required behavior |
| --- | --- |
| Create credential, lifecycle, or flow-snapshot record | Reject an existing identifier, including a withdrawn or deleted Wallet Unit; never overwrite |
| Replace or delete a record | Compare the expected opaque revision |
| Delete a credential | Burn every presentation copy of that credential in the same transaction |
| Apply a lifecycle event | Replace state and append matching evidence together; reject an evidence identifier already in the history |
| Claim a presentation copy | Check that the parent credential exists and is active, then durably mark the selected copy unavailable before returning bytes or key handles |
| Claim an active ZK copy | Also check the credential's ZK format and protected claim selector in the same transaction as the claim |
| Append a transaction log entry | Compare the durable chain head and reject duplicate IDs or sequence/predecessor mismatches |
| Append a QTSP decision | Store the complete validated record atomically; reject a duplicate kind, input digest, and decision time |
| Reserve an operation | Bind the fixed idempotency key to the canonical request digest |
| Commit an operation | Retain the exact replay record supplied by the runtime; accept a repeated commit of the same reservation with the same record |

Observable read-then-write sequences do not satisfy these requirements.
Cross-process isolation and durability belong to the provider implementation.

The runtime retries a failed commit a small number of times. If a commit was
durable but its response was lost, the retry must succeed rather than report a
conflict; otherwise the caller sees `IdempotencyStoreRejected` for work that was
committed, and a claimed copy is lost.

Consent capture claims and credential-request dispatch are not part of the v1
provider exchange. They are Rust storage traits in `reallyme-wallet-storage`
(`ConsentCaptureStore` and `CredentialDispatchStore`), and their atomicity rules
are documented on those traits.

The DID, portable-key, and hardware-binding storage calls are storage
primitives. They check record shape, identity, and revision, and reject a
revision of zero, but they do not apply lifecycle policy. The layer that
composes them must check the Wallet Unit's lifecycle state first.

Mutating runtime operations require a 32-byte idempotency key. Read-only
operations reject a supplied key. Reusing a key with a different request digest
must fail; an uncommitted reservation must never become executable implicitly.
Ordinary committed outcomes, including typed errors, replay their stored
response, so a typed error is final for its key and a retry needs a new key. A
successful once-only presentation-copy claim stores a terminal claim marker
instead: retries return `PresentationCopyAlreadyClaimed` without exposing the
copy again.
Regulated operations recheck live lifecycle authorization before replay.

## Data and error handling

Provider errors carry typed reasons without backend exception text, identifiers,
raw input, or arbitrary metadata. Codec limits apply before protobuf decoding;
sensitive generated message owners redact diagnostics and zeroize owned fields.
Hosts must wipe temporary native and browser byte copies when ownership permits.

Implementations of the native callback and asynchronous completion interfaces
must test output ownership, concurrency, reentrancy, and invalid completion.
The protobuf field numbers remain the shared method identifiers across those
interfaces.

## Reconciled lifecycle retries

`VerifyLifecycleAuthority` may return `retry_reconciliation` only after
reconciling the exact failed recovery or migration and authenticating its new
retry evidence. The receipt echoes the full failed predecessor, retry evidence,
and the provider's trusted reconciliation time. The clock may advance during
reconciliation within the bounded freshness window. Any substituted predecessor
or evidence, missing field, or invalid time is rejected.
A successful ordinary authority response without this receipt is insufficient
for a failed retry. Providers must refuse outstanding, completed, unsafe, or
unavailable reconciliation; they must not interpret an unknown outcome as a
safe restart. Rust hosts may inject the same capability through
`WalletLifecycleAuthorityVerifier::reconcile_wallet_lifecycle_retry`.
