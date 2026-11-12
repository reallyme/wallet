# Domain Serialization Policy

## Canonical boundaries

Wallet operations, responses, provider exchanges, errors, and persisted engine
records use the versioned protobuf schema. Rust domain types do not define a
second JSON protocol. The [codec crate](../../crates/proto-codec/README.md)
converts between generated messages and domain values; decoding a message does
not itself authenticate credentials, entitlements, or status evidence.

Generated ProtoJSON is the only JSON representation of the public Wallet
operation contract. The strict codec rejects duplicate keys, unknown fields,
invalid enums and shapes, trailing data, and excessive nesting. Runtime adapters
map framing and codec failures into `WalletOperationResponse.error` with typed
details. HTTP status and content encoding remain transport metadata. Connect
clients and platform bindings belong to Identity.

| Boundary | Limit |
| --- | --- |
| Wallet protobuf message | 2,097,152 bytes (2 MiB) |
| Provider protobuf message | 2,162,688 bytes (2 MiB + 64 KiB) |
| Wallet ProtoJSON | 3,145,728 bytes (3 MiB), also subject to the encoded protobuf limit |
| Protobuf recursion | 64 |
| JSON nesting | 64 |
| Materialized unknown protobuf fields | 0 |

These values come from `crates/proto-codec/src/limits.rs`. Transport adapters may
impose tighter request limits.

## Registration policy, SSI plans, and wire decisions

ARF `EW-DM-44-027` assigns the unregistered-attribute policy to the Wallet
Provider. Wallet's trusted Rust configuration selects `WarnAndAllowAll`,
`RegisteredOnly`, or `RejectRequest`. SSI supplies the disclosure or derivation
satisfaction plan; Wallet applies the provider's registration policy to the
resulting consent options. A derivation with unregistered inputs is refused
under `RegisteredOnly`, because deleting an input would change the proof.

The protobuf `DisclosurePolicyDecision` is the evaluation result, not that
provider configuration. It carries domain results `Allowed`, `Denied`, and
`AllowedWithUnregisteredRequest` through the corresponding
`DISCLOSURE_POLICY_DECISION_*` wire values. Both a permitted full request and a
permitted registered-only subset retain the warning result when the original
request over-asked. Conversion into the Wallet domain rejects unspecified or
unknown decision values. A decoded decision or consent request is evidence;
it does not reconstruct the proof-bearing preparation or authorize disclosure.

Wallet Unit Attestation decoding likewise returns an unverified owner. The
attestation verifier applies the exclusive technical lifetime bound after
decoding and before cryptographic promotion; protobuf timestamps do not bypass
the Wallet policy. These checks use the current wire contract without adding
caller-controlled provider policy or duplicating SSI-owned claim semantics.

## Persisted state

`FlowSnapshot.state` contains a versioned protobuf state message. Schema version
1 selects `OpenId4VciIssuanceSnapshot` or `OpenId4VpPresentationSnapshot` using
`FlowKind`. The codec rejects empty, malformed, and kind-mismatched state and
validates issuance-stage invariants before returning a domain snapshot.

Encrypted record headers use the shared `reallyme.crypto.v1.AeadAlgorithm` enum.
Wallet accepts AES-256-GCM-SIV and XChaCha20-Poly1305 only. Inventory validation
checks nonce length and a minimum authentication-tag length; encryption and
authentication remain the storage adapter's responsibility. The former
`algorithm` field name and number are reserved. The protobuf field is
`encryption_algorithm`; generated JSON follows ProtoJSON naming rules.

## Domain serialization

Wallet domain types do not implement Serde. Distribution-card values go
directly to renderers, and contact delivery uses typed, bounded messages.
Standards-specific JSON stays inside the owning adapter, with explicit bounds
and malicious-input tests. Renderer output and OIDF launch envelopes must not
be reused as Wallet operation or storage DTOs.

The OIDF adapter treats launch URLs, request objects, nonces, client bindings,
and stored request-URI records as sensitive. Launch diagnostics are redacted,
and parsed bodies and session records wipe owned strings on drop.

## Sensitive ownership

Privacy-bearing identifiers redact `Debug` and wipe owned text on drop.
Key handles, key-attestation evidence, and Wallet Unit Attestations omit
`Debug` and implement `ZeroizeOnDrop`. Credential and status records, consent
values, transaction records, flow state, contact-message owners, and deferred
issuance identifiers also have explicit drop-time zeroization.

Signing inputs and contact payload/frame owners are non-cloneable. Encrypted
records, credential records, presentation copies, and resumable snapshots may
be cloned where storage and compare-and-swap APIs need owned snapshots. Each
copy owns and wipes its buffers independently. Issuance sessions may also clone
protocol state to leave the caller's state unchanged when an injected operation
fails; that permission does not make plaintext safe to log or retain.

Any change to copying or serialization must document why it is needed at the
owning type and retain zeroization for every sensitive owned copy. Hosts remain
responsible for copies outside Rust-owned values.
