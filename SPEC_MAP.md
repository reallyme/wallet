# Wallet Core Specification Map

This map assigns Wallet's eIDAS 2.0 and Architecture and Reference Framework
(ARF) responsibilities to implementation crates. Requirement status and evidence
live in the [conformance inventory](conformance/README.md); this map does not
establish certification or complete standards coverage.

| Area | Owner | Responsibility |
| --- | --- | --- |
| Credential inventory | `crates/inventory` | Validate receipt-checked records, apply authenticated status lists, reissue and delete records, and select once-only copies. Issuer refresh is not public. |
| Relying-party authorization | `crates/consent` | Verify registration evidence through injected trust interfaces, evaluate entitlements, bind consent to a verified request, and claim each capture once. |
| Wallet Unit lifecycle | `crates/lifecycle` | Validate evidence and transitions for provisioning, suspension, recovery, migration, withdrawal, and deletion. |
| Wallet unit attestation | `crates/attestation`, `crates/flows` | Obtain, verify, and rotate attestations; bind a verified attestation to issuance. |
| Transaction history | `crates/log` | Validate and hash-chain transaction entries and validate QTSP decision records. Durable append is a provider responsibility. |
| Key custody | `crates/keystore` | Sign and attest through opaque handles. The v1 hardware profile targets iOS Secure Enclave and Android StrongBox/TEE; platform implementations are downstream. |
| Persistence | `crates/storage` | Define revisioned storage, atomic issuance commits and notification outbox, lifecycle updates, consent claims, and once-only presentation-copy claims. |
| Vault-backed storage | [VaultWallet](https://github.com/reallyme/vaultwallet), composed by the host | Implement opaque persistence and the optional Wallet Store integration. Wallet defines authorization and record meaning; hosts enforce wrapping, recovery, retention, and hardware-handle rebinding. |
| Headless flows | `crates/flows` | Sequence issuance and deferred polling through injected protocol interfaces; retain reuse and issuer-metadata policy; prepare presentation consent; validate and frame contact delivery. |
| ZK derivation | `crates/wallet-zk` | Accept an injected `ZkProver`, check request/proof metadata and session binding, and define encrypted artifact policy. Selected-record OpenID4VP common-root proving is not a published Wallet entry point. |
| Wire contract | `crates/proto`, `crates/proto-codec` | Define Wallet schemas, hardened Buffa messages, bounded decoding, strict ProtoJSON, and domain conversions. |
| Runtime and providers | `crates/runtime`, `crates/provider` | Dispatch versioned operations and enforce descriptor, correlation, result-pairing, revision, and replay policy. |
| Native HTTP | `crates/http` | Frame authenticated operation requests and provide an opt-in OIDF test listener. |
| Distribution | `crates/render` | Render Apple passes and Google Wallet JWTs; construct QR-safe text and deep links. PDF and QR image output are not implemented. |
| Application SDKs | [Identity](https://github.com/reallyme/identity) | Own platform bindings, client APIs, composed protocol drivers, and final native/Wasm artifacts. |

## Protocol boundaries

OpenID4VCI owns offers, metadata, token and credential endpoint semantics, proof
formats, deferred responses, and protocol HTTP framing. Wallet sequences its
public wallet APIs and retains sibling-owned protobuf bytes in
`OpenId4VciIssuanceSnapshot` without redefining their schemas.

OpenID4VP owns request verification, DCQL, session binding, presentation response
modes, and protocol proof composition. SSI owns credential envelopes, claims,
trust, status, and disclosure semantics. Wallet owns durable state and consent
around those operations. Lower-layer protocol and credential crates must not
depend back on Wallet.

## Binary packaging

Identity composes lower Rust libraries into one ReallyMe native binary or one
combined Wasm module per application. Wallet exposes no independent FFI, JNI,
or `wasm-bindgen` package. See [SDK composition](docs/architecture/SDK_COMPOSITION.md)
and the [package policy](docs/architecture/RUST_PACKAGE_POLICY.md).
