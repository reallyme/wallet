<div align="center">

# ReallyMe Wallet

**Wallet inventory, lifecycle, consent, attestation, and audit state**

[![Rust CI](https://github.com/reallyme/wallet/actions/workflows/rust-ci.yml/badge.svg)](https://github.com/reallyme/wallet/actions/workflows/rust-ci.yml)
[![EUDI Wallet Conformance](https://github.com/reallyme/wallet/actions/workflows/eudi-wallet-conformance.yml/badge.svg)](https://github.com/reallyme/wallet/actions/workflows/eudi-wallet-conformance.yml)
[![crates.io](https://img.shields.io/crates/v/reallyme-wallet.svg)](https://crates.io/crates/reallyme-wallet)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)

[Identity](https://github.com/reallyme/identity) · [SSI](https://github.com/reallyme/ssi) · [OpenID4VCI](https://github.com/reallyme/openid4vci) · [OpenID4VP](https://github.com/reallyme/openid4vp) · **Wallet** · [ZK](https://github.com/reallyme/zk)

</div>

ReallyMe Wallet is an embeddable Rust wallet state and authorization engine.
It manages credential inventory, consent, lifecycle, attestation, and recoverable
flows. Host applications provide storage, keys, networking, and user interaction.
ReallyMe Identity supplies application SDKs and platform bindings.

OpenID4VCI handles issuance mechanics, OpenID4VP handles presentation mechanics,
and SSI supplies credential formats, trust, status, and disclosure policy.
Wallet coordinates those capabilities with wallet state and authorization.

> **Looking for the ReallyMe SDK?** Start with
> [ReallyMe Identity](https://github.com/reallyme/identity), the
> application-facing SDK for building issuers, verifiers, wallets, and
> identity-enabled applications. It composes this engine with protocol
> implementations, storage providers, and platform bindings.

## Capabilities

| Area | Responsibility |
| --- | --- |
| Credential inventory | Receipt-validated records, authenticated status-list updates, reissuance, deletion, and presentation-copy selection |
| Wallet lifecycle | Evidence-backed provisioning, suspension, recovery, migration, withdrawal, and deletion transitions |
| Consent | Relying-party registration and entitlement checks, request-bound decisions, and single-use disclosure authorization |
| Wallet unit attestation | Acquisition, verification, and rotation through injected providers |
| Key custody | Opaque key handles, signing requests, and key-attestation verification |
| Transaction history | Validated, hash-chained transaction records and qualified trust service provider (QTSP) decisions |
| Integration | Versioned protobuf operations and provider exchanges, bounded codecs, ProtoJSON, and typed errors |
| Distribution | Optional Apple Wallet passes, Google Wallet JWTs, QR-safe text, and deep links |
| Assurance evidence | Requirement mappings, synthetic fixtures, interoperability vectors, fuzzing, and release checks |

## Architecture

This diagram describes conceptual ownership and composition, not Cargo
dependency edges.

```text
                           Applications
                                │
                                ▼
                       ReallyMe Identity
                 application SDKs and composition
                                │
            ┌───────────────────┼───────────────────┐
            ▼                   ▼                   ▼
       OpenID4VCI          OpenID4VP              Wallet
         issuance       presentation/session   state · consent
            │               /       \          lifecycle · audit
            │              /         \
            └─────────────▼           ▼
                          SSI      ReallyMe ZK
                identity and credential   circuits and proof
                      semantics           infrastructure
                       /      \               /
                    JOSE      COSE            /
                       \       │             /
                        └──────┴────────────┘
                               ▼
                        reallyme/crypto
```

Wallet owns the state and authorization that persist across issuance and
presentation sessions. Protocol crates own wire semantics; SSI owns credential
and trust semantics. ReallyMe Identity composes the stack into application SDKs
and a single native binary or WebAssembly module.

### Repository boundaries

| Repository | Responsibility |
| --- | --- |
| [ReallyMe Identity](https://github.com/reallyme/identity) | Application SDKs, platform bindings, and final composed artifacts |
| [OpenID4VCI](https://github.com/reallyme/openid4vci) | Issuance protocol mechanics and HTTP framing |
| [OpenID4VP](https://github.com/reallyme/openid4vp) | Presentation mechanics, DCQL, session binding, and response modes |
| [SSI](https://github.com/reallyme/ssi) | Credential formats, trust, status, claims, and disclosure policy |
| [ZK](https://github.com/reallyme/zk) | Proof contracts, circuits, artifacts, and proving backends |
| [VaultWallet](https://github.com/reallyme/vaultwallet) | Opaque storage and the optional Wallet Store integration |
| [VaultKit](https://github.com/reallyme/vaultkit) | Generic client handles and orchestration used by Identity |
| [Vault](https://github.com/reallyme/vault) | Encrypted persistence beneath VaultWallet |

## Standards

Wallet composes the OpenID4VCI 1.0 Final and OpenID4VP 1.0 Final implementations
and HAIP 1.0 profile support from the protocol repositories. It owns wallet
state, consent, and evidence around those exchanges. The
[conformance guide](conformance/README.md) records the supported scope and
external evidence still required; local test results do not establish full
standards coverage or certification.

## Which layer should I use?

| Goal | Start here |
| --- | --- |
| Build a wallet application | Use [ReallyMe Identity](https://github.com/reallyme/identity) |
| Embed the Rust engine | Compose `reallyme-wallet` with implementations of its storage, keystore, and protocol interfaces |
| Integrate a provider or language binding | Read the [provider contract](docs/architecture/WALLET_PROVIDER_CONTRACT.md) and [SDK composition guide](docs/architecture/SDK_COMPOSITION.md) |
| Develop or audit Wallet | Use the source workspace and validation commands under Development |

## Repository structure

| Path | Purpose |
| --- | --- |
| `crates/wallet` | Rust facade over Wallet domain and adapter crates |
| `crates/types` | Domain records, identifiers, revisions, and validation errors |
| `crates/flows` | Resumable issuance, presentation consent, and contact-delivery sequencing |
| `crates/inventory`, `crates/lifecycle` | Credential inventory and Wallet Unit state transitions |
| `crates/consent`, `crates/attestation`, `crates/log` | Consent, attestation, and transaction history |
| `crates/storage`, `crates/keystore` | Persistence and opaque-key interfaces |
| `crates/proto`, `crates/proto-codec` | Canonical schemas, generated messages, bounded codecs, and domain conversions |
| `crates/runtime`, `crates/provider` | Operation dispatch and typed provider exchanges |
| `crates/wallet-zk` | Optional integration with an injected ZK prover |
| `crates/render` | Apple Wallet, Google Wallet, and web delivery helpers |
| `crates/http` | Native Axum adapter and optional OIDF conformance listener |
| `conformance`, `contracts/compliance` | Requirement mappings, fixtures, and evidence contracts |
| `vectors`, `fuzz` | Shared wire vectors and adversarial input testing |

## Architecture boundaries

Credential import requires receipt verification through the credential format
layer. Constructing a protobuf record does not authenticate its issuer, trust,
validity, or holder binding. The v1 operation runtime rejects raw credential
writes, raw status claims, self-asserted verifier entitlements, and standalone
lifecycle-evidence appends. Public issuer refresh remains unavailable until a
verified issuer-response interface is provided.

Storage providers must preserve atomic claims, compare-and-swap revisions, and
durable replay state. In-memory presentation-copy selection alone cannot prevent
reuse after a crash. Successful once-only claims are never replayed with token
bytes. Wallet defines these storage requirements; hosts implement and enforce
them. This repository contains no concrete encrypted store or VaultWallet
adapter. See [VaultWallet's Wallet Store integration](https://github.com/reallyme/vaultwallet/blob/main/docs/WALLET_STORE_INTEGRATION.md)
for its storage contract.

Key operations use opaque handles; non-exportable private key bytes stay with
the keystore provider. Unsupported providers and algorithms return typed errors
without silent fallback. Time-sensitive checks require explicit trusted time.

The optional [ZK integration](crates/wallet-zk/README.md) accepts an injected
prover and defines encrypted artifact policy. Wallet can record issued
`reallyme_zk_v1` credentials, but its published crates do not expose the
selected-record OpenID4VP common-root presentation builder. That path currently
belongs to Identity's conformance host. Hosts must validate issuer-signed
credentials and fresh status, and retain holder-private claim openings under
protected storage; public credential responses cannot recreate those openings.

PDF output and QR image rendering are not implemented. The web helper returns
bounded QR-safe text for a host renderer.

## Development

Use Rust 1.99.0, pinned in `rust-toolchain.toml`. A Wallet checkout builds with
external dependencies from crates.io. The workspace and fuzz lockfiles record
the resolved versions and checksums. Release preflight verifies the protocol
and ZK archives against the reviewed [source revisions](scripts/sibling-source-provenance.json).

For the normal Rust edit cycle:

```sh
cargo fmt --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
```

Before release-sensitive changes, run the repository gate:

```sh
scripts/check_security_gates.sh
```

It requires Node.js, npm, Buf, `cargo-audit`, `cargo-deny`, `cargo-fuzz`, and the
pinned fuzz nightly in addition to Rust. It runs schema linting, boundary and
package policy checks, formatting, Clippy, tests, the composed Wasm check,
dependency audits, release-readiness checks, and fuzz-target builds. Individual
dependency and fuzz checks are also available:

```sh
cargo deny check
scripts/audit_committed_lockfiles.sh
cargo +nightly-2026-09-15 fuzz build -Z cargo-lints
```

Schema generation and freshness checks run in the separate protobuf CI lane.
Canonical Wallet schemas live under `crates/proto/proto/reallyme/wallet/v1`;
see the [proto guide](crates/proto/README.md) before changing them.

### Features

| Feature | Scope |
| --- | --- |
| `native` | Default runtime feature for the facade and most engine crates |
| `wasm` | Ten lower-layer crates used in Identity's `wasm32-unknown-unknown` build; absent from the Wallet facade |
| `render` | Optional facade re-export of `reallyme-wallet-render` |
| `http` | Optional facade re-export of the native HTTP adapter |
| `zk` | Optional codec and storage support for ZK artifacts; `reallyme-wallet-zk` is a separate crate |
| `oidf-conformance-harness` | Opt-in test listener in `reallyme-wallet-http` |

The [package policy](docs/architecture/RUST_PACKAGE_POLICY.md) lists the exact
release and Wasm package sets. Identity owns FFI, JNI, `wasm-bindgen`, Swift,
Kotlin, and TypeScript packaging.

## Technical reference

| Topic | Reference |
| --- | --- |
| Wallet obligations and crate ownership | [Specification map](SPEC_MAP.md) |
| Wallet and Identity API ownership | [SDK composition](docs/architecture/SDK_COMPOSITION.md) |
| Provider requests, atomicity, and replay | [Provider contract](docs/architecture/WALLET_PROVIDER_CONTRACT.md) |
| Rust publication and feature policy | [Package policy](docs/architecture/RUST_PACKAGE_POLICY.md) |
| Wire formats and sensitive ownership | [Serialization policy](docs/architecture/DOMAIN_SERIALIZATION_POLICY.md) |
| OIDF, EUDI, and evidence limits | [Conformance guide](conformance/README.md) |

## Security

Report vulnerabilities through the [security policy](SECURITY.md). Do not
include credentials, personal data, private keys, attestation material, access
tokens, or production wallet, issuer, or verifier data in reports.

## Versioning

Wallet is in pre-1.0 development. The seventeen Rust crates in the approved
release set use version `0.1.1` and declare Rust 1.99 as their minimum supported
version. Conformance tooling is not published. Publication requires matching
registry dependencies, packaged-source tests, and release preflight; the
package manifest alone does not establish release readiness.

## License

Licensed under either the [MIT License](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.

Third-party components retain their own licenses and notices.

## Copyright and Trademarks

Copyright © 2026 by ReallyMe Technologies Limited.

ReallyMe® is a registered trademark of ReallyMe Technologies Limited.
