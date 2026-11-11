# ReallyMe Wallet Conformance

This directory contains executable contracts for Wallet's part of an EUDI
wallet: pinned standards inputs, requirement mappings, feature manifests,
synthetic fixtures, shared-vector checks, and tests.

These are engineering evidence, not a certification claim. Passing local tests
does not establish OIDF approval, certification-body acceptance, or end-to-end
application readiness.

## Contents

| Path | Purpose |
| --- | --- |
| `sources.lock` | Pinned legal, ARF, FCAF, and technical inputs; tracking sources are separate from normative requirements |
| `requirements/` | Wallet obligations, ownership, status, and evidence |
| `features/` | Supported use cases, operation capabilities, package policy, and Identity handoff contracts |
| [`fixtures/`](fixtures/README.md) | Synthetic inputs grouped by Wallet responsibility |
| `eudi/` | Pinned reference targets, test cases, fixture hashes, and required run artifacts |
| `reports/` | Security-control evidence, external dependencies, and hardware qualification limits |
| `tests/` | Checks that contracts agree with schemas, implementation, and fixtures |

[`wallet-operation-capabilities-v1.json`](features/wallet-operation-capabilities-v1.json)
records provider calls, mutability, atomicity, runtime lanes, and rejection policy
for all fourteen v1 operation variants. Its tests compare those entries with
request/result field pairs and runtime dispatch. Four variants remain in the
wire schema but reject at runtime: raw credential writes, raw status evidence,
self-asserted verifier entitlements, and standalone lifecycle-evidence appends.

[`wallet-package-policy-v1.json`](features/wallet-package-policy-v1.json)
defines the release graph and platform ownership. Serialization-policy tests
keep hand-written Serde out of domain crates. Imported OpenID4VCI, OpenID4VP,
SSI, and Crypto messages remain owned by their source repositories.

## Scope ownership

[`wallet-scope-ownership-v1.json`](features/wallet-scope-ownership-v1.json)
records explicit ownership for obligations at the Wallet boundary:

- Wallet owns lifecycle and revocation state, retention and portability policy,
  and credential classification where it affects Wallet decisions. Each area
  states whether it is implemented, partial, or not yet implemented.
- Identity and the wallet provider own attestation acquisition, proximity and
  Digital Credentials API integration, and user-facing rights workflows.
- VaultWallet owns storage mechanics for authorized backup and migration.
- Wallet-to-wallet transfer, legal-person wallets, and payment authentication
  require product scope decisions; Wallet claims no support for them.

Its tests require every area to name its owner and status, and every
implemented or partial area to cite evidence in this repository.

## Evidence boundaries

Wallet tests use injected protocol, storage, consent, clock, and attestation
interfaces. Composed issuer/verifier runs belong to
[Identity Conformance](https://github.com/reallyme/identity-conformance), with
the deployed hosts and retained execution evidence.

Automatic GitHub CI checks Wallet's contracts and local fixtures without fetching
Identity Conformance or Identity Taxonomy. Taxonomy ledger regeneration is a
separate producer operation. ZK integration tests exercise the public API and
Wallet's injected-provider boundary without reading a ZK source checkout.

The separate [manual EUDI Wallet workflow](MANUAL_EUDI_RUN.md) calls a pinned
Identity Conformance revision on a protected self-hosted runner. The caller
selects the exact Wallet candidate, release artifact, and component attestation.
It does not run on pushes, pull requests, schedules, or release publication.

[`external-readiness.json`](reports/external-readiness.json) and
[`reference-run-manifest.json`](eudi/reference-run-manifest.json) identify the
external results still required. Reference fixtures describe expected checks;
executed suite exports and accepted assessment evidence must be retained
separately. Local fixtures alone do not satisfy those requirements.

## Reference-code coverage review

The [reference-code review](reports/reference-code-review.json) compares the
Rust engine with locally inspected EU reference libraries and OIDF wallet-role
tests, alongside the sibling repository boundaries. It records source heads,
file hashes, ownership, gaps, and acceptance criteria. It supplements the
pinned standards and interoperability targets; it does not replace them or
claim that every reference feature is mandatory.

The Wallet-owned policy and state changes are described by
[`wallet-policy-contracts-v1.json`](features/wallet-policy-contracts-v1.json) and
[Wallet policy state](../docs/architecture/WALLET_POLICY_STATE.md). They include
bounded durable reuse/replenishment, versioned history and export, authenticated
reader/session consent, approved policy receipts, terminal execution guards, and
producer taxonomy mappings. Issuance additionally retains trusted nonce/proof
bindings across request preparation and restore.

Concrete providers must implement the atomic ports before the corresponding
capabilities are advertised. These Rust contracts do not add a platform SDK,
mobile transport, or new public operation-union variant. Rights-request history
and issuer failure/deletion notifications still require an explicit product
scope decision. Complete composed suite and device results remain owned by
Identity Conformance and are not established by local contract tests.

The [policy validation record](reports/wallet-policy-validation.json) lists the
local checks, source compatibility changes, skipped release lanes, and remaining
source-lock/deployment limits. Composed execution results remain centralized.

## OIDF Wallet Harness

The native HTTP crate provides an opt-in test listener for OpenID4VP wallet
launches. It exposes `/oidf/wallet/authorize`, `/oidf/wallet/sessions/latest`,
`/oidf/wallet/error`, `/oidf/wallet/reset`, and `/healthz`.

For a loopback transport smoke test, run from the repository root:

```sh
cargo run --locked -p reallyme-wallet-http --features oidf-conformance-harness --example serve_oidf_wallet_harness -- 127.0.0.1:8787
```

The example has no composed driver. A launch first has its callbacks checked
against `OIDF_WALLET_HARNESS_CALLBACK_ORIGINS` and is refused with
`invalid_request` if any fall outside it, including when the variable is unset.
A launch that passes then fails with `unsupported`. Starting this listener is
not a complete OIDF wallet execution.
The `oidf-conformance-harness` feature is required explicitly.

Every route checks the exact allowed `Host`. Session reads and reset also require
`OIDF_WALLET_HARNESS_CONTROL_TOKEN` (32–256 ASCII bytes). Without that setting,
those routes remain closed. Configure deployed ingress hosts, callback origins,
and a control token on `OidfWalletHarnessState`, and restrict networked access
to authenticated test runners.

The launch endpoint accepts GET parameters, JSON, form-encoded POST bodies,
and bounded Browser API launch envelopes. Wallet validates framing and callback
policy. An injected `OidfWalletFlowDriver` performs the protocol flow through
OpenID4VP.

Real suite runs use Identity's provider-wired
[`reallyme-identity-oidf-openid4vp-wallet-host`](https://github.com/reallyme/identity/tree/main/conformance/oidf-openid4vp-wallet-host).
Its composed driver verifies requests, obtains consent, selects credentials,
builds the DCQL-keyed `vp_token`, encrypts responses, and submits them to the
suite. The [host guide](https://github.com/reallyme/identity/blob/main/conformance/oidf-openid4vp-wallet-host/README.md)
defines configuration, inventory, trust, token, and deployment requirements.

Point `OIDF_WALLET_HARNESS_ENDPOINT` at that composed host before invoking
`../openid4vp/conformance/scripts/run_oidf_wallet_plan.sh`. For a remote suite,
use the composed host's reachable HTTPS ingress. Retain the suite export and
host-session evidence required by the run manifest.
