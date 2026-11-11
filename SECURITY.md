# Security

ReallyMe Wallet processes credentials, consent, transaction history, key handles,
and Wallet Unit Attestations. Treat these records and any derived test artifacts
as sensitive.

## Reporting

Do not open public issues for suspected vulnerabilities. Use GitHub's private
vulnerability-reporting form under this repository's **Security** tab, or email
**security@really.me**. For encrypted email, first request the current PGP key
without including vulnerability details.

Include the affected crate, enabled features, protocol flow, and a minimal
reproduction using synthetic data. Exclude live credentials, personal data,
private keys, tokens, attestation material, and production issuer or verifier
records.

## Local validation

Before release-sensitive changes, run:

```sh
scripts/check_security_gates.sh
```

The gate requires Rust, Node.js, npm, Buf, `cargo-audit`, `cargo-deny`,
`cargo-fuzz`, and `nightly-2026-09-15`. It runs schema linting, boundary policy,
formatting, Clippy with warnings denied, tests, the composed Wasm check,
`cargo deny check`, an advisory audit of every committed Cargo lockfile,
package inspection, release-readiness checks, and fuzz-target builds.
Missing tools fail the gate. Protobuf regeneration, hardening, and freshness
checks also run in the separate protobuf CI workflow.

## Dependency policy

[`deny.toml`](deny.toml) rejects unknown registries, unknown Git sources, and
wildcard dependencies. Dependency and license-policy changes require review.
Sibling source provenance and package checks ensure release archives use the
reviewed dependency versions.

## Fuzzing

The [fuzz guide](fuzz/README.md) covers protobuf, ProtoJSON, and identifier
boundaries. Build all targets with the pinned nightly:

```sh
cargo +nightly-2026-09-15 fuzz build -Z cargo-lints
```

Run a bounded campaign for a changed boundary:

```sh
cargo +nightly-2026-09-15 fuzz run wallet_proto_decode -Z cargo-lints -- -max_total_time=300
```

Review crash artifacts before sharing them. They can contain input derived from
wallet records or credential fixtures.
