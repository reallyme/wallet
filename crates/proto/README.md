# ReallyMe Wallet Proto

`reallyme-wallet-proto` contains the canonical `reallyme.wallet.v1` schemas and
hardened [Buffa](https://github.com/anthropics/buffa) Rust messages. The default
`generated` feature exposes the bindings.

This is a message-only crate. Domain conversion and bounded decoding belong to
`reallyme-wallet-proto-codec`; dispatch and transport adapters are separate.
The `wallet_service.proto` declaration introduces no transport implementation.
Use the codec at untrusted byte boundaries rather than decoding generated
messages directly.

Sensitive generated owners redact `Debug` and wipe owned sensitive fields and
unknown length-delimited data on drop. Post-generation hardening also enforces
strict oneof and JSON field handling. This does not replace domain validation
or cryptographic verification.

## Schema changes

Canonical Wallet sources live in `proto/reallyme/wallet/v1`. Imported schemas
remain owned by their source repositories and are pinned in
`proto-source-lock.json`. The [compatibility baseline](baselines/README.md)
contains the reviewed schema image and its imported descriptors.

After a schema change, check source locks and compatibility, regenerate and
harden the bindings, format them, and verify idempotence:

```sh
node scripts/check_schema_source_lock.mjs
buf lint
node scripts/check_wallet_schema_breaking.mjs
buf generate
node scripts/harden-generated-wallet-proto.mjs
cargo fmt
node scripts/harden-generated-wallet-proto.mjs --check-idempotent
node scripts/check-proto-hardening-concurrency.mjs
node scripts/check-proto-first-boundaries.mjs
```

Run these commands from the repository root with the Buf and Buffa generator
versions pinned in the protobuf CI workflow. Update affected vectors and negative
decode tests with the contract. Do not hand-edit generated Rust.

## Shared vectors

[`vectors/`](../../vectors/README.md) is the source of truth for wire goldens
and malformed ProtoJSON cases. Package-local test fixtures mirror those bytes
so the crate can be tested in isolation. Release checks enforce parity; codec
tests assert typed failures, and the ProtoJSON cases also seed fuzzing.
Identity consumes the schemas and vectors at a pinned Wallet revision for its
Swift, Kotlin/Android, and TypeScript/Wasm bindings.
