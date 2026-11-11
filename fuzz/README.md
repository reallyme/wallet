# Fuzzing Harnesses

Coverage-guided libFuzzer targets exercise Wallet's untrusted-input boundaries.
They check that malformed input is rejected through typed errors and help find
panics, arithmetic errors, and resource-limit failures. Fuzzing supplements the
deterministic negative tests; a passing campaign does not prove safety for all
inputs.

The fuzz crate has its own workspace and lockfile and is excluded from the root
workspace. This keeps libFuzzer's `#![no_main]` runtime separate from the main
workspace's lint configuration.

## Targets

| Target | Boundary | Entry point |
| --- | --- | --- |
| `wallet_proto_decode` | Generated Wallet protobuf bytes and domain conversions | `reallyme_wallet_proto_codec::decode::decode_*` |
| `wallet_proto_json` | Canonical operation request, result, and response ProtoJSON | `wallet_proto_from_json` |
| `wallet_identifier` | Identifiers and attribute names | `NonEmptyIdentifier::new`, `AttributeName::new` |

Domain types do not implement Serde, so there is no separate domain-JSON target.
`corpus/wallet_proto_json` mirrors the canonical accepted and malicious
[ProtoJSON vectors](../vectors/README.md), including duplicate keys, unknown
fields and enums, and wrong shapes.

## Running

Install the nightly and `cargo-fuzz` versions used by CI:

```sh
rustup toolchain install nightly-2026-09-15
cargo install cargo-fuzz --version 0.13.2 --locked
```

Run from the repository root:

```sh
cargo +nightly-2026-09-15 fuzz list
cargo +nightly-2026-09-15 fuzz build -Z cargo-lints
cargo +nightly-2026-09-15 fuzz run wallet_proto_decode -Z cargo-lints -- -max_total_time=60
cargo +nightly-2026-09-15 fuzz run wallet_proto_json -Z cargo-lints -- -max_total_time=60
cargo +nightly-2026-09-15 fuzz run wallet_identifier -Z cargo-lints -- -max_total_time=60
```

Reproduce a crash artifact, replacing the placeholders with its target and path:

```sh
cargo +nightly-2026-09-15 fuzz run <target> -Z cargo-lints fuzz/artifacts/<target>/<crash-file>
```

CI builds every target. Scheduled and manually dispatched campaigns run each
target for up to 300 seconds with a memory limit and upload crash artifacts on
failure. Review artifacts for sensitive input before sharing them.
