# Rust Package Policy

Wallet publishes Rust libraries and owns the canonical Wallet protobuf contract.
Identity owns application APIs, platform bindings, and final multi-domain
artifacts. VaultKit supplies generic handles; VaultWallet supplies opaque
storage and the optional Wallet Store integration.

The [package manifest](../../conformance/features/wallet-package-policy-v1.json)
defines the release set, order, toolchain, and Wasm participants.
The [client ownership contract](../../conformance/features/wallet-client-surface-ownership-v1.json)
records semantic ownership separately from the package layout.

## Rust publication order

Publish dependencies before their consumers, in this order:

1. `reallyme-wallet-proto` and `reallyme-wallet-types`;
2. `reallyme-wallet-lifecycle`, `reallyme-wallet-render`, and `reallyme-wallet-zk`;
3. `reallyme-wallet-keystore`;
4. `reallyme-wallet-attestation`;
5. `reallyme-wallet-proto-codec`;
6. `reallyme-wallet-storage`;
7. `reallyme-wallet-inventory` and `reallyme-wallet-log`;
8. `reallyme-wallet-consent`;
9. `reallyme-wallet-flows` and `reallyme-wallet-runtime`;
10. `reallyme-wallet-http` and `reallyme-wallet-provider`; and
11. `reallyme-wallet`.

`reallyme-wallet-conformance` is repository tooling and remains
`publish = false`. The ZK integration requires the matching `reallyme-zk-api`
registry release before it can be published.

## Publication gate

The seventeen Wallet Rust crates in the approved release graph are authorized
by package policy for version `0.1.2`, with `rust-version = "1.99"`.
Development and release checks use the pinned Rust 1.100.0 toolchain. This policy
classification does not establish that dependencies or packages are ready to
publish.

Wallet builds use the published OpenID4VCI 0.3.2 and OpenID4VP 0.3.1 packages,
ZK 0.3.2, and SSI 0.6.2, including ETSI EAA conformance. Both Cargo lockfiles
record external dependencies from crates.io. Release preflight checks the protocol
and ZK archives against Cargo.lock and the reviewed source revisions.
The protobuf gate compares imported schemas byte for byte with the resolved
crate archives.

[`check_rust_package_surfaces.mjs`](../../scripts/check_rust_package_surfaces.mjs)
lists each release package with `cargo package --locked --list --allow-dirty`.
It checks metadata, required files, duplicate and escaping paths, and unwanted
build or environment files. The proto package includes canonical schemas, its
compatibility baseline, and test-fixture mirrors. Identity consumes shared
[vectors](../../vectors/README.md) from a pinned Wallet revision.

The credential-free preflight checks the exact commit, version, packaged source,
and archive hashes. The release workflow verifies that attestation before its
publish job can access the registry token. See the
[preflight workflow](../../.github/workflows/crates-package-preflight.yml) and
[release workflow](../../.github/workflows/crates-release.yml).

Maintainers must configure the `crates-io` GitHub environment with required
reviewers, a `main`-only deployment rule, and the `CARGO_REGISTRY_TOKEN` secret.
The token must not be a repository or organization secret. Publication uses
that token rather than OIDC or crates.io Trusted Publishing. After publication,
the release workflow creates the versioned tag and GitHub release.

## WebAssembly and platform ownership

Ten lower-layer crates expose `wasm` for Identity's combined WebAssembly graph.
CI checks that exact set for `wasm32-unknown-unknown`. The facade, flows,
inventory, render, HTTP, and ZK integration crates have no `wasm` feature; the
message-only proto crate uses `generated` instead of a runtime lane.

Wallet has no FFI, JNI, `wasm-bindgen`, Swift, Kotlin, Android, or TypeScript
package. It publishes no `cdylib`, standalone Wasm binary, or npm package.
Identity owns the combined Wasm module, shared memory, and language facades.
Its iOS Secure Enclave qualification adapter lives with the example host and
tests in `identity/examples/ios`.
