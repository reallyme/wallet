# Wallet Fixtures

Synthetic Wallet Unit Attestation and SDK ownership inputs used by conformance
tests.

Canonical operation, provider, and key-storage vectors live in
[`vectors/`](../../../vectors/README.md). Copies under
`crates/proto/tests/fixtures` and `crates/proto-codec/tests/fixtures/proto`
are package-local mirrors checked for byte parity. Downstream bindings consume
the canonical bytes from a pinned Wallet revision.

The provider vector uses strict key/value fields for exact descriptor, request,
and typed-error protobuf encodings. Consumers reject missing, duplicate, unknown,
or malformed fields.

The [operation capability manifest](../../features/wallet-operation-capabilities-v1.json)
defines provider calls, mutability, atomicity, and rejection policy. Wire vectors
check encoding parity; the manifest checks operation coverage.
