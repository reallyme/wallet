# Wallet interoperability vectors

This directory is the canonical source of Wallet operation, provider,
key-storage, and ProtoJSON vectors. Rust and downstream Swift, Kotlin, and
TypeScript bindings can use them without depending on a crate-relative layout.

`manifest.json` pins each vector by SHA-256. The copies in
`crates/proto/tests/fixtures` and `crates/proto-codec/tests/fixtures/proto`
let published crates test the same contract in isolation. Release-readiness
checks require byte-for-byte parity. The ProtoJSON cases also seed
`fuzz/corpus/wallet_proto_json`.

Accepted and malicious ProtoJSON cases define expected decoding behavior.
Consumers must preserve rejection of duplicate keys, unknown fields and enums,
and non-canonical shapes. Encoding parity does not by itself establish runtime
authorization or provider durability.
