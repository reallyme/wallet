# ReallyMe Wallet Proto Codec

`reallyme-wallet-proto-codec` provides bounded protobuf decoding, strict generated
ProtoJSON, typed errors, and conversions between Wallet messages and domain
values. It depends on the message-only `reallyme-wallet-proto` crate; the
message crate does not depend on codecs or domain crates.

Use `decode::decode_*` and `encode::encode_*` at byte boundaries. Domain decoders
apply conversion checks; operation and provider decoders return messages for
subsequent runtime or provider validation. Decoding cannot establish issuer
trust, user consent, or authenticated status by itself.

`wallet_proto_from_json` and `wallet_proto_to_json` accept only the sealed
operation request, result, and response types. They reject duplicate keys,
unknown fields and enums, non-canonical shapes, excessive nesting, and trailing
data. Provider exchanges use protobuf bytes.

Encoded buffers use `Zeroizing<Vec<u8>>`; ProtoJSON output uses
`Zeroizing<String>`. Errors carry typed reasons without input material. The
[serialization policy](../../docs/architecture/DOMAIN_SERIALIZATION_POLICY.md)
lists resource limits and sensitive-owner requirements.

Enable `native` (the default) or `wasm` explicitly when composing without default
features. The optional `zk` feature adds encrypted artifact and prepared-token
codecs; it does not install a prover.
