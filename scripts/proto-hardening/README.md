# Generated Proto Hardening Core

`core.mjs` applies deterministic hardening to Buffa-generated Wallet messages.
The Wallet wrapper, `scripts/harden-generated-wallet-proto.mjs`, selects the
schemas, generated files, and sensitive oneof variants. Keep repository policy
in that wrapper and reusable transformations in the core.

The transform discovers sensitive owners from source schemas and propagates
sensitivity through local wrapper messages. It redacts `Debug`, wipes owned
string and byte fields during clear and drop, wipes unknown length-delimited
fields, rejects unknown JSON fields, hardens oneof deserialization, and removes
input values from JSON error text.

Imported message internals remain outside the local ownership graph. Mark
wrappers containing privacy-sensitive imports with
`reallyme.security: sensitive-owner`. Explicit `sensitiveOneofs` entries cover
owned byte variants that need separate handling.

Generated files are replaced by atomic renames within the same directory. This
keeps concurrent readers from observing partially written source.

After generation, run from the repository root:

```sh
node scripts/harden-generated-wallet-proto.mjs
cargo fmt
node scripts/harden-generated-wallet-proto.mjs --check-idempotent
node scripts/check-proto-hardening-concurrency.mjs
```

The idempotence check rejects output that would change under another hardening
pass. Protobuf CI regenerates, hardens, formats, and checks source freshness;
see the [proto guide](../../crates/proto/README.md).
