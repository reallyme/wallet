# Wallet protobuf compatibility baseline

`wallet-v1.binpb` is the reviewed Buf image for the pre-release Wallet v1
contract. It includes imported descriptors so compatibility checks do not need
sibling checkouts or a live registry to load the baseline.

`manifest.json` pins its SHA-256 digest, checked by
`scripts/check_schema_source_lock.mjs`. Baseline updates change the compatibility
reference and require contract review; they must not be used to hide an
unreviewed breaking change.
