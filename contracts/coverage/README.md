# Wallet producer evidence

Identity Taxonomy owns the shared inventory, requirement digests and federation
rules. Wallet supplies the source-local producer ledger and reviewed dispositions
through `generate_wallet_taxonomy_evidence.mjs`. Identity Conformance retains
composed test plans, deployment provenance and reviewed execution results.

The source lock identifies the exact committed taxonomy inventory used for this
mapping. It does not require implementation work to wait for a release. Generate
and check the ledger with:

```sh
node scripts/generate_wallet_taxonomy_evidence.mjs
node scripts/generate_wallet_taxonomy_evidence.mjs --check
```

Regeneration requires the pinned Identity Taxonomy checkout. Public GitHub CI
does not regenerate the ledger or fetch the evidence repositories; the producer
unit tests use injected synthetic inventory instead:

```sh
node --test scripts/generate_wallet_taxonomy_evidence.test.mjs
```

The pinned inventory assigns 26 conditional BLE, NFC, proximity and transport
commands to Wallet. Those platform command facades are not selected here;
Identity and application providers own platform engagement and I/O. Each row is
explicitly `not_applicable` with `capability_not_selected`. This is a scope
disposition, not implementation or interoperability evidence. The generator
rejects new or changed requirement assignments until their dispositions receive
review. Shared ownership changes and federation promotion remain separate
Taxonomy changes.

Wallet's domain behavior is described by
[`wallet-policy-contracts-v1.json`](../../conformance/features/wallet-policy-contracts-v1.json)
and its source/test locators. It does not invent shared requirement identifiers
or promote the conditional platform rows to `implemented`. Evidence maps use a
JSON-compatible YAML body so schema validation and deterministic generation use
the same data model.
