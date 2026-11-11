# EUDI Reference Fixtures

These manifests describe expected Wallet checks for runs against the targets in
[`reference-implementation.lock`](../../eudi/reference-implementation.lock).
Their hashes are pinned in
[`reference-fixture-hashes.json`](../../eudi/reference-fixture-hashes.json).
They are synthetic test specifications, not proof that interoperability runs passed.

Executed outputs and suite artifacts must meet the
[run manifest](../../eudi/reference-run-manifest.json) before they can support
an interoperability or assessment claim. Certification-body acceptance remains
a separate requirement.

Wallet supplies state, consent, inventory, attestation, contact-delivery, and
runtime evidence. Protocol parsing and credential/proof assembly remain with
OpenID4VCI, OpenID4VP, and SSI; platform facades remain with Identity.
