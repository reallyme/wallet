# Wallet policy state and durable authorization

Wallet implements credential allocation, consent receipts, transaction history,
and flow disposition in Rust. The existing operation union and platform SDK
surfaces remain unchanged. Identity selects and wires providers; storage adapters
implement the atomic ports in `crates/storage/src/policy.rs`. A host must not
advertise a restricted capability until its provider implements those contracts.

## Credential reuse

A reuse cohort binds an immutable credential configuration policy to a bounded
set of independently issued inventory identities and authenticated validity
windows. The provider binds each inventory identity to at most one cohort,
including retired cohorts, and checks active inventory state in the same
transaction that commits a use. Unrestricted and lifetime-limited selection,
once-only consumption, rotation, and stable per-party allocation have distinct
rules. Party bindings are wallet-scoped privacy-preserving digests supplied by
the authenticated requester boundary.

`claim_credential_use` commits the attempt identity, exact intent digest, selected
instance, counter and party assignment before returning selection to the caller.
A repeated attempt returns `AlreadyCommitted`, never another signing
capability. Claims are bounded and never evicted to permit reuse. Reaching the
claim budget requires retiring the cohort. Trusted time cannot move backwards.

Replenishment thresholds are inclusive. `request_replenishment` durably records
one retry identity; the host owns issuer requests and scheduling.
`fulfill_replenishment` retires the old cohort and creates a disjoint validated
replacement through one provider transaction. Old usage and assignments remain
retained. Failure must preserve both cohorts, and a new import must never
resurrect an old identity.

## Consent and proximity

The existing OpenID4VP preparation boundary remains available. Receipt-aware
preparation additionally authenticates policy identity, version, purpose,
retention and transaction assignment through an injected SSI policy provider.
Unsupported mandatory semantics fail closed. Exact approved terms are retained,
without claim values or copies of policy documents.

Proximity preparation accepts authenticated reader identity, certificate,
SessionTranscript digest, request digest, entitlement, requested claims and
freshness from the SSI/Identity reader verifier. Wallet performs no ISO parsing
or BLE/NFC engagement. A domain-separated binding joins those facts to existing
scope, action, trusted-time and final-disclosure checks.

Receipt capture atomically claims the Wallet Unit/RP/nonce and appends the full
receipt. Plain capture uses the same claim operation and nonce namespace.
Decoding or cloning a receipt conveys evidence only. Online final authorization
checks the live verified request and signer, the approved scope and the
exclusive deadline. Receipt authorization also checks the approved context.

## History and bounded export

Version-two records distinguish completed, refused, cancelled, failed, expired
and delivery-unknown attempts. They retain requested and presented attribute
names, credential references, request/consent digest and an operation identity.
They exclude claim values and backend exception text. Uncertain delivery retains
the attempted disclosure scope instead of claiming nothing was disclosed.

The v2 transcript is domain-separated and length-framed. Existing v1 hashes and
validators are unchanged. A separately verified v1 head may anchor migration;
the provider must share the append head with v1 writers to prevent a split
history. Append compares the head and unique event identity atomically.

Queries and exports return contiguous pages of at most 128 entries, pinned to
one observed end sequence/hash. Wallet verifies every sequence, predecessor,
entry hash, page count and final pinned hash. Concurrent appends do not move the
export boundary. Identity owns user authorization and export delivery.

## Cancellation, failure and uncertain delivery

A flow guard stores disposition, exact canonical effect bytes, their identities
and digests, and the opaque protocol snapshot in one CAS aggregate. The protocol owner must validate that
snapshot before resumption. A write-ahead reservation precedes consent, signing,
submission or storage commit. Only the successful reservation returns a
single-use capability; stale writers and failed writes return typed errors.

A restored outstanding reservation is `ReconcileOnly`: a missing response does
not authorize resend. Cancellation before reservation prevents the effect;
cancellation after a possible submission or storage commit records
`DeliveryUnknown`. Terminal records cannot resume or be recreated. No transition
releases consumed copies, clears prior reservations, or asserts remote erasure.

## Recovery and migration retries

A failed recovery or migration stays closed to signing, presentation, issuance,
and attestation renewal. Retrying uses the matching `BeginRecovery` or
`BeginMigration` event with new authority-authenticated evidence. The ordinary
transition helper cannot authorize that retry. A trusted provider must first
reconcile every partial effect of the exact failed attempt and return a
`ReconciledWalletLifecycleRetry` receipt bound to the predecessor and new
evidence. Outstanding, completed, unsafe, and unavailable outcomes refuse retry.

The runtime rechecks trusted time after reconciliation. Both the evidence and
decision must remain within the 60-second freshness window at commit. Lifecycle
state and evidence history commit atomically at the observed revision. Reusing
evidence or a stale revision never starts another attempt. A successful retry
returns to its pending state and preserves its original Active or Suspended
resume state; completing the operation is still separately authorized.

Identity composes the lifecycle evidence authenticator with its explicit
`WalletLifecycleOperationReconciler`. Platform key, migration, recovery, and
remote delivery reconciliation stays with that provider. Providers answering
`VerifyLifecycleAuthority` over the wire must return the exact
`WalletLifecycleRetryReconciliation` for retries; an ordinary empty approval
cannot authorize them.

## Issuer nonce state

Wallet retains the digest of an authenticated nonce observation, its trusted
freshness window and a binding to issuer, exact endpoint, configuration set,
wallet-unit key and unique token handle. Identity's nonce adapter checks the
configured endpoint against authenticated session metadata before network I/O.
Authenticated holder proofs must carry the same nonce digest and be issued
within the retained window. Initial submission also checks the explicit current
time. Restore verifies the original session and signed proof binding rather
than treating a persisted nonce digest as fresh authorization.

The nonce observation accompanies the canonical request and atomic issuance
snapshot. A missing observation, changed nonce, wrong session, expired first
submission or absent proof claim fails closed. The old blanket nonce-endpoint
rejection remains the missing-evidence error, rather than an unconditional
rejection when valid evidence exists.

## Issuance restore and dispatch

Restoring an issuance stage after receipt of the offer requires a checkpoint
authenticated with a key dedicated to the owning Wallet Unit. The checkpoint
binds the stage, offer, metadata, grant, token handle, and retained protocol
material. Persist it with the encrypted snapshot in revisioned storage. A
trusted snapshot revision is required to reject rollback.

The issuer transport persists its finalized request body and dispatch context
before sending. If the response is unavailable, the attempt remains reserved
for reconciliation. Hosts can read the protected request using the same
attempt identity. An existing reservation blocks a second dispatch with either
the retained bytes or newly generated proofs.

## Evidence and deployment qualification

`conformance/features/wallet-policy-contracts-v1.json` connects these APIs to
behavioral and invalid-input tests. Wallet's taxonomy producer ledger describes
its assigned requirement scope. Shared vocabulary and ownership remain in
Identity Taxonomy, while complete composed executions and reviewed results
remain in Identity Conformance. These core contracts do not establish hardware
qualification or a passing composed certification run.
