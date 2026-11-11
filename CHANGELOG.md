# Changelog

All notable changes to the Wallet Rust crates and wire contract are recorded here.

## 0.1.0

First public release.

### Added

- Added signed-request consent regression tests through the public OpenID4VP verifier, including expiry, request changes, and shared replay claims for ordinary consent and receipts.
- Added authenticated recovery and migration retries that require provider reconciliation, fresh evidence, atomic revision checks, and preserved Active/Suspended resume state.
- Seventeen Wallet Rust crates: domain types, credential inventory, Wallet Unit lifecycle, consent, attestation, storage and keystore boundaries, issuance and presentation flows, rendering, protobuf schema and codecs, runtime, provider adapter, HTTP adapter, and an optional ZK integration.
- The `reallyme.wallet.v1` operation and provider protobuf contract, with bounded binary and ProtoJSON codecs.
- Source and package policy checks, conformance fixtures, fuzz targets, and release archive attestation.

### Security

#### Lifecycle and runtime

- Every Wallet Unit lifecycle event after provisioning begins needs authority verified by the host. Evidence time must equal transition time and may not precede the current state. Transitions in the same second are allowed; the lifecycle store must refuse any evidence identifier it has already committed, so earlier evidence cannot be replayed.
- Lifecycle requests must name the Wallet Unit the backend is bound to.
- Once withdrawal or deletion begins, credential records and flow snapshots can no longer be read. Transaction history stays readable, and a deleted unit can still erase leftover records.
- Withdrawn and deleted units record no new transaction history other than erasure entries. Transaction-log appends are rechecked against the unit's lifecycle state on replay.
- Trusted time comes from a host-injected clock or the provider's `ReadTrustedTime`. Neither the provider backend nor the HTTP adapter reads the system clock.
- Mutating operations need an idempotency key bound to the request digest. A replay is released only when it answers the retried operation, and a once-only copy claim never replays its copy.
- v1 operations the runtime cannot execute safely are refused before any key check or journaling, with `RUNTIME_ERROR_REASON_OPERATION_UNSUPPORTED`. A provider that lacks a capability reports `RUNTIME_ERROR_REASON_PROVIDER_CAPABILITY_UNSUPPORTED`.
- Presentation copies are refused for missing, suspended, revoked, or deleted credentials. A copy burned while its credential became inactive is reported as `RUNTIME_ERROR_REASON_CLAIMED_COPY_DISCARDED`.
- Revision zero is refused for flow snapshots and for key-storage compare-and-swap calls.

#### Consent and presentation

- The consent nonce and request digest are derived from the verified OpenID4VP request. Consent claims are keyed on the verified `client_id`, so different spellings of one verifier share a nonce namespace.
- Requested attributes that a relying party did not register are reported for a user warning on online, proximity, and receipt paths. The Wallet Provider's `UnregisteredAttributePolicy` then allows them, keeps registered attributes only, or rejects the request (ARF EW-DM-44-027, legacy RPRC_21). The warning is recorded in the consent decision, which the capture and any receipt must carry.
- Consent, registration, and contact deadlines are exclusive.
- An expired request, an expired consent, and a changed request each have their own reason rather than a generic failure.
- A consent store that cannot keep receipts must refuse them with `ReceiptUnsupported`; it may not drop them.
- Consent claims carry the namespace and the deadline after which every capture of the request is refused, so stores can prune claim markers by trusted time. Plain and receipt captures of one request share one claim.
- Presentation state is opaque, and each stage can be entered only from the one before it.

#### Issuance

- Exact credential request bytes are kept across retries. An issuer refusal is reported as such, so a new request can be recorded; any other failure is reported as uncertain, and that request is not sent again from the same session.
- Deferred polling follows the issuer interval, an attempt budget, and a maximum wait.
- The Wallet Unit Attestation cannot be replaced after token exchange.
- Restored sessions keep their nonce bindings, and consent states without consent evidence cannot be restored.
- Reissuance cannot reactivate a suspended credential, and the replacement must keep status-list coverage.
- Credential status commits reject source times later than trusted time.

#### Attestation and keys

- Wallet Unit Attestation rotation needs fresh key evidence checked against a Wallet-issued challenge. The replacement must carry that evidence and the same key.
- Restored attestations are verified against the expected key.
- Key custody is authenticated through the attestation verifier.

#### Logs and storage

- Transaction logs are checked against the durable head, and duplicate entry identifiers are rejected. Log and QTSP records dated more than 60 seconds ahead of trusted time are refused.
- Decoding is bounded by message size, element memory, and transaction-log attribute count.
- Validated types wipe their contents when dropped and have no public `zeroize()`, so they cannot be wiped into values their constructors refuse.
- Identifiers and key handles refuse `..` segments, including ones hidden behind nested percent-encoding. Other percent-encoding is accepted.
- The storage trait documentation states the atomicity each store must provide.

#### Rendering and adapters

- QR text refuses script, data, local-file, and cleartext `http` schemes, control and bidirectional characters, invisible format characters, and leading or trailing whitespace. Wallet schemes and plain text are accepted.
- Apple pass assets must be valid PNG images with plain lowercase names, up to 1,048,576 pixels each.
- Google Wallet save JWTs are built from Wallet-owned claims and must be RS256 compact JWS over exactly those claims.
- The HTTP adapter accepts one content coding and fails closed after a backend panic.
- The OIDF harness checks callback origins for every request transport, bounds concurrent launches, and compiles its dependencies only with `oidf-conformance-harness`.
- ZK presentations require the production proof suite. ZK artifacts are bound to their circuit revision and creation time, and prepared artifacts have a bounded lifetime.
