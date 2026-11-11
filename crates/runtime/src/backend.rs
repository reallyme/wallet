// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Injected backend trait for wallet runtime handlers.

use reallyme_wallet_lifecycle::{
    WalletLifecycleEvent, WalletLifecycleEvidenceRecord, WalletLifecycleRecord, WalletOperation,
};
use reallyme_wallet_storage::{
    OperationIdempotencyKey, OperationReplayDecision, OperationRequestDigest, OperationReservation,
    PresentationCopyClaimPolicy,
};
use reallyme_wallet_types::{
    CredentialRecord, CredentialRecordId, FlowSnapshot, FlowSnapshotId, NonEmptyIdentifier,
    OnceOnlyPresentationCopy, PresentationCopyId, QtspDecisionRecord, RecordRevision,
    TransactionLogEntry, UnixTimestamp, Versioned,
};

use crate::RuntimeResult;

/// Credential record paired with the revision observed by the backend read.
///
/// The wrapper deliberately omits `Debug`, serialization, and cloning so a
/// platform boundary cannot accidentally log or duplicate credential material.
pub type VersionedCredentialRecord = Versioned<CredentialRecord>;

/// Wallet lifecycle record paired with its observed backend revision.
///
/// Lifecycle state contains privacy-bearing identifiers, so this owner also
/// omits `Debug`, serialization, and cloning.
pub type VersionedWalletLifecycleRecord = Versioned<WalletLifecycleRecord>;

/// Flow snapshot paired with the revision observed by the backend read.
///
/// Snapshot state is secret-bearing, so this wrapper omits diagnostics,
/// serialization, and cloning.
pub type VersionedFlowSnapshot = Versioned<FlowSnapshot>;

/// Identifier and revision returned by an atomic flow-snapshot write.
pub struct FlowSnapshotWriteResult {
    id: FlowSnapshotId,
    revision: RecordRevision,
}

impl FlowSnapshotWriteResult {
    /// Bind the stored snapshot identifier to its new revision.
    #[must_use]
    pub const fn new(id: FlowSnapshotId, revision: RecordRevision) -> Self {
        Self { id, revision }
    }

    /// Consume the result into its identifier and revision.
    #[must_use]
    pub fn into_parts(self) -> (FlowSnapshotId, RecordRevision) {
        (self.id, self.revision)
    }
}

/// Backend operations needed by the canonical Wallet operation runtime.
///
/// SDK and service packages implement this trait with platform encrypted
/// storage, batch-pool persistence, and append-only log backends. The runtime
/// remains transport-neutral and never owns platform storage or key material.
pub trait WalletRuntimeBackend {
    /// Recheck the bound Wallet Unit's durable lifecycle before a regulated action.
    ///
    /// The backend must bind its credential, flow, and key storage to the same
    /// Wallet Unit. An unbound backend must fail closed; a cached state or a
    /// caller-supplied lifecycle DTO is not an authorization source.
    fn authorize_wallet_operation(&mut self, operation: WalletOperation) -> RuntimeResult<()>;

    /// Return the Wallet Unit this backend stores, if it is bound to one.
    ///
    /// Lifecycle operations name a Wallet Unit in the request. The runtime
    /// accepts only the bound unit, so a handle for one unit cannot create,
    /// read, or transition another. An unbound backend refuses them.
    fn bound_wallet_instance_id(&self) -> Option<NonEmptyIdentifier>;

    /// Return host-trusted current time for lifecycle and other security gates.
    ///
    /// The clock must not read a timestamp from the operation request. A
    /// failure returns `TrustedClockUnavailable` and leaves state unchanged.
    fn trusted_now(&mut self) -> RuntimeResult<UnixTimestamp>;

    /// Authenticate the authority behind authority-bearing lifecycle evidence.
    ///
    /// The runtime calls this before committing an event for which
    /// `lifecycle_event_requires_verified_authority` returns `true`. Evidence
    /// carried by an operation request is untrusted input; the backend must
    /// authenticate the referenced provider evidence, its digest, and that
    /// `authority_id` is trusted to authorize `event` for the Wallet Unit in
    /// `current`. A backend that cannot perform this check, or any failed
    /// check, returns an error and leaves state unchanged.
    fn verify_wallet_lifecycle_authority(
        &mut self,
        current: &WalletLifecycleRecord,
        event: WalletLifecycleEvent,
        evidence: &WalletLifecycleEvidenceRecord,
        now: UnixTimestamp,
    ) -> RuntimeResult<()>;

    /// Authenticate fresh retry evidence and reconcile all partial provider effects.
    ///
    /// Return a receipt only when the exact failed operation is safe to retry.
    /// Unresolved, already-completed, unsafe, or unavailable reconciliation
    /// leaves the failed record unchanged. Existing providers fail closed.
    fn reconcile_wallet_lifecycle_retry(
        &mut self,
        _current: &WalletLifecycleRecord,
        _event: WalletLifecycleEvent,
        _evidence: &WalletLifecycleEvidenceRecord,
        _now: UnixTimestamp,
    ) -> RuntimeResult<reallyme_wallet_lifecycle::ReconciledWalletLifecycleRetry> {
        Err(crate::RuntimeError::new(
            crate::RuntimeErrorReason::LifecyclePolicyDenied,
        ))
    }

    /// Atomically reserve a canonical mutating operation for first execution.
    ///
    /// A new key/digest pair returns `Execute`. A completed matching pair
    /// returns the exact previously committed response. A reused key with a
    /// different digest returns `IdempotencyConflict`; an uncommitted matching
    /// reservation returns `OperationInProgress`. Reservations never expire or
    /// become executable again implicitly, preventing a crash window from
    /// duplicating a mutation.
    fn begin_idempotent_operation(
        &mut self,
        key: &OperationIdempotencyKey,
        request_digest: &OperationRequestDigest,
    ) -> RuntimeResult<OperationReplayDecision>;

    /// Atomically commit the exact canonical response for a reservation.
    ///
    /// Failure leaves the key reserved and therefore fail-closed. Providers
    /// must not expose a partially committed response or allow another execute
    /// decision for the same key.
    fn commit_idempotent_operation(
        &mut self,
        reservation: &OperationReservation,
        response: &[u8],
    ) -> RuntimeResult<()>;

    /// Atomically create an encrypted credential record.
    ///
    /// Existing identifiers return `CredentialAlreadyExists`; this method must
    /// never degrade into an unconditional overwrite.
    fn create_credential_record(
        &mut self,
        record: CredentialRecord,
    ) -> RuntimeResult<CredentialRecordId>;

    /// Load an encrypted credential record.
    fn get_credential_record(
        &mut self,
        id: &CredentialRecordId,
    ) -> RuntimeResult<VersionedCredentialRecord>;

    /// Replace an existing credential only if its revision is unchanged.
    ///
    /// The provider must perform comparison and replacement in one atomic
    /// transaction. A stale revision returns
    /// `RuntimeErrorReason::CredentialRevisionConflict`; it must never fall
    /// back to an unconditional overwrite.
    fn compare_and_swap_credential_record(
        &mut self,
        expected_revision: RecordRevision,
        record: &CredentialRecord,
    ) -> RuntimeResult<CredentialRecordId>;

    /// Atomically delete or tombstone an encrypted credential revision.
    ///
    /// A provider must compare and delete in one transaction. If the record
    /// changed after the runtime read it, the provider returns
    /// `CredentialRevisionConflict` and preserves the newer revision. The
    /// same transaction burns every presentation copy of the credential so no
    /// copy remains claimable after deletion commits.
    fn delete_credential_record(
        &mut self,
        id: &CredentialRecordId,
        expected_revision: RecordRevision,
    ) -> RuntimeResult<()>;

    /// Atomically claim a verifier-unlinkable presentation copy.
    ///
    /// Selection, the policy check, and the available-to-claimed transition
    /// occur in one provider transaction. Every policy must read the parent
    /// credential inside that transaction and fail without burning a copy
    /// when the credential is missing or not active. `ActiveZkCredential`
    /// additionally checks the credential's format and the protected claim
    /// selector. Concurrent callers must never receive the same copy.
    fn claim_presentation_copy(
        &mut self,
        credential_id: &CredentialRecordId,
        copy_id: &PresentationCopyId,
        policy: PresentationCopyClaimPolicy,
        prepared_claim_selector_digest: Option<&[u8; 32]>,
    ) -> RuntimeResult<OnceOnlyPresentationCopy>;

    /// Atomically compare the entry with the durable head and append it.
    ///
    /// The provider must reject duplicate entry identifiers, a second genesis,
    /// skipped sequences, and any predecessor hash other than the current head.
    /// Head comparison, duplicate check, and append must share one transaction.
    fn append_transaction_log(&mut self, entry: TransactionLogEntry) -> RuntimeResult<()>;

    /// Atomically append a qualified trust decision record.
    ///
    /// Records are append-only. A record whose kind, input digest, and
    /// decision time duplicate a stored record must be rejected.
    fn append_qtsp_decision(&mut self, record: QtspDecisionRecord) -> RuntimeResult<()>;

    /// Create or atomically replace a versioned resumable flow snapshot.
    ///
    /// `None` creates a new record and fails if it already exists. `Some`
    /// performs compare-and-swap and fails with `FlowSnapshotRevisionConflict`
    /// when the observed revision is stale or the record is absent.
    fn save_flow_snapshot(
        &mut self,
        snapshot: FlowSnapshot,
        expected_revision: Option<RecordRevision>,
    ) -> RuntimeResult<FlowSnapshotWriteResult>;

    /// Load a resumable flow snapshot with its current revision.
    fn get_flow_snapshot(&mut self, id: &FlowSnapshotId) -> RuntimeResult<VersionedFlowSnapshot>;

    /// Atomically create a durable Wallet Unit lifecycle record.
    ///
    /// Existing identifiers return `LifecycleAlreadyExists`; this method must
    /// never degrade into an unconditional overwrite.
    fn create_wallet_lifecycle_record(
        &mut self,
        record: WalletLifecycleRecord,
    ) -> RuntimeResult<NonEmptyIdentifier>;

    /// Load a durable Wallet Unit lifecycle record.
    fn get_wallet_lifecycle_record(
        &mut self,
        wallet_instance_id: &NonEmptyIdentifier,
    ) -> RuntimeResult<VersionedWalletLifecycleRecord>;

    /// Atomically replace lifecycle state and append its evidence at the observed revision.
    ///
    /// Both writes must commit or neither may commit. The evidence must match
    /// the record's last evidence and may be appended only once. A stale
    /// revision returns `LifecycleRevisionConflict`; a failed append preserves
    /// the old state and revision.
    fn compare_and_swap_wallet_lifecycle_record(
        &mut self,
        expected_revision: RecordRevision,
        record: &WalletLifecycleRecord,
        evidence: &WalletLifecycleEvidenceRecord,
    ) -> RuntimeResult<NonEmptyIdentifier>;
}
