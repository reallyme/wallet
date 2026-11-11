// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Store wallet records through platform-provided encrypted storage.

use reallyme_wallet_lifecycle::{WalletLifecycleEvidenceRecord, WalletLifecycleRecord};
use reallyme_wallet_proto_codec::convert::OpenId4VciIssuanceCommit;
use reallyme_wallet_types::{
    CredentialRecordId, EncryptedRecord, FlowSnapshot, FlowSnapshotId, NonEmptyIdentifier,
    OnceOnlyPresentationCopy, OpenId4VciNotificationOutboxEntry, PresentationCopyId,
    QtspDecisionRecord, RecordRevision, TransactionLogEntry, TransactionLogEntryId, UnixTimestamp,
    Versioned,
};

use crate::StorageResult;

/// Encrypted credential payload paired with its observed revision.
pub type VersionedEncryptedRecord = Versioned<EncryptedRecord>;
/// Flow snapshot paired with its observed revision.
pub type VersionedFlowSnapshot = Versioned<FlowSnapshot>;
/// Pending notification outbox entry paired with its observed revision.
pub type VersionedOpenId4VciNotificationOutboxEntry = Versioned<OpenId4VciNotificationOutboxEntry>;
/// Wallet lifecycle state paired with its observed revision.
pub type VersionedWalletLifecycleRecord = Versioned<WalletLifecycleRecord>;

/// Platform-provided encrypted credential store.
pub trait CredentialRecordStore {
    /// Atomically create an encrypted credential record.
    ///
    /// Existing identifiers return `RecordAlreadyExists`; creation must never
    /// degrade into an unconditional overwrite.
    fn create_credential(
        &mut self,
        id: &CredentialRecordId,
        record: EncryptedRecord,
    ) -> StorageResult<RecordRevision>;

    /// Load an encrypted credential record.
    fn get_credential(&self, id: &CredentialRecordId) -> StorageResult<VersionedEncryptedRecord>;

    /// Atomically replace an encrypted credential at the expected revision.
    fn compare_and_swap_credential(
        &mut self,
        id: &CredentialRecordId,
        expected_revision: RecordRevision,
        record: EncryptedRecord,
    ) -> StorageResult<RecordRevision>;

    /// Atomically delete or tombstone an encrypted credential revision.
    ///
    /// The same transaction must burn every presentation copy that belongs
    /// to the credential. After deletion commits, no copy of that credential
    /// may be claimable through any claim policy, including after restart.
    /// An implementation therefore keeps credentials and their copies in one
    /// transactional store; this trait and `PresentationCopyStore` are two
    /// views of that store, not independent backends.
    fn delete_credential(
        &mut self,
        id: &CredentialRecordId,
        expected_revision: RecordRevision,
    ) -> StorageResult<()>;
}

/// Platform-provided store for resumable wallet flow snapshots.
pub trait FlowSnapshotStore {
    /// Create or atomically replace a resumable flow snapshot.
    ///
    /// `None` creates a new snapshot and must fail with `RecordAlreadyExists`
    /// when the identifier exists; it never overwrites. `Some` replaces only
    /// the record at exactly that revision and fails when it is stale or the
    /// record is absent.
    fn save_flow_snapshot(
        &mut self,
        snapshot: FlowSnapshot,
        expected_revision: Option<RecordRevision>,
    ) -> StorageResult<RecordRevision>;

    /// Load a resumable flow snapshot.
    fn get_flow_snapshot(&self, id: &FlowSnapshotId) -> StorageResult<VersionedFlowSnapshot>;

    /// Delete a resumable flow snapshot after completion or expiry.
    fn delete_flow_snapshot(
        &mut self,
        id: &FlowSnapshotId,
        expected_revision: RecordRevision,
    ) -> StorageResult<()>;
}

/// Result of an atomic OpenID4VCI issuance commit.
#[derive(Clone, PartialEq, Eq)]
pub struct OpenId4VciIssuanceCommitResult {
    /// Every independently stored credential id in canonical response order.
    pub credential_ids: Vec<CredentialRecordId>,
    /// Identifier of the stored resumable flow and notification outbox.
    pub flow_snapshot_id: FlowSnapshotId,
    /// Revision of the committed resumable flow snapshot.
    pub flow_snapshot_revision: RecordRevision,
    /// Revision of the pending outbox entry, when notification is required.
    pub notification_outbox_revision: Option<RecordRevision>,
}

/// Atomic credential import and durable notification-outbox storage port.
pub trait OpenId4VciIssuanceCommitStore {
    /// Resume only a commit whose launch intent matches the caller's durable
    /// fingerprint. The fingerprint must cover the exact launch supplied to
    /// the issuer; a reused key with another launch is a conflict.
    fn get_openid4vci_issuance_commit_result_for_launch(
        &self,
        idempotency_key: &[u8; reallyme_wallet_types::OPENID4VCI_ISSUANCE_IDEMPOTENCY_BYTES],
        launch_digest: &[u8; reallyme_wallet_types::OPENID4VCI_ISSUANCE_IDEMPOTENCY_BYTES],
    ) -> StorageResult<Option<OpenId4VciIssuanceCommitResult>>;

    /// Look up a prior atomic commit before repeating issuer-side effects.
    ///
    /// This index is durable and keyed by both the aggregate's idempotency
    /// key and its canonical content digest. A matching key with a different
    /// digest must return `IdempotencyConflict`, never a prior success.
    fn get_openid4vci_issuance_commit_result(
        &self,
        idempotency_key: &[u8; reallyme_wallet_types::OPENID4VCI_ISSUANCE_IDEMPOTENCY_BYTES],
        request_digest: &[u8; reallyme_wallet_types::OPENID4VCI_ISSUANCE_IDEMPOTENCY_BYTES],
    ) -> StorageResult<Option<OpenId4VciIssuanceCommitResult>>;

    /// Commit all credential records, the stored-state snapshot, and optional
    /// pending notification as one durable transaction.
    ///
    /// Repeating the same key and request digest returns the original result.
    /// Reusing a key with another digest returns `IdempotencyConflict`.
    fn commit_openid4vci_issuance(
        &mut self,
        commit: OpenId4VciIssuanceCommit,
        launch_digest: &[u8; reallyme_wallet_types::OPENID4VCI_ISSUANCE_IDEMPOTENCY_BYTES],
    ) -> StorageResult<OpenId4VciIssuanceCommitResult>;

    /// Load pending notification work for a resumable issuance flow.
    fn get_openid4vci_notification_outbox(
        &self,
        flow_id: &FlowSnapshotId,
    ) -> StorageResult<Option<VersionedOpenId4VciNotificationOutboxEntry>>;

    /// Atomically record one delivery attempt before external I/O.
    /// Providers use checked arithmetic and return `WriteRejected` instead of
    /// wrapping the attempt counter.
    fn record_openid4vci_notification_attempt(
        &mut self,
        flow_id: &FlowSnapshotId,
        expected_revision: RecordRevision,
        attempted_at: UnixTimestamp,
    ) -> StorageResult<VersionedOpenId4VciNotificationOutboxEntry>;

    /// Mark notification delivery complete at the observed outbox revision.
    /// Repeating a delivered transition is idempotent and returns its current
    /// revision; stale pending revisions fail with `RevisionConflict`.
    fn mark_openid4vci_notification_delivered(
        &mut self,
        flow_id: &FlowSnapshotId,
        expected_revision: RecordRevision,
        delivered_at: UnixTimestamp,
    ) -> StorageResult<RecordRevision>;
}

/// Platform-provided store for durable Wallet Unit lifecycle state.
pub trait WalletLifecycleStore {
    /// Atomically create a Wallet Unit lifecycle record.
    ///
    /// An existing Wallet Unit identifier, in any state including withdrawn
    /// or deleted, must fail with `RecordAlreadyExists`. Creation never
    /// overwrites, so a terminal Wallet Unit cannot be recreated as new.
    fn create_wallet_lifecycle(
        &mut self,
        record: WalletLifecycleRecord,
    ) -> StorageResult<RecordRevision>;

    /// Load a Wallet Unit lifecycle record.
    fn get_wallet_lifecycle(
        &self,
        wallet_instance_id: &NonEmptyIdentifier,
    ) -> StorageResult<VersionedWalletLifecycleRecord>;

    /// Atomically replace lifecycle state and append its matching evidence.
    ///
    /// The implementation must use one durable transaction; if either write
    /// fails, both state and history retain their prior values. `evidence`
    /// must equal `record`'s last evidence, and an evidence identifier already
    /// in the Wallet Unit's history must be rejected rather than appended again.
    fn compare_and_swap_wallet_lifecycle(
        &mut self,
        expected_revision: RecordRevision,
        record: WalletLifecycleRecord,
        evidence: WalletLifecycleEvidenceRecord,
    ) -> StorageResult<RecordRevision>;
}

/// Policy attached to a canonical once-only-copy claim operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresentationCopyClaimPolicy {
    /// Generic once-only presentation copy.
    Generic,
    /// Claim only while the exact selected record is an active ZK credential.
    ActiveZkCredential,
}

/// Platform-provided store for once-only presentation copies.
pub trait PresentationCopyStore {
    /// Persist a verifier-unlinkable presentation copy for a credential.
    ///
    /// A prepared private-persona token belongs here as one encrypted copy
    /// containing its exact proof packages and one-time signing-key handle.
    /// Duplicate copy identities must fail; a consumed identity must never
    /// become available again, even after credential import or app restart.
    fn put_presentation_copy(
        &mut self,
        credential_id: &CredentialRecordId,
        copy: OnceOnlyPresentationCopy,
    ) -> StorageResult<()>;

    /// Atomically claim the exact consent-selected presentation copy.
    ///
    /// Providers must durably commit the unavailable state before returning
    /// any encrypted token bytes or signing-key handle. Selection and state
    /// transition are one transaction so concurrent callers cannot receive
    /// the same copy. A crash after this commit burns the token; recovery must
    /// never return it to the available pool, even if no response was sent.
    /// Copies with a prepared-claim selector require the separate active-ZK
    /// claim capability and must be rejected by this generic operation.
    ///
    /// The transaction must also read the parent credential and fail closed,
    /// leaving every copy available, when the credential is missing or its
    /// status is not active. A suspended, revoked, or deleted credential must
    /// never yield a presentation copy. The encrypted payload held through
    /// `CredentialRecordStore` does not reveal status, so the implementation
    /// must also hold the inventory status the Wallet writes, under the same
    /// lock or transaction as the copies.
    fn claim_presentation_copy(
        &mut self,
        credential_id: &CredentialRecordId,
        copy_id: &PresentationCopyId,
    ) -> StorageResult<OnceOnlyPresentationCopy>;
}

/// Storage capability for a prepared ZK token selected from an active credential.
///
/// This is the active-ZK policy of the `ClaimPresentationCopyRequest` protobuf
/// operation. The backend must read the exact
/// credential and reserve the one-time copy in one transaction. A separate
/// inventory read followed by `PresentationCopyStore::claim_presentation_copy`
/// does not provide that guarantee when credential state changes concurrently.
pub trait PreparedZkPresentationCopyStore {
    /// Durably burn one copy only while its selected ZK credential is active.
    ///
    /// A missing, non-ZK, duplicate, or inactive credential, or a token whose
    /// protected claim selector differs from the verified request, fails
    /// closed and leaves every available copy untouched. The returned copy is
    /// already unavailable to concurrent callers and after restart.
    fn claim_active_zk_presentation_copy(
        &mut self,
        credential_id: &CredentialRecordId,
        copy_id: &PresentationCopyId,
        prepared_claim_selector_digest: &[u8; 32],
    ) -> StorageResult<OnceOnlyPresentationCopy>;
}

/// Platform-provided append-only transaction log store.
pub trait TransactionLogStore {
    /// Compare the durable head and append in one transaction.
    ///
    /// Reject duplicate identifiers and any sequence or predecessor mismatch;
    /// failure must preserve the prior head and history.
    fn append_transaction_log_entry(&mut self, entry: TransactionLogEntry) -> StorageResult<()>;

    /// Read the durable head as `(sequence, entry_hash)`, or `(0, [0; 32])`
    /// for an empty log.
    ///
    /// Callers anchor `validate_transaction_log_chain_to_head` on this value
    /// so entries missing from an export or a read-back are detected. A head
    /// read from this store cannot detect a rollback of the store as a whole;
    /// that needs a head the caller keeps somewhere the store cannot rewrite.
    fn transaction_log_head(&self) -> StorageResult<(u64, [u8; 32])>;

    /// Load one transaction log entry by id.
    fn get_transaction_log_entry(
        &self,
        id: &TransactionLogEntryId,
    ) -> StorageResult<TransactionLogEntry>;
}

/// Platform-provided QTSP decision record store.
pub trait QtspDecisionStore {
    /// Atomically append a qualified trust decision record.
    ///
    /// Records are append-only and are never rewritten or removed. A record
    /// whose kind, input digest, and decision time duplicate a stored record
    /// must be rejected rather than appended again.
    fn append_qtsp_decision_record(&mut self, record: QtspDecisionRecord) -> StorageResult<()>;
}
