// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Atomic persistence boundaries for policy state. Providers encrypt records at rest.

use crate::StorageResult;
use reallyme_wallet_types::{
    CredentialReuseState, FlowExecutionRecord, FlowSnapshotId, HistoryCursor, NonEmptyIdentifier,
    RecordRevision, TransactionHistoryRecord, Versioned,
};

/// Durable reuse cohorts. No operation may reset claims or resurrect a retired identity.
pub trait CredentialReuseStore {
    /// Create a unique cohort and bind its credential identities atomically.
    /// Reject credentials already bound to any cohort, including retired cohorts.
    fn create_reuse_state(&mut self, state: CredentialReuseState) -> StorageResult<RecordRevision>;
    /// Retire the old cohort, fulfill its existing intent, create its replacement,
    /// and bind the replacement credential identities in one durable transaction.
    /// Never reset old claims/assignments. A failed write changes neither cohort.
    fn commit_replenishment(
        &mut self,
        expected: RecordRevision,
        retired: CredentialReuseState,
        replacement: CredentialReuseState,
    ) -> StorageResult<RecordRevision>;

    /// Read the complete authenticated aggregate, including every prior claim.
    fn get_reuse_state(
        &self,
        id: &NonEmptyIdentifier,
    ) -> StorageResult<Versioned<CredentialReuseState>>;
    /// Replace only the observed revision. Policy and instance identities are immutable;
    /// claims, assignments, counters and retirement cannot roll back. The provider
    /// must retain the old value on failure and must not expose material before commit.
    /// For a new claim it must atomically check that the exact referenced inventory
    /// record is still active and matches this cohort's authenticated policy/validity.
    /// A separate status read followed by CAS does not satisfy this contract.
    fn compare_and_swap_reuse_state(
        &mut self,
        expected: RecordRevision,
        state: CredentialReuseState,
    ) -> StorageResult<RecordRevision>;
}

/// Version-two append/query boundary. Existing v1 records remain immutable.
pub trait TransactionHistoryStore {
    /// Read the authenticated head. The migration head must be independently
    /// verified with the v1 chain validator before initializing a v2 store.
    fn history_head(&self) -> StorageResult<(u64, [u8; 32])>;
    /// Compare the durable head and append a unique identity in one transaction.
    /// Reject duplicates, sequence gaps and predecessor mismatches without changing
    /// the head. The head is shared with legacy writers during migration.
    fn append_history(
        &mut self,
        expected_head: (u64, [u8; 32]),
        record: TransactionHistoryRecord,
    ) -> StorageResult<()>;
    /// Return the next contiguous range within the pinned export head, in ascending
    /// sequence order. Do not filter, skip, scan unbounded history, or exceed limit.
    fn query_history(&self, cursor: &HistoryCursor)
        -> StorageResult<Vec<TransactionHistoryRecord>>;
}

/// Flow state and side-effect reservations share one durable CAS aggregate.
pub trait FlowExecutionStore {
    /// Create a unique flow; a terminal identity can never be recreated.
    fn create_execution(&mut self, record: FlowExecutionRecord) -> StorageResult<RecordRevision>;
    /// Read the complete guard and opaque protocol snapshot atomically.
    fn get_execution(&self, id: &FlowSnapshotId) -> StorageResult<Versioned<FlowExecutionRecord>>;
    /// Commit guard and protocol snapshot together. Reject stale revisions and
    /// preserve terminal records, effect reservations, exact payload digests and
    /// copy burns. Never replace this with separate snapshot and metadata writes.
    fn compare_and_swap_execution(
        &mut self,
        expected: RecordRevision,
        record: FlowExecutionRecord,
    ) -> StorageResult<RecordRevision>;
}
