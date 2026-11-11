// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    append_history_record, chain_history_record, export_history_page, validate_history_record,
    HistoryError,
};
use reallyme_wallet_storage::{
    StorageError, StorageErrorReason, StorageResult, TransactionHistoryStore,
};
use reallyme_wallet_types::{
    AttributeName, HistoryCursor, HistoryFailureReason, HistoryOutcome, HistoryPurpose,
    NonEmptyIdentifier, RelyingPartyId, TransactionHistoryRecord, TransactionLogEntryId,
    UnixTimestamp, WalletTypesError,
};
use thiserror::Error;
#[derive(Default)]
struct Store {
    entries: Vec<TransactionHistoryRecord>,
    fail: bool,
    omit: bool,
}
impl TransactionHistoryStore for Store {
    fn history_head(&self) -> StorageResult<(u64, [u8; 32])> {
        Ok(self
            .entries
            .last()
            .map_or((0, [0; 32]), |r| (r.sequence, r.entry_hash)))
    }
    fn append_history(
        &mut self,
        head: (u64, [u8; 32]),
        r: TransactionHistoryRecord,
    ) -> StorageResult<()> {
        if self.fail {
            return Err(StorageError::new(StorageErrorReason::WriteRejected));
        }
        if self.history_head()? != head
            || head.0.checked_add(1) != Some(r.sequence)
            || r.previous_hash != head.1
        {
            return Err(StorageError::new(StorageErrorReason::RevisionConflict));
        }
        if self.entries.iter().any(|e| e.id == r.id) {
            return Err(StorageError::new(StorageErrorReason::RecordAlreadyExists));
        }
        self.entries.push(r);
        Ok(())
    }
    fn query_history(&self, c: &HistoryCursor) -> StorageResult<Vec<TransactionHistoryRecord>> {
        let limit = usize::try_from(c.limit)
            .map_err(|_| StorageError::new(StorageErrorReason::ReadRejected))?;
        let mut page: Vec<_> = self
            .entries
            .iter()
            .filter(|r| r.sequence > c.after_sequence && r.sequence <= c.through_sequence)
            .take(limit)
            .cloned()
            .collect();
        if self.omit {
            page.pop();
        }
        Ok(page)
    }
}
fn record(
    id: &str,
    outcome: HistoryOutcome,
    reason: HistoryFailureReason,
) -> Result<TransactionHistoryRecord, WalletTypesError> {
    Ok(TransactionHistoryRecord {
        id: TransactionLogEntryId::new(id.into())?,
        purpose: HistoryPurpose::Presentation,
        outcome,
        reason,
        relying_party_id: Some(RelyingPartyId::new("https://reader.example".into())?),
        requested: vec![AttributeName::new("age".into())?],
        presented: if matches!(
            outcome,
            HistoryOutcome::Completed | HistoryOutcome::DeliveryUnknown
        ) {
            vec![AttributeName::new("age".into())?]
        } else {
            vec![]
        },
        credential_ids: vec![],
        consent_digest: Some([4; 32]),
        operation_id: NonEmptyIdentifier::new("op".into())?,
        occurred_at: UnixTimestamp::from_seconds(20)?,
        sequence: 0,
        previous_hash: [0; 32],
        entry_hash: [0; 32],
    })
}
#[test]
fn all_outcomes_and_pinned_pagination_round_trip() -> Result<(), TestError> {
    let mut store = Store::default();
    for (id, outcome, reason) in [
        ("a", HistoryOutcome::Completed, HistoryFailureReason::None),
        (
            "b",
            HistoryOutcome::Refused,
            HistoryFailureReason::UserDecision,
        ),
        (
            "c",
            HistoryOutcome::Cancelled,
            HistoryFailureReason::UserDecision,
        ),
        ("d", HistoryOutcome::Failed, HistoryFailureReason::Provider),
        ("e", HistoryOutcome::Expired, HistoryFailureReason::Expiry),
        (
            "f",
            HistoryOutcome::DeliveryUnknown,
            HistoryFailureReason::Transport,
        ),
    ] {
        append_history_record(&mut store, record(id, outcome, reason)?)?;
    }
    let head = store.history_head()?;
    let mut cursor = HistoryCursor {
        after_sequence: 0,
        after_hash: [0; 32],
        through_sequence: head.0,
        through_hash: head.1,
        limit: 2,
    };
    // An append after export starts must not move the pinned through boundary.
    append_history_record(
        &mut store,
        record("g", HistoryOutcome::Completed, HistoryFailureReason::None)?,
    )?;
    for _ in 0..3 {
        let (page, next) = export_history_page(&store, &cursor)?;
        assert_eq!(page.len(), 2);
        cursor = next;
    }
    assert_eq!(cursor.after_sequence, 6);
    assert!(export_history_page(&store, &cursor)?.0.is_empty());
    Ok(())
}
#[test]
fn tampering_wrong_head_omissions_and_invalid_limits_fail() -> Result<(), TestError> {
    let mut store = Store::default();
    append_history_record(
        &mut store,
        record("a", HistoryOutcome::Completed, HistoryFailureReason::None)?,
    )?;
    let h = store.history_head()?;
    let cursor = HistoryCursor {
        after_sequence: 0,
        after_hash: [0; 32],
        through_sequence: h.0,
        through_hash: h.1,
        limit: 1,
    };
    let mut wrong = cursor.clone();
    wrong.through_hash = [8; 32];
    assert!(export_history_page(&store, &wrong).is_err());
    wrong = cursor.clone();
    wrong.limit = 0;
    assert!(export_history_page(&store, &wrong).is_err());
    wrong.limit = u32::MAX;
    assert!(export_history_page(&store, &wrong).is_err());
    store.omit = true;
    assert!(export_history_page(&store, &cursor).is_err());
    store.omit = false;
    store.entries[0].reason = HistoryFailureReason::Provider;
    assert!(export_history_page(&store, &cursor).is_err());
    Ok(())
}
#[test]
fn duplicate_and_interrupted_append_preserve_head() -> Result<(), TestError> {
    let mut store = Store::default();
    append_history_record(
        &mut store,
        record("a", HistoryOutcome::Completed, HistoryFailureReason::None)?,
    )?;
    let head = store.history_head()?;
    assert!(append_history_record(
        &mut store,
        record("a", HistoryOutcome::Completed, HistoryFailureReason::None)?
    )
    .is_err());
    assert_eq!(store.history_head()?, head);
    store.fail = true;
    assert!(append_history_record(
        &mut store,
        record("b", HistoryOutcome::Completed, HistoryFailureReason::None)?
    )
    .is_err());
    assert_eq!(store.history_head()?, head);
    Ok(())
}
#[test]
fn metadata_bounds_and_impossible_outcomes_fail() -> Result<(), TestError> {
    let base = record("a", HistoryOutcome::Completed, HistoryFailureReason::None)?;
    let mut r = base.clone();
    r.requested.push(r.requested[0].clone());
    assert!(chain_history_record(r, (0, [0; 32])).is_err());
    let mut r = base.clone();
    r.presented.push(AttributeName::new("extra".into())?);
    assert!(chain_history_record(r, (0, [0; 32])).is_err());
    let mut r = base.clone();
    r.outcome = HistoryOutcome::Refused;
    r.reason = HistoryFailureReason::UserDecision;
    assert!(chain_history_record(r, (0, [0; 32])).is_err());
    assert!(chain_history_record(base.clone(), (u64::MAX, [1; 32])).is_err());
    let r = chain_history_record(base, (5, [7; 32]))?;
    validate_history_record(&r)?;
    assert_eq!(r.sequence, 6);
    assert_eq!(r.previous_hash, [7; 32]);
    Ok(())
}
#[derive(Debug, Error)]
enum TestError {
    #[error("types")]
    Types(#[from] WalletTypesError),
    #[error("history")]
    History(#[from] HistoryError),
    #[error("storage")]
    Storage(#[from] StorageError),
}
