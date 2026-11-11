// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Version-two transaction hashing and contiguous bounded history/export pages.

use reallyme_wallet_storage::{StorageError, StorageErrorReason, TransactionHistoryStore};
use reallyme_wallet_types::{
    HistoryCursor, HistoryFailureReason as Reason, HistoryOutcome as Outcome,
    HistoryPurpose as Purpose, TransactionHistoryRecord, MAX_HISTORY_ATTRIBUTES,
    MAX_HISTORY_CREDENTIALS, MAX_HISTORY_PAGE_SIZE,
};
use std::collections::BTreeSet;
use thiserror::Error;
use zeroize::Zeroizing;

const HISTORY_DOMAIN: &[u8] = b"reallyme.wallet.transaction-history.v2\0";
const MAX_HISTORY_TRANSCRIPT_BYTES: usize = 262_144;
/// Fixed history failures, excluding backend strings and claim values.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum HistoryErrorReason {
    /// Event shape, bound, outcome, or canonical ordering was invalid.
    #[error("invalid_record")]
    InvalidRecord,
    /// Hash, sequence, or pinned export-head verification failed.
    #[error("invalid_chain")]
    InvalidChain,
    /// Query/export limits or cursor were invalid.
    #[error("invalid_cursor")]
    InvalidCursor,
    /// Durable provider failure.
    #[error("storage")]
    Storage,
}
/// Typed history operation failure.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("history operation failed: {reason}")]
pub struct HistoryError {
    /// Domain reason.
    pub reason: HistoryErrorReason,
    /// Fixed provider reason when applicable.
    pub storage_reason: Option<StorageErrorReason>,
}
impl From<StorageError> for HistoryError {
    fn from(e: StorageError) -> Self {
        Self {
            reason: HistoryErrorReason::Storage,
            storage_reason: Some(e.reason),
        }
    }
}
fn error(reason: HistoryErrorReason) -> HistoryError {
    HistoryError {
        reason,
        storage_reason: None,
    }
}

/// Validate metadata without changing order or hashing ambiguous representations.
pub fn validate_history_metadata(record: &TransactionHistoryRecord) -> Result<(), HistoryError> {
    if record.requested.len() > MAX_HISTORY_ATTRIBUTES
        || record.presented.len() > MAX_HISTORY_ATTRIBUTES
        || record.credential_ids.len() > MAX_HISTORY_CREDENTIALS
    {
        return Err(error(HistoryErrorReason::InvalidRecord));
    }
    let valid_outcome = matches!(
        (record.outcome, record.reason),
        (Outcome::Completed, Reason::None)
            | (Outcome::Refused | Outcome::Cancelled, Reason::UserDecision)
            | (Outcome::Expired, Reason::Expiry)
            | (Outcome::DeliveryUnknown, Reason::Transport)
            | (
                Outcome::Failed,
                Reason::Policy | Reason::InvalidInput | Reason::Provider | Reason::Transport
            )
    );
    if record.id.as_str().is_empty()
        || record.operation_id.as_str().is_empty()
        || record
            .relying_party_id
            .as_ref()
            .is_some_and(|id| id.as_str().is_empty())
        || record
            .requested
            .iter()
            .chain(&record.presented)
            .any(|name| name.as_str().is_empty())
        || record
            .credential_ids
            .iter()
            .any(|id| id.as_str().is_empty())
        || !valid_outcome
        || record.requested.len() > MAX_HISTORY_ATTRIBUTES
        || record.presented.len() > MAX_HISTORY_ATTRIBUTES
        || record.credential_ids.len() > MAX_HISTORY_CREDENTIALS
        || (record.purpose == Purpose::Presentation
            && (record.relying_party_id.is_none() || record.consent_digest.is_none()))
        || record
            .consent_digest
            .is_some_and(|digest| digest == [0; 32])
        || (!matches!(
            record.outcome,
            Outcome::Completed | Outcome::DeliveryUnknown
        ) && !record.presented.is_empty())
    {
        return Err(error(HistoryErrorReason::InvalidRecord));
    }
    let requested: BTreeSet<_> = record.requested.iter().collect();
    let presented: BTreeSet<_> = record.presented.iter().collect();
    let credentials: BTreeSet<_> = record.credential_ids.iter().collect();
    if requested.len() != record.requested.len()
        || presented.len() != record.presented.len()
        || credentials.len() != record.credential_ids.len()
        || !presented.is_subset(&requested)
    {
        return Err(error(HistoryErrorReason::InvalidRecord));
    }
    Ok(())
}
fn append(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), HistoryError> {
    let count = u32::try_from(value.len()).map_err(|_| error(HistoryErrorReason::InvalidRecord))?;
    let end = bytes
        .len()
        .checked_add(4)
        .and_then(|n| n.checked_add(value.len()))
        .ok_or_else(|| error(HistoryErrorReason::InvalidRecord))?;
    if end > MAX_HISTORY_TRANSCRIPT_BYTES {
        return Err(error(HistoryErrorReason::InvalidRecord));
    }
    bytes.extend_from_slice(&count.to_be_bytes());
    bytes.extend_from_slice(value);
    Ok(())
}
fn history_hash(record: &TransactionHistoryRecord) -> Result<[u8; 32], HistoryError> {
    validate_history_metadata(record)?;
    let mut bytes = Zeroizing::new(Vec::new());
    // Reserve before copying any sensitive correlation or attribute data.
    bytes
        .try_reserve_exact(MAX_HISTORY_TRANSCRIPT_BYTES)
        .map_err(|_| error(HistoryErrorReason::InvalidRecord))?;
    append(&mut bytes, HISTORY_DOMAIN)?;
    append(&mut bytes, record.id.as_str().as_bytes())?;
    let purpose = match record.purpose {
        Purpose::Issuance => 1,
        Purpose::Presentation => 2,
        Purpose::Refresh => 3,
        Purpose::Deletion => 4,
        Purpose::QualifiedSignature => 5,
        Purpose::QualifiedSeal => 6,
    };
    let outcome = match record.outcome {
        Outcome::Completed => 1,
        Outcome::Refused => 2,
        Outcome::Cancelled => 3,
        Outcome::Failed => 4,
        Outcome::Expired => 5,
        Outcome::DeliveryUnknown => 6,
    };
    let reason = match record.reason {
        Reason::None => 0,
        Reason::UserDecision => 1,
        Reason::Policy => 2,
        Reason::InvalidInput => 3,
        Reason::Provider => 4,
        Reason::Transport => 5,
        Reason::Expiry => 6,
    };
    append(&mut bytes, &[purpose, outcome, reason])?;
    append(
        &mut bytes,
        record
            .relying_party_id
            .as_ref()
            .map_or(&[][..], |id| id.as_str().as_bytes()),
    )?;
    for names in [&record.requested, &record.presented] {
        append(
            &mut bytes,
            &u32::try_from(names.len())
                .map_err(|_| error(HistoryErrorReason::InvalidRecord))?
                .to_be_bytes(),
        )?;
        for name in names {
            append(&mut bytes, name.as_str().as_bytes())?;
        }
    }
    append(
        &mut bytes,
        &u32::try_from(record.credential_ids.len())
            .map_err(|_| error(HistoryErrorReason::InvalidRecord))?
            .to_be_bytes(),
    )?;
    for id in &record.credential_ids {
        append(&mut bytes, id.as_str().as_bytes())?;
    }
    append(
        &mut bytes,
        record
            .consent_digest
            .as_ref()
            .map_or(&[][..], |digest| digest.as_slice()),
    )?;
    append(&mut bytes, record.operation_id.as_str().as_bytes())?;
    append(&mut bytes, &record.occurred_at.as_seconds().to_be_bytes())?;
    append(&mut bytes, &record.sequence.to_be_bytes())?;
    append(&mut bytes, &record.previous_hash)?;
    Ok(crypto_sha2_256::digest(&bytes).into_bytes())
}
/// Bind metadata to a verified predecessor. Existing v1 hashes are never recomputed
/// with v2 semantics; a verified v1 head can serve as this migration anchor.
pub fn chain_history_record(
    mut record: TransactionHistoryRecord,
    head: (u64, [u8; 32]),
) -> Result<TransactionHistoryRecord, HistoryError> {
    if (head.0 == 0) != (head.1 == [0; 32]) {
        return Err(error(HistoryErrorReason::InvalidChain));
    }
    record.sequence = head
        .0
        .checked_add(1)
        .ok_or_else(|| error(HistoryErrorReason::InvalidChain))?;
    record.previous_hash = head.1;
    record.entry_hash = history_hash(&record)?;
    Ok(record)
}
/// Check one v2 entry without changing the legacy v1 validator.
pub fn validate_history_record(record: &TransactionHistoryRecord) -> Result<(), HistoryError> {
    if record.sequence == 0
        || (record.sequence == 1) != (record.previous_hash == [0; 32])
        || history_hash(record)? != record.entry_hash
    {
        return Err(error(HistoryErrorReason::InvalidChain));
    }
    Ok(())
}
/// Append after reading the head; a race is rejected by the provider's atomic CAS.
pub fn append_history_record(
    store: &mut dyn TransactionHistoryStore,
    record: TransactionHistoryRecord,
) -> Result<(), HistoryError> {
    let head = store.history_head()?;
    let record = chain_history_record(record, head)?;
    Ok(store.append_history(head, record)?)
}
/// Export one bounded, hash-verified page. Callers deliver it only after their
/// application authorization checks; this API does not authorize export itself.
pub fn export_history_page(
    store: &dyn TransactionHistoryStore,
    cursor: &HistoryCursor,
) -> Result<(Vec<TransactionHistoryRecord>, HistoryCursor), HistoryError> {
    if cursor.limit == 0
        || cursor.limit > MAX_HISTORY_PAGE_SIZE
        || cursor.after_sequence > cursor.through_sequence
        || (cursor.after_sequence == 0) != (cursor.after_hash == [0; 32])
        || (cursor.through_sequence == 0) != (cursor.through_hash == [0; 32])
    {
        return Err(error(HistoryErrorReason::InvalidCursor));
    }
    let records = store.query_history(cursor)?;
    let remaining = cursor
        .through_sequence
        .checked_sub(cursor.after_sequence)
        .ok_or_else(|| error(HistoryErrorReason::InvalidCursor))?;
    let expected = usize::try_from(core::cmp::min(remaining, u64::from(cursor.limit)))
        .map_err(|_| error(HistoryErrorReason::InvalidCursor))?;
    if records.len() != expected {
        return Err(error(HistoryErrorReason::InvalidChain));
    }
    let mut next = cursor.clone();
    for record in &records {
        next.after_sequence = next
            .after_sequence
            .checked_add(1)
            .ok_or_else(|| error(HistoryErrorReason::InvalidChain))?;
        if record.sequence != next.after_sequence || record.previous_hash != next.after_hash {
            return Err(error(HistoryErrorReason::InvalidChain));
        }
        validate_history_record(record)?;
        next.after_hash = record.entry_hash;
    }
    if next.after_sequence == next.through_sequence && next.after_hash != next.through_hash {
        return Err(error(HistoryErrorReason::InvalidChain));
    }
    Ok((records, next))
}
#[cfg(test)]
#[path = "history_tests.rs"]
mod tests;
