// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Lifecycle transition helpers.

use crate::{
    validate_wallet_lifecycle_evidence_record, LifecycleError, LifecycleErrorReason,
    LifecycleResult, WalletLifecycleEvent, WalletLifecycleEvidenceRecord, WalletLifecycleRecord,
    WalletLifecycleState,
};
use reallyme_wallet_types::{NonEmptyIdentifier, UnixTimestamp};

/// Build the first durable lifecycle record for a Wallet Unit.
#[must_use]
pub fn new_wallet_lifecycle(
    wallet_instance_id: NonEmptyIdentifier,
    created_at: UnixTimestamp,
) -> WalletLifecycleRecord {
    WalletLifecycleRecord {
        wallet_instance_id,
        state: WalletLifecycleState::Unprovisioned,
        updated_at: created_at,
        last_event: None,
        resume_state: None,
        failed_from: None,
        last_evidence: None,
    }
}

/// Restore a lifecycle record from durable storage after validating its state provenance.
pub fn restore_wallet_lifecycle(
    wallet_instance_id: NonEmptyIdentifier,
    state: WalletLifecycleState,
    updated_at: UnixTimestamp,
    last_event: Option<WalletLifecycleEvent>,
    resume_state: Option<WalletLifecycleState>,
    failed_from: Option<WalletLifecycleState>,
    last_evidence: Option<WalletLifecycleEvidenceRecord>,
) -> LifecycleResult<WalletLifecycleRecord> {
    let record = WalletLifecycleRecord {
        wallet_instance_id,
        state,
        updated_at,
        last_event,
        resume_state,
        failed_from,
        last_evidence,
    };
    validate_restored_record(&record)?;
    Ok(record)
}

fn validate_restored_record(record: &WalletLifecycleRecord) -> LifecycleResult<()> {
    match (record.last_event, record.last_evidence.as_ref()) {
        (None, None) => {}
        (Some(event), Some(evidence)) => {
            validate_wallet_lifecycle_evidence_record(evidence)?;
            if evidence.wallet_instance_id != record.wallet_instance_id
                || evidence.event != event
                || evidence.occurred_at != record.updated_at
                || (record.state == WalletLifecycleState::Failed
                    && record.failed_from.and_then(failure_evidence_kind_for_state)
                        != Some(evidence.kind))
            {
                return Err(LifecycleError::new(LifecycleErrorReason::InvalidEvidence));
            }
        }
        (None, Some(_)) | (Some(_), None) => {
            return Err(LifecycleError::new(LifecycleErrorReason::InvalidEvidence));
        }
    }
    let valid = match record.state {
        WalletLifecycleState::Unprovisioned => {
            record.last_event.is_none()
                && record.resume_state.is_none()
                && record.failed_from.is_none()
        }
        WalletLifecycleState::Provisioning => {
            matches!(
                record.last_event,
                Some(
                    WalletLifecycleEvent::BeginProvisioning
                        | WalletLifecycleEvent::RetryProvisioning
                )
            ) && record.resume_state.is_none()
                && record.failed_from.is_none()
        }
        WalletLifecycleState::Active => {
            matches!(
                record.last_event,
                Some(
                    WalletLifecycleEvent::CompleteProvisioning
                        | WalletLifecycleEvent::Reactivate
                        | WalletLifecycleEvent::CompleteRecovery
                        | WalletLifecycleEvent::CompleteMigration
                )
            ) && record.resume_state.is_none()
                && record.failed_from.is_none()
        }
        WalletLifecycleState::Suspended => {
            matches!(
                record.last_event,
                Some(
                    WalletLifecycleEvent::Suspend
                        | WalletLifecycleEvent::CompleteRecovery
                        | WalletLifecycleEvent::CompleteMigration
                )
            ) && record.resume_state.is_none()
                && record.failed_from.is_none()
        }
        WalletLifecycleState::RecoveryPending => {
            record.last_event == Some(WalletLifecycleEvent::BeginRecovery)
                && matches!(
                    record.resume_state,
                    Some(WalletLifecycleState::Active | WalletLifecycleState::Suspended)
                )
                && record.failed_from.is_none()
        }
        WalletLifecycleState::MigrationPending => {
            record.last_event == Some(WalletLifecycleEvent::BeginMigration)
                && matches!(
                    record.resume_state,
                    Some(WalletLifecycleState::Active | WalletLifecycleState::Suspended)
                )
                && record.failed_from.is_none()
        }
        WalletLifecycleState::WithdrawalPending => {
            record.last_event == Some(WalletLifecycleEvent::BeginWithdrawal)
                && record.resume_state.is_none()
                && record.failed_from.is_none()
        }
        WalletLifecycleState::DeletionPending => {
            record.last_event == Some(WalletLifecycleEvent::BeginDeletion)
                && record.resume_state.is_none()
                && record.failed_from.is_none()
        }
        WalletLifecycleState::Withdrawn => {
            record.last_event == Some(WalletLifecycleEvent::CompleteWithdrawal)
                && record.resume_state.is_none()
                && record.failed_from.is_none()
        }
        WalletLifecycleState::Deleted => {
            record.last_event == Some(WalletLifecycleEvent::CompleteDeletion)
                && record.resume_state.is_none()
                && record.failed_from.is_none()
        }
        WalletLifecycleState::Failed => {
            record.last_event == Some(WalletLifecycleEvent::MarkFailed)
                && matches!(
                    record.failed_from,
                    Some(
                        WalletLifecycleState::Provisioning
                            | WalletLifecycleState::RecoveryPending
                            | WalletLifecycleState::MigrationPending
                            | WalletLifecycleState::WithdrawalPending
                            | WalletLifecycleState::DeletionPending
                    )
                )
                && match record.failed_from {
                    Some(
                        WalletLifecycleState::RecoveryPending
                        | WalletLifecycleState::MigrationPending,
                    ) => matches!(
                        record.resume_state,
                        Some(WalletLifecycleState::Active | WalletLifecycleState::Suspended)
                    ),
                    Some(_) => record.resume_state.is_none(),
                    None => false,
                }
        }
    };
    if valid {
        Ok(())
    } else {
        Err(LifecycleError::new(LifecycleErrorReason::InvalidTransition))
    }
}

/// Apply a lifecycle event to a durable record.
pub fn apply_wallet_lifecycle_event(
    record: WalletLifecycleRecord,
    event: WalletLifecycleEvent,
    updated_at: UnixTimestamp,
    evidence: Option<&WalletLifecycleEvidenceRecord>,
) -> LifecycleResult<WalletLifecycleRecord> {
    apply_event(record, event, updated_at, evidence, false)
}

/// Retry a reconciled failure without restoring signing or presentation access.
pub fn apply_reconciled_wallet_lifecycle_retry(
    record: WalletLifecycleRecord,
    evidence: &WalletLifecycleEvidenceRecord,
    reconciliation: crate::ReconciledWalletLifecycleRetry,
    now: UnixTimestamp,
) -> LifecycleResult<WalletLifecycleRecord> {
    reconciliation.validate(&record, evidence, now)?;
    apply_event(
        record,
        evidence.event,
        evidence.occurred_at,
        Some(evidence),
        true,
    )
}

fn apply_event(
    mut record: WalletLifecycleRecord,
    event: WalletLifecycleEvent,
    updated_at: UnixTimestamp,
    evidence: Option<&WalletLifecycleEvidenceRecord>,
    retry_authorized: bool,
) -> LifecycleResult<WalletLifecycleRecord> {
    // Trusted clocks may have second-level resolution. Evidence identity and
    // atomic history insertion provide replay protection even when distinct
    // authorized transitions have the same time. The durable lifecycle store
    // must reject every previously committed evidence identifier.
    if updated_at < record.updated_at {
        return Err(LifecycleError::new(LifecycleErrorReason::ClockRollback));
    }

    validate_transition_evidence(&record, event, updated_at, evidence)?;
    let prior_state = record.state;
    let next = next_state(&record, event, retry_authorized)?;
    record.resume_state = next_resume_state(&record, prior_state, event);
    record.failed_from = next_failed_from(&record, prior_state, event);
    record.state = next;
    record.updated_at = updated_at;
    record.last_event = Some(event);
    record.last_evidence = evidence.cloned();

    Ok(record)
}

/// Check the structural successor persisted by an already-authorized writer.
///
/// Storage adapters cannot reconstruct a consumed reconciliation capability.
/// This check validates the exact state/evidence edge, including the preserved
/// resume state. It grants no authority and returns no transition capability;
/// authentication and reconciliation remain the runtime/provider's duty.
pub fn validate_wallet_lifecycle_successor(
    current: &WalletLifecycleRecord,
    successor: &WalletLifecycleRecord,
    evidence: &WalletLifecycleEvidenceRecord,
) -> LifecycleResult<()> {
    let expected = apply_event(
        current.clone(),
        evidence.event,
        successor.updated_at(),
        Some(evidence),
        crate::is_wallet_lifecycle_retry(current, evidence.event),
    )?;
    if expected != *successor {
        return Err(LifecycleError::new(LifecycleErrorReason::InvalidTransition));
    }
    Ok(())
}

fn next_state(
    record: &WalletLifecycleRecord,
    event: WalletLifecycleEvent,
    retry_authorized: bool,
) -> LifecycleResult<WalletLifecycleState> {
    let state = record.state;
    match (state, event) {
        (WalletLifecycleState::Failed, WalletLifecycleEvent::BeginRecovery)
            if retry_authorized
                && record.failed_from == Some(WalletLifecycleState::RecoveryPending) =>
        {
            Ok(WalletLifecycleState::RecoveryPending)
        }
        (WalletLifecycleState::Failed, WalletLifecycleEvent::BeginMigration)
            if retry_authorized
                && record.failed_from == Some(WalletLifecycleState::MigrationPending) =>
        {
            Ok(WalletLifecycleState::MigrationPending)
        }
        (WalletLifecycleState::Unprovisioned, WalletLifecycleEvent::BeginProvisioning) => {
            Ok(WalletLifecycleState::Provisioning)
        }
        (WalletLifecycleState::Provisioning, WalletLifecycleEvent::CompleteProvisioning) => {
            Ok(WalletLifecycleState::Active)
        }
        (WalletLifecycleState::Provisioning, WalletLifecycleEvent::MarkFailed)
        | (WalletLifecycleState::RecoveryPending, WalletLifecycleEvent::MarkFailed)
        | (WalletLifecycleState::MigrationPending, WalletLifecycleEvent::MarkFailed)
        | (WalletLifecycleState::WithdrawalPending, WalletLifecycleEvent::MarkFailed)
        | (WalletLifecycleState::DeletionPending, WalletLifecycleEvent::MarkFailed) => {
            Ok(WalletLifecycleState::Failed)
        }
        (WalletLifecycleState::Failed, WalletLifecycleEvent::RetryProvisioning)
            if record.failed_from == Some(WalletLifecycleState::Provisioning) =>
        {
            Ok(WalletLifecycleState::Provisioning)
        }
        (WalletLifecycleState::Active, WalletLifecycleEvent::Suspend) => {
            Ok(WalletLifecycleState::Suspended)
        }
        (WalletLifecycleState::Suspended, WalletLifecycleEvent::Reactivate) => {
            Ok(WalletLifecycleState::Active)
        }
        (
            WalletLifecycleState::Active | WalletLifecycleState::Suspended,
            WalletLifecycleEvent::BeginRecovery,
        ) => Ok(WalletLifecycleState::RecoveryPending),
        (WalletLifecycleState::RecoveryPending, WalletLifecycleEvent::CompleteRecovery) => record
            .resume_state
            .filter(|state| {
                matches!(
                    state,
                    WalletLifecycleState::Active | WalletLifecycleState::Suspended
                )
            })
            .ok_or_else(|| LifecycleError::new(LifecycleErrorReason::InvalidTransition)),
        (
            WalletLifecycleState::Active | WalletLifecycleState::Suspended,
            WalletLifecycleEvent::BeginMigration,
        ) => Ok(WalletLifecycleState::MigrationPending),
        (WalletLifecycleState::MigrationPending, WalletLifecycleEvent::CompleteMigration) => record
            .resume_state
            .filter(|state| {
                matches!(
                    state,
                    WalletLifecycleState::Active | WalletLifecycleState::Suspended
                )
            })
            .ok_or_else(|| LifecycleError::new(LifecycleErrorReason::InvalidTransition)),
        (
            WalletLifecycleState::Active
            | WalletLifecycleState::Suspended
            | WalletLifecycleState::RecoveryPending
            | WalletLifecycleState::MigrationPending,
            WalletLifecycleEvent::BeginWithdrawal,
        ) => Ok(WalletLifecycleState::WithdrawalPending),
        // A failed withdrawal may be retried, and a failed recovery or
        // migration may be abandoned by withdrawing instead of only deleting.
        (WalletLifecycleState::Failed, WalletLifecycleEvent::BeginWithdrawal)
            if matches!(
                record.failed_from,
                Some(
                    WalletLifecycleState::WithdrawalPending
                        | WalletLifecycleState::RecoveryPending
                        | WalletLifecycleState::MigrationPending
                )
            ) =>
        {
            Ok(WalletLifecycleState::WithdrawalPending)
        }
        (WalletLifecycleState::WithdrawalPending, WalletLifecycleEvent::CompleteWithdrawal) => {
            Ok(WalletLifecycleState::Withdrawn)
        }
        (
            WalletLifecycleState::Unprovisioned
            | WalletLifecycleState::Provisioning
            | WalletLifecycleState::Active
            | WalletLifecycleState::Suspended
            | WalletLifecycleState::RecoveryPending
            | WalletLifecycleState::MigrationPending
            | WalletLifecycleState::WithdrawalPending
            | WalletLifecycleState::Withdrawn
            | WalletLifecycleState::Failed,
            WalletLifecycleEvent::BeginDeletion,
        ) => Ok(WalletLifecycleState::DeletionPending),
        (WalletLifecycleState::DeletionPending, WalletLifecycleEvent::CompleteDeletion) => {
            Ok(WalletLifecycleState::Deleted)
        }
        _ => Err(LifecycleError::new(LifecycleErrorReason::InvalidTransition)),
    }
}

fn validate_transition_evidence(
    record: &WalletLifecycleRecord,
    event: WalletLifecycleEvent,
    updated_at: UnixTimestamp,
    evidence: Option<&WalletLifecycleEvidenceRecord>,
) -> LifecycleResult<()> {
    let evidence =
        evidence.ok_or_else(|| LifecycleError::new(LifecycleErrorReason::InvalidEvidence))?;
    validate_wallet_lifecycle_evidence_record(evidence)?;
    // Reject an immediate replay before storage. The store also checks the
    // complete evidence history atomically with the state replacement.
    if evidence.wallet_instance_id != record.wallet_instance_id
        || evidence.event != event
        || evidence.occurred_at != updated_at
        || record
            .last_evidence
            .as_ref()
            .is_some_and(|last| last.id == evidence.id)
        || expected_failure_evidence_kind(record, event)
            .is_some_and(|expected| evidence.kind != expected)
    {
        return Err(LifecycleError::new(LifecycleErrorReason::InvalidEvidence));
    }
    Ok(())
}

fn expected_failure_evidence_kind(
    record: &WalletLifecycleRecord,
    event: WalletLifecycleEvent,
) -> Option<crate::WalletLifecycleEvidenceKind> {
    use crate::WalletLifecycleEvidenceKind;

    match event {
        WalletLifecycleEvent::RetryProvisioning => Some(WalletLifecycleEvidenceKind::Provisioning),
        WalletLifecycleEvent::MarkFailed => failure_evidence_kind_for_state(record.state),
        WalletLifecycleEvent::BeginProvisioning
        | WalletLifecycleEvent::CompleteProvisioning
        | WalletLifecycleEvent::Suspend
        | WalletLifecycleEvent::Reactivate
        | WalletLifecycleEvent::BeginRecovery
        | WalletLifecycleEvent::CompleteRecovery
        | WalletLifecycleEvent::BeginMigration
        | WalletLifecycleEvent::CompleteMigration
        | WalletLifecycleEvent::BeginWithdrawal
        | WalletLifecycleEvent::CompleteWithdrawal
        | WalletLifecycleEvent::BeginDeletion
        | WalletLifecycleEvent::CompleteDeletion => None,
    }
}

fn failure_evidence_kind_for_state(
    state: WalletLifecycleState,
) -> Option<crate::WalletLifecycleEvidenceKind> {
    use crate::WalletLifecycleEvidenceKind;

    match state {
        WalletLifecycleState::Provisioning => Some(WalletLifecycleEvidenceKind::Provisioning),
        WalletLifecycleState::RecoveryPending => Some(WalletLifecycleEvidenceKind::Recovery),
        WalletLifecycleState::MigrationPending => Some(WalletLifecycleEvidenceKind::Migration),
        WalletLifecycleState::WithdrawalPending => Some(WalletLifecycleEvidenceKind::Withdrawal),
        WalletLifecycleState::DeletionPending => Some(WalletLifecycleEvidenceKind::Deletion),
        _ => None,
    }
}

fn next_resume_state(
    record: &WalletLifecycleRecord,
    prior_state: WalletLifecycleState,
    event: WalletLifecycleEvent,
) -> Option<WalletLifecycleState> {
    match event {
        WalletLifecycleEvent::BeginRecovery | WalletLifecycleEvent::BeginMigration => {
            if prior_state == WalletLifecycleState::Failed {
                record.resume_state
            } else {
                Some(prior_state)
            }
        }
        WalletLifecycleEvent::MarkFailed => record.resume_state,
        _ => None,
    }
}

fn next_failed_from(
    record: &WalletLifecycleRecord,
    prior_state: WalletLifecycleState,
    event: WalletLifecycleEvent,
) -> Option<WalletLifecycleState> {
    match event {
        WalletLifecycleEvent::MarkFailed => Some(prior_state),
        _ if record.state == WalletLifecycleState::Failed => None,
        _ => record.failed_from,
    }
}

#[cfg(test)]
#[path = "transition_tests.rs"]
mod tests;
