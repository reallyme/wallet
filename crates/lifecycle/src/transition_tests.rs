// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    apply_wallet_lifecycle_event as apply_event_with_evidence, ensure_wallet_operation_allowed,
    new_wallet_lifecycle, restore_wallet_lifecycle, LifecycleError, LifecycleErrorReason,
    LifecycleResult, WalletLifecycleEvent, WalletLifecycleEvidenceKind,
    WalletLifecycleEvidenceRecord, WalletLifecycleRecord, WalletLifecycleState, WalletOperation,
};
use reallyme_wallet_types::{NonEmptyIdentifier, UnixTimestamp, WalletTypesError};

#[path = "retry_tests.rs"]
mod retry_tests;

#[derive(Debug)]
enum TestError {
    Lifecycle,
    Types,
}

impl From<LifecycleError> for TestError {
    fn from(_error: LifecycleError) -> Self {
        Self::Lifecycle
    }
}

impl From<WalletTypesError> for TestError {
    fn from(_error: WalletTypesError) -> Self {
        Self::Types
    }
}

fn wallet_id() -> Result<NonEmptyIdentifier, WalletTypesError> {
    NonEmptyIdentifier::new("wallet-unit-1".to_owned())
}

fn timestamp(seconds: i64) -> Result<UnixTimestamp, WalletTypesError> {
    UnixTimestamp::from_seconds(seconds)
}

fn apply_wallet_lifecycle_event(
    record: WalletLifecycleRecord,
    event: WalletLifecycleEvent,
    updated_at: UnixTimestamp,
) -> LifecycleResult<WalletLifecycleRecord> {
    let kind = match event {
        WalletLifecycleEvent::BeginProvisioning | WalletLifecycleEvent::CompleteProvisioning => {
            WalletLifecycleEvidenceKind::Provisioning
        }
        WalletLifecycleEvent::Suspend => WalletLifecycleEvidenceKind::Suspension,
        WalletLifecycleEvent::Reactivate => WalletLifecycleEvidenceKind::Reactivation,
        WalletLifecycleEvent::BeginRecovery | WalletLifecycleEvent::CompleteRecovery => {
            WalletLifecycleEvidenceKind::Recovery
        }
        WalletLifecycleEvent::BeginMigration | WalletLifecycleEvent::CompleteMigration => {
            WalletLifecycleEvidenceKind::Migration
        }
        WalletLifecycleEvent::BeginWithdrawal | WalletLifecycleEvent::CompleteWithdrawal => {
            WalletLifecycleEvidenceKind::Withdrawal
        }
        WalletLifecycleEvent::BeginDeletion | WalletLifecycleEvent::CompleteDeletion => {
            WalletLifecycleEvidenceKind::Deletion
        }
        WalletLifecycleEvent::RetryProvisioning => WalletLifecycleEvidenceKind::Provisioning,
        WalletLifecycleEvent::MarkFailed => match record.state() {
            WalletLifecycleState::Provisioning => WalletLifecycleEvidenceKind::Provisioning,
            WalletLifecycleState::RecoveryPending => WalletLifecycleEvidenceKind::Recovery,
            WalletLifecycleState::MigrationPending => WalletLifecycleEvidenceKind::Migration,
            WalletLifecycleState::WithdrawalPending => WalletLifecycleEvidenceKind::Withdrawal,
            WalletLifecycleState::DeletionPending => WalletLifecycleEvidenceKind::Deletion,
            _ => return Err(LifecycleError::new(LifecycleErrorReason::InvalidEvidence)),
        },
    };
    let evidence = WalletLifecycleEvidenceRecord {
        id: NonEmptyIdentifier::new(format!("evidence-{event:?}-{}", updated_at.as_seconds()))
            .map_err(|_| LifecycleError::new(LifecycleErrorReason::InvalidEvidence))?,
        wallet_instance_id: record.wallet_instance_id.clone(),
        kind,
        event,
        occurred_at: updated_at,
        authority_id: NonEmptyIdentifier::new("provider-1".to_owned())
            .map_err(|_| LifecycleError::new(LifecycleErrorReason::InvalidEvidence))?,
        evidence_ref: NonEmptyIdentifier::new("reference-1".to_owned())
            .map_err(|_| LifecycleError::new(LifecycleErrorReason::InvalidEvidence))?,
        evidence_digest: vec![1],
    };
    apply_event_with_evidence(record, event, updated_at, Some(&evidence))
}

fn active_record() -> Result<WalletLifecycleRecord, TestError> {
    let record = new_wallet_lifecycle(wallet_id()?, timestamp(1)?);
    let record = apply_wallet_lifecycle_event(
        record,
        WalletLifecycleEvent::BeginProvisioning,
        timestamp(2)?,
    )?;

    Ok(apply_wallet_lifecycle_event(
        record,
        WalletLifecycleEvent::CompleteProvisioning,
        timestamp(3)?,
    )?)
}

#[test]
fn starts_unprovisioned() -> Result<(), TestError> {
    let record = new_wallet_lifecycle(wallet_id()?, timestamp(1)?);

    assert_eq!(record.state, WalletLifecycleState::Unprovisioned);
    assert_eq!(record.last_event, None);

    Ok(())
}

#[test]
fn provisions_into_active_state() -> Result<(), TestError> {
    let record = active_record()?;

    assert_eq!(record.state, WalletLifecycleState::Active);
    assert_eq!(
        record.last_event,
        Some(WalletLifecycleEvent::CompleteProvisioning)
    );

    Ok(())
}

#[test]
fn rejects_duplicate_provisioning_start() -> Result<(), TestError> {
    let record = active_record()?;
    let result = apply_wallet_lifecycle_event(
        record,
        WalletLifecycleEvent::BeginProvisioning,
        timestamp(4)?,
    );

    assert!(matches!(
        result,
        Err(error) if error.reason == LifecycleErrorReason::InvalidTransition
    ));

    Ok(())
}

#[test]
fn rejects_clock_rollback() -> Result<(), TestError> {
    let record = active_record()?;
    let result = apply_wallet_lifecycle_event(record, WalletLifecycleEvent::Suspend, timestamp(2)?);

    assert!(matches!(
        result,
        Err(error) if error.reason == LifecycleErrorReason::ClockRollback
    ));

    Ok(())
}

#[test]
fn suspended_wallet_blocks_presentation_and_signing() -> Result<(), TestError> {
    let record = apply_wallet_lifecycle_event(
        active_record()?,
        WalletLifecycleEvent::Suspend,
        timestamp(4)?,
    )?;

    assert!(matches!(
        ensure_wallet_operation_allowed(&record, WalletOperation::PresentCredential),
        Err(error) if error.reason == LifecycleErrorReason::WalletNotActive
    ));
    assert!(matches!(
        ensure_wallet_operation_allowed(&record, WalletOperation::SignWithWalletKey),
        Err(error) if error.reason == LifecycleErrorReason::WalletNotActive
    ));
    assert!(
        ensure_wallet_operation_allowed(&record, WalletOperation::ReadTransactionHistory).is_ok()
    );
    assert!(ensure_wallet_operation_allowed(&record, WalletOperation::ReadWalletRecords).is_ok());

    Ok(())
}

#[test]
fn withdrawal_is_terminal_for_regulated_actions() -> Result<(), TestError> {
    let record = apply_wallet_lifecycle_event(
        active_record()?,
        WalletLifecycleEvent::BeginWithdrawal,
        timestamp(4)?,
    )?;
    let record = apply_wallet_lifecycle_event(
        record,
        WalletLifecycleEvent::CompleteWithdrawal,
        timestamp(5)?,
    )?;

    assert!(matches!(
        ensure_wallet_operation_allowed(&record, WalletOperation::BeginIssuance),
        Err(error) if error.reason == LifecycleErrorReason::WalletWithdrawn
    ));
    assert!(matches!(
        ensure_wallet_operation_allowed(&record, WalletOperation::PresentCredential),
        Err(error) if error.reason == LifecycleErrorReason::WalletWithdrawn
    ));
    assert!(matches!(
        ensure_wallet_operation_allowed(&record, WalletOperation::SignWithWalletKey),
        Err(error) if error.reason == LifecycleErrorReason::WalletWithdrawn
    ));
    assert!(matches!(
        ensure_wallet_operation_allowed(&record, WalletOperation::ReadWalletRecords),
        Err(error) if error.reason == LifecycleErrorReason::WalletWithdrawn
    ));

    Ok(())
}

#[test]
fn deletion_is_terminal_for_regulated_actions() -> Result<(), TestError> {
    let record = apply_wallet_lifecycle_event(
        active_record()?,
        WalletLifecycleEvent::BeginDeletion,
        timestamp(4)?,
    )?;
    let record = apply_wallet_lifecycle_event(
        record,
        WalletLifecycleEvent::CompleteDeletion,
        timestamp(5)?,
    )?;

    assert!(matches!(
        ensure_wallet_operation_allowed(&record, WalletOperation::BeginIssuance),
        Err(error) if error.reason == LifecycleErrorReason::WalletDeleted
    ));
    assert!(matches!(
        ensure_wallet_operation_allowed(&record, WalletOperation::PresentCredential),
        Err(error) if error.reason == LifecycleErrorReason::WalletDeleted
    ));
    assert!(matches!(
        ensure_wallet_operation_allowed(&record, WalletOperation::SignWithWalletKey),
        Err(error) if error.reason == LifecycleErrorReason::WalletDeleted
    ));
    assert!(matches!(
        ensure_wallet_operation_allowed(&record, WalletOperation::ReadWalletRecords),
        Err(error) if error.reason == LifecycleErrorReason::WalletDeleted
    ));

    Ok(())
}

#[test]
fn withdrawal_and_deletion_close_records_before_they_complete() -> Result<(), TestError> {
    let withdrawing = apply_wallet_lifecycle_event(
        active_record()?,
        WalletLifecycleEvent::BeginWithdrawal,
        timestamp(4)?,
    )?;
    assert!(matches!(
        ensure_wallet_operation_allowed(&withdrawing, WalletOperation::ReadWalletRecords),
        Err(error) if error.reason == LifecycleErrorReason::WalletNotActive
    ));
    let withdrawn = apply_wallet_lifecycle_event(
        withdrawing,
        WalletLifecycleEvent::CompleteWithdrawal,
        timestamp(5)?,
    )?;
    assert!(matches!(
        ensure_wallet_operation_allowed(&withdrawn, WalletOperation::RecordTransactionHistory),
        Err(error) if error.reason == LifecycleErrorReason::WalletWithdrawn
    ));

    let deleting = apply_wallet_lifecycle_event(
        withdrawn,
        WalletLifecycleEvent::BeginDeletion,
        timestamp(6)?,
    )?;
    assert!(matches!(
        ensure_wallet_operation_allowed(&deleting, WalletOperation::ReadWalletRecords),
        Err(error) if error.reason == LifecycleErrorReason::WalletNotActive
    ));
    assert!(
        ensure_wallet_operation_allowed(&deleting, WalletOperation::ReadTransactionHistory).is_ok()
    );
    let deleted = apply_wallet_lifecycle_event(
        deleting,
        WalletLifecycleEvent::CompleteDeletion,
        timestamp(7)?,
    )?;
    assert!(matches!(
        ensure_wallet_operation_allowed(&deleted, WalletOperation::RecordTransactionHistory),
        Err(error) if error.reason == LifecycleErrorReason::WalletDeleted
    ));
    Ok(())
}

#[test]
fn failed_provisioning_can_retry() -> Result<(), TestError> {
    let record = new_wallet_lifecycle(wallet_id()?, timestamp(1)?);
    let record = apply_wallet_lifecycle_event(
        record,
        WalletLifecycleEvent::BeginProvisioning,
        timestamp(2)?,
    )?;
    let record =
        apply_wallet_lifecycle_event(record, WalletLifecycleEvent::MarkFailed, timestamp(3)?)?;
    let record = apply_wallet_lifecycle_event(
        record,
        WalletLifecycleEvent::RetryProvisioning,
        timestamp(4)?,
    )?;

    assert_eq!(record.state, WalletLifecycleState::Provisioning);

    Ok(())
}

#[test]
fn withdrawal_failure_cannot_retry_provisioning() -> Result<(), TestError> {
    let record = apply_wallet_lifecycle_event(
        active_record()?,
        WalletLifecycleEvent::BeginWithdrawal,
        timestamp(4)?,
    )?;
    let record =
        apply_wallet_lifecycle_event(record, WalletLifecycleEvent::MarkFailed, timestamp(5)?)?;

    let result = apply_wallet_lifecycle_event(
        record,
        WalletLifecycleEvent::RetryProvisioning,
        timestamp(6)?,
    );

    assert!(matches!(
        result,
        Err(error) if error.reason == LifecycleErrorReason::InvalidTransition
    ));
    Ok(())
}

#[test]
fn deletion_failure_cannot_be_changed_into_withdrawal() -> Result<(), TestError> {
    let record = apply_wallet_lifecycle_event(
        active_record()?,
        WalletLifecycleEvent::BeginDeletion,
        timestamp(4)?,
    )?;
    let record =
        apply_wallet_lifecycle_event(record, WalletLifecycleEvent::MarkFailed, timestamp(5)?)?;

    let withdrawal = apply_wallet_lifecycle_event(
        record.clone(),
        WalletLifecycleEvent::BeginWithdrawal,
        timestamp(6)?,
    );
    assert!(matches!(
        withdrawal,
        Err(error) if error.reason == LifecycleErrorReason::InvalidTransition
    ));

    let deletion =
        apply_wallet_lifecycle_event(record, WalletLifecycleEvent::BeginDeletion, timestamp(6)?)?;
    assert_eq!(deletion.state(), WalletLifecycleState::DeletionPending);
    Ok(())
}

#[test]
fn recovery_preserves_suspended_state() -> Result<(), TestError> {
    let record = apply_wallet_lifecycle_event(
        active_record()?,
        WalletLifecycleEvent::Suspend,
        timestamp(4)?,
    )?;
    let record =
        apply_wallet_lifecycle_event(record, WalletLifecycleEvent::BeginRecovery, timestamp(5)?)?;
    let record = apply_wallet_lifecycle_event(
        record,
        WalletLifecycleEvent::CompleteRecovery,
        timestamp(6)?,
    )?;

    assert_eq!(record.state(), WalletLifecycleState::Suspended);
    Ok(())
}

#[test]
fn restore_rejects_state_event_resurrection() -> Result<(), TestError> {
    let evidence = WalletLifecycleEvidenceRecord {
        id: NonEmptyIdentifier::new("evidence-restore".to_owned())?,
        wallet_instance_id: wallet_id()?,
        kind: WalletLifecycleEvidenceKind::Withdrawal,
        event: WalletLifecycleEvent::CompleteWithdrawal,
        occurred_at: timestamp(5)?,
        authority_id: NonEmptyIdentifier::new("provider-1".to_owned())?,
        evidence_ref: NonEmptyIdentifier::new("reference-restore".to_owned())?,
        evidence_digest: vec![1],
    };
    let result = restore_wallet_lifecycle(
        wallet_id()?,
        WalletLifecycleState::Active,
        timestamp(5)?,
        Some(WalletLifecycleEvent::CompleteWithdrawal),
        None,
        None,
        Some(evidence),
    );

    assert!(matches!(
        result,
        Err(error) if error.reason == LifecycleErrorReason::InvalidTransition
    ));
    Ok(())
}

#[test]
fn restore_rejects_failed_state_with_evidence_from_another_stage() -> Result<(), TestError> {
    let evidence = WalletLifecycleEvidenceRecord {
        id: NonEmptyIdentifier::new("evidence-failed".to_owned())?,
        wallet_instance_id: wallet_id()?,
        kind: WalletLifecycleEvidenceKind::Provisioning,
        event: WalletLifecycleEvent::MarkFailed,
        occurred_at: timestamp(5)?,
        authority_id: NonEmptyIdentifier::new("provider-1".to_owned())?,
        evidence_ref: NonEmptyIdentifier::new("reference-failed".to_owned())?,
        evidence_digest: vec![1],
    };
    let result = restore_wallet_lifecycle(
        wallet_id()?,
        WalletLifecycleState::Failed,
        timestamp(5)?,
        Some(WalletLifecycleEvent::MarkFailed),
        None,
        Some(WalletLifecycleState::DeletionPending),
        Some(evidence),
    );

    assert!(matches!(
        result,
        Err(error) if error.reason == LifecycleErrorReason::InvalidEvidence
    ));
    Ok(())
}

#[test]
fn evidence_that_produced_the_current_state_cannot_be_replayed() -> Result<(), TestError> {
    let suspended = apply_wallet_lifecycle_event(
        active_record()?,
        WalletLifecycleEvent::Suspend,
        timestamp(4)?,
    )?;
    let reused = suspended
        .last_evidence()
        .cloned()
        .ok_or(LifecycleError::new(LifecycleErrorReason::InvalidEvidence))?;
    let mut reactivation = reused.clone();
    reactivation.event = WalletLifecycleEvent::Reactivate;
    reactivation.kind = WalletLifecycleEvidenceKind::Reactivation;
    reactivation.occurred_at = timestamp(5)?;
    assert!(matches!(
        apply_event_with_evidence(
            suspended,
            WalletLifecycleEvent::Reactivate,
            timestamp(5)?,
            Some(&reactivation),
        ),
        Err(error) if error.reason == LifecycleErrorReason::InvalidEvidence
    ));
    Ok(())
}

#[test]
fn older_evidence_cannot_move_the_clock_backwards() -> Result<(), TestError> {
    let suspended = apply_wallet_lifecycle_event(
        active_record()?,
        WalletLifecycleEvent::Suspend,
        timestamp(4)?,
    )?;
    let first_suspension = suspended
        .last_evidence()
        .cloned()
        .ok_or(LifecycleError::new(LifecycleErrorReason::InvalidEvidence))?;
    // The cycle cannot close within one second, and the old suspension
    // evidence cannot be reused later either: its time no longer matches.
    let reactivated =
        apply_wallet_lifecycle_event(suspended, WalletLifecycleEvent::Reactivate, timestamp(5)?)?;
    assert!(matches!(
        apply_event_with_evidence(
            reactivated,
            WalletLifecycleEvent::Suspend,
            timestamp(6)?,
            Some(&first_suspension),
        ),
        Err(error) if error.reason == LifecycleErrorReason::InvalidEvidence
    ));
    Ok(())
}

#[test]
fn distinct_authorized_transitions_may_share_a_clock_second() -> Result<(), TestError> {
    let suspended = apply_wallet_lifecycle_event(
        active_record()?,
        WalletLifecycleEvent::Suspend,
        timestamp(4)?,
    )?;
    let suspension_id = suspended
        .last_evidence()
        .ok_or(LifecycleError::new(LifecycleErrorReason::InvalidEvidence))?
        .id
        .clone();
    let active =
        apply_wallet_lifecycle_event(suspended, WalletLifecycleEvent::Reactivate, timestamp(4)?)?;
    assert_eq!(active.state(), WalletLifecycleState::Active);
    assert_eq!(active.updated_at(), timestamp(4)?);
    assert_ne!(
        &suspension_id,
        &active
            .last_evidence()
            .ok_or(LifecycleError::new(LifecycleErrorReason::InvalidEvidence))?
            .id
    );
    Ok(())
}

#[test]
fn failed_recovery_can_be_abandoned_by_withdrawal() -> Result<(), TestError> {
    let record = apply_wallet_lifecycle_event(
        active_record()?,
        WalletLifecycleEvent::BeginRecovery,
        timestamp(4)?,
    )?;
    let failed =
        apply_wallet_lifecycle_event(record, WalletLifecycleEvent::MarkFailed, timestamp(5)?)?;
    let withdrawing =
        apply_wallet_lifecycle_event(failed, WalletLifecycleEvent::BeginWithdrawal, timestamp(6)?)?;
    assert_eq!(withdrawing.state(), WalletLifecycleState::WithdrawalPending);
    Ok(())
}

#[test]
fn completing_a_pending_operation_may_share_its_start_second() -> Result<(), TestError> {
    let record = new_wallet_lifecycle(wallet_id()?, timestamp(1)?);
    let record = apply_wallet_lifecycle_event(
        record,
        WalletLifecycleEvent::BeginProvisioning,
        timestamp(2)?,
    )?;
    let record = apply_wallet_lifecycle_event(
        record,
        WalletLifecycleEvent::CompleteProvisioning,
        timestamp(2)?,
    )?;
    assert_eq!(record.state(), WalletLifecycleState::Active);

    let record =
        apply_wallet_lifecycle_event(record, WalletLifecycleEvent::BeginDeletion, timestamp(3)?)?;
    let record = apply_wallet_lifecycle_event(
        record,
        WalletLifecycleEvent::CompleteDeletion,
        timestamp(3)?,
    )?;
    assert_eq!(record.state(), WalletLifecycleState::Deleted);
    Ok(())
}

#[test]
fn distinct_new_operations_accept_the_current_clock_second() -> Result<(), TestError> {
    let active = active_record()?;
    let at = active.updated_at();
    for (event, expected) in [
        (
            WalletLifecycleEvent::Suspend,
            WalletLifecycleState::Suspended,
        ),
        (
            WalletLifecycleEvent::BeginRecovery,
            WalletLifecycleState::RecoveryPending,
        ),
        (
            WalletLifecycleEvent::BeginDeletion,
            WalletLifecycleState::DeletionPending,
        ),
    ] {
        let transitioned = apply_wallet_lifecycle_event(active.clone(), event, at)?;
        assert_eq!(transitioned.state(), expected);
        assert_eq!(transitioned.updated_at(), at);
    }
    Ok(())
}
