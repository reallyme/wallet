// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{active_record, apply_wallet_lifecycle_event, timestamp, TestError};
use crate::{
    apply_reconciled_wallet_lifecycle_retry, ensure_wallet_operation_allowed, LifecycleErrorReason,
    ReconciledWalletLifecycleRetry, WalletLifecycleEvent, WalletLifecycleEvidenceKind,
    WalletLifecycleEvidenceRecord, WalletLifecycleRecord, WalletLifecycleState, WalletOperation,
};
use reallyme_wallet_types::NonEmptyIdentifier;

fn failed(
    event: WalletLifecycleEvent,
    suspended: bool,
) -> Result<WalletLifecycleRecord, TestError> {
    let mut record = active_record()?;
    if suspended {
        record =
            apply_wallet_lifecycle_event(record, WalletLifecycleEvent::Suspend, timestamp(4)?)?;
    }
    let record = apply_wallet_lifecycle_event(record, event, timestamp(5)?)?;
    Ok(apply_wallet_lifecycle_event(
        record,
        WalletLifecycleEvent::MarkFailed,
        timestamp(6)?,
    )?)
}

fn retry_evidence(
    record: &WalletLifecycleRecord,
    event: WalletLifecycleEvent,
) -> Result<WalletLifecycleEvidenceRecord, TestError> {
    Ok(WalletLifecycleEvidenceRecord {
        id: NonEmptyIdentifier::new("fresh-retry".into())?,
        wallet_instance_id: record.wallet_instance_id().clone(),
        kind: if event == WalletLifecycleEvent::BeginRecovery {
            WalletLifecycleEvidenceKind::Recovery
        } else {
            WalletLifecycleEvidenceKind::Migration
        },
        event,
        occurred_at: timestamp(7)?,
        authority_id: NonEmptyIdentifier::new("provider-1".into())?,
        evidence_ref: NonEmptyIdentifier::new("reconciled-operation".into())?,
        evidence_digest: vec![2; 32],
    })
}

#[test]
fn reconciled_retries_preserve_active_and_suspended_state_until_completion() -> Result<(), TestError>
{
    for (begin, complete, pending) in [
        (
            WalletLifecycleEvent::BeginRecovery,
            WalletLifecycleEvent::CompleteRecovery,
            WalletLifecycleState::RecoveryPending,
        ),
        (
            WalletLifecycleEvent::BeginMigration,
            WalletLifecycleEvent::CompleteMigration,
            WalletLifecycleState::MigrationPending,
        ),
    ] {
        for suspended in [false, true] {
            let record = failed(begin, suspended)?;
            let evidence = retry_evidence(&record, begin)?;
            assert!(
                matches!(crate::apply_wallet_lifecycle_event(record.clone(), begin, timestamp(7)?, Some(&evidence)),
                Err(error) if error.reason == LifecycleErrorReason::InvalidTransition)
            );
            let receipt = ReconciledWalletLifecycleRetry::new(
                record.clone(),
                evidence.clone(),
                timestamp(7)?,
            )?;
            let retry =
                apply_reconciled_wallet_lifecycle_retry(record, &evidence, receipt, timestamp(7)?)?;
            assert_eq!(retry.state(), pending);
            assert_eq!(retry.failed_from(), None);
            assert!(
                ensure_wallet_operation_allowed(&retry, WalletOperation::SignWithWalletKey)
                    .is_err()
            );
            let prior = if suspended {
                WalletLifecycleState::Suspended
            } else {
                WalletLifecycleState::Active
            };
            assert_eq!(retry.resume_state(), Some(prior));
            let completed = apply_wallet_lifecycle_event(retry, complete, timestamp(8)?)?;
            assert_eq!(completed.state(), prior);
        }
    }
    Ok(())
}

#[test]
fn reconciliation_rejects_wrong_operation_stale_future_and_reused_evidence() -> Result<(), TestError>
{
    let record = failed(WalletLifecycleEvent::BeginRecovery, false)?;
    let valid = retry_evidence(&record, WalletLifecycleEvent::BeginRecovery)?;
    for mode in 0..6 {
        let mut evidence = valid.clone();
        let mut now = timestamp(7)?;
        match mode {
            0 => evidence = retry_evidence(&record, WalletLifecycleEvent::BeginMigration)?,
            1 => evidence.wallet_instance_id = NonEmptyIdentifier::new("another-wallet".into())?,
            2 => {
                evidence.id = record
                    .last_evidence()
                    .ok_or(TestError::Lifecycle)?
                    .id
                    .clone()
            }
            3 => evidence.occurred_at = timestamp(5)?,
            4 => evidence.occurred_at = timestamp(8)?,
            _ => now = timestamp(68)?,
        }
        assert!(
            matches!(ReconciledWalletLifecycleRetry::new(record.clone(), evidence, now),
            Err(error) if error.reason == LifecycleErrorReason::InvalidEvidence)
        );
    }
    Ok(())
}

#[test]
fn reconciliation_is_bound_to_predecessor_evidence_and_current_observation() -> Result<(), TestError>
{
    for mode in 0..3 {
        let record = failed(WalletLifecycleEvent::BeginRecovery, false)?;
        let evidence = retry_evidence(&record, WalletLifecycleEvent::BeginRecovery)?;
        let receipt =
            ReconciledWalletLifecycleRetry::new(record.clone(), evidence.clone(), timestamp(7)?)?;
        let mut presented_record = record;
        let mut presented_evidence = evidence;
        let mut now = timestamp(7)?;
        match mode {
            0 => presented_record = failed(WalletLifecycleEvent::BeginRecovery, true)?,
            1 => presented_evidence.evidence_digest = vec![3; 32],
            _ => now = timestamp(68)?,
        }
        assert!(
            matches!(apply_reconciled_wallet_lifecycle_retry(presented_record, &presented_evidence, receipt, now),
            Err(error) if error.reason == LifecycleErrorReason::InvalidEvidence)
        );
    }
    Ok(())
}

#[test]
fn fresh_reconciliation_can_finish_in_the_next_clock_second() -> Result<(), TestError> {
    let record = failed(WalletLifecycleEvent::BeginRecovery, false)?;
    let evidence = retry_evidence(&record, WalletLifecycleEvent::BeginRecovery)?;
    let receipt =
        ReconciledWalletLifecycleRetry::new(record.clone(), evidence.clone(), timestamp(7)?)?;
    assert!(
        apply_reconciled_wallet_lifecycle_retry(record, &evidence, receipt, timestamp(8)?).is_ok()
    );
    Ok(())
}

#[test]
fn storage_consistency_validation_refuses_a_changed_resume_state() -> Result<(), TestError> {
    let record = failed(WalletLifecycleEvent::BeginRecovery, true)?;
    let evidence = retry_evidence(&record, WalletLifecycleEvent::BeginRecovery)?;
    let receipt =
        ReconciledWalletLifecycleRetry::new(record.clone(), evidence.clone(), timestamp(7)?)?;
    let mut next =
        apply_reconciled_wallet_lifecycle_retry(record.clone(), &evidence, receipt, timestamp(7)?)?;
    crate::validate_wallet_lifecycle_successor(&record, &next, &evidence)?;
    next.resume_state = Some(WalletLifecycleState::Active);
    assert!(
        matches!(crate::validate_wallet_lifecycle_successor(&record, &next, &evidence),
        Err(error) if error.reason == LifecycleErrorReason::InvalidTransition)
    );
    Ok(())
}
