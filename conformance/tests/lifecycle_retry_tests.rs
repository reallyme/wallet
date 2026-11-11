// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Independent decision vectors for failed-operation retry authorization.

use reallyme_wallet::lifecycle::{
    apply_reconciled_wallet_lifecycle_retry, apply_wallet_lifecycle_event,
    restore_wallet_lifecycle, validate_wallet_lifecycle_successor, LifecycleError,
    LifecycleErrorReason, ReconciledWalletLifecycleRetry, WalletLifecycleEvent,
    WalletLifecycleEvidenceKind, WalletLifecycleEvidenceRecord, WalletLifecycleState,
};
use reallyme_wallet::types::{NonEmptyIdentifier, UnixTimestamp, WalletTypesError};
use serde_json::Value;
use thiserror::Error;

#[test]
fn retry_vectors_require_reconciliation_and_preserve_resume_state() -> Result<(), VectorError> {
    let fixture: Value = serde_json::from_str(include_str!(
        "../fixtures/lifecycle/reconciled-retries.json"
    ))
    .map_err(|_| VectorError::InvalidVector)?;
    if fixture["schema_version"] != 1 {
        return Err(VectorError::InvalidVector);
    }
    let failure_at = timestamp(
        fixture["failure_at"]
            .as_i64()
            .ok_or(VectorError::InvalidVector)?,
    )?;
    let retry_at = timestamp(
        fixture["retry_at"]
            .as_i64()
            .ok_or(VectorError::InvalidVector)?,
    )?;
    let cases = fixture["cases"]
        .as_array()
        .ok_or(VectorError::InvalidVector)?;
    if cases.len() != 8 {
        return Err(VectorError::InvalidVector);
    }
    for case in cases {
        let (event, kind, pending) = match text(case, "operation")? {
            "recovery" => (
                WalletLifecycleEvent::BeginRecovery,
                WalletLifecycleEvidenceKind::Recovery,
                WalletLifecycleState::RecoveryPending,
            ),
            "migration" => (
                WalletLifecycleEvent::BeginMigration,
                WalletLifecycleEvidenceKind::Migration,
                WalletLifecycleState::MigrationPending,
            ),
            _ => return Err(VectorError::InvalidVector),
        };
        let resume = match text(case, "resume_state")? {
            "active" => WalletLifecycleState::Active,
            "suspended" => WalletLifecycleState::Suspended,
            _ => return Err(VectorError::InvalidVector),
        };
        let mut evidence = WalletLifecycleEvidenceRecord {
            id: NonEmptyIdentifier::new("failure".into())?,
            wallet_instance_id: NonEmptyIdentifier::new("wallet-unit".into())?,
            kind,
            event: WalletLifecycleEvent::MarkFailed,
            occurred_at: failure_at,
            authority_id: NonEmptyIdentifier::new("provider".into())?,
            evidence_ref: NonEmptyIdentifier::new("provider-operation".into())?,
            evidence_digest: vec![1; 32],
        };
        let failed = restore_wallet_lifecycle(
            evidence.wallet_instance_id.clone(),
            WalletLifecycleState::Failed,
            failure_at,
            Some(evidence.event),
            Some(resume),
            Some(pending),
            Some(evidence.clone()),
        )?;
        evidence.id = NonEmptyIdentifier::new("retry".into())?;
        evidence.event = event;
        evidence.occurred_at = retry_at;
        evidence.evidence_digest = vec![2; 32];
        let now = timestamp(
            case["observed_at"]
                .as_i64()
                .ok_or(VectorError::InvalidVector)?,
        )?;
        let authorized = case["authorized"]
            .as_bool()
            .ok_or(VectorError::InvalidVector)?;
        let outcome = if authorized {
            ReconciledWalletLifecycleRetry::new(failed.clone(), evidence.clone(), now).and_then(
                |receipt| {
                    apply_reconciled_wallet_lifecycle_retry(failed.clone(), &evidence, receipt, now)
                },
            )
        } else {
            apply_wallet_lifecycle_event(failed.clone(), event, retry_at, Some(&evidence))
        };
        match (text(case, "expected")?, outcome) {
            (expected @ ("recovery_pending" | "migration_pending"), Ok(next)) => {
                let expected_pending = if expected == "recovery_pending" {
                    WalletLifecycleState::RecoveryPending
                } else {
                    WalletLifecycleState::MigrationPending
                };
                if next.state() != expected_pending
                    || next.resume_state() != Some(resume)
                    || next.failed_from().is_some()
                {
                    return Err(VectorError::Outcome);
                }
                validate_wallet_lifecycle_successor(&failed, &next, &evidence)?;
            }
            ("invalid_evidence", Err(error))
                if error.reason == LifecycleErrorReason::InvalidEvidence => {}
            ("invalid_transition", Err(error))
                if error.reason == LifecycleErrorReason::InvalidTransition => {}
            _ => return Err(VectorError::Outcome),
        }
    }
    Ok(())
}

fn timestamp(seconds: i64) -> Result<UnixTimestamp, WalletTypesError> {
    UnixTimestamp::from_seconds(seconds)
}
fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str, VectorError> {
    value[field].as_str().ok_or(VectorError::InvalidVector)
}
#[derive(Debug, Error)]
enum VectorError {
    #[error("invalid_vector")]
    InvalidVector,
    #[error("outcome")]
    Outcome,
    #[error("wallet_types")]
    Types(#[from] WalletTypesError),
    #[error("lifecycle")]
    Lifecycle(#[from] LifecycleError),
}
