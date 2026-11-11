// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    active_record, at, backend, evidence, lifecycle, AuthorityAnswer, ScriptedProvider, TestError,
    TimeAnswer, WalletLifecycleEvent, WalletLifecycleEvidenceKind, WalletRuntimeBackend,
};

fn failure() -> Result<lifecycle::WalletLifecycleRecord, TestError> {
    let begin = evidence(
        "begin-recovery",
        WalletLifecycleEvent::BeginRecovery,
        WalletLifecycleEvidenceKind::Recovery,
        110,
    )?;
    let pending = lifecycle::apply_wallet_lifecycle_event(
        active_record()?,
        begin.event,
        begin.occurred_at,
        Some(&begin),
    )?;
    let failed = evidence(
        "failed-recovery",
        WalletLifecycleEvent::MarkFailed,
        WalletLifecycleEvidenceKind::Recovery,
        111,
    )?;
    Ok(lifecycle::apply_wallet_lifecycle_event(
        pending,
        failed.event,
        failed.occurred_at,
        Some(&failed),
    )?)
}

#[test]
fn provider_rpc_requires_an_exact_reconciliation_receipt() -> Result<(), TestError> {
    let current = failure()?;
    let retry = evidence(
        "retry-recovery",
        WalletLifecycleEvent::BeginRecovery,
        WalletLifecycleEvidenceKind::Recovery,
        112,
    )?;
    let mut backend = backend(ScriptedProvider::new(
        TimeAnswer::Seconds(112),
        AuthorityAnswer::Reconciled,
    ))?;
    let receipt = backend
        .reconcile_wallet_lifecycle_retry(&current, retry.event, &retry, at(112)?)
        .map_err(|_| TestError::UnexpectedResult)?;
    let pending =
        lifecycle::apply_reconciled_wallet_lifecycle_retry(current, &retry, receipt, at(112)?)?;
    assert_eq!(
        pending.state(),
        lifecycle::WalletLifecycleState::RecoveryPending
    );
    assert_eq!(backend.transport().authority_requests.len(), 1);
    Ok(())
}

#[test]
fn ordinary_approval_and_malformed_or_substituted_receipts_do_not_authorize_retry(
) -> Result<(), TestError> {
    let current = failure()?;
    let retry = evidence(
        "retry-recovery",
        WalletLifecycleEvent::BeginRecovery,
        WalletLifecycleEvidenceKind::Recovery,
        112,
    )?;
    for answer in [
        AuthorityAnswer::Approve,
        AuthorityAnswer::Reject,
        AuthorityAnswer::WrongResult,
        AuthorityAnswer::InvalidReconciliation(0),
        AuthorityAnswer::InvalidReconciliation(1),
        AuthorityAnswer::InvalidReconciliation(2),
        AuthorityAnswer::InvalidReconciliation(3),
        AuthorityAnswer::InvalidReconciliation(4),
        AuthorityAnswer::InvalidReconciliation(5),
    ] {
        let mut backend = backend(ScriptedProvider::new(TimeAnswer::Seconds(112), answer))?;
        assert!(backend
            .reconcile_wallet_lifecycle_retry(&current, retry.event, &retry, at(112)?)
            .is_err());
    }
    Ok(())
}

#[test]
fn provider_clock_may_advance_during_reconciliation() -> Result<(), TestError> {
    let current = failure()?;
    let retry = evidence(
        "retry-recovery",
        WalletLifecycleEvent::BeginRecovery,
        WalletLifecycleEvidenceKind::Recovery,
        112,
    )?;
    let mut backend = backend(ScriptedProvider::new(
        TimeAnswer::Seconds(113),
        AuthorityAnswer::ReconciledLater,
    ))?;
    let receipt = backend
        .reconcile_wallet_lifecycle_retry(&current, retry.event, &retry, at(112)?)
        .map_err(|_| TestError::UnexpectedResult)?;
    assert!(
        lifecycle::apply_reconciled_wallet_lifecycle_retry(current, &retry, receipt, at(113)?)
            .is_ok()
    );
    Ok(())
}
