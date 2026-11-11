// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    lifecycle, mutating_operation_request, pb, wallet, wallet_lifecycle_evidence_record,
    wallet_lifecycle_evidence_record_to_proto, EnumValue, MemoryBackend, MessageField,
    RecordRevision, RuntimeError, RuntimeErrorReason, TestError, WalletCoreRuntime,
    WalletRuntimeBackend,
};

fn failed_backend(migration: bool, suspended: bool) -> Result<MemoryBackend, TestError> {
    let mut evidence = wallet_lifecycle_evidence_record()?;
    evidence.id = wallet::NonEmptyIdentifier::new("failure-1".into())?;
    evidence.event = lifecycle::WalletLifecycleEvent::MarkFailed;
    evidence.kind = if migration {
        lifecycle::WalletLifecycleEvidenceKind::Migration
    } else {
        lifecycle::WalletLifecycleEvidenceKind::Recovery
    };
    evidence.occurred_at = wallet::UnixTimestamp::from_seconds(7)?;
    let pending = if migration {
        lifecycle::WalletLifecycleState::MigrationPending
    } else {
        lifecycle::WalletLifecycleState::RecoveryPending
    };
    let prior = if suspended {
        lifecycle::WalletLifecycleState::Suspended
    } else {
        lifecycle::WalletLifecycleState::Active
    };
    let record = lifecycle::restore_wallet_lifecycle(
        evidence.wallet_instance_id.clone(),
        lifecycle::WalletLifecycleState::Failed,
        evidence.occurred_at,
        Some(evidence.event),
        Some(prior),
        Some(pending),
        Some(evidence),
    )?;
    let mut backend = MemoryBackend::default();
    backend.lifecycles.insert("wallet-unit-1".into(), record);
    backend
        .lifecycle_revisions
        .insert("wallet-unit-1".into(), RecordRevision::new(1));
    backend.trusted_lifecycle_authority = Some("wallet-provider-1".into());
    backend.allow_retry_reconciliation = true;
    Ok(backend)
}

fn retry_request(migration: bool) -> Result<pb::WalletOperationRequest, TestError> {
    let mut evidence = wallet_lifecycle_evidence_record()?;
    evidence.id = wallet::NonEmptyIdentifier::new("retry-1".into())?;
    evidence.event = if migration {
        lifecycle::WalletLifecycleEvent::BeginMigration
    } else {
        lifecycle::WalletLifecycleEvent::BeginRecovery
    };
    evidence.kind = if migration {
        lifecycle::WalletLifecycleEvidenceKind::Migration
    } else {
        lifecycle::WalletLifecycleEvidenceKind::Recovery
    };
    evidence.occurred_at = wallet::UnixTimestamp::from_seconds(11)?;
    let mut request = pb::ApplyWalletLifecycleEventRequest::default();
    request.wallet_instance_id = "wallet-unit-1".into();
    request.event = EnumValue::from(if migration {
        pb::WalletLifecycleEvent::WALLET_LIFECYCLE_EVENT_BEGIN_MIGRATION
    } else {
        pb::WalletLifecycleEvent::WALLET_LIFECYCLE_EVENT_BEGIN_RECOVERY
    });
    request.evidence = MessageField::some(wallet_lifecycle_evidence_record_to_proto(&evidence));
    Ok(mutating_operation_request(request.into()))
}

#[test]
fn runtime_commits_only_reconciled_retries_and_keeps_the_previous_resume_state(
) -> Result<(), TestError> {
    for migration in [false, true] {
        for suspended in [false, true] {
            let mut runtime = WalletCoreRuntime::new(failed_backend(migration, suspended)?);
            let request = retry_request(migration)?;
            let response = runtime.execute_operation(request.clone());
            assert!(matches!(
                response.outcome.as_ref(),
                Some(pb::wallet_operation_response::Outcome::Result(_))
            ));
            assert!(matches!(
                runtime.execute_operation(request).outcome.as_ref(),
                Some(pb::wallet_operation_response::Outcome::Result(_))
            ));
            assert_eq!(runtime.backend().lifecycle_authority_checks, 1);
            assert_eq!(runtime.backend().lifecycle_evidence_count, 1);
            let record = runtime
                .backend()
                .lifecycles
                .get("wallet-unit-1")
                .ok_or(TestError::MissingResponseField)?;
            assert_eq!(
                record.state(),
                if migration {
                    lifecycle::WalletLifecycleState::MigrationPending
                } else {
                    lifecycle::WalletLifecycleState::RecoveryPending
                }
            );
            assert_eq!(
                record.resume_state(),
                Some(if suspended {
                    lifecycle::WalletLifecycleState::Suspended
                } else {
                    lifecycle::WalletLifecycleState::Active
                })
            );
            assert!(lifecycle::ensure_wallet_operation_allowed(
                record,
                lifecycle::WalletOperation::PresentCredential
            )
            .is_err());
        }
    }
    Ok(())
}

#[test]
fn refused_reconciliation_untrusted_authority_and_failed_cas_preserve_failure(
) -> Result<(), TestError> {
    for mode in 0..4 {
        let mut backend = failed_backend(false, false)?;
        match mode {
            0 => backend.allow_retry_reconciliation = false,
            1 => backend.trusted_lifecycle_authority = None,
            2 => backend.reject_lifecycle_compare_and_swap = true,
            _ => backend.trusted_now_after_first = Some(72),
        }
        let original = backend
            .lifecycles
            .get("wallet-unit-1")
            .ok_or(TestError::MissingResponseField)?
            .clone();
        let mut runtime = WalletCoreRuntime::new(backend);
        let response = runtime.execute_operation(retry_request(false)?);
        assert!(matches!(
            response.outcome.as_ref(),
            Some(pb::wallet_operation_response::Outcome::Error(_))
        ));
        assert_eq!(
            runtime.backend().lifecycles.get("wallet-unit-1"),
            Some(&original)
        );
        assert_eq!(runtime.backend().lifecycle_evidence_count, 0);
    }
    Ok(())
}

pub(super) fn trusted_now(
    backend: &mut MemoryBackend,
) -> Result<wallet::UnixTimestamp, super::RuntimeError> {
    let initial = backend.trusted_now_seconds.unwrap_or(11);
    let seconds = if backend.trusted_time_reads == 0 {
        initial
    } else {
        backend.trusted_now_after_first.unwrap_or(initial)
    };
    backend.trusted_time_reads = backend.trusted_time_reads.saturating_add(1);
    wallet::UnixTimestamp::from_seconds(seconds)
        .map_err(|_| RuntimeError::new(RuntimeErrorReason::TrustedClockUnavailable))
}
pub(super) fn reconcile(
    backend: &mut MemoryBackend,
    current: &lifecycle::WalletLifecycleRecord,
    event: lifecycle::WalletLifecycleEvent,
    evidence: &lifecycle::WalletLifecycleEvidenceRecord,
    now: wallet::UnixTimestamp,
) -> Result<lifecycle::ReconciledWalletLifecycleRetry, super::RuntimeError> {
    backend.verify_wallet_lifecycle_authority(current, event, evidence, now)?;
    if !backend.allow_retry_reconciliation {
        return Err(RuntimeError::new(RuntimeErrorReason::LifecyclePolicyDenied));
    }
    lifecycle::ReconciledWalletLifecycleRetry::new(current.clone(), evidence.clone(), now)
        .map_err(|_| RuntimeError::new(RuntimeErrorReason::LifecyclePolicyDenied))
}
