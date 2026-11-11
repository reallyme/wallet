// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    create_lifecycle_operation_request, mutating_operation_request, pb,
    response_has_runtime_reason, wallet_lifecycle_evidence_record,
    wallet_lifecycle_evidence_record_to_proto, wallet_lifecycle_record, EnumValue, MemoryBackend,
    MessageField, RecordRevision, TestError, WalletCoreRuntime,
};

#[test]
fn lifecycle_replay_rechecks_the_executor_wallet_binding() -> Result<(), TestError> {
    let mut backend = MemoryBackend::default();
    backend
        .lifecycles
        .insert("wallet-unit-1".to_owned(), wallet_lifecycle_record()?);
    backend
        .lifecycle_revisions
        .insert("wallet-unit-1".to_owned(), RecordRevision::new(1));
    backend.trusted_lifecycle_authority = Some("wallet-provider-1".to_owned());
    let mut runtime = WalletCoreRuntime::new(backend);
    let mut event = pb::ApplyWalletLifecycleEventRequest::default();
    event.wallet_instance_id = "wallet-unit-1".to_owned();
    event.event =
        EnumValue::from(pb::WalletLifecycleEvent::WALLET_LIFECYCLE_EVENT_COMPLETE_PROVISIONING);
    event.evidence = MessageField::some(wallet_lifecycle_evidence_record_to_proto(
        &wallet_lifecycle_evidence_record()?,
    ));
    let request = mutating_operation_request(event.into());
    assert!(matches!(
        runtime.execute_operation(request.clone()).outcome.as_ref(),
        Some(pb::wallet_operation_response::Outcome::Result(_))
    ));

    let mut backend = runtime.into_backend();
    backend.bound_wallet_override = Some("wallet-unit-2");
    let mut rebound = WalletCoreRuntime::new(backend);
    assert!(response_has_runtime_reason(
        &rebound.execute_operation(request),
        pb::WalletErrorReason::WALLET_ERROR_REASON_INVALID_STATE,
        pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_LIFECYCLE_POLICY_DENIED,
    ));
    assert_eq!(rebound.backend().lifecycle_authority_checks, 1);
    assert_eq!(rebound.backend().journal.len(), 1);
    Ok(())
}

#[test]
fn lifecycle_creation_replay_cannot_cross_wallet_units() -> Result<(), TestError> {
    let mut runtime = WalletCoreRuntime::new(MemoryBackend::default());
    let request = create_lifecycle_operation_request(0x71, "wallet-unit-1")?;
    assert!(matches!(
        runtime.execute_operation(request.clone()).outcome.as_ref(),
        Some(pb::wallet_operation_response::Outcome::Result(_))
    ));
    let mut backend = runtime.into_backend();
    backend.bound_wallet_override = Some("wallet-unit-2");
    let mut rebound = WalletCoreRuntime::new(backend);
    assert!(response_has_runtime_reason(
        &rebound.execute_operation(request),
        pb::WalletErrorReason::WALLET_ERROR_REASON_INVALID_STATE,
        pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_LIFECYCLE_POLICY_DENIED,
    ));
    assert_eq!(rebound.backend().lifecycle_create_count, 1);
    Ok(())
}
