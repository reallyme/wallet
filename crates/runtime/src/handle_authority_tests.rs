// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Credential-status and lifecycle-authority gates in front of state changes.

use super::{
    active_backend, backend_with_credential, credential_record_with_status, id, lifecycle,
    mutating_operation_request, pb, presentation_copy, read_operation_request,
    response_has_runtime_reason, transaction_log_entry_to_proto, transition_backend, wallet,
    wallet_lifecycle_evidence_record, wallet_lifecycle_evidence_record_to_proto,
    wallet_lifecycle_record, EnumValue, JournalEntry, MemoryBackend, MessageField, RecordRevision,
    RuntimeErrorReason, TestError, WalletCoreRuntime,
};
use reallyme_wallet_proto_codec::encode::encode_wallet_operation_response;

#[test]
fn presentation_copy_claim_rejects_an_inactive_credential() -> Result<(), TestError> {
    for status in [
        wallet::CredentialStatus::Suspended,
        wallet::CredentialStatus::Revoked,
        wallet::CredentialStatus::Deleted,
    ] {
        let mut backend = backend_with_credential(status)?;
        backend
            .copies
            .insert("credential-1".to_owned(), presentation_copy()?);
        let mut runtime = WalletCoreRuntime::new(backend);

        let mut request = pb::ClaimPresentationCopyRequest::default();
        request.credential_id = "credential-1".to_owned();
        request.copy_id = "copy-1".to_owned();
        request.policy = EnumValue::from(pb::PresentationCopyClaimPolicy::Generic);
        assert!(matches!(
            runtime.claim_presentation_copy(request),
            Err(error) if error.reason == RuntimeErrorReason::CredentialNotActive
        ));
        assert!(runtime.backend().copies.contains_key("credential-1"));
    }
    Ok(())
}

#[test]
fn presentation_copy_claim_rejects_a_missing_credential() -> Result<(), TestError> {
    let mut backend = active_backend()?;
    backend
        .copies
        .insert("credential-1".to_owned(), presentation_copy()?);
    let mut runtime = WalletCoreRuntime::new(backend);

    let mut request = pb::ClaimPresentationCopyRequest::default();
    request.credential_id = "credential-1".to_owned();
    request.copy_id = "copy-1".to_owned();
    request.policy = EnumValue::from(pb::PresentationCopyClaimPolicy::Generic);
    // This backend reports the missing record as a store fault; the claim
    // keeps that reason rather than guessing the credential's state.
    assert!(matches!(
        runtime.claim_presentation_copy(request),
        Err(error) if error.reason == RuntimeErrorReason::CredentialStoreRejected
    ));
    assert!(runtime.backend().copies.contains_key("credential-1"));
    Ok(())
}

#[test]
fn presentation_copy_claim_withholds_a_copy_revoked_during_the_claim() -> Result<(), TestError> {
    let mut backend = backend_with_credential(wallet::CredentialStatus::Active)?;
    backend
        .copies
        .insert("credential-1".to_owned(), presentation_copy()?);
    backend.credential_replacement_during_claim = Some(credential_record_with_status(
        wallet::CredentialStatus::Revoked,
    )?);
    let mut runtime = WalletCoreRuntime::new(backend);

    let mut request = pb::ClaimPresentationCopyRequest::default();
    request.credential_id = "credential-1".to_owned();
    request.copy_id = "copy-1".to_owned();
    request.policy = EnumValue::from(pb::PresentationCopyClaimPolicy::Generic);
    assert!(matches!(
        runtime.claim_presentation_copy(request),
        Err(error) if error.reason == RuntimeErrorReason::ClaimedCopyDiscarded
    ));
    // The backend burned the copy; the runtime released none of its bytes.
    assert!(!runtime.backend().copies.contains_key("credential-1"));
    Ok(())
}

#[test]
fn self_asserted_provisioning_evidence_cannot_activate_a_wallet() -> Result<(), TestError> {
    let mut backend = MemoryBackend::default();
    backend
        .lifecycles
        .insert("wallet-unit-1".to_owned(), wallet_lifecycle_record()?);
    backend
        .lifecycle_revisions
        .insert("wallet-unit-1".to_owned(), RecordRevision::new(1));
    backend.trusted_lifecycle_authority = Some("wallet-provider-1".to_owned());
    let mut runtime = WalletCoreRuntime::new(backend);

    let mut evidence = wallet_lifecycle_evidence_record()?;
    evidence.authority_id = id("self-asserted-caller")?;
    let mut request = pb::ApplyWalletLifecycleEventRequest::default();
    request.wallet_instance_id = "wallet-unit-1".to_owned();
    request.event =
        EnumValue::from(pb::WalletLifecycleEvent::WALLET_LIFECYCLE_EVENT_COMPLETE_PROVISIONING);
    request.evidence = MessageField::some(wallet_lifecycle_evidence_record_to_proto(&evidence));

    assert!(matches!(
        runtime.apply_wallet_lifecycle_event(request),
        Err(error) if error.reason == RuntimeErrorReason::LifecyclePolicyDenied
    ));
    assert_eq!(runtime.backend().lifecycle_authority_checks, 1);
    assert_eq!(runtime.backend().lifecycle_evidence_count, 0);
    assert!(matches!(
        runtime.backend().lifecycles.get("wallet-unit-1"),
        Some(record) if record.state() == lifecycle::WalletLifecycleState::Provisioning
    ));
    Ok(())
}

#[test]
fn capability_granting_events_fail_closed_without_a_verifier() -> Result<(), TestError> {
    let mut backend = MemoryBackend::default();
    backend
        .lifecycles
        .insert("wallet-unit-1".to_owned(), wallet_lifecycle_record()?);
    backend
        .lifecycle_revisions
        .insert("wallet-unit-1".to_owned(), RecordRevision::new(1));
    let mut runtime = WalletCoreRuntime::new(backend);

    let mut request = pb::ApplyWalletLifecycleEventRequest::default();
    request.wallet_instance_id = "wallet-unit-1".to_owned();
    request.event =
        EnumValue::from(pb::WalletLifecycleEvent::WALLET_LIFECYCLE_EVENT_COMPLETE_PROVISIONING);
    request.evidence = MessageField::some(wallet_lifecycle_evidence_record_to_proto(
        &wallet_lifecycle_evidence_record()?,
    ));

    assert!(matches!(
        runtime.apply_wallet_lifecycle_event(request),
        Err(error) if error.reason == RuntimeErrorReason::LifecyclePolicyDenied
    ));
    assert_eq!(runtime.backend().lifecycle_evidence_count, 0);
    Ok(())
}

#[test]
fn self_asserted_reactivation_cannot_restore_a_suspended_wallet() -> Result<(), TestError> {
    let mut backend = active_backend()?;
    backend
        .lifecycle_revisions
        .insert("wallet-unit-1".to_owned(), RecordRevision::new(2));
    backend.trusted_lifecycle_authority = Some("wallet-provider-1".to_owned());
    backend.trusted_now_seconds = Some(13);
    let mut runtime = WalletCoreRuntime::new(backend);

    // Suspension also needs verified authority; the provider issues it here.
    let suspension = lifecycle::WalletLifecycleEvidenceRecord {
        id: id("suspension-evidence-1")?,
        wallet_instance_id: id("wallet-unit-1")?,
        kind: lifecycle::WalletLifecycleEvidenceKind::Suspension,
        event: lifecycle::WalletLifecycleEvent::Suspend,
        occurred_at: wallet::UnixTimestamp::from_seconds(12)?,
        authority_id: id("wallet-provider-1")?,
        evidence_ref: id("suspension-reference-1")?,
        evidence_digest: vec![5, 5, 5, 5],
    };
    let mut suspend = pb::ApplyWalletLifecycleEventRequest::default();
    suspend.wallet_instance_id = "wallet-unit-1".to_owned();
    suspend.event = EnumValue::from(pb::WalletLifecycleEvent::WALLET_LIFECYCLE_EVENT_SUSPEND);
    suspend.evidence = MessageField::some(wallet_lifecycle_evidence_record_to_proto(&suspension));
    runtime.apply_wallet_lifecycle_event(suspend)?;
    assert_eq!(runtime.backend().lifecycle_authority_checks, 1);

    let reactivation = lifecycle::WalletLifecycleEvidenceRecord {
        id: id("reactivation-evidence-1")?,
        wallet_instance_id: id("wallet-unit-1")?,
        kind: lifecycle::WalletLifecycleEvidenceKind::Reactivation,
        event: lifecycle::WalletLifecycleEvent::Reactivate,
        occurred_at: wallet::UnixTimestamp::from_seconds(13)?,
        authority_id: id("self-asserted-caller")?,
        evidence_ref: id("reactivation-reference-1")?,
        evidence_digest: vec![6, 6, 6, 6],
    };
    let mut reactivate = pb::ApplyWalletLifecycleEventRequest::default();
    reactivate.wallet_instance_id = "wallet-unit-1".to_owned();
    reactivate.event = EnumValue::from(pb::WalletLifecycleEvent::WALLET_LIFECYCLE_EVENT_REACTIVATE);
    reactivate.evidence =
        MessageField::some(wallet_lifecycle_evidence_record_to_proto(&reactivation));

    assert!(matches!(
        runtime.apply_wallet_lifecycle_event(reactivate),
        Err(error) if error.reason == RuntimeErrorReason::LifecyclePolicyDenied
    ));
    assert_eq!(runtime.backend().lifecycle_authority_checks, 2);
    assert!(matches!(
        runtime.backend().lifecycles.get("wallet-unit-1"),
        Some(record) if record.state() == lifecycle::WalletLifecycleState::Suspended
    ));
    Ok(())
}

#[test]
fn forged_journal_record_cannot_replay_claimed_copy_bytes() -> Result<(), TestError> {
    let mut backend = backend_with_credential(wallet::CredentialStatus::Active)?;
    backend
        .copies
        .insert("credential-1".to_owned(), presentation_copy()?);
    let mut runtime = WalletCoreRuntime::new(backend);
    let mut claim = pb::ClaimPresentationCopyRequest::default();
    claim.credential_id = "credential-1".to_owned();
    claim.copy_id = "copy-1".to_owned();
    claim.policy = EnumValue::from(pb::PresentationCopyClaimPolicy::Generic);
    let request = mutating_operation_request(claim.into());
    let first = runtime.execute_operation(request.clone());
    let encoded_first =
        encode_wallet_operation_response(&first).map_err(|_| TestError::OperationCodec)?;

    // Rewrite the terminal claim marker as an ordinary response record that
    // carries the claimed copy, as a faulty or tampered journal could.
    let Some(JournalEntry::Complete {
        request_digest,
        response,
    }) = runtime.backend_mut().journal.get_mut(&[0xA5; 32])
    else {
        return Err(TestError::MissingResponseField);
    };
    let mut forged = b"RMWRP001".to_vec();
    forged.extend_from_slice(request_digest);
    forged.extend_from_slice(encoded_first.as_slice());
    *response = forged;

    let replay = runtime.execute_operation(request);
    assert!(response_has_runtime_reason(
        &replay,
        pb::WalletErrorReason::WALLET_ERROR_REASON_IDEMPOTENCY_STORE_UNAVAILABLE,
        pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_IDEMPOTENCY_STORE_REJECTED,
    ));
    Ok(())
}

#[test]
fn withdrawn_wallet_no_longer_exposes_credential_records() -> Result<(), TestError> {
    let mut backend = backend_with_credential(wallet::CredentialStatus::Active)?;
    let mut get = pb::GetCredentialRecordRequest::default();
    get.credential_id = "credential-1".to_owned();
    let mut active_runtime =
        WalletCoreRuntime::new(backend_with_credential(wallet::CredentialStatus::Active)?);
    let readable = active_runtime.execute_operation(read_operation_request(get.clone().into()));
    assert!(matches!(
        readable.outcome,
        Some(pb::wallet_operation_response::Outcome::Result(_))
    ));

    transition_backend(
        &mut backend,
        lifecycle::WalletLifecycleEvent::BeginWithdrawal,
        lifecycle::WalletLifecycleEvidenceKind::Withdrawal,
        12,
    )?;
    transition_backend(
        &mut backend,
        lifecycle::WalletLifecycleEvent::CompleteWithdrawal,
        lifecycle::WalletLifecycleEvidenceKind::Withdrawal,
        13,
    )?;
    let mut runtime = WalletCoreRuntime::new(backend);
    let response = runtime.execute_operation(read_operation_request(get.into()));
    assert!(response_has_runtime_reason(
        &response,
        pb::WalletErrorReason::WALLET_ERROR_REASON_INVALID_STATE,
        pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_LIFECYCLE_POLICY_DENIED,
    ));
    Ok(())
}

#[test]
fn future_dated_transaction_log_entry_is_refused() -> Result<(), TestError> {
    let mut runtime = WalletCoreRuntime::new(active_backend()?);
    let entry = reallyme_wallet_log::chain_transaction_log_entry(
        wallet::TransactionLogEntry {
            id: id("log-future")?,
            purpose: wallet::TransactionPurpose::Issuance,
            relying_party_id: None,
            disclosed_attributes: Vec::new(),
            occurred_at: wallet::UnixTimestamp::from_seconds(4_102_444_800)?,
            sequence: 0,
            previous_entry_hash: [0; 32],
            entry_hash: [0; 32],
        },
        1,
        [0; 32],
    )?;
    let result = runtime.append_transaction_log(pb::AppendTransactionLogRequest {
        entry: MessageField::some(transaction_log_entry_to_proto(&entry)),
        ..pb::AppendTransactionLogRequest::default()
    });
    assert!(matches!(
        result,
        Err(error) if error.reason == RuntimeErrorReason::RecordClockSkew
    ));
    assert!(runtime.backend().transaction_log_entries.is_empty());
    Ok(())
}

#[test]
fn self_asserted_suspension_cannot_deny_service() -> Result<(), TestError> {
    let mut backend = active_backend()?;
    backend
        .lifecycle_revisions
        .insert("wallet-unit-1".to_owned(), RecordRevision::new(2));
    backend.trusted_lifecycle_authority = Some("wallet-provider-1".to_owned());
    backend.trusted_now_seconds = Some(12);
    let mut runtime = WalletCoreRuntime::new(backend);
    let suspension = lifecycle::WalletLifecycleEvidenceRecord {
        id: id("suspension-evidence-forged")?,
        wallet_instance_id: id("wallet-unit-1")?,
        kind: lifecycle::WalletLifecycleEvidenceKind::Suspension,
        event: lifecycle::WalletLifecycleEvent::Suspend,
        occurred_at: wallet::UnixTimestamp::from_seconds(12)?,
        authority_id: id("self-asserted-caller")?,
        evidence_ref: id("suspension-reference-forged")?,
        evidence_digest: vec![5, 5, 5, 5],
    };
    let mut suspend = pb::ApplyWalletLifecycleEventRequest::default();
    suspend.wallet_instance_id = "wallet-unit-1".to_owned();
    suspend.event = EnumValue::from(pb::WalletLifecycleEvent::WALLET_LIFECYCLE_EVENT_SUSPEND);
    suspend.evidence = MessageField::some(wallet_lifecycle_evidence_record_to_proto(&suspension));

    assert!(matches!(
        runtime.apply_wallet_lifecycle_event(suspend),
        Err(error) if error.reason == RuntimeErrorReason::LifecyclePolicyDenied
    ));
    assert!(matches!(
        runtime.backend().lifecycles.get("wallet-unit-1"),
        Some(record) if record.state() == lifecycle::WalletLifecycleState::Active
    ));
    Ok(())
}

#[test]
fn withdrawn_wallet_unit_records_no_new_history() -> Result<(), TestError> {
    let mut backend = active_backend()?;
    transition_backend(
        &mut backend,
        lifecycle::WalletLifecycleEvent::BeginWithdrawal,
        lifecycle::WalletLifecycleEvidenceKind::Withdrawal,
        12,
    )?;
    transition_backend(
        &mut backend,
        lifecycle::WalletLifecycleEvent::CompleteWithdrawal,
        lifecycle::WalletLifecycleEvidenceKind::Withdrawal,
        13,
    )?;
    backend.trusted_now_seconds = Some(14);
    let mut runtime = WalletCoreRuntime::new(backend);
    let entry = reallyme_wallet_log::chain_transaction_log_entry(
        wallet::TransactionLogEntry {
            id: id("log-after-withdrawal")?,
            purpose: wallet::TransactionPurpose::Issuance,
            relying_party_id: None,
            disclosed_attributes: Vec::new(),
            occurred_at: wallet::UnixTimestamp::from_seconds(14)?,
            sequence: 0,
            previous_entry_hash: [0; 32],
            entry_hash: [0; 32],
        },
        1,
        [0; 32],
    )?;

    let result = runtime.append_transaction_log(pb::AppendTransactionLogRequest {
        entry: MessageField::some(transaction_log_entry_to_proto(&entry)),
        ..pb::AppendTransactionLogRequest::default()
    });

    assert!(matches!(
        result,
        Err(error) if error.reason == RuntimeErrorReason::LifecyclePolicyDenied
    ));
    assert!(runtime.backend().transaction_log_entries.is_empty());
    Ok(())
}

#[test]
fn transaction_log_entry_within_clock_skew_is_accepted() -> Result<(), TestError> {
    let mut runtime = WalletCoreRuntime::new(active_backend()?);
    // Trusted time in the test backend is 11; the device clock runs ahead.
    let entry = reallyme_wallet_log::chain_transaction_log_entry(
        wallet::TransactionLogEntry {
            id: id("log-skewed")?,
            purpose: wallet::TransactionPurpose::Issuance,
            relying_party_id: None,
            disclosed_attributes: Vec::new(),
            occurred_at: wallet::UnixTimestamp::from_seconds(11 + 60)?,
            sequence: 0,
            previous_entry_hash: [0; 32],
            entry_hash: [0; 32],
        },
        1,
        [0; 32],
    )?;
    runtime.append_transaction_log(pb::AppendTransactionLogRequest {
        entry: MessageField::some(transaction_log_entry_to_proto(&entry)),
        ..pb::AppendTransactionLogRequest::default()
    })?;
    assert_eq!(runtime.backend().transaction_log_entries.len(), 1);
    Ok(())
}

#[test]
fn a_deleted_wallet_unit_can_still_log_erasure() -> Result<(), TestError> {
    let mut backend = active_backend()?;
    for (event, at) in [
        (lifecycle::WalletLifecycleEvent::BeginDeletion, 12),
        (lifecycle::WalletLifecycleEvent::CompleteDeletion, 13),
    ] {
        transition_backend(
            &mut backend,
            event,
            lifecycle::WalletLifecycleEvidenceKind::Deletion,
            at,
        )?;
    }
    backend.trusted_now_seconds = Some(14);
    let mut runtime = WalletCoreRuntime::new(backend);
    let erasure = reallyme_wallet_log::chain_transaction_log_entry(
        wallet::TransactionLogEntry {
            id: id("log-erasure")?,
            purpose: wallet::TransactionPurpose::Deletion,
            relying_party_id: None,
            disclosed_attributes: Vec::new(),
            occurred_at: wallet::UnixTimestamp::from_seconds(14)?,
            sequence: 0,
            previous_entry_hash: [0; 32],
            entry_hash: [0; 32],
        },
        1,
        [0; 32],
    )?;

    runtime.append_transaction_log(pb::AppendTransactionLogRequest {
        entry: MessageField::some(transaction_log_entry_to_proto(&erasure)),
        ..pb::AppendTransactionLogRequest::default()
    })?;

    assert_eq!(runtime.backend().transaction_log_entries.len(), 1);
    Ok(())
}
