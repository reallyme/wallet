// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    active_backend, backend_with_credential, consent_scope_to_proto, credential_record,
    credential_record_to_proto, credential_status_evidence, credential_status_evidence_to_proto,
    flow_snapshot, flow_snapshot_to_proto, id, issuance_flow_state, lifecycle,
    mutating_operation_request, pb, presentation_copy, presentation_copy_to_proto,
    qtsp_decision_record_to_proto, response_has_runtime_reason, timestamp,
    transaction_log_entry_to_proto, verifier_entitlement_to_proto, wallet,
    wallet_lifecycle_evidence_record, wallet_lifecycle_evidence_record_to_proto,
    wallet_lifecycle_record, wallet_lifecycle_record_to_proto, EnumValue, MemoryBackend,
    MessageField, RecordRevision, RuntimeErrorReason, TestError, WalletCoreRuntime,
};

#[test]
fn credential_record_handler_rejects_unverified_receipt() -> Result<(), TestError> {
    let mut runtime = WalletCoreRuntime::new(MemoryBackend::default());
    let record = credential_record()?;

    let put_response = runtime.put_credential_record(pb::PutCredentialRecordRequest {
        record: MessageField::some(credential_record_to_proto(&record)),
        ..pb::PutCredentialRecordRequest::default()
    });
    assert!(matches!(
        put_response,
        Err(error) if error.reason == RuntimeErrorReason::OperationUnsupported
    ));
    assert!(runtime.backend().credentials.is_empty());
    Ok(())
}

#[test]
fn status_evidence_handler_rejects_unverified_claims() -> Result<(), TestError> {
    let mut runtime = WalletCoreRuntime::new(MemoryBackend::default());
    let response =
        runtime.apply_credential_status_evidence(pb::ApplyCredentialStatusEvidenceRequest {
            evidence: MessageField::some(credential_status_evidence_to_proto(
                &credential_status_evidence()?,
            )),
            now: MessageField::some(pb::UnixTimestamp {
                seconds: 15,
                ..pb::UnixTimestamp::default()
            }),
            ..pb::ApplyCredentialStatusEvidenceRequest::default()
        });

    assert!(matches!(
        response,
        Err(error) if error.reason == RuntimeErrorReason::OperationUnsupported
    ));
    Ok(())
}

#[test]
fn credential_delete_preserves_a_concurrently_advanced_revision() -> Result<(), TestError> {
    let mut backend = active_backend()?;
    backend.advance_credential_revision_before_delete = true;
    backend
        .credentials
        .insert("credential-1".to_owned(), credential_record()?);
    backend
        .credential_revisions
        .insert("credential-1".to_owned(), RecordRevision::new(7));
    let mut runtime = WalletCoreRuntime::new(backend);
    let mut delete = pb::DeleteCredentialRecordRequest::default();
    delete.credential_id = "credential-1".to_owned();

    let response = runtime.execute_operation(mutating_operation_request(delete.into()));

    assert!(response_has_runtime_reason(
        &response,
        pb::WalletErrorReason::WALLET_ERROR_REASON_REVISION_CONFLICT,
        pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_CREDENTIAL_REVISION_CONFLICT,
    ));
    assert!(runtime.backend().credentials.contains_key("credential-1"));
    assert!(matches!(
        runtime.backend().credential_revisions.get("credential-1"),
        Some(revision) if revision.value() == 8
    ));
    Ok(())
}

#[test]
fn raw_entitlement_handler_rejects_self_asserted_claims() -> Result<(), TestError> {
    let runtime = WalletCoreRuntime::new(MemoryBackend::default());
    let entitlement = wallet::VerifierEntitlement {
        relying_party_id: id("rp-1")?,
        authorized_scope: wallet::ConsentScope {
            attributes: vec![wallet::AttributeName::new("age_over_18".to_owned())?],
        },
        valid_until: timestamp()?,
    };
    let requested_scope = entitlement.authorized_scope.clone();

    let result = runtime.evaluate_verifier_entitlement(pb::EvaluateVerifierEntitlementRequest {
        entitlement: MessageField::some(verifier_entitlement_to_proto(&entitlement)),
        requested_scope: MessageField::some(consent_scope_to_proto(&requested_scope)),
        now: MessageField::some(pb::UnixTimestamp {
            seconds: timestamp()?.as_seconds(),
            ..pb::UnixTimestamp::default()
        }),
        ..pb::EvaluateVerifierEntitlementRequest::default()
    });

    assert!(
        matches!(result, Err(error) if error.reason == RuntimeErrorReason::OperationUnsupported)
    );
    Ok(())
}

#[test]
fn presentation_copy_handler_delegates_to_backend() -> Result<(), TestError> {
    let mut backend = backend_with_credential(wallet::CredentialStatus::Active)?;
    backend
        .copies
        .insert("credential-1".to_owned(), presentation_copy()?);
    let mut runtime = WalletCoreRuntime::new(backend);

    let mut request = pb::ClaimPresentationCopyRequest::default();
    request.credential_id = "credential-1".to_owned();
    request.copy_id = "copy-1".to_owned();
    request.policy = EnumValue::from(pb::PresentationCopyClaimPolicy::Generic);
    let response = runtime.claim_presentation_copy(request)?;
    let expected = presentation_copy_to_proto(&presentation_copy()?);

    assert!(matches!(response.copy.as_option(), Some(copy) if copy == &expected));
    Ok(())
}

#[test]
fn wrong_copy_identity_does_not_reach_the_claimed_copy() -> Result<(), TestError> {
    let mut backend = backend_with_credential(wallet::CredentialStatus::Active)?;
    backend
        .copies
        .insert("credential-1".to_owned(), presentation_copy()?);
    let mut runtime = WalletCoreRuntime::new(backend);

    let mut wrong = pb::ClaimPresentationCopyRequest::default();
    wrong.credential_id = "credential-1".to_owned();
    wrong.copy_id = "copy-2".to_owned();
    wrong.policy = EnumValue::from(pb::PresentationCopyClaimPolicy::Generic);
    assert!(matches!(
        runtime.claim_presentation_copy(wrong),
        Err(error) if error.reason == RuntimeErrorReason::PresentationCopyStoreRejected
    ));
    assert!(runtime.backend().copies.contains_key("credential-1"));

    let mut missing = pb::ClaimPresentationCopyRequest::default();
    missing.credential_id = "credential-1".to_owned();
    missing.policy = EnumValue::from(pb::PresentationCopyClaimPolicy::Generic);
    assert!(matches!(
        runtime.claim_presentation_copy(missing),
        Err(error) if error.reason == RuntimeErrorReason::InvalidRequest
    ));
    assert!(runtime.backend().copies.contains_key("credential-1"));
    Ok(())
}

#[test]
fn presentation_copy_claim_policy_is_explicit_and_fail_closed() -> Result<(), TestError> {
    let mut backend = backend_with_credential(wallet::CredentialStatus::Active)?;
    backend
        .copies
        .insert("credential-1".to_owned(), presentation_copy()?);
    let mut runtime = WalletCoreRuntime::new(backend);

    let mut unspecified = pb::ClaimPresentationCopyRequest::default();
    unspecified.credential_id = "credential-1".to_owned();
    assert!(matches!(
        runtime.claim_presentation_copy(unspecified),
        Err(error) if error.reason == RuntimeErrorReason::InvalidRequest
    ));
    assert!(runtime.backend().copies.contains_key("credential-1"));

    let mut active_zk = pb::ClaimPresentationCopyRequest::default();
    active_zk.credential_id = "credential-1".to_owned();
    active_zk.copy_id = "copy-1".to_owned();
    active_zk.policy = EnumValue::from(pb::PresentationCopyClaimPolicy::ActiveZkCredential);
    assert!(matches!(
        runtime.claim_presentation_copy(active_zk),
        Err(error) if error.reason == RuntimeErrorReason::InvalidRequest
    ));
    assert!(runtime.backend().copies.contains_key("credential-1"));

    let mut active_zk = pb::ClaimPresentationCopyRequest::default();
    active_zk.credential_id = "credential-1".to_owned();
    active_zk.copy_id = "copy-1".to_owned();
    active_zk.policy = EnumValue::from(pb::PresentationCopyClaimPolicy::ActiveZkCredential);
    active_zk.prepared_claim_selector_digest = vec![7; 32];
    assert!(matches!(
        runtime.claim_presentation_copy(active_zk),
        Err(error) if error.reason == RuntimeErrorReason::PresentationCopyStoreRejected
    ));
    assert!(runtime.backend().copies.contains_key("credential-1"));
    Ok(())
}

#[test]
fn presentation_copy_handler_rejects_unclaimed_backend_copy() -> Result<(), TestError> {
    let mut backend = backend_with_credential(wallet::CredentialStatus::Active)?;
    let mut copy = presentation_copy()?;
    copy.state = wallet::BatchCopyState::Available;
    backend.copies.insert("credential-1".to_owned(), copy);
    let mut runtime = WalletCoreRuntime::new(backend);

    let mut request = pb::ClaimPresentationCopyRequest::default();
    request.credential_id = "credential-1".to_owned();
    request.copy_id = "copy-1".to_owned();
    request.policy = EnumValue::from(pb::PresentationCopyClaimPolicy::Generic);
    assert!(matches!(
        runtime.claim_presentation_copy(request),
        Err(error) if error.reason == RuntimeErrorReason::PresentationCopyStoreRejected
    ));
    Ok(())
}

#[test]
fn generic_claim_rejects_a_prepared_copy_from_an_injected_backend() -> Result<(), TestError> {
    let mut backend = backend_with_credential(wallet::CredentialStatus::Active)?;
    let mut copy = presentation_copy()?;
    copy.prepared_claim_selector_digest = Some([7; 32]);
    backend.copies.insert("credential-1".to_owned(), copy);
    let mut runtime = WalletCoreRuntime::new(backend);

    let mut request = pb::ClaimPresentationCopyRequest::default();
    request.credential_id = "credential-1".to_owned();
    request.copy_id = "copy-1".to_owned();
    request.policy = EnumValue::from(pb::PresentationCopyClaimPolicy::Generic);
    assert!(matches!(
        runtime.claim_presentation_copy(request),
        Err(error) if error.reason == RuntimeErrorReason::PresentationCopyStoreRejected
    ));
    Ok(())
}

#[test]
fn presentation_copy_handler_rejects_another_credentials_copy() -> Result<(), TestError> {
    let mut backend = backend_with_credential(wallet::CredentialStatus::Active)?;
    let mut copy = presentation_copy()?;
    copy.credential_id = id("credential-2")?;
    backend.copies.insert("credential-1".to_owned(), copy);
    let mut runtime = WalletCoreRuntime::new(backend);

    let mut request = pb::ClaimPresentationCopyRequest::default();
    request.credential_id = "credential-1".to_owned();
    request.copy_id = "copy-1".to_owned();
    request.policy = EnumValue::from(pb::PresentationCopyClaimPolicy::Generic);
    assert!(matches!(
        runtime.claim_presentation_copy(request),
        Err(error) if error.reason == RuntimeErrorReason::PresentationCopyStoreRejected
    ));
    Ok(())
}

#[test]
fn log_handlers_delegate_to_backend() -> Result<(), TestError> {
    let mut runtime = WalletCoreRuntime::new(active_backend()?);
    let entry = reallyme_wallet_log::chain_transaction_log_entry(
        wallet::TransactionLogEntry {
            id: id("log-1")?,
            purpose: wallet::TransactionPurpose::Presentation,
            relying_party_id: Some(id("rp-1")?),
            disclosed_attributes: vec![wallet::DisclosedAttribute {
                name: wallet::AttributeName::new("age_over_18".to_owned())?,
            }],
            occurred_at: timestamp()?,
            sequence: 0,
            previous_entry_hash: [0; 32],
            entry_hash: [0; 32],
        },
        1,
        [0; 32],
    )?;
    let decision = wallet::QtspDecisionRecord {
        kind: wallet::QtspDecisionKind::QualifiedElectronicSignature,
        outcome: wallet::DecisionOutcome::Accept,
        input_sha256_b64url: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
        decided_at: timestamp()?,
    };

    let transaction_response = runtime.append_transaction_log(pb::AppendTransactionLogRequest {
        entry: MessageField::some(transaction_log_entry_to_proto(&entry)),
        ..pb::AppendTransactionLogRequest::default()
    })?;
    let qtsp_response = runtime.append_qtsp_decision(pb::AppendQtspDecisionRequest {
        record: MessageField::some(qtsp_decision_record_to_proto(&decision)),
        ..pb::AppendQtspDecisionRequest::default()
    })?;

    assert_eq!(
        transaction_response,
        pb::AppendTransactionLogResponse::default()
    );
    assert_eq!(qtsp_response, pb::AppendQtspDecisionResponse::default());
    assert_eq!(runtime.backend().transaction_log_count, 1);
    assert_eq!(runtime.backend().qtsp_decision_count, 1);
    Ok(())
}

#[test]
fn transaction_log_handler_rejects_invalid_presentation_entry() -> Result<(), TestError> {
    let mut runtime = WalletCoreRuntime::new(MemoryBackend::default());
    let entry = wallet::TransactionLogEntry {
        id: id("log-1")?,
        purpose: wallet::TransactionPurpose::Presentation,
        relying_party_id: None,
        disclosed_attributes: vec![wallet::DisclosedAttribute {
            name: wallet::AttributeName::new("age_over_18".to_owned())?,
        }],
        occurred_at: timestamp()?,
        sequence: 0,
        previous_entry_hash: [0; 32],
        entry_hash: [0; 32],
    };

    let result = runtime.append_transaction_log(pb::AppendTransactionLogRequest {
        entry: MessageField::some(transaction_log_entry_to_proto(&entry)),
        ..pb::AppendTransactionLogRequest::default()
    });

    assert!(matches!(
        result,
        Err(error) if error.reason == RuntimeErrorReason::InvalidRequest
    ));
    assert_eq!(runtime.backend().transaction_log_count, 0);
    Ok(())
}

#[test]
fn transaction_log_append_rejects_second_genesis_orphan_and_duplicate_id() -> Result<(), TestError>
{
    let mut runtime = WalletCoreRuntime::new(active_backend()?);
    let base = wallet::TransactionLogEntry {
        id: id("log-first")?,
        purpose: wallet::TransactionPurpose::Issuance,
        relying_party_id: None,
        disclosed_attributes: Vec::new(),
        occurred_at: timestamp()?,
        sequence: 0,
        previous_entry_hash: [0; 32],
        entry_hash: [0; 32],
    };
    let genesis = reallyme_wallet_log::chain_transaction_log_entry(base.clone(), 1, [0; 32])?;
    runtime.append_transaction_log(pb::AppendTransactionLogRequest {
        entry: MessageField::some(transaction_log_entry_to_proto(&genesis)),
        ..Default::default()
    })?;

    let mut second_base = base.clone();
    second_base.id = id("log-second")?;
    let second_genesis =
        reallyme_wallet_log::chain_transaction_log_entry(second_base.clone(), 1, [0; 32])?;
    let orphan =
        reallyme_wallet_log::chain_transaction_log_entry(second_base, 42, genesis.entry_hash)?;
    let duplicate_id =
        reallyme_wallet_log::chain_transaction_log_entry(base, 2, genesis.entry_hash)?;
    for rejected in [second_genesis, orphan, duplicate_id] {
        let result = runtime.append_transaction_log(pb::AppendTransactionLogRequest {
            entry: MessageField::some(transaction_log_entry_to_proto(&rejected)),
            ..Default::default()
        });
        assert!(matches!(
            result,
            Err(error) if error.reason == RuntimeErrorReason::LogStoreRejected
        ));
        assert_eq!(runtime.backend().transaction_log_entries.len(), 1);
        assert_eq!(runtime.backend().transaction_log_count, 1);
    }
    Ok(())
}

#[test]
fn qtsp_decision_handler_rejects_missing_digest() -> Result<(), TestError> {
    let mut runtime = WalletCoreRuntime::new(MemoryBackend::default());
    let decision = wallet::QtspDecisionRecord {
        kind: wallet::QtspDecisionKind::CredentialStatus,
        outcome: wallet::DecisionOutcome::Accept,
        input_sha256_b64url: String::new(),
        decided_at: timestamp()?,
    };

    let result = runtime.append_qtsp_decision(pb::AppendQtspDecisionRequest {
        record: MessageField::some(qtsp_decision_record_to_proto(&decision)),
        ..pb::AppendQtspDecisionRequest::default()
    });

    assert!(matches!(
        result,
        Err(error) if error.reason == RuntimeErrorReason::InvalidRequest
    ));
    assert_eq!(runtime.backend().qtsp_decision_count, 0);
    Ok(())
}

#[test]
fn flow_snapshot_handlers_round_trip_generated_dtos() -> Result<(), TestError> {
    let mut runtime = WalletCoreRuntime::new(active_backend()?);
    let snapshot = flow_snapshot()?;

    let mut save_response = runtime.save_flow_snapshot(pb::SaveFlowSnapshotRequest {
        snapshot: MessageField::some(flow_snapshot_to_proto(&snapshot)),
        ..pb::SaveFlowSnapshotRequest::default()
    })?;
    assert!(matches!(
        save_response.revision.as_option(),
        Some(revision) if revision.value == 1
    ));
    let mut get_request = pb::GetFlowSnapshotRequest::default();
    get_request.snapshot_id = core::mem::take(&mut save_response.snapshot_id);
    let get_response = runtime.get_flow_snapshot(get_request)?;

    assert!(matches!(
        get_response.snapshot.as_option(),
        Some(snapshot) if snapshot.id == "flow-1"
    ));
    assert!(matches!(
        get_response.revision.as_option(),
        Some(revision) if revision.value == 1
    ));

    let mut replacement = flow_snapshot()?;
    replacement.state = issuance_flow_state(
        pb::OpenId4VciIssuanceStage::OPEN_ID4_VCI_ISSUANCE_STAGE_CONSENT_CAPTURED,
    );
    let replacement_response = runtime.save_flow_snapshot(pb::SaveFlowSnapshotRequest {
        snapshot: MessageField::some(flow_snapshot_to_proto(&replacement)),
        expected_revision: MessageField::some(pb::RecordRevision {
            value: 1,
            ..Default::default()
        }),
        ..Default::default()
    })?;
    assert!(matches!(
        replacement_response.revision.as_option(),
        Some(revision) if revision.value == 2
    ));

    let stale = runtime.save_flow_snapshot(pb::SaveFlowSnapshotRequest {
        snapshot: MessageField::some(flow_snapshot_to_proto(&snapshot)),
        expected_revision: MessageField::some(pb::RecordRevision {
            value: 1,
            ..Default::default()
        }),
        ..Default::default()
    });
    assert!(matches!(
        stale,
        Err(error) if error.reason == RuntimeErrorReason::FlowSnapshotRevisionConflict
    ));
    assert!(matches!(
        runtime.backend().snapshots.get("flow-1"),
        Some(stored) if stored.state == replacement.state
    ));
    Ok(())
}

#[test]
fn wallet_lifecycle_handlers_round_trip_generated_dtos() -> Result<(), TestError> {
    let mut runtime = WalletCoreRuntime::new(MemoryBackend::default());
    let record = lifecycle::new_wallet_lifecycle(id("wallet-unit-1")?, timestamp()?);

    let mut put_response =
        runtime.put_wallet_lifecycle_record(pb::PutWalletLifecycleRecordRequest {
            record: MessageField::some(wallet_lifecycle_record_to_proto(&record)),
            ..pb::PutWalletLifecycleRecordRequest::default()
        })?;
    let mut get_request = pb::GetWalletLifecycleRecordRequest::default();
    get_request.wallet_instance_id = core::mem::take(&mut put_response.wallet_instance_id);
    let get_response = runtime.get_wallet_lifecycle_record(get_request)?;

    assert!(matches!(
        get_response.record.as_option(),
        Some(record) if record.wallet_instance_id == "wallet-unit-1"
    ));
    Ok(())
}

#[test]
fn lifecycle_create_rejects_self_asserted_active_record() -> Result<(), TestError> {
    let mut runtime = WalletCoreRuntime::new(MemoryBackend::default());
    let forged = lifecycle::restore_wallet_lifecycle(
        id("wallet-unit-1")?,
        lifecycle::WalletLifecycleState::Active,
        wallet::UnixTimestamp::from_seconds(11)?,
        Some(lifecycle::WalletLifecycleEvent::CompleteProvisioning),
        None,
        None,
        Some(wallet_lifecycle_evidence_record()?),
    )?;
    let result = runtime.put_wallet_lifecycle_record(pb::PutWalletLifecycleRecordRequest {
        record: MessageField::some(wallet_lifecycle_record_to_proto(&forged)),
        ..Default::default()
    });
    assert!(matches!(
        result,
        Err(error) if error.reason == RuntimeErrorReason::InvalidRequest
    ));
    assert!(runtime.backend().lifecycles.is_empty());
    Ok(())
}

#[test]
fn wallet_lifecycle_evidence_handler_rejects_standalone_append() -> Result<(), TestError> {
    let mut runtime = WalletCoreRuntime::new(MemoryBackend::default());
    let record = wallet_lifecycle_evidence_record()?;

    let result =
        runtime.append_wallet_lifecycle_evidence(pb::AppendWalletLifecycleEvidenceRequest {
            record: MessageField::some(wallet_lifecycle_evidence_record_to_proto(&record)),
            ..pb::AppendWalletLifecycleEvidenceRequest::default()
        });

    assert!(matches!(
        result,
        Err(error) if error.reason == RuntimeErrorReason::OperationUnsupported
    ));
    assert_eq!(runtime.backend().lifecycle_evidence_count, 0);
    Ok(())
}

#[test]
fn wallet_lifecycle_event_handler_applies_and_persists_transition() -> Result<(), TestError> {
    let mut backend = MemoryBackend::default();
    backend
        .lifecycles
        .insert("wallet-unit-1".to_owned(), wallet_lifecycle_record()?);
    backend
        .lifecycle_revisions
        .insert("wallet-unit-1".to_owned(), RecordRevision::new(1));
    backend.trusted_lifecycle_authority = Some("wallet-provider-1".to_owned());
    let mut runtime = WalletCoreRuntime::new(backend);

    let mut request = pb::ApplyWalletLifecycleEventRequest::default();
    request.wallet_instance_id = "wallet-unit-1".to_owned();
    request.event =
        EnumValue::from(pb::WalletLifecycleEvent::WALLET_LIFECYCLE_EVENT_COMPLETE_PROVISIONING);
    request.now = MessageField::some(pb::UnixTimestamp {
        seconds: 4_102_444_800,
        ..pb::UnixTimestamp::default()
    });
    request.evidence = MessageField::some(wallet_lifecycle_evidence_record_to_proto(
        &wallet_lifecycle_evidence_record()?,
    ));
    let response = runtime.apply_wallet_lifecycle_event(request)?;

    assert!(matches!(
        response.record.as_option(),
        Some(record) if record.state
            == EnumValue::from(pb::WalletLifecycleState::WALLET_LIFECYCLE_STATE_ACTIVE)
    ));
    assert!(matches!(
        runtime.backend().lifecycles.get("wallet-unit-1"),
        Some(record) if record.state() == lifecycle::WalletLifecycleState::Active
            && record.updated_at().as_seconds() == 11
    ));
    assert_eq!(runtime.backend().lifecycle_evidence_count, 1);
    Ok(())
}

#[test]
fn lifecycle_transition_rolls_back_when_evidence_cannot_be_appended() -> Result<(), TestError> {
    let mut backend = MemoryBackend {
        reject_lifecycle_evidence_append: true,
        ..Default::default()
    };
    backend
        .lifecycles
        .insert("wallet-unit-1".to_owned(), wallet_lifecycle_record()?);
    backend
        .lifecycle_revisions
        .insert("wallet-unit-1".to_owned(), RecordRevision::new(1));
    backend.trusted_lifecycle_authority = Some("wallet-provider-1".to_owned());
    let mut runtime = WalletCoreRuntime::new(backend);
    let mut request = pb::ApplyWalletLifecycleEventRequest::default();
    request.wallet_instance_id = "wallet-unit-1".to_owned();
    request.event =
        EnumValue::from(pb::WalletLifecycleEvent::WALLET_LIFECYCLE_EVENT_COMPLETE_PROVISIONING);
    request.evidence = MessageField::some(wallet_lifecycle_evidence_record_to_proto(
        &wallet_lifecycle_evidence_record()?,
    ));

    let result = runtime.apply_wallet_lifecycle_event(request);
    assert!(matches!(
        result,
        Err(error) if error.reason == RuntimeErrorReason::LifecycleEvidenceStoreRejected
    ));
    assert!(matches!(
        runtime.backend().lifecycles.get("wallet-unit-1"),
        Some(record) if record.state() == lifecycle::WalletLifecycleState::Provisioning
    ));
    assert!(matches!(
        runtime.backend().lifecycle_revisions.get("wallet-unit-1"),
        Some(revision) if *revision == RecordRevision::new(1)
    ));
    assert_eq!(runtime.backend().lifecycle_evidence_count, 0);
    Ok(())
}

#[test]
fn lifecycle_transition_rejects_future_and_stale_evidence() -> Result<(), TestError> {
    for (trusted_now, evidence_time) in [(11, 12), (100, 11)] {
        let mut backend = MemoryBackend {
            trusted_now_seconds: Some(trusted_now),
            ..Default::default()
        };
        backend
            .lifecycles
            .insert("wallet-unit-1".to_owned(), wallet_lifecycle_record()?);
        backend
            .lifecycle_revisions
            .insert("wallet-unit-1".to_owned(), RecordRevision::new(1));
        let mut runtime = WalletCoreRuntime::new(backend);
        let mut evidence = wallet_lifecycle_evidence_record()?;
        evidence.occurred_at = wallet::UnixTimestamp::from_seconds(evidence_time)?;
        let mut request = pb::ApplyWalletLifecycleEventRequest::default();
        request.wallet_instance_id = "wallet-unit-1".to_owned();
        request.event =
            EnumValue::from(pb::WalletLifecycleEvent::WALLET_LIFECYCLE_EVENT_COMPLETE_PROVISIONING);
        request.evidence = MessageField::some(wallet_lifecycle_evidence_record_to_proto(&evidence));

        let result = runtime.apply_wallet_lifecycle_event(request);
        assert!(matches!(
            result,
            Err(error) if error.reason == RuntimeErrorReason::LifecycleClockSkew
        ));
        assert!(matches!(
            runtime.backend().lifecycles.get("wallet-unit-1"),
            Some(record) if record.state() == lifecycle::WalletLifecycleState::Provisioning
        ));
    }
    Ok(())
}

#[test]
fn lifecycle_create_rejects_future_state_watermark() -> Result<(), TestError> {
    let mut runtime = WalletCoreRuntime::new(MemoryBackend::default());
    let original = wallet_lifecycle_record()?;
    let record = lifecycle::restore_wallet_lifecycle(
        original.wallet_instance_id().clone(),
        lifecycle::WalletLifecycleState::Unprovisioned,
        wallet::UnixTimestamp::from_seconds(100)?,
        None,
        None,
        None,
        None,
    )?;
    let result = runtime.put_wallet_lifecycle_record(pb::PutWalletLifecycleRecordRequest {
        record: MessageField::some(wallet_lifecycle_record_to_proto(&record)),
        ..Default::default()
    });
    assert!(matches!(
        result,
        Err(error) if error.reason == RuntimeErrorReason::LifecycleClockSkew
    ));
    assert!(runtime.backend().lifecycles.is_empty());
    Ok(())
}

#[test]
fn lifecycle_transition_does_not_overwrite_a_stale_revision() -> Result<(), TestError> {
    let mut backend = MemoryBackend {
        reject_lifecycle_compare_and_swap: true,
        ..Default::default()
    };
    backend
        .lifecycles
        .insert("wallet-unit-1".to_owned(), wallet_lifecycle_record()?);
    backend
        .lifecycle_revisions
        .insert("wallet-unit-1".to_owned(), RecordRevision::new(11));
    backend.trusted_lifecycle_authority = Some("wallet-provider-1".to_owned());
    let mut runtime = WalletCoreRuntime::new(backend);
    let mut request = pb::ApplyWalletLifecycleEventRequest::default();
    request.wallet_instance_id = "wallet-unit-1".to_owned();
    request.event =
        EnumValue::from(pb::WalletLifecycleEvent::WALLET_LIFECYCLE_EVENT_COMPLETE_PROVISIONING);
    request.now = MessageField::some(pb::UnixTimestamp {
        seconds: 11,
        ..Default::default()
    });
    request.evidence = MessageField::some(wallet_lifecycle_evidence_record_to_proto(
        &wallet_lifecycle_evidence_record()?,
    ));

    let result = runtime.apply_wallet_lifecycle_event(request);

    assert!(matches!(
        result,
        Err(error) if error.reason == RuntimeErrorReason::LifecycleRevisionConflict
    ));
    assert!(matches!(
        runtime.backend().lifecycles.get("wallet-unit-1"),
        Some(record) if record.state() == lifecycle::WalletLifecycleState::Provisioning
    ));
    assert_eq!(runtime.backend().lifecycle_evidence_count, 0);
    Ok(())
}
