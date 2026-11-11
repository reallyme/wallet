// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    active_backend, backend_with_credential, consent_scope_to_proto,
    create_lifecycle_operation_request, credential_record, credential_record_to_proto,
    decode_wallet_operation_response, encode_wallet_operation_request, mutating_operation_request,
    pb, presentation_copy, read_operation_request, response_has_runtime_reason, timestamp,
    transition_backend, verifier_entitlement_to_proto, wallet, wallet_lifecycle_evidence_record,
    wallet_lifecycle_evidence_record_to_proto, wallet_lifecycle_record, JournalEntry,
    MemoryBackend, MessageField, ProtoErrorReason, RuntimeErrorReason, TestError,
    WalletCoreRuntime, WalletOperationExecutor, WalletRuntimeBackend,
    MAX_WALLET_PROTO_MESSAGE_BYTES,
};

#[test]
fn lifecycle_gate_fails_closed_and_respects_state_policy() -> Result<(), TestError> {
    use super::lifecycle::{
        WalletLifecycleEvent as Event, WalletLifecycleEvidenceKind as EvidenceKind,
        WalletOperation as Operation,
    };

    let regulated = [
        Operation::BeginIssuance,
        Operation::PresentCredential,
        Operation::SignWithWalletKey,
        Operation::RefreshCredentialStatus,
        Operation::ReadTransactionHistory,
        Operation::DeleteWallet,
        Operation::RenewAttestation,
    ];
    let mut missing = MemoryBackend::default();
    for operation in regulated {
        assert!(matches!(
            missing.authorize_wallet_operation(operation),
            Err(error) if error.reason == RuntimeErrorReason::LifecycleStoreRejected
        ));
    }

    let mut backend = active_backend()?;
    for operation in regulated {
        assert!(backend.authorize_wallet_operation(operation).is_ok());
    }

    transition_backend(&mut backend, Event::Suspend, EvidenceKind::Suspension, 12)?;
    for operation in [
        Operation::BeginIssuance,
        Operation::PresentCredential,
        Operation::SignWithWalletKey,
        Operation::RenewAttestation,
    ] {
        assert!(matches!(
            backend.authorize_wallet_operation(operation),
            Err(error) if error.reason == RuntimeErrorReason::LifecyclePolicyDenied
        ));
    }
    for operation in [
        Operation::RefreshCredentialStatus,
        Operation::ReadTransactionHistory,
        Operation::DeleteWallet,
    ] {
        assert!(backend.authorize_wallet_operation(operation).is_ok());
    }

    transition_backend(
        &mut backend,
        Event::BeginWithdrawal,
        EvidenceKind::Withdrawal,
        13,
    )?;
    transition_backend(
        &mut backend,
        Event::CompleteWithdrawal,
        EvidenceKind::Withdrawal,
        14,
    )?;
    assert!(backend
        .authorize_wallet_operation(Operation::ReadTransactionHistory)
        .is_ok());
    assert!(backend
        .authorize_wallet_operation(Operation::DeleteWallet)
        .is_ok());
    assert!(matches!(
        backend.authorize_wallet_operation(Operation::PresentCredential),
        Err(error) if error.reason == RuntimeErrorReason::LifecyclePolicyDenied
    ));

    transition_backend(
        &mut backend,
        Event::BeginDeletion,
        EvidenceKind::Deletion,
        15,
    )?;
    transition_backend(
        &mut backend,
        Event::CompleteDeletion,
        EvidenceKind::Deletion,
        16,
    )?;
    // History stays readable, and leftover records can still be erased.
    for operation in [Operation::ReadTransactionHistory, Operation::DeleteWallet] {
        assert!(backend.authorize_wallet_operation(operation).is_ok());
    }
    for operation in [
        Operation::BeginIssuance,
        Operation::PresentCredential,
        Operation::SignWithWalletKey,
        Operation::RefreshCredentialStatus,
        Operation::RecordTransactionHistory,
        Operation::ReadWalletRecords,
        Operation::RenewAttestation,
    ] {
        assert!(matches!(
            backend.authorize_wallet_operation(operation),
            Err(error) if error.reason == RuntimeErrorReason::LifecyclePolicyDenied
        ));
    }
    Ok(())
}

#[test]
fn a_cached_copy_claim_cannot_replay_after_suspension() -> Result<(), TestError> {
    use super::lifecycle::{WalletLifecycleEvent, WalletLifecycleEvidenceKind};

    let mut backend = backend_with_credential(wallet::CredentialStatus::Active)?;
    backend
        .copies
        .insert("credential-1".to_owned(), presentation_copy()?);
    let mut runtime = WalletCoreRuntime::new(backend);
    let mut claim = pb::ClaimPresentationCopyRequest::default();
    claim.credential_id = "credential-1".to_owned();
    claim.copy_id = "copy-1".to_owned();
    claim.policy = super::EnumValue::from(pb::PresentationCopyClaimPolicy::Generic);
    let request = mutating_operation_request(claim.into());
    let first = runtime.execute_operation(request.clone());
    assert!(matches!(
        first.outcome,
        Some(pb::wallet_operation_response::Outcome::Result(_))
    ));

    transition_backend(
        runtime.backend_mut(),
        WalletLifecycleEvent::Suspend,
        WalletLifecycleEvidenceKind::Suspension,
        12,
    )?;
    let replay = runtime.execute_operation(request);
    assert!(response_has_runtime_reason(
        &replay,
        pb::WalletErrorReason::WALLET_ERROR_REASON_INVALID_STATE,
        pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_LIFECYCLE_POLICY_DENIED,
    ));
    Ok(())
}

#[test]
fn an_unbound_claim_does_not_reserve_an_idempotency_key() -> Result<(), TestError> {
    let mut backend = MemoryBackend::default();
    backend
        .copies
        .insert("credential-1".to_owned(), presentation_copy()?);
    let mut runtime = WalletCoreRuntime::new(backend);
    let mut claim = pb::ClaimPresentationCopyRequest::default();
    claim.credential_id = "credential-1".to_owned();
    claim.copy_id = "copy-1".to_owned();
    claim.policy = super::EnumValue::from(pb::PresentationCopyClaimPolicy::Generic);

    let response = runtime.execute_operation(mutating_operation_request(claim.into()));

    assert!(response_has_runtime_reason(
        &response,
        pb::WalletErrorReason::WALLET_ERROR_REASON_STORAGE_UNAVAILABLE,
        pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_LIFECYCLE_STORE_REJECTED,
    ));
    assert!(runtime.backend().copies.contains_key("credential-1"));
    assert!(runtime.backend().journal.is_empty());
    Ok(())
}

#[test]
fn protobuf_entitlement_operation_rejects_forged_registration_claims() -> Result<(), TestError> {
    let mut runtime = WalletCoreRuntime::new(MemoryBackend::default());
    let scope = wallet::ConsentScope {
        attributes: vec![wallet::AttributeName::new("age_over_18".to_owned())?],
    };
    let entitlement = wallet::VerifierEntitlement {
        relying_party_id: wallet::RelyingPartyId::new("rp-1".to_owned())?,
        authorized_scope: scope.clone(),
        valid_until: timestamp()?,
    };
    let request = read_operation_request(
        pb::EvaluateVerifierEntitlementRequest {
            entitlement: MessageField::some(verifier_entitlement_to_proto(&entitlement)),
            requested_scope: MessageField::some(consent_scope_to_proto(&scope)),
            now: MessageField::some(pb::UnixTimestamp {
                seconds: timestamp()?.as_seconds(),
                ..pb::UnixTimestamp::default()
            }),
            ..pb::EvaluateVerifierEntitlementRequest::default()
        }
        .into(),
    );

    let response = runtime.execute_operation(request);

    assert!(response_has_runtime_reason(
        &response,
        pb::WalletErrorReason::WALLET_ERROR_REASON_RUNTIME_REQUEST_INVALID,
        pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_OPERATION_UNSUPPORTED,
    ));
    Ok(())
}

#[test]
fn operation_executor_rejects_forged_credential_receipt() -> Result<(), TestError> {
    let mut runtime = WalletCoreRuntime::new(MemoryBackend::default());
    let request = mutating_operation_request(
        pb::PutCredentialRecordRequest {
            record: MessageField::some(credential_record_to_proto(&credential_record()?)),
            ..Default::default()
        }
        .into(),
    );

    let response = runtime.execute_operation(request);

    assert!(response_has_runtime_reason(
        &response,
        pb::WalletErrorReason::WALLET_ERROR_REASON_RUNTIME_REQUEST_INVALID,
        pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_OPERATION_UNSUPPORTED,
    ));
    assert!(runtime.backend().credentials.is_empty());
    Ok(())
}

#[test]
fn once_only_copy_replay_never_returns_the_copy_again() -> Result<(), TestError> {
    let mut backend = backend_with_credential(wallet::CredentialStatus::Active)?;
    backend
        .copies
        .insert("credential-1".to_owned(), presentation_copy()?);
    let mut runtime = WalletCoreRuntime::new(backend);
    let mut claim = pb::ClaimPresentationCopyRequest::default();
    claim.credential_id = "credential-1".to_owned();
    claim.copy_id = "copy-1".to_owned();
    claim.policy = super::EnumValue::from(pb::PresentationCopyClaimPolicy::Generic);
    let request = mutating_operation_request(claim.into());

    let first = runtime.execute_operation(request.clone());
    assert!(matches!(
        first.outcome,
        Some(pb::wallet_operation_response::Outcome::Result(_))
    ));
    let journal_entry = runtime.backend().journal.get(&[0xA5; 32]);
    assert!(
        matches!(journal_entry, Some(JournalEntry::Complete { response, .. })
        if response.starts_with(b"RMWRP002") && response.len() < 512 && !response.windows(16).any(|part| part == [3; 16]))
    );

    let replay = runtime.execute_operation(request);
    assert!(response_has_runtime_reason(
        &replay,
        pb::WalletErrorReason::WALLET_ERROR_REASON_INVALID_STATE,
        pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_PRESENTATION_COPY_ALREADY_CLAIMED,
    ));
    assert!(!runtime.backend().copies.contains_key("credential-1"));
    Ok(())
}

#[test]
fn oversized_post_claim_response_commits_a_terminal_error() -> Result<(), TestError> {
    let mut backend = backend_with_credential(wallet::CredentialStatus::Active)?;
    let mut copy = presentation_copy()?;
    copy.encrypted_payload.ciphertext = vec![0x5A; MAX_WALLET_PROTO_MESSAGE_BYTES];
    backend.copies.insert("credential-1".to_owned(), copy);
    let mut runtime = WalletCoreRuntime::new(backend);
    let mut claim = pb::ClaimPresentationCopyRequest::default();
    claim.credential_id = "credential-1".to_owned();
    claim.copy_id = "copy-1".to_owned();
    claim.policy = super::EnumValue::from(pb::PresentationCopyClaimPolicy::Generic);
    let request = mutating_operation_request(claim.into());

    let first = runtime.execute_operation(request.clone());
    assert!(response_has_runtime_reason(
        &first,
        pb::WalletErrorReason::WALLET_ERROR_REASON_SERIALIZATION_FAILED,
        pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_OPERATION_RESPONSE_TOO_LARGE,
    ));
    assert!(matches!(
        runtime.backend().journal.get(&[0xA5; 32]),
        Some(JournalEntry::Complete { .. })
    ));

    let replay = runtime.execute_operation(request);
    assert_eq!(replay, first);
    Ok(())
}

#[test]
fn canonical_mutation_requires_a_nonzero_fixed_size_idempotency_key() -> Result<(), TestError> {
    let mut runtime = WalletCoreRuntime::new(MemoryBackend {
        bound_wallet_override: Some("credential-1"),
        ..MemoryBackend::default()
    });
    let mut missing = create_lifecycle_operation_request(0x21, "credential-1")?;
    missing.idempotency_key = Vec::new();

    let missing_response = runtime.execute_operation(missing);
    assert!(response_has_runtime_reason(
        &missing_response,
        pb::WalletErrorReason::WALLET_ERROR_REASON_IDEMPOTENCY_KEY_INVALID,
        pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_IDEMPOTENCY_KEY_MISSING,
    ));

    for invalid_key in [vec![0x11; 31], vec![0_u8; 32], vec![0x11; 33]] {
        let mut request = create_lifecycle_operation_request(0x22, "credential-1")?;
        request.idempotency_key = invalid_key;
        let response = runtime.execute_operation(request);
        assert!(response_has_runtime_reason(
            &response,
            pb::WalletErrorReason::WALLET_ERROR_REASON_IDEMPOTENCY_KEY_INVALID,
            pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_IDEMPOTENCY_KEY_INVALID,
        ));
    }
    assert_eq!(runtime.backend().credential_create_count, 0);
    Ok(())
}

#[test]
fn canonical_read_rejects_an_idempotency_key() -> Result<(), TestError> {
    let mut runtime = WalletCoreRuntime::new(active_backend()?);
    let mut get = pb::GetCredentialRecordRequest::default();
    get.credential_id = "credential-1".to_owned();
    let mut request = read_operation_request(get.into());
    request.idempotency_key = vec![0x33; 32];

    let response = runtime.execute_operation(request);

    assert!(response_has_runtime_reason(
        &response,
        pb::WalletErrorReason::WALLET_ERROR_REASON_IDEMPOTENCY_KEY_INVALID,
        pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_IDEMPOTENCY_KEY_INVALID,
    ));
    Ok(())
}

#[test]
fn canonical_mutation_replay_returns_the_exact_response_without_reexecution(
) -> Result<(), TestError> {
    let mut runtime = WalletCoreRuntime::new(MemoryBackend {
        bound_wallet_override: Some("credential-replay-1"),
        ..MemoryBackend::default()
    });

    let first = runtime.execute_operation(create_lifecycle_operation_request(
        0x44,
        "credential-replay-1",
    )?);
    let replay = runtime.execute_operation(create_lifecycle_operation_request(
        0x44,
        "credential-replay-1",
    )?);

    assert_eq!(replay, first);
    assert_eq!(runtime.backend().lifecycle_create_count, 1);
    assert_eq!(runtime.backend().lifecycles.len(), 1);
    Ok(())
}

#[test]
fn lifecycle_replay_ignores_legacy_caller_time() -> Result<(), TestError> {
    let mut backend = MemoryBackend::default();
    backend
        .lifecycles
        .insert("wallet-unit-1".to_owned(), wallet_lifecycle_record()?);
    backend
        .lifecycle_revisions
        .insert("wallet-unit-1".to_owned(), super::RecordRevision::new(1));
    backend.trusted_lifecycle_authority = Some("wallet-provider-1".to_owned());
    let mut runtime = WalletCoreRuntime::new(backend);

    let mut transition = pb::ApplyWalletLifecycleEventRequest::default();
    transition.wallet_instance_id = "wallet-unit-1".to_owned();
    transition.event = super::EnumValue::from(
        pb::WalletLifecycleEvent::WALLET_LIFECYCLE_EVENT_COMPLETE_PROVISIONING,
    );
    transition.evidence = MessageField::some(wallet_lifecycle_evidence_record_to_proto(
        &wallet_lifecycle_evidence_record()?,
    ));
    let mut replay_transition = transition.clone();
    transition.now = MessageField::some(pb::UnixTimestamp {
        seconds: 4_102_444_800,
        ..Default::default()
    });
    replay_transition.now = MessageField::some(pb::UnixTimestamp {
        seconds: 11,
        ..Default::default()
    });

    let first = runtime.execute_operation(mutating_operation_request(transition.into()));
    let replay = runtime.execute_operation(mutating_operation_request(replay_transition.into()));
    assert_eq!(first, replay);
    assert!(matches!(
        first.outcome,
        Some(pb::wallet_operation_response::Outcome::Result(_))
    ));
    assert!(matches!(
        runtime.backend().lifecycle_revisions.get("wallet-unit-1"),
        Some(revision) if revision.value() == 2
    ));
    Ok(())
}

#[test]
fn canonical_mutation_rejects_a_response_replayed_for_another_request() -> Result<(), TestError> {
    let mut runtime = WalletCoreRuntime::new(MemoryBackend {
        bound_wallet_override: Some("credential-replay-binding-1"),
        ..MemoryBackend::default()
    });
    let first_key = [0x47; 32];
    let second_key = [0x48; 32];
    let _first = runtime.execute_operation(create_lifecycle_operation_request(
        first_key[0],
        "credential-replay-binding-1",
    )?);
    let _second = runtime.execute_operation(create_lifecycle_operation_request(
        second_key[0],
        "credential-replay-binding-1",
    )?);

    let second_response = match runtime.backend().journal.get(&second_key) {
        Some(JournalEntry::Complete { response, .. }) => response.clone(),
        Some(JournalEntry::InProgress { .. }) | None => {
            return Err(TestError::MissingResponseField)
        }
    };
    match runtime.backend_mut().journal.get_mut(&first_key) {
        Some(JournalEntry::Complete { response, .. }) => *response = second_response,
        Some(JournalEntry::InProgress { .. }) | None => {
            return Err(TestError::MissingResponseField)
        }
    }

    let replay = runtime.execute_operation(create_lifecycle_operation_request(
        first_key[0],
        "credential-replay-binding-1",
    )?);
    assert!(response_has_runtime_reason(
        &replay,
        pb::WalletErrorReason::WALLET_ERROR_REASON_IDEMPOTENCY_STORE_UNAVAILABLE,
        pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_IDEMPOTENCY_STORE_REJECTED,
    ));
    Ok(())
}

#[test]
fn new_idempotency_key_cannot_overwrite_an_existing_lifecycle() -> Result<(), TestError> {
    let mut runtime = WalletCoreRuntime::new(MemoryBackend {
        bound_wallet_override: Some("credential-create-only-1"),
        ..MemoryBackend::default()
    });
    let first = runtime.execute_operation(create_lifecycle_operation_request(
        0x45,
        "credential-create-only-1",
    )?);
    assert!(matches!(
        first.outcome,
        Some(pb::wallet_operation_response::Outcome::Result(_))
    ));

    let duplicate_request = create_lifecycle_operation_request(0x46, "credential-create-only-1")?;
    let duplicate = runtime.execute_operation(duplicate_request);
    assert!(response_has_runtime_reason(
        &duplicate,
        pb::WalletErrorReason::WALLET_ERROR_REASON_INVALID_STATE,
        pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_LIFECYCLE_ALREADY_EXISTS,
    ));

    let replay = runtime.execute_operation(create_lifecycle_operation_request(
        0x46,
        "credential-create-only-1",
    )?);
    assert_eq!(replay, duplicate);
    assert_eq!(runtime.backend().lifecycle_create_count, 1);
    assert_eq!(runtime.backend().lifecycles.len(), 1);
    Ok(())
}

#[test]
fn idempotency_key_reuse_for_a_different_request_fails_closed() -> Result<(), TestError> {
    let mut runtime = WalletCoreRuntime::new(MemoryBackend {
        bound_wallet_override: Some("credential-conflict-1"),
        ..MemoryBackend::default()
    });
    let first = runtime.execute_operation(create_lifecycle_operation_request(
        0x55,
        "credential-conflict-1",
    )?);
    assert!(matches!(
        first.outcome,
        Some(pb::wallet_operation_response::Outcome::Result(_))
    ));

    let changed_record = super::lifecycle::new_wallet_lifecycle(
        super::id("credential-conflict-1")?,
        super::timestamp_at(11)?,
    );
    let changed = pb::PutWalletLifecycleRecordRequest {
        record: MessageField::some(super::wallet_lifecycle_record_to_proto(&changed_record)),
        ..Default::default()
    };
    let mut changed_request = mutating_operation_request(changed.into());
    changed_request.idempotency_key = vec![0x55; 32];
    let conflict = runtime.execute_operation(changed_request);

    assert!(response_has_runtime_reason(
        &conflict,
        pb::WalletErrorReason::WALLET_ERROR_REASON_IDEMPOTENCY_CONFLICT,
        pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_IDEMPOTENCY_CONFLICT,
    ));
    assert_eq!(runtime.backend().lifecycle_create_count, 1);
    assert_eq!(runtime.backend().lifecycles.len(), 1);
    Ok(())
}

#[test]
fn lifecycle_requests_for_another_wallet_unit_are_refused() -> Result<(), TestError> {
    let mut runtime = WalletCoreRuntime::new(MemoryBackend::default());

    let response = runtime.execute_operation(create_lifecycle_operation_request(
        0x67,
        "wallet-unit-other",
    )?);

    assert!(response_has_runtime_reason(
        &response,
        pb::WalletErrorReason::WALLET_ERROR_REASON_INVALID_STATE,
        pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_LIFECYCLE_POLICY_DENIED,
    ));
    assert_eq!(runtime.backend().lifecycle_create_count, 0);
    Ok(())
}

#[test]
fn failed_journal_commit_leaves_the_mutation_in_progress() -> Result<(), TestError> {
    let backend = MemoryBackend {
        reject_journal_commit: true,
        bound_wallet_override: Some("credential-in-progress-1"),
        ..Default::default()
    };
    let mut runtime = WalletCoreRuntime::new(backend);

    let first = runtime.execute_operation(create_lifecycle_operation_request(
        0x66,
        "credential-in-progress-1",
    )?);
    assert!(response_has_runtime_reason(
        &first,
        pb::WalletErrorReason::WALLET_ERROR_REASON_IDEMPOTENCY_STORE_UNAVAILABLE,
        pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_IDEMPOTENCY_STORE_REJECTED,
    ));

    let retry = runtime.execute_operation(create_lifecycle_operation_request(
        0x66,
        "credential-in-progress-1",
    )?);
    assert!(response_has_runtime_reason(
        &retry,
        pb::WalletErrorReason::WALLET_ERROR_REASON_OPERATION_IN_PROGRESS,
        pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_OPERATION_IN_PROGRESS,
    ));
    assert_eq!(runtime.backend().lifecycle_create_count, 1);
    Ok(())
}

#[test]
fn operation_executor_returns_typed_error_for_missing_variant() {
    let mut runtime = WalletCoreRuntime::new(MemoryBackend::default());

    let response = runtime.execute_operation(pb::WalletOperationRequest::default());

    assert!(matches!(
        response.outcome,
        Some(pb::wallet_operation_response::Outcome::Error(error))
            if matches!(
                error.wallet.as_option(),
                Some(wallet_error)
                    if wallet_error.reason.as_known()
                        == Some(pb::WalletErrorReason::WALLET_ERROR_REASON_RUNTIME_REQUEST_INVALID)
                        && matches!(
                            &wallet_error.detail,
                            Some(pb::wallet_error::Detail::Runtime(reason))
                                if reason.as_known()
                                    == Some(pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_INVALID_REQUEST)
                        )
            )
    ));
}

#[test]
fn operation_executor_preserves_backend_failure_category() -> Result<(), TestError> {
    let mut runtime = WalletCoreRuntime::new(active_backend()?);
    let mut get = pb::GetCredentialRecordRequest::default();
    get.credential_id = "missing-credential".to_owned();
    let request = read_operation_request(get.into());

    let response = runtime.execute_operation(request);

    assert!(matches!(
        response.outcome,
        Some(pb::wallet_operation_response::Outcome::Error(error))
            if matches!(
                error.wallet.as_option(),
                Some(wallet_error)
                    if wallet_error.reason.as_known()
                        == Some(pb::WalletErrorReason::WALLET_ERROR_REASON_STORAGE_UNAVAILABLE)
                        && matches!(
                            &wallet_error.detail,
                            Some(pb::wallet_error::Detail::Runtime(reason))
                                if reason.as_known()
                                    == Some(
                                        pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_CREDENTIAL_STORE_REJECTED
                                    )
                        )
            )
    ));
    Ok(())
}

#[test]
fn versioned_byte_adapter_rejects_forged_credential_receipt() -> Result<(), TestError> {
    let mut runtime = WalletCoreRuntime::new(MemoryBackend::default());
    let request = mutating_operation_request(
        pb::PutCredentialRecordRequest {
            record: MessageField::some(credential_record_to_proto(&credential_record()?)),
            ..Default::default()
        }
        .into(),
    );
    let encoded_request =
        encode_wallet_operation_request(&request).map_err(|_| TestError::OperationCodec)?;

    let encoded_response = runtime
        .execute_wallet_operation_v1(&encoded_request)
        .map_err(|_| TestError::OperationCodec)?;
    let response = decode_wallet_operation_response(&encoded_response)
        .map_err(|_| TestError::OperationCodec)?;

    assert!(response_has_runtime_reason(
        &response,
        pb::WalletErrorReason::WALLET_ERROR_REASON_RUNTIME_REQUEST_INVALID,
        pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_OPERATION_UNSUPPORTED,
    ));
    Ok(())
}

#[test]
fn versioned_byte_adapter_rejects_malformed_framing() {
    let mut runtime = WalletCoreRuntime::new(MemoryBackend::default());

    let result = runtime.execute_wallet_operation_v1(&[0x0f]);

    assert!(matches!(
        result,
        Err(error) if error.reason == ProtoErrorReason::MalformedWire
    ));
}

#[test]
fn versioned_byte_adapter_rejects_oversized_input_before_decode() {
    let mut runtime = WalletCoreRuntime::new(MemoryBackend::default());
    let oversized_length = MAX_WALLET_PROTO_MESSAGE_BYTES
        .checked_add(1)
        .unwrap_or(MAX_WALLET_PROTO_MESSAGE_BYTES);
    let oversized = vec![0_u8; oversized_length];

    let result = runtime.execute_wallet_operation_v1(&oversized);

    assert!(matches!(
        result,
        Err(error) if error.reason == ProtoErrorReason::MessageTooLarge
    ));
}

#[test]
fn versioned_byte_adapter_encodes_domain_error_response() -> Result<(), TestError> {
    let mut runtime = WalletCoreRuntime::new(MemoryBackend::default());
    let encoded_request = encode_wallet_operation_request(&pb::WalletOperationRequest::default())
        .map_err(|_| TestError::OperationCodec)?;

    let encoded_response = runtime
        .execute_wallet_operation_v1(&encoded_request)
        .map_err(|_| TestError::OperationCodec)?;
    let response = decode_wallet_operation_response(&encoded_response)
        .map_err(|_| TestError::OperationCodec)?;

    assert!(matches!(
        response.outcome,
        Some(pb::wallet_operation_response::Outcome::Error(_))
    ));
    Ok(())
}

#[test]
fn type_erased_executor_preserves_the_versioned_byte_contract() -> Result<(), TestError> {
    let request = encode_wallet_operation_request(&pb::WalletOperationRequest::default())
        .map_err(|_| TestError::OperationCodec)?;
    let mut runtime = WalletCoreRuntime::new(MemoryBackend::default());
    let executor: &mut dyn WalletOperationExecutor = &mut runtime;

    let response = executor
        .execute_wallet_operation_v1(&request)
        .map_err(|_| TestError::OperationCodec)?;
    let decoded =
        decode_wallet_operation_response(&response).map_err(|_| TestError::OperationCodec)?;

    assert!(matches!(
        decoded.outcome,
        Some(pb::wallet_operation_response::Outcome::Error(_))
    ));
    Ok(())
}
