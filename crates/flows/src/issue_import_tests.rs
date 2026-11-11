// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Issued-credential import and wallet-attestation flow tests.

#[test]
fn imports_validated_credential_after_immediate_response() -> Result<(), TestError> {
    let session = token_exchanged_session_with_attestation()?;
    let session = record_openid4vci_credential_request(session, &request()?, timestamp(15)?)?;
    let response = CredentialResponse::immediate(
        vec![CredentialEnvelope {
            credential: CredentialPayload::Json(json!({"vct": "pid"})),
        }],
        None,
    )?;
    let session = record_openid4vci_credential_response(session, response)?;

    let (session, record) =
        import_openid4vci_issued_credential(session, credential_record(CredentialStatus::Active)?)?;

    assert_eq!(record.id.as_str(), "credential-1");
    assert!(matches!(
        &session.state,
        IssuanceState::CredentialStored { credential_ids }
            if credential_ids.len() == 1 && credential_ids[0].as_str() == "credential-1"
    ));
    Ok(())
}

#[test]
fn preserves_distinct_authenticated_signed_issuer() -> Result<(), TestError> {
    let session = token_exchanged_session_with_attestation()?;
    let session = record_openid4vci_credential_request(session, &request()?, timestamp(15)?)?;
    let response = CredentialResponse::immediate(
        vec![CredentialEnvelope {
            credential: CredentialPayload::Json(json!({"vct": "pid"})),
        }],
        None,
    )?;
    let session = record_openid4vci_credential_response(session, response)?;
    let mut record = credential_record(CredentialStatus::Active)?;
    record.signed_issuer = Some(SignedCredentialIssuer::new(
        "https://credential-signer.example".to_owned(),
    )?);

    let (_, imported) = import_openid4vci_issued_credential(session, record)?;

    assert!(matches!(
        imported.signed_issuer.as_ref(),
        Some(issuer) if issuer.as_str() == "https://credential-signer.example"
    ));
    Ok(())
}

#[test]
fn rejects_record_bound_to_different_metadata_issuer() -> Result<(), TestError> {
    let session = token_exchanged_session_with_attestation()?;
    let session = record_openid4vci_credential_request(session, &request()?, timestamp(15)?)?;
    let response = CredentialResponse::immediate(
        vec![CredentialEnvelope {
            credential: CredentialPayload::Json(json!({"vct": "pid"})),
        }],
        None,
    )?;
    let session = record_openid4vci_credential_response(session, response)?;
    let mut record = credential_record(CredentialStatus::Active)?;
    record.issuer_id = id("https://different-issuer.example")?;

    let result = import_openid4vci_issued_credential(session, record);

    assert!(matches!(
        result,
        Err(error) if error.reason == FlowErrorReason::InvalidCredentialReceipt
    ));
    Ok(())
}

#[test]
fn imports_each_batch_credential_as_a_distinct_inventory_record() -> Result<(), TestError> {
    let session = token_exchanged_session_with_attestation()?;
    let session = record_openid4vci_credential_request(session, &batch_request()?, timestamp(15)?)?;
    let response = CredentialResponse::immediate(
        vec![
            CredentialEnvelope {
                credential: CredentialPayload::Json(json!({"vct": "pid"})),
            },
            CredentialEnvelope {
                credential: CredentialPayload::Json(json!({"vct": "pid"})),
            },
        ],
        None,
    )?;
    let session = record_openid4vci_credential_response(session, response)?;
    let first = credential_record(CredentialStatus::Active)?;
    let mut second = credential_record(CredentialStatus::Active)?;
    second.id = id("credential-2")?;
    second.holder_key_handle_id = Some(second_credential_key_handle_id()?);

    let (session, records) = import_openid4vci_issued_credentials(session, vec![first, second])?;

    assert_eq!(records.len(), 2);
    assert!(matches!(
        &session.state,
        IssuanceState::CredentialStored { credential_ids }
            if credential_ids.len() == 2
                && credential_ids[0].as_str() == "credential-1"
                && credential_ids[1].as_str() == "credential-2"
    ));
    Ok(())
}

#[test]
fn preserves_issuer_response_order_for_batch_storage_commit() -> Result<(), TestError> {
    let session = token_exchanged_session_with_attestation()?;
    let session = record_openid4vci_credential_request(session, &batch_request()?, timestamp(15)?)?;
    let response = CredentialResponse::immediate(
        vec![
            CredentialEnvelope {
                credential: CredentialPayload::Json(json!({"vct": "pid"})),
            },
            CredentialEnvelope {
                credential: CredentialPayload::Json(json!({"vct": "pid"})),
            },
        ],
        None,
    )?;
    let session = record_openid4vci_credential_response(session, response)?;
    let mut first = credential_record(CredentialStatus::Active)?;
    first.id = id("credential-z")?;
    first.holder_key_handle_id = Some(second_credential_key_handle_id()?);
    let mut second = credential_record(CredentialStatus::Active)?;
    second.id = id("credential-a")?;
    second.holder_key_handle_id = Some(credential_key_handle_id()?);

    let (session, records) = import_openid4vci_issued_credentials(session, vec![first, second])?;

    assert_eq!(records[0].id.as_str(), "credential-z");
    assert_eq!(records[1].id.as_str(), "credential-a");
    assert!(matches!(
        &session.state,
        IssuanceState::CredentialStored { credential_ids }
            if credential_ids.len() == 2
                && credential_ids[0].as_str() == "credential-z"
                && credential_ids[1].as_str() == "credential-a"
    ));
    Ok(())
}

#[test]
fn rejects_batch_receipts_reusing_one_proof_key() -> Result<(), TestError> {
    let session = token_exchanged_session_with_attestation()?;
    let session = record_openid4vci_credential_request(session, &batch_request()?, timestamp(15)?)?;
    let response = CredentialResponse::immediate(
        vec![
            CredentialEnvelope {
                credential: CredentialPayload::Json(json!({"vct": "pid"})),
            },
            CredentialEnvelope {
                credential: CredentialPayload::Json(json!({"vct": "pid"})),
            },
        ],
        None,
    )?;
    let session = record_openid4vci_credential_response(session, response)?;
    let first = credential_record(CredentialStatus::Active)?;
    let mut second = credential_record(CredentialStatus::Active)?;
    second.id = id("credential-2")?;

    assert!(matches!(
        import_openid4vci_issued_credentials(session, vec![first, second]),
        Err(error) if error.reason == FlowErrorReason::InvalidCredentialReceipt
    ));
    Ok(())
}

#[test]
fn rejects_duplicate_batch_inventory_identifiers() -> Result<(), TestError> {
    let session = token_exchanged_session_with_attestation()?;
    let session = record_openid4vci_credential_request(session, &batch_request()?, timestamp(15)?)?;
    let response = CredentialResponse::immediate(
        vec![
            CredentialEnvelope {
                credential: CredentialPayload::Json(json!({"vct": "pid"})),
            },
            CredentialEnvelope {
                credential: CredentialPayload::Json(json!({"vct": "pid"})),
            },
        ],
        None,
    )?;
    let session = record_openid4vci_credential_response(session, response)?;
    let first = credential_record(CredentialStatus::Active)?;
    let mut duplicate = credential_record(CredentialStatus::Active)?;
    duplicate.holder_key_handle_id = Some(second_credential_key_handle_id()?);

    assert!(matches!(
        import_openid4vci_issued_credentials(session, vec![first, duplicate]),
        Err(error) if error.reason == FlowErrorReason::InvalidCredentialReceipt
    ));
    Ok(())
}

#[test]
fn rejects_import_before_credential_response() -> Result<(), TestError> {
    let session = token_exchanged_session_with_attestation()?;
    let session = record_openid4vci_credential_request(session, &request()?, timestamp(15)?)?;

    let result =
        import_openid4vci_issued_credential(session, credential_record(CredentialStatus::Active)?);

    assert!(matches!(
        result,
        Err(error) if error.reason == FlowErrorReason::InvalidTransition
    ));
    Ok(())
}

#[test]
fn rejects_deferred_import_before_polling_returns_credentials() -> Result<(), TestError> {
    let session = token_exchanged_session_with_attestation()?;
    let session = record_openid4vci_credential_request(session, &request()?, timestamp(15)?)?;
    let response = CredentialResponse::deferred("txn-1".to_owned(), 30)?;
    let session = record_openid4vci_credential_response(session, response)?;

    let result =
        import_openid4vci_issued_credential(session, credential_record(CredentialStatus::Active)?);

    assert!(matches!(
        result,
        Err(error) if error.reason == FlowErrorReason::InvalidTransition
    ));
    Ok(())
}

#[test]
fn imports_validated_credential_after_deferred_poll_response() -> Result<(), TestError> {
    let session = token_exchanged_session_with_attestation()?;
    let session = record_openid4vci_credential_request(session, &request()?, timestamp(15)?)?;
    let response = CredentialResponse::deferred("txn-1".to_owned(), 30)?;
    let session = record_openid4vci_credential_response(session, response)?;
    let response = CredentialResponse::immediate(
        vec![CredentialEnvelope {
            credential: CredentialPayload::Json(json!({"vct": "pid"})),
        }],
        None,
    )?;
    let session = record_openid4vci_deferred_credential_response(session, response)?;

    let (session, record) =
        import_openid4vci_issued_credential(session, credential_record(CredentialStatus::Active)?)?;

    assert_eq!(record.status(), CredentialStatus::Active);
    assert!(matches!(
        &session.state,
        IssuanceState::CredentialStored { credential_ids }
            if credential_ids.len() == 1 && credential_ids[0].as_str() == "credential-1"
    ));
    Ok(())
}

#[test]
fn rejects_invalid_inventory_record_at_issuance_import() -> Result<(), TestError> {
    let session = token_exchanged_session_with_attestation()?;
    let session = record_openid4vci_credential_request(session, &request()?, timestamp(15)?)?;
    let response = CredentialResponse::immediate(
        vec![CredentialEnvelope {
            credential: CredentialPayload::Json(json!({"vct": "pid"})),
        }],
        None,
    )?;
    let session = record_openid4vci_credential_response(session, response)?;

    let result = import_openid4vci_issued_credential(
        session,
        credential_record(CredentialStatus::Suspended)?,
    );

    assert!(matches!(
        result,
        Err(error) if error.reason == FlowErrorReason::InvalidCredentialReceipt
    ));
    Ok(())
}

#[test]
fn presents_bound_wallet_unit_attestation() -> Result<(), TestError> {
    let session = authorized_session_with_attestation()?;

    let presented = present_openid4vci_wallet_unit_attestation(&session, timestamp(15)?)?;

    assert_eq!(presented.id().as_str(), "wua-1");
    Ok(())
}

#[test]
fn requires_wallet_unit_attestation_before_credential_request() -> Result<(), TestError> {
    let session = start_authorization_code_issuance(offer()?)?;
    let session = record_openid4vci_consent(session, &mut crate::test_support::ApprovedIssuanceConsentProvider)?;
    let session = record_openid4vci_authorized(session)?;
    let session = record_openid4vci_token_exchanged(
        session,
        NonEmptyIdentifier::new("token-handle-1".to_owned())?,
    )?;

    let result = record_openid4vci_credential_request(session, &request()?, timestamp(15)?);

    assert!(matches!(
        result,
        Err(error) if error.reason == FlowErrorReason::WalletUnitAttestationRequired
    ));
    Ok(())
}

#[test]
fn rejects_wallet_unit_attestation_before_user_consent() -> Result<(), TestError> {
    let session = start_authorization_code_issuance(offer()?)?;

    let result = bind_openid4vci_wallet_unit_attestation(session, attestation(20)?, timestamp(15)?);

    assert!(matches!(
        result,
        Err(error) if error.reason == FlowErrorReason::InvalidTransition
    ));
    Ok(())
}

#[test]
fn rejects_expired_wallet_unit_attestation_at_binding() -> Result<(), TestError> {
    let session = start_authorization_code_issuance(offer()?)?;
    let session = record_openid4vci_consent(session, &mut crate::test_support::ApprovedIssuanceConsentProvider)?;

    let result = bind_openid4vci_wallet_unit_attestation(session, attestation(14)?, timestamp(15)?);

    assert!(matches!(
        result,
        Err(error) if error.reason == FlowErrorReason::InvalidWalletUnitAttestation
    ));
    Ok(())
}

#[test]
fn rejects_attestation_rebinding_after_credential_request() -> Result<(), TestError> {
    let session = token_exchanged_session_with_attestation()?;
    let session = record_openid4vci_credential_request(session, &request()?, timestamp(15)?)?;

    let result = bind_openid4vci_wallet_unit_attestation(session, attestation(20)?, timestamp(15)?);

    assert!(matches!(
        result,
        Err(error) if error.reason == FlowErrorReason::InvalidTransition
    ));
    Ok(())
}

#[test]
fn rejects_expired_wallet_unit_attestation_at_presentation() -> Result<(), TestError> {
    let session = authorized_session_with_attestation()?;

    let result = present_openid4vci_wallet_unit_attestation(&session, timestamp(21)?);

    assert!(matches!(
        result,
        Err(error) if error.reason == FlowErrorReason::InvalidWalletUnitAttestation
    ));
    Ok(())
}

#[test]
fn rejects_response_before_credential_request() -> Result<(), TestError> {
    let session = start_authorization_code_issuance(offer()?)?;
    let response = CredentialResponse::deferred("txn-1".to_owned(), 30)?;

    let result = record_openid4vci_credential_response(session, response);

    assert!(matches!(
        result,
        Err(error) if error.reason == FlowErrorReason::InvalidTransition
    ));
    Ok(())
}
