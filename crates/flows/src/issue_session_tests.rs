// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0


#[test]
fn builds_pre_authorized_token_request_after_consent() -> Result<(), TestError> {
    let session = start_pre_authorized_code_issuance(pre_authorized_offer()?)?;
    let session = record_openid4vci_consent(
        session,
        &mut crate::test_support::ApprovedIssuanceConsentProvider,
    )?;
    let session =
        bind_openid4vci_wallet_unit_attestation(session, attestation(30)?, timestamp(15)?)?;
    let tx_code = transaction_code("123456")?;

    let request = build_openid4vci_pre_authorized_token_request(
        &session,
        Some(&tx_code),
        Some("wallet-client".to_owned()),
    )?;
    let serialized = serde_json::to_value(&request).map_err(|_| TestError::Serde)?;

    assert_eq!(
        serialized["grant_type"],
        "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    );
    assert_eq!(serialized["pre-authorized_code"], "code-123");
    assert_eq!(serialized["tx_code"], "123456");
    assert_eq!(serialized["client_id"], "wallet-client");
    Ok(())
}

#[test]
fn rejects_pre_authorized_token_request_without_wallet_attestation() -> Result<(), TestError> {
    let session = start_pre_authorized_code_issuance(pre_authorized_offer()?)?;
    let session = record_openid4vci_consent(
        session,
        &mut crate::test_support::ApprovedIssuanceConsentProvider,
    )?;
    let tx_code = transaction_code("123456")?;

    let result = build_openid4vci_pre_authorized_token_request(&session, Some(&tx_code), None);

    assert!(matches!(
        result,
        Err(error) if error.reason == FlowErrorReason::WalletUnitAttestationRequired
    ));
    Ok(())
}

#[test]
fn rejects_pre_authorized_token_request_before_consent() -> Result<(), TestError> {
    let session = start_pre_authorized_code_issuance(pre_authorized_offer()?)?;
    let tx_code = transaction_code("123456")?;

    let result = build_openid4vci_pre_authorized_token_request(&session, Some(&tx_code), None);

    assert!(matches!(
        result,
        Err(error) if error.reason == FlowErrorReason::InvalidTransition
    ));
    Ok(())
}

#[test]
fn rejects_pre_authorized_token_request_for_authorization_code_offer() -> Result<(), TestError> {
    let session = start_authorization_code_issuance(offer()?)?;
    let session = record_openid4vci_consent(
        session,
        &mut crate::test_support::ApprovedIssuanceConsentProvider,
    )?;

    let result = build_openid4vci_pre_authorized_token_request(&session, None, None);

    assert!(matches!(
        result,
        Err(error) if error.reason == FlowErrorReason::PreAuthorizedCodeGrantRequired
    ));
    Ok(())
}

#[test]
fn rejects_missing_transaction_code_when_offer_requires_one() -> Result<(), TestError> {
    let session = start_pre_authorized_code_issuance(pre_authorized_offer()?)?;
    let session = record_openid4vci_consent(
        session,
        &mut crate::test_support::ApprovedIssuanceConsentProvider,
    )?;

    let result = build_openid4vci_pre_authorized_token_request(&session, None, None);

    assert!(matches!(
        result,
        Err(error) if error.reason == FlowErrorReason::TransactionCodeRequired
    ));
    Ok(())
}

#[test]
fn rejects_transaction_code_that_violates_offer_metadata() -> Result<(), TestError> {
    let session = start_pre_authorized_code_issuance(pre_authorized_offer()?)?;
    let session = record_openid4vci_consent(
        session,
        &mut crate::test_support::ApprovedIssuanceConsentProvider,
    )?;
    let tx_code = transaction_code("abc123")?;

    let result = build_openid4vci_pre_authorized_token_request(&session, Some(&tx_code), None);

    assert!(matches!(
        result,
        Err(error) if error.reason == FlowErrorReason::TransactionCodeInvalidForOffer
    ));
    Ok(())
}

#[test]
fn records_token_exchange_before_credential_request() -> Result<(), TestError> {
    let session = authorized_session_with_attestation()?;

    let session = record_openid4vci_token_exchanged(
        session,
        NonEmptyIdentifier::new("token-handle-1".to_owned())?,
    )?;
    let session = record_openid4vci_credential_request(session, &request()?, timestamp(15)?)?;

    assert!(matches!(session.state, IssuanceState::TokenExchanged));
    assert!(session.credential_request.is_some());
    Ok(())
}

#[test]
fn accepts_a_verified_credential_key_distinct_from_the_wallet_attestation_key(
) -> Result<(), TestError> {
    let session = token_exchanged_session_with_attestation()?;

    let session = record_openid4vci_credential_request(session, &request()?, timestamp(15)?)?;

    assert!(session.credential_request.is_some());
    Ok(())
}

#[test]
fn rejects_a_proof_verifier_bound_to_a_different_wallet_unit_key() -> Result<(), TestError> {
    let session = token_exchanged_session_with_attestation()?;

    let result = record_verified_credential_request(
        session,
        &request()?,
        timestamp(15)?,
        &WrongWalletUnitProofVerifier,
    );

    assert!(matches!(
        result,
        Err(error) if error.reason == FlowErrorReason::InvalidOpenId4VciState
    ));
    Ok(())
}

#[test]
fn rejects_holder_proof_reusing_wallet_unit_key() -> Result<(), TestError> {
    let session = token_exchanged_session_with_attestation()?;
    let result = record_verified_credential_request(
        session,
        &request()?,
        timestamp(15)?,
        &SharedWalletUnitProofVerifier,
    );
    assert!(matches!(
        result,
        Err(error) if error.reason == FlowErrorReason::InvalidOpenId4VciState
    ));
    Ok(())
}

#[test]
fn rejects_batch_proofs_reusing_one_credential_key() -> Result<(), TestError> {
    let session = token_exchanged_session_with_attestation()?;

    let result = record_verified_credential_request(
        session,
        &batch_request()?,
        timestamp(15)?,
        &DuplicateCredentialKeyProofVerifier,
    );

    assert!(matches!(
        result,
        Err(error) if error.reason == FlowErrorReason::InvalidOpenId4VciState
    ));
    Ok(())
}

#[test]
fn accepts_attestation_batch_with_distinct_verified_holder_keys() -> Result<(), TestError> {
    let session = token_exchanged_session_with_attestation()?;
    let request = prepared_credential_request(
        Some(Proofs {
            jwt: Vec::new(),
            di_vp: Vec::new(),
            attestation: vec!["attestation-1".to_owned()],
        }),
        None,
    )?;
    let session = record_verified_credential_request(
        session,
        &request,
        timestamp(15)?,
        &AttestationBatchProofVerifier,
    )?;
    assert_eq!(session.credential_binding_key_handle_ids().len(), 2);
    assert_ne!(
        session.credential_binding_key_handle_ids()[0],
        session.credential_binding_key_handle_ids()[1]
    );
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
    assert!(matches!(session.state, IssuanceState::CredentialReceived));
    Ok(())
}

#[test]
fn attestation_batch_rejects_oversized_verified_key_count() {
    let proofs = Proofs {
        jwt: Vec::new(),
        di_vp: Vec::new(),
        attestation: vec!["attestation-1".to_owned()],
    };
    assert!(!crate::validate_credential_request::proof_shape_matches_binding(&proofs, 1_025));
}

#[test]
fn resumable_issuance_state_excludes_transport_dpop_proof() -> Result<(), TestError> {
    let session = token_exchanged_session_with_attestation()?;
    let transport_request = prepared_credential_request(
        Some(Proofs {
            jwt: vec!["proof-1".to_owned()],
            di_vp: Vec::new(),
            attestation: Vec::new(),
        }),
        Some("header.payload.signature".to_owned()),
    )?;

    let session =
        record_openid4vci_credential_request(session, &transport_request, timestamp(15)?)?;
    let stored_request = session
        .credential_request
        .as_ref()
        .ok_or(TestError::MissingCredentialRequest)?;

    assert_eq!(
        stored_request.credential_configuration_id.as_deref(),
        Some("pid")
    );
    assert!(transport_request.dpop_proof_jwt().is_some());
    Ok(())
}

#[test]
fn restricted_reuse_policy_requires_an_explicit_wallet_capability() -> Result<(), TestError> {
    let mut metadata = issuer_metadata()?;
    let configuration = metadata
        .credential_configurations_supported
        .get_mut("pid")
        .ok_or(TestError::MissingCredentialRequest)?;
    configuration.credential_metadata = Some(json!({
        "credential_reuse_policy": {
            "id": "arf_annex_ii",
            "options": [{
                "details": ["once_only"],
                "batch_size": 4,
                "reissue_trigger_unused": 1
            }]
        }
    }));
    let offer = CredentialOffer::authorization_code(
        "https://issuer.example".to_owned(),
        vec!["pid".to_owned()],
        None,
    )?;

    let result = crate::start_openid4vci_issuance(
        offer,
        &metadata,
        CredentialOfferGrantType::AuthorizationCode,
        "https://issuer.example".to_owned(),
    );

    assert!(matches!(
        result,
        Err(error) if error.reason == FlowErrorReason::UnsupportedCredentialReusePolicy
    ));
    Ok(())
}

