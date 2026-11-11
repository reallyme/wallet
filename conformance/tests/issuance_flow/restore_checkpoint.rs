// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Authenticate Wallet Unit issuance checkpoints before restoring consent or token stages.

use reallyme_openid4vci_wallet::CredentialOfferGrantType;
use reallyme_wallet::flows::{
    record_openid4vci_authorized, record_openid4vci_consent, restore_openid4vci_issuance_session,
    FlowErrorReason, IssuanceState,
};

use super::{
    bind_authorization_code_token, id, issuer_metadata, no_restricted_reuse_methods, offer,
    start_authorization_code_issuance, wallet_unit_attestation, AcceptProofVerifier,
    ApprovedIssuanceConsentProvider, TestError,
};

#[test]
fn authorization_code_session_restores_after_token_binding_without_attestation(
) -> Result<(), TestError> {
    let session = start_authorization_code_issuance(offer()?)?;
    let session = record_openid4vci_consent(session, &mut ApprovedIssuanceConsentProvider)?;
    let session = record_openid4vci_authorized(session)?;
    let (session, _) = bind_authorization_code_token(&session)?;
    assert!(session.wallet_unit_attestation().is_none());
    let checkpoint_key = reallyme_wallet::flows::IssuanceCheckpointKey::new(
        secrecy::SecretBox::new(Box::new([0x2a; 32])),
    )?;
    let tag = checkpoint_key.seal(&session)?;

    let restored = restore_openid4vci_issuance_session(
        IssuanceState::TokenExchanged,
        offer()?,
        &issuer_metadata()?,
        CredentialOfferGrantType::AuthorizationCode,
        "https://issuer.example".to_owned(),
        no_restricted_reuse_methods()?,
        None,
        Vec::new(),
        None,
        None,
        None,
        session.access_token_binding_handle().cloned(),
        &AcceptProofVerifier,
        Some(reallyme_wallet::flows::IssuanceResumeProof::new(
            &checkpoint_key,
            &tag,
        )),
    )?;
    assert_eq!(restored.state(), &IssuanceState::TokenExchanged);
    Ok(())
}

#[test]
fn restore_refuses_consent_states_without_consent_evidence() -> Result<(), TestError> {
    for state in [
        IssuanceState::ConsentCaptured,
        IssuanceState::Authorized,
        IssuanceState::TokenExchanged,
    ] {
        let (attestation, token) = if state == IssuanceState::TokenExchanged {
            (
                Some(wallet_unit_attestation()?),
                Some(id("token-handle-1")?),
            )
        } else {
            (None, None)
        };
        let restored = restore_openid4vci_issuance_session(
            state,
            offer()?,
            &issuer_metadata()?,
            CredentialOfferGrantType::AuthorizationCode,
            "https://issuer.example".to_owned(),
            no_restricted_reuse_methods()?,
            None,
            Vec::new(),
            attestation,
            None,
            None,
            token,
            &AcceptProofVerifier,
            None,
        );
        assert!(matches!(
            restored,
            Err(error) if error.reason == FlowErrorReason::InvalidOpenId4VciState
        ));
    }

    let offer_stage = restore_openid4vci_issuance_session(
        IssuanceState::OfferReceived,
        offer()?,
        &issuer_metadata()?,
        CredentialOfferGrantType::AuthorizationCode,
        "https://issuer.example".to_owned(),
        no_restricted_reuse_methods()?,
        None,
        Vec::new(),
        None,
        None,
        None,
        None,
        &AcceptProofVerifier,
        None,
    )?;
    let consented = record_openid4vci_consent(offer_stage, &mut ApprovedIssuanceConsentProvider)?;
    assert_eq!(consented.state(), &IssuanceState::ConsentCaptured);
    Ok(())
}
