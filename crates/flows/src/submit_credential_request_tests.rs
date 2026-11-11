// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use openid4vci_types::{CredentialEnvelope, CredentialPayload, CredentialResponse, Proofs};
use reallyme_openid4vci_wallet::WalletCredentialRequest;
use reallyme_wallet_attestation::{
    verify_wallet_unit_attestation, AttestationResult, UnverifiedWalletUnitAttestation,
    WalletUnitAttestation, WalletUnitAttestationVerifier,
};
use reallyme_wallet_keystore::KeyAttestationEvidence;
use reallyme_wallet_types::{NonEmptyIdentifier, UnixTimestamp, WalletTypesError};
use serde_json::json;

#[path = "submit_recorded_credential_tests.rs"]
mod recorded_dispatch_tests;

use crate::exchange_pre_authorized_token::test_support::token_handle_for_session;
use crate::test_support::{prepared_credential_request, start_authorization_code_issuance};
use crate::{
    bind_openid4vci_wallet_unit_attestation, record_openid4vci_authorized,
    record_openid4vci_consent, record_openid4vci_credential_request,
    record_openid4vci_token_exchanged, submit_openid4vci_credential_request,
    submit_recorded_openid4vci_credential_request, CredentialProofBinding,
    CredentialRequestProofBinding, CredentialRequestProofVerifier, FlowError, FlowErrorReason,
    FlowResult, IssuanceState, OpenId4VciAccessTokenHandle, OpenId4VciCredentialRequester,
    OpenId4VciIssuanceSession, PreparedOpenId4VciCredentialRequest,
};

struct AcceptProofVerifier;

impl CredentialRequestProofVerifier for AcceptProofVerifier {
    fn verify_credential_request_proof(
        &self,
        _request: &openid4vci_types::CredentialRequest,
    ) -> FlowResult<CredentialRequestProofBinding> {
        Ok(CredentialRequestProofBinding {
            proofs: vec![CredentialProofBinding {
                nonce_digest: None,
                audience: "https://issuer.example".to_owned(),
                holder_key_handle_id: reallyme_wallet_types::KeyHandleId::new(
                    "holder-key-1".to_owned(),
                )
                .map_err(|_| FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?,
                issued_at: timestamp(20)
                    .map_err(|_| FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?,
            }],
            wallet_unit_key_handle_id: reallyme_wallet_types::KeyHandleId::new("key-1".to_owned())
                .map_err(|_| FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?,
        })
    }
}

struct AcceptRequester;

impl OpenId4VciCredentialRequester for AcceptRequester {
    fn submit_credential_request(
        &mut self,
        token_handle: &OpenId4VciAccessTokenHandle,
        _request: &WalletCredentialRequest,
    ) -> Result<CredentialResponse, FlowError> {
        if token_handle.id().as_str() != "token-handle-1" {
            return Err(FlowError::new(
                FlowErrorReason::OpenId4VciIssuerTransportRejected,
            ));
        }

        CredentialResponse::immediate(
            vec![CredentialEnvelope {
                credential: CredentialPayload::Json(json!({"vct": "pid"})),
            }],
            None,
        )
        .map_err(|_| FlowError::new(FlowErrorReason::OpenId4VciIssuerTransportRejected))
    }
}

struct RejectRequester;

impl OpenId4VciCredentialRequester for RejectRequester {
    fn submit_credential_request(
        &mut self,
        _token_handle: &OpenId4VciAccessTokenHandle,
        _request: &WalletCredentialRequest,
    ) -> Result<CredentialResponse, FlowError> {
        Err(FlowError::new(
            FlowErrorReason::OpenId4VciIssuerTransportRejected,
        ))
    }
}

fn id(value: &str) -> Result<NonEmptyIdentifier, WalletTypesError> {
    NonEmptyIdentifier::new(value.to_owned())
}

fn timestamp(seconds: i64) -> Result<UnixTimestamp, WalletTypesError> {
    UnixTimestamp::from_seconds(seconds)
}

struct AcceptAttestationVerifier;

impl WalletUnitAttestationVerifier for AcceptAttestationVerifier {
    fn verify_wallet_unit_attestation(
        &self,
        _attestation: &UnverifiedWalletUnitAttestation,
        _now: UnixTimestamp,
    ) -> AttestationResult<reallyme_wallet_attestation::VerifiedWalletKeyThumbprint> {
        reallyme_wallet_attestation::VerifiedWalletKeyThumbprint::new([1; 32])
    }
}

fn attestation() -> Result<WalletUnitAttestation, TestError> {
    let unverified = UnverifiedWalletUnitAttestation::new(
        id("wua-1")?,
        KeyAttestationEvidence {
            key_handle_id: reallyme_wallet_types::KeyHandleId::new("key-1".to_owned())?,
            evidence: vec![1, 2, 3],
            issued_at: timestamp(10)?,
            challenge: [7; 32],
        },
        timestamp(30)?,
        vec![9, 8, 7],
    )?;
    Ok(verify_wallet_unit_attestation(
        unverified,
        &AcceptAttestationVerifier,
        timestamp(10)?,
    )?)
}

fn credential_request() -> FlowResult<PreparedOpenId4VciCredentialRequest> {
    prepared_credential_request(
        Some(Proofs {
            jwt: vec!["proof-1".to_owned()],
            di_vp: Vec::new(),
            attestation: Vec::new(),
        }),
        None,
    )
}

fn token_handle(
    session: &OpenId4VciIssuanceSession,
) -> Result<OpenId4VciAccessTokenHandle, WalletTypesError> {
    Ok(token_handle_for_session(id("token-handle-1")?, session))
}

fn token_exchanged_session() -> Result<OpenId4VciIssuanceSession, TestError> {
    let offer = openid4vci_types::CredentialOffer::authorization_code(
        "https://issuer.example".to_owned(),
        vec!["pid".to_owned()],
        None,
    )?;
    let session = start_authorization_code_issuance(offer)?;
    let session = record_openid4vci_consent(
        session,
        &mut crate::test_support::ApprovedIssuanceConsentProvider,
    )?;
    let session = bind_openid4vci_wallet_unit_attestation(session, attestation()?, timestamp(20)?)?;
    let session = record_openid4vci_authorized(session)?;
    Ok(record_openid4vci_token_exchanged(
        session,
        NonEmptyIdentifier::new("token-handle-1".to_owned())?,
    )?)
}

#[test]
fn submit_records_valid_credential_response_after_transport_accepts() -> Result<(), TestError> {
    let session = token_exchanged_session()?;
    let token_handle = token_handle(&session)?;
    let mut requester = AcceptRequester;

    let session = submit_openid4vci_credential_request(
        &session,
        &token_handle,
        &credential_request()?,
        timestamp(20)?,
        &AcceptProofVerifier,
        &mut requester,
    )?;

    assert!(matches!(session.state, IssuanceState::CredentialReceived));
    assert!(session.credential_response.is_some());
    Ok(())
}

#[test]
fn an_issuer_refusal_is_definitive_and_a_new_request_can_be_sent() -> Result<(), TestError> {
    let session = token_exchanged_session()?;
    let token_handle = token_handle(&session)?;

    let refused = submit_openid4vci_credential_request(
        &session,
        &token_handle,
        &credential_request()?,
        timestamp(20)?,
        &AcceptProofVerifier,
        &mut RejectRequester,
    );
    assert!(matches!(
        refused,
        Err(error) if error.reason == FlowErrorReason::OpenId4VciIssuerTransportRejected
    ));
    assert!(session.credential_response.is_none());

    // The borrowed session is unchanged, so a new request is recorded and sent.
    let accepted = submit_openid4vci_credential_request(
        &session,
        &token_handle,
        &credential_request()?,
        timestamp(20)?,
        &AcceptProofVerifier,
        &mut AcceptRequester,
    )?;
    assert!(accepted.credential_response.is_some());
    Ok(())
}

/// Transport that fails without saying whether the issuer received anything.
struct LostRequester {
    calls: usize,
}

impl OpenId4VciCredentialRequester for LostRequester {
    fn submit_credential_request(
        &mut self,
        _token_handle: &OpenId4VciAccessTokenHandle,
        _request: &WalletCredentialRequest,
    ) -> Result<CredentialResponse, FlowError> {
        self.calls = self.calls.saturating_add(1);
        Err(FlowError::new(FlowErrorReason::InvalidOpenId4VciState))
    }
}

#[test]
fn an_uncertain_delivery_is_never_sent_again_from_the_same_recording() -> Result<(), TestError> {
    let session = token_exchanged_session()?;
    let token_handle = token_handle(&session)?;
    let request = credential_request()?;
    let recorded = crate::record_openid4vci_credential_request(
        session,
        &request,
        timestamp(20)?,
        &AcceptProofVerifier,
    )?;
    let mut lost = LostRequester { calls: 0 };

    for _attempt in 0..2 {
        let result = crate::submit_recorded_openid4vci_credential_request(
            &recorded.clone(),
            &token_handle,
            &request,
            timestamp(20)?,
            &AcceptProofVerifier,
            &mut lost,
        );
        assert!(matches!(
            result,
            Err(error) if error.reason == FlowErrorReason::CredentialSubmissionUncertain
        ));
    }
    assert_eq!(lost.calls, 1);
    Ok(())
}

#[test]
fn submit_rejects_request_prepared_under_different_issuer_metadata() -> Result<(), TestError> {
    let session = token_exchanged_session()?;
    let token_handle = token_handle(&session)?;
    let mut other_session = session.clone();
    let mut other_metadata = session.issuer_metadata.as_ref().clone();
    other_metadata.nonce_endpoint = Some("https://issuer.example/nonce".to_owned());
    other_session.issuer_metadata = std::sync::Arc::new(other_metadata);
    let request = crate::prepare_openid4vci_credential_request(
        &other_session,
        "pid".to_owned(),
        Some(Proofs {
            jwt: vec!["proof-1".to_owned()],
            di_vp: Vec::new(),
            attestation: Vec::new(),
        }),
        None,
        None,
    )?;
    let mut requester = AcceptRequester;

    let result = submit_openid4vci_credential_request(
        &session,
        &token_handle,
        &request,
        timestamp(20)?,
        &AcceptProofVerifier,
        &mut requester,
    );

    assert!(matches!(
        result,
        Err(error) if error.reason == FlowErrorReason::InvalidOpenId4VciState
    ));
    assert!(session.credential_request.is_none());
    Ok(())
}

#[test]
fn submit_rejects_nonce_endpoint_without_a_trusted_nonce_binding() -> Result<(), TestError> {
    let mut session = token_exchanged_session()?;
    let mut metadata = session.issuer_metadata.as_ref().clone();
    metadata.nonce_endpoint = Some("https://issuer.example/nonce".to_owned());
    session.issuer_metadata = std::sync::Arc::new(metadata);
    let token_handle = token_handle(&session)?;
    let request = crate::prepare_openid4vci_credential_request(
        &session,
        "pid".to_owned(),
        Some(Proofs {
            jwt: vec!["proof-1".to_owned()],
            di_vp: Vec::new(),
            attestation: Vec::new(),
        }),
        None,
        None,
    )?;
    let mut requester = AcceptRequester;

    let result = submit_openid4vci_credential_request(
        &session,
        &token_handle,
        &request,
        timestamp(20)?,
        &AcceptProofVerifier,
        &mut requester,
    );

    assert!(matches!(
        result,
        Err(error)
            if error.reason == FlowErrorReason::CredentialProofNonceBindingUnavailable
    ));
    assert!(session.credential_request.is_none());
    Ok(())
}

#[derive(Debug, thiserror::Error)]
enum TestError {
    #[error("flow")]
    Flow(#[from] crate::FlowError),
    #[error("reallyme_openid4vci_wallet")]
    Wallet(#[from] reallyme_openid4vci_wallet::WalletError),
    #[error("openid4vci")]
    OpenId4Vci(#[from] openid4vci_types::OpenId4VciError),
    #[error("wallet_types")]
    WalletTypes(#[from] reallyme_wallet_types::WalletTypesError),
    #[error("attestation")]
    Attestation(#[from] reallyme_wallet_attestation::AttestationError),
}

struct NonceProofVerifier(Option<[u8; 32]>);
impl CredentialRequestProofVerifier for NonceProofVerifier {
    fn verify_credential_request_proof(
        &self,
        request: &openid4vci_types::CredentialRequest,
    ) -> FlowResult<CredentialRequestProofBinding> {
        let mut binding = AcceptProofVerifier.verify_credential_request_proof(request)?;
        for proof in &mut binding.proofs {
            proof.nonce_digest = self.0;
        }
        Ok(binding)
    }
}
fn nonce_bound_session() -> Result<OpenId4VciIssuanceSession, TestError> {
    let mut session = token_exchanged_session()?;
    let mut metadata = session.issuer_metadata.as_ref().clone();
    metadata.nonce_endpoint = Some("https://issuer.example/nonce".into());
    session.issuer_metadata = std::sync::Arc::new(metadata);
    let binding = reallyme_wallet_types::IssuerNonceBinding {
        nonce_digest: [7; 32],
        session_digest: crate::issuer_nonce_session_digest(&session)?,
        received_at: timestamp(19)?,
        expires_at: timestamp(25)?,
    };
    crate::bind_openid4vci_issuer_nonce(&mut session, binding, timestamp(20)?)?;
    Ok(session)
}
fn nonce_request(
    session: &OpenId4VciIssuanceSession,
) -> FlowResult<PreparedOpenId4VciCredentialRequest> {
    crate::prepare_openid4vci_credential_request(
        session,
        "pid".into(),
        Some(Proofs {
            jwt: vec!["proof-1".into()],
            di_vp: vec![],
            attestation: vec![],
        }),
        None,
        None,
    )
}
#[test]
fn nonce_observation_and_authenticated_proof_allow_submission_and_restore() -> Result<(), TestError>
{
    let session = nonce_bound_session()?;
    let token = token_handle(&session)?;
    let received = submit_openid4vci_credential_request(
        &session,
        &token,
        &nonce_request(&session)?,
        timestamp(20)?,
        &NonceProofVerifier(Some([7; 32])),
        &mut AcceptRequester,
    )?;
    let offer = openid4vci_types::CredentialOffer::authorization_code(
        "https://issuer.example".into(),
        vec!["pid".into()],
        None,
    )?;
    let checkpoint_key =
        crate::IssuanceCheckpointKey::new(secrecy::SecretBox::new(Box::new([0x2a; 32])))?;
    let tag = checkpoint_key.seal(&received)?;
    let restored = crate::restore_openid4vci_issuance_session_with_nonce_binding(
        received.state.clone(),
        offer,
        &session.issuer_metadata,
        reallyme_openid4vci_wallet::CredentialOfferGrantType::AuthorizationCode,
        "https://issuer.example".into(),
        openid4vci_profiles::ReuseMethodSet::new(0)
            .map_err(|_| FlowError::new(FlowErrorReason::InvalidCredentialReusePolicy))?,
        received.credential_request.clone(),
        received.credential_binding_key_handle_ids.clone(),
        received.wallet_unit_attestation.clone(),
        received.credential_response.clone(),
        None,
        received.access_token_binding_handle.clone(),
        &NonceProofVerifier(Some([7; 32])),
        Some(crate::IssuanceResumeProof::new(&checkpoint_key, &tag)),
        received.issuer_nonce_binding.clone(),
    )?;
    assert!(matches!(restored.state, IssuanceState::CredentialReceived));
    assert!(restored.issuer_nonce_binding == received.issuer_nonce_binding);
    Ok(())
}
#[test]
fn missing_changed_expired_and_wrong_session_nonce_fail_before_transport() -> Result<(), TestError>
{
    let session = nonce_bound_session()?;
    let token = token_handle(&session)?;
    for digest in [None, Some([8; 32])] {
        let result = submit_openid4vci_credential_request(
            &session,
            &token,
            &nonce_request(&session)?,
            timestamp(20)?,
            &NonceProofVerifier(digest),
            &mut AcceptRequester,
        );
        assert!(
            matches!(result,Err(error) if error.reason==FlowErrorReason::CredentialProofNonceBindingUnavailable)
        );
    }
    let result = submit_openid4vci_credential_request(
        &session,
        &token,
        &nonce_request(&session)?,
        timestamp(25)?,
        &NonceProofVerifier(Some([7; 32])),
        &mut AcceptRequester,
    );
    assert!(
        matches!(result,Err(error) if error.reason==FlowErrorReason::CredentialProofNonceBindingUnavailable)
    );
    let mut wrong = session.clone();
    wrong.access_token_binding_handle = Some(id("other-token")?);
    let result = crate::bind_issuer_nonce::validate_nonce_binding(
        &wrong,
        &NonceProofVerifier(Some([7; 32])).verify_credential_request_proof(
            &openid4vci_types::CredentialRequest {
                credential_configuration_id: Some("pid".into()),
                credential_identifier: None,
                proofs: None,
                credential_response_encryption: None,
                reallyme_zk_v1_issuance: None,
            },
        )?,
        Some(timestamp(20)?),
    );
    assert!(
        matches!(result,Err(error) if error.reason==FlowErrorReason::CredentialProofNonceBindingUnavailable)
    );
    assert!(session.credential_request.is_none());
    Ok(())
}

#[test]
fn recorded_request_is_retained_and_refuses_resend_after_a_transport_failure(
) -> Result<(), TestError> {
    let session = token_exchanged_session()?;
    let token_handle = token_handle(&session)?;
    let request = credential_request()?;
    let requested = record_openid4vci_credential_request(
        session,
        &request,
        timestamp(20)?,
        &AcceptProofVerifier,
    )?;

    // The recorded proof bytes survive the issuer's refusal, but this
    // recording is spent: it is never dispatched a second time.
    let failed = submit_recorded_openid4vci_credential_request(
        &requested,
        &token_handle,
        &request,
        timestamp(20)?,
        &AcceptProofVerifier,
        &mut RejectRequester,
    );
    assert!(matches!(
        failed,
        Err(error) if error.reason == FlowErrorReason::OpenId4VciIssuerTransportRejected
    ));
    assert!(requested.credential_response.is_none());

    assert_eq!(
        requested.credential_request(),
        Some(&request.canonical_request)
    );
    let retry = submit_recorded_openid4vci_credential_request(
        &requested.clone(),
        &token_handle,
        &request,
        timestamp(20)?,
        &AcceptProofVerifier,
        &mut AcceptRequester,
    );
    assert!(matches!(
        retry,
        Err(error) if error.reason == FlowErrorReason::CredentialSubmissionUncertain
    ));
    Ok(())
}

#[test]
fn recorded_session_rejects_a_request_rebuilt_with_new_proofs() -> Result<(), TestError> {
    let session = token_exchanged_session()?;
    let token_handle = token_handle(&session)?;
    let requested = record_openid4vci_credential_request(
        session.clone(),
        &credential_request()?,
        timestamp(20)?,
        &AcceptProofVerifier,
    )?;
    let rebuilt = prepared_credential_request(
        Some(Proofs {
            jwt: vec!["proof-2".to_owned()],
            di_vp: Vec::new(),
            attestation: Vec::new(),
        }),
        None,
    )?;

    for candidate in [&session, &requested] {
        let result = submit_recorded_openid4vci_credential_request(
            candidate,
            &token_handle,
            &rebuilt,
            timestamp(20)?,
            &AcceptProofVerifier,
            &mut AcceptRequester,
        );
        assert!(matches!(
            result,
            Err(error) if error.reason == FlowErrorReason::InvalidOpenId4VciState
        ));
    }
    Ok(())
}

#[test]
fn bound_attestation_cannot_be_swapped_after_token_exchange() -> Result<(), TestError> {
    let session = token_exchanged_session()?;
    assert!(session.wallet_unit_attestation.is_some());
    let result = bind_openid4vci_wallet_unit_attestation(session, attestation()?, timestamp(20)?);
    assert!(matches!(
        result,
        Err(error) if error.reason == FlowErrorReason::InvalidTransition
    ));
    Ok(())
}

#[test]
fn authorization_code_token_requires_completed_authorization() -> Result<(), TestError> {
    let offer = openid4vci_types::CredentialOffer::authorization_code(
        "https://issuer.example".to_owned(),
        vec!["pid".to_owned()],
        None,
    )?;
    let session = start_authorization_code_issuance(offer)?;
    let session = record_openid4vci_consent(
        session,
        &mut crate::test_support::ApprovedIssuanceConsentProvider,
    )?;
    let handle = OpenId4VciAccessTokenHandle::from_transport(id("token-handle-1")?);
    let result = crate::bind_openid4vci_authorization_code_token(&session, handle);
    assert!(matches!(
        result,
        Err(error) if error.reason == FlowErrorReason::InvalidTransition
    ));
    Ok(())
}

#[test]
fn uncertain_submission_is_reconciled_without_resending() -> Result<(), TestError> {
    let session = token_exchanged_session()?;
    let token_handle = token_handle(&session)?;
    let request = credential_request()?;
    let requested = record_openid4vci_credential_request(
        session.clone(),
        &request,
        timestamp(20)?,
        &AcceptProofVerifier,
    )?;
    let failed = submit_recorded_openid4vci_credential_request(
        &requested,
        &token_handle,
        &request,
        timestamp(20)?,
        &AcceptProofVerifier,
        &mut RejectRequester,
    );
    assert!(failed.is_err());

    let recovered = CredentialResponse::immediate(
        vec![CredentialEnvelope {
            credential: CredentialPayload::Json(json!({"vct": "pid"})),
        }],
        None,
    )?;
    let reconciled = requested.record_reconciled_credential_response(&request, recovered)?;
    assert!(matches!(
        reconciled.state,
        IssuanceState::CredentialReceived
    ));

    // A session that never recorded this request cannot absorb a response.
    let unrecorded = CredentialResponse::immediate(
        vec![CredentialEnvelope {
            credential: CredentialPayload::Json(json!({"vct": "pid"})),
        }],
        None,
    )?;
    assert!(matches!(
        session.record_reconciled_credential_response(&request, unrecorded),
        Err(error) if error.reason == FlowErrorReason::InvalidOpenId4VciState
    ));
    Ok(())
}
