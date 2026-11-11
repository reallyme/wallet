// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use openid4vci_types::{
    CredentialEnvelope, CredentialPayload, CredentialResponse, DeferredCredentialRequest, Proofs,
};
use reallyme_wallet_attestation::{
    verify_wallet_unit_attestation, AttestationResult, UnverifiedWalletUnitAttestation,
    WalletUnitAttestation, WalletUnitAttestationVerifier,
};
use reallyme_wallet_keystore::KeyAttestationEvidence;
use reallyme_wallet_types::{NonEmptyIdentifier, UnixTimestamp, WalletTypesError};
use serde_json::json;

use crate::exchange_pre_authorized_token::test_support::token_handle_for_session;
use crate::test_support::{prepared_credential_request, start_authorization_code_issuance};
use crate::{
    bind_openid4vci_wallet_unit_attestation, build_openid4vci_deferred_credential_request,
    poll_openid4vci_deferred_credential, record_openid4vci_authorized, record_openid4vci_consent,
    record_openid4vci_credential_request as record_verified_credential_request,
    record_openid4vci_credential_response, record_openid4vci_token_exchanged,
    CredentialProofBinding, CredentialRequestProofBinding, CredentialRequestProofVerifier,
    FlowError, FlowErrorReason, FlowResult, IssuanceState, OpenId4VciAccessTokenHandle,
    OpenId4VciDeferredCredentialRequester, OpenId4VciIssuanceSession,
    PreparedOpenId4VciCredentialRequest,
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

struct AcceptDeferredRequester;

impl OpenId4VciDeferredCredentialRequester for AcceptDeferredRequester {
    fn request_deferred_credential(
        &mut self,
        token_handle: &OpenId4VciAccessTokenHandle,
        request: &DeferredCredentialRequest,
    ) -> Result<CredentialResponse, FlowError> {
        if token_handle.id().as_str() != "token-handle-1"
            || request.transaction_id.as_str() != "txn-1"
        {
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

struct PendingThenAcceptDeferredRequester {
    request_count: u8,
}

impl OpenId4VciDeferredCredentialRequester for PendingThenAcceptDeferredRequester {
    fn request_deferred_credential(
        &mut self,
        token_handle: &OpenId4VciAccessTokenHandle,
        request: &DeferredCredentialRequest,
    ) -> Result<CredentialResponse, FlowError> {
        if token_handle.id().as_str() != "token-handle-1" {
            return Err(FlowError::new(
                FlowErrorReason::OpenId4VciIssuerTransportRejected,
            ));
        }
        let response = match self.request_count {
            0 if request.transaction_id == "txn-1" => {
                CredentialResponse::deferred("txn-1".to_owned(), 45)
            }
            1 if request.transaction_id == "txn-1" => CredentialResponse::immediate(
                vec![CredentialEnvelope {
                    credential: CredentialPayload::Json(json!({"vct": "pid"})),
                }],
                None,
            ),
            _ => {
                return Err(FlowError::new(
                    FlowErrorReason::OpenId4VciIssuerTransportRejected,
                ));
            }
        };
        self.request_count = self
            .request_count
            .checked_add(1)
            .ok_or_else(|| FlowError::new(FlowErrorReason::OpenId4VciIssuerTransportRejected))?;
        response.map_err(|_| FlowError::new(FlowErrorReason::OpenId4VciIssuerTransportRejected))
    }
}

struct RejectDeferredRequester;

impl OpenId4VciDeferredCredentialRequester for RejectDeferredRequester {
    fn request_deferred_credential(
        &mut self,
        _token_handle: &OpenId4VciAccessTokenHandle,
        _request: &DeferredCredentialRequest,
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

fn record_openid4vci_credential_request(
    session: OpenId4VciIssuanceSession,
    request: &PreparedOpenId4VciCredentialRequest,
    now: UnixTimestamp,
) -> FlowResult<OpenId4VciIssuanceSession> {
    record_verified_credential_request(session, request, now, &AcceptProofVerifier)
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

fn deferred_session() -> Result<OpenId4VciIssuanceSession, TestError> {
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
    let session = record_openid4vci_token_exchanged(
        session,
        NonEmptyIdentifier::new("token-handle-1".to_owned())?,
    )?;
    let session =
        record_openid4vci_credential_request(session, &credential_request()?, timestamp(20)?)?;
    Ok(record_openid4vci_credential_response(
        session,
        CredentialResponse::deferred("txn-1".to_owned(), 30)?,
    )?)
}

#[test]
fn build_deferred_request_uses_session_transaction_id() -> Result<(), TestError> {
    let session = deferred_session()?;

    let request = build_openid4vci_deferred_credential_request(&session, None)?;

    assert_eq!(request.transaction_id, "txn-1");
    Ok(())
}

#[test]
fn poll_records_final_deferred_credential_response() -> Result<(), TestError> {
    let session = deferred_session()?;
    let token_handle = token_handle(&session)?;
    let mut requester = AcceptDeferredRequester;
    let mut schedule = schedule_due_at(&session, 100)?;

    let session = poll_openid4vci_deferred_credential(
        &session,
        &token_handle,
        None,
        &mut schedule,
        timestamp(100)?,
        &mut requester,
    )?;

    assert!(matches!(session.state, IssuanceState::CredentialReceived));
    assert!(session.deferred_issuance.is_none());
    assert!(session.credential_response.is_some());
    Ok(())
}

#[test]
fn repeated_poll_preserves_latest_transaction_until_completion() -> Result<(), TestError> {
    let session = deferred_session()?;
    let token_handle = token_handle(&session)?;
    let mut requester = PendingThenAcceptDeferredRequester { request_count: 0 };
    let mut schedule = schedule_due_at(&session, 100)?;

    let session = poll_openid4vci_deferred_credential(
        &session,
        &token_handle,
        None,
        &mut schedule,
        timestamp(100)?,
        &mut requester,
    )?;
    let pending = session
        .deferred_issuance
        .as_ref()
        .ok_or_else(|| FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
    assert_eq!(pending.transaction_id.as_str(), "txn-1");
    assert_eq!(pending.interval_seconds, 45);

    let session = poll_openid4vci_deferred_credential(
        &session,
        &token_handle,
        None,
        &mut schedule,
        timestamp(145)?,
        &mut requester,
    )?;

    assert!(matches!(session.state, IssuanceState::CredentialReceived));
    assert!(session.deferred_issuance.is_none());
    assert!(session.credential_response.is_some());
    assert_eq!(requester.request_count, 2);
    Ok(())
}

#[test]
fn poll_leaves_borrowed_state_unchanged_when_transport_rejects() -> Result<(), TestError> {
    let session = deferred_session()?;
    let token_handle = token_handle(&session)?;
    let mut requester = RejectDeferredRequester;
    let mut schedule = schedule_due_at(&session, 100)?;

    let result = poll_openid4vci_deferred_credential(
        &session,
        &token_handle,
        None,
        &mut schedule,
        timestamp(100)?,
        &mut requester,
    );

    assert!(matches!(
        result,
        Err(error) if error.reason == FlowErrorReason::OpenId4VciIssuerTransportRejected
    ));
    assert!(session.deferred_issuance.is_some());
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

#[test]
fn poll_schedule_enforces_interval_attempts_and_wait() -> Result<(), TestError> {
    let session = deferred_session()?;
    let token_handle = token_handle(&session)?;
    let interval = session
        .deferred_issuance
        .as_ref()
        .map(|status| i64::try_from(status.interval_seconds).unwrap_or(i64::MAX))
        .ok_or_else(|| FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
    let mut requester = RejectDeferredRequester;

    let mut schedule = schedule_due_at(&session, 100)?;
    let first = poll_openid4vci_deferred_credential(
        &session,
        &token_handle,
        None,
        &mut schedule,
        timestamp(100)?,
        &mut requester,
    );
    assert!(first.is_err());
    assert_eq!(schedule.attempts(), 1);
    let too_early = poll_openid4vci_deferred_credential(
        &session,
        &token_handle,
        None,
        &mut schedule,
        timestamp(100 + interval - 1)?,
        &mut requester,
    );
    assert!(matches!(
        too_early,
        Err(error) if error.reason == FlowErrorReason::DeferredPollTooEarly
    ));
    assert_eq!(schedule.attempts(), 1);

    let mut exhausted = crate::DeferredPollSchedule::restore(
        NonEmptyIdentifier::new("txn-1".to_owned())?,
        timestamp(100)?,
        Some(timestamp(100)?),
        crate::DeferredPollSchedule::MAX_ATTEMPTS,
    )?;
    let result = poll_openid4vci_deferred_credential(
        &session,
        &token_handle,
        None,
        &mut exhausted,
        timestamp(100 + interval)?,
        &mut requester,
    );
    assert!(matches!(
        result,
        Err(error) if error.reason == FlowErrorReason::DeferredIssuanceExpired
    ));

    let mut stale = crate::DeferredPollSchedule::start(&session, timestamp(100)?)?;
    let result = poll_openid4vci_deferred_credential(
        &session,
        &token_handle,
        None,
        &mut stale,
        timestamp(100 + crate::DeferredPollSchedule::MAX_WAIT_SECONDS + 1)?,
        &mut requester,
    );
    assert!(matches!(
        result,
        Err(error) if error.reason == FlowErrorReason::DeferredIssuanceExpired
    ));
    Ok(())
}

#[test]
fn poll_schedule_restore_rejects_inconsistent_state() -> Result<(), TestError> {
    for (last, attempts) in [
        (None, 1),
        (Some(timestamp(99)?), 1),
        (Some(timestamp(100)?), 0),
        (
            Some(timestamp(100)?),
            crate::DeferredPollSchedule::MAX_ATTEMPTS + 1,
        ),
    ] {
        assert!(matches!(
            crate::DeferredPollSchedule::restore(
                NonEmptyIdentifier::new("txn-1".to_owned())?,
                timestamp(100)?,
                last,
                attempts,
            ),
            Err(error) if error.reason == FlowErrorReason::InvalidOpenId4VciState
        ));
    }
    Ok(())
}

fn schedule_due_at(
    session: &crate::OpenId4VciIssuanceSession,
    due: i64,
) -> Result<crate::DeferredPollSchedule, TestError> {
    let interval = session
        .deferred_issuance
        .as_ref()
        .map(|status| i64::try_from(status.interval_seconds))
        .ok_or_else(|| FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?
        .map_err(|_| FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
    Ok(crate::DeferredPollSchedule::start(
        session,
        timestamp(due - interval)?,
    )?)
}

#[test]
fn first_poll_waits_the_issuer_interval_and_schedule_is_bound() -> Result<(), TestError> {
    let session = deferred_session()?;
    let token_handle = token_handle(&session)?;
    let mut requester = RejectDeferredRequester;
    let mut schedule = crate::DeferredPollSchedule::start(&session, timestamp(100)?)?;
    let early = poll_openid4vci_deferred_credential(
        &session,
        &token_handle,
        None,
        &mut schedule,
        timestamp(100)?,
        &mut requester,
    );
    assert!(matches!(
        early,
        Err(error) if error.reason == FlowErrorReason::DeferredPollTooEarly
    ));
    assert_eq!(schedule.attempts(), 0);

    let mut foreign = crate::DeferredPollSchedule::restore(
        NonEmptyIdentifier::new("txn-other".to_owned())?,
        timestamp(1)?,
        None,
        0,
    )?;
    let result = poll_openid4vci_deferred_credential(
        &session,
        &token_handle,
        None,
        &mut foreign,
        timestamp(100_000)?,
        &mut requester,
    );
    assert!(matches!(
        result,
        Err(error) if error.reason == FlowErrorReason::InvalidOpenId4VciState
    ));
    Ok(())
}
