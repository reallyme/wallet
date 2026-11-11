// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! OpenID4VCI issuance golden-flow conformance tests.

use openid4vci_profiles::ReuseMethodSet;
use openid4vci_types::{
    build_credential_offer_uri, CredentialEnvelope, CredentialOffer, CredentialPayload,
    CredentialResponse, DeferredCredentialRequest, IssuerMetadata, Proofs, TxCode, TxCodeInputMode,
};
use reallyme_openid4vci_wallet::{
    CredentialOfferFetcher, CredentialOfferGrantType, PreAuthorizedTokenRequest, TransactionCode,
    WalletCredentialRequest, WalletResult,
};
use reallyme_wallet::attestation::{
    verify_wallet_unit_attestation, AttestationResult, UnverifiedWalletUnitAttestation,
    WalletUnitAttestation, WalletUnitAttestationVerifier,
};
use reallyme_wallet::flows::{
    bind_openid4vci_authorization_code_token, bind_openid4vci_wallet_unit_attestation,
    build_openid4vci_pre_authorized_token_request, exchange_openid4vci_pre_authorized_token,
    poll_openid4vci_deferred_credential, prepare_openid4vci_credential_request,
    present_openid4vci_wallet_unit_attestation, record_openid4vci_authorized,
    record_openid4vci_consent, restore_openid4vci_access_token_handle,
    restore_openid4vci_issuance_session, start_openid4vci_issuance,
    start_openid4vci_issuance_from_offer_uri, submit_openid4vci_credential_request,
    CredentialProofBinding, CredentialRequestProofBinding, CredentialRequestProofVerifier,
    DeferredPollSchedule, FlowError, FlowErrorReason, FlowResult, IssuanceConsentDecision,
    IssuanceConsentProvider, IssuanceConsentRequest, IssuanceState, OpenId4VciAccessTokenHandle,
    OpenId4VciCredentialRequester, OpenId4VciDeferredCredentialRequester,
    OpenId4VciIssuanceSession, OpenId4VciTokenExchanger, PreparedOpenId4VciCredentialRequest,
};
use reallyme_wallet::keystore::KeyAttestationEvidence;
use reallyme_wallet::types as wallet;
use secrecy::SecretString;
use std::sync::Mutex;

struct ApprovedIssuanceConsentProvider;

impl IssuanceConsentProvider for ApprovedIssuanceConsentProvider {
    fn capture_issuance_consent(
        &mut self,
        request: IssuanceConsentRequest<'_>,
    ) -> FlowResult<IssuanceConsentDecision> {
        if request.credential_issuer() != "https://issuer.example"
            || request.credential_configuration_ids() != ["pid"]
        {
            return Err(FlowError::new(FlowErrorReason::InvalidOpenId4VciState));
        }
        Ok(IssuanceConsentDecision::Approved)
    }
}

fn id(value: &str) -> Result<wallet::NonEmptyIdentifier, wallet::WalletTypesError> {
    wallet::NonEmptyIdentifier::new(value.to_owned())
}

fn timestamp(seconds: i64) -> Result<wallet::UnixTimestamp, wallet::WalletTypesError> {
    wallet::UnixTimestamp::from_seconds(seconds)
}

fn no_restricted_reuse_methods() -> Result<ReuseMethodSet, TestError> {
    ReuseMethodSet::new(0).map_err(|_| TestError::Proto)
}

fn offer() -> openid4vci_types::OpenId4VciResult<CredentialOffer> {
    CredentialOffer::authorization_code(
        "https://issuer.example".to_owned(),
        vec!["pid".to_owned()],
        None,
    )
}

fn issuer_metadata() -> openid4vci_types::OpenId4VciResult<IssuerMetadata> {
    IssuerMetadata::parse_json(
        r#"{
            "credential_issuer":"https://issuer.example",
            "credential_endpoint":"https://issuer.example/credential",
            "credential_configurations_supported":{
                "pid":{"format":"dc+sd-jwt","vct":"urn:example:pid"}
            }
        }"#,
    )
}

fn start_authorization_code_issuance(
    offer: CredentialOffer,
) -> Result<OpenId4VciIssuanceSession, TestError> {
    Ok(start_openid4vci_issuance(
        offer,
        &issuer_metadata()?,
        CredentialOfferGrantType::AuthorizationCode,
        "https://issuer.example".to_owned(),
    )?)
}

fn start_pre_authorized_code_issuance(
    offer: CredentialOffer,
) -> Result<OpenId4VciIssuanceSession, TestError> {
    Ok(start_openid4vci_issuance(
        offer,
        &issuer_metadata()?,
        CredentialOfferGrantType::PreAuthorizedCode,
        "https://issuer.example".to_owned(),
    )?)
}

fn credential_request() -> Result<PreparedOpenId4VciCredentialRequest, TestError> {
    let session = start_authorization_code_issuance(offer()?)?;
    Ok(prepare_openid4vci_credential_request(
        &session,
        "pid".to_owned(),
        Some(Proofs {
            jwt: vec!["proof-1".to_owned()],
            di_vp: Vec::new(),
            attestation: Vec::new(),
        }),
        None,
        None,
    )?)
}

fn pre_authorized_offer() -> openid4vci_types::OpenId4VciResult<CredentialOffer> {
    CredentialOffer::pre_authorized_code(
        "https://issuer.example".to_owned(),
        vec!["pid".to_owned()],
        "code-123".to_owned(),
        Some(TxCode {
            input_mode: Some(TxCodeInputMode::Numeric),
            length: Some(6),
            description: Some("Issuer-provided transaction code".to_owned()),
        }),
    )
}

fn transaction_code(value: &str) -> reallyme_openid4vci_wallet::WalletResult<TransactionCode> {
    TransactionCode::new(SecretString::from(value.to_owned()))
}

struct StaticOfferFetcher {
    offer: Mutex<Option<CredentialOffer>>,
}

impl CredentialOfferFetcher for StaticOfferFetcher {
    fn fetch_offer(&self, _credential_offer_uri: &str) -> WalletResult<CredentialOffer> {
        self.offer
            .lock()
            .map_err(|_| {
                reallyme_openid4vci_wallet::WalletError::new(
                    reallyme_openid4vci_wallet::WalletStatus::InvalidRequest,
                )
            })?
            .take()
            .ok_or_else(|| {
                reallyme_openid4vci_wallet::WalletError::new(
                    reallyme_openid4vci_wallet::WalletStatus::InvalidRequest,
                )
            })
    }
}

struct AcceptTokenExchanger;

impl OpenId4VciTokenExchanger for AcceptTokenExchanger {
    fn exchange_pre_authorized_token(
        &mut self,
        _request: &PreAuthorizedTokenRequest,
        _attestation_client_authentication: Option<
            &reallyme_openid_oauth::AttestationClientAuthentication,
        >,
    ) -> Result<OpenId4VciAccessTokenHandle, FlowError> {
        let id = wallet::NonEmptyIdentifier::new("token-handle-1".to_owned())
            .map_err(|_| FlowError::new(FlowErrorReason::OpenId4VciIssuerTransportRejected))?;
        Ok(OpenId4VciAccessTokenHandle::from_transport(id))
    }
}

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
                holder_key_handle_id: wallet::KeyHandleId::new("holder-key-1".to_owned())
                    .map_err(|_| FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?,
                issued_at: timestamp(20)
                    .map_err(|_| FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?,
            }],
            wallet_unit_key_handle_id: wallet::KeyHandleId::new("key-1".to_owned())
                .map_err(|_| FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?,
        })
    }
}

struct AcceptCredentialRequester;

impl OpenId4VciCredentialRequester for AcceptCredentialRequester {
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
                credential: CredentialPayload::Json(serde_json::json!({"vct": "pid"})),
            }],
            None,
        )
        .map_err(|_| FlowError::new(FlowErrorReason::OpenId4VciIssuerTransportRejected))
    }
}

struct DeferredCredentialRequester;

impl OpenId4VciCredentialRequester for DeferredCredentialRequester {
    fn submit_credential_request(
        &mut self,
        _token_handle: &OpenId4VciAccessTokenHandle,
        _request: &WalletCredentialRequest,
    ) -> Result<CredentialResponse, FlowError> {
        CredentialResponse::deferred("txn-1".to_owned(), 30)
            .map_err(|_| FlowError::new(FlowErrorReason::OpenId4VciIssuerTransportRejected))
    }
}

fn bind_authorization_code_token(
    session: &OpenId4VciIssuanceSession,
) -> Result<(OpenId4VciIssuanceSession, OpenId4VciAccessTokenHandle), TestError> {
    let handle = OpenId4VciAccessTokenHandle::from_transport(id("token-handle-1")?);
    Ok(bind_openid4vci_authorization_code_token(session, handle)?)
}

struct AcceptDeferredCredentialRequester;

impl OpenId4VciDeferredCredentialRequester for AcceptDeferredCredentialRequester {
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
                credential: CredentialPayload::Json(serde_json::json!({"vct": "pid"})),
            }],
            None,
        )
        .map_err(|_| FlowError::new(FlowErrorReason::OpenId4VciIssuerTransportRejected))
    }
}

struct AcceptAttestationVerifier;

impl WalletUnitAttestationVerifier for AcceptAttestationVerifier {
    fn verify_wallet_unit_attestation(
        &self,
        _attestation: &UnverifiedWalletUnitAttestation,
        _now: wallet::UnixTimestamp,
    ) -> AttestationResult<reallyme_wallet::attestation::VerifiedWalletKeyThumbprint> {
        reallyme_wallet::attestation::VerifiedWalletKeyThumbprint::new([1; 32])
    }
}

fn wallet_unit_attestation() -> Result<WalletUnitAttestation, TestError> {
    let unverified = UnverifiedWalletUnitAttestation::new(
        id("wua-1")?,
        KeyAttestationEvidence {
            key_handle_id: wallet::KeyHandleId::new("key-1".to_owned())?,
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

#[test]
fn eudi_issuance_resolves_inline_offer_uri_through_openid4vci() -> Result<(), TestError> {
    let offer = offer()?;
    let uri = build_credential_offer_uri("openid-credential-offer://", &offer.to_json()?)?;

    let session = start_openid4vci_issuance_from_offer_uri(
        &uri,
        None,
        &issuer_metadata()?,
        CredentialOfferGrantType::AuthorizationCode,
        "https://issuer.example".to_owned(),
    )?;

    assert!(matches!(session.state(), IssuanceState::OfferReceived));
    assert_eq!(session.credential_issuer(), "https://issuer.example");
    Ok(())
}

#[test]
fn eudi_issuance_referenced_offer_requires_injected_fetcher() -> Result<(), TestError> {
    let result = start_openid4vci_issuance_from_offer_uri(
        "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffer%2F1",
        None,
        &issuer_metadata()?,
        CredentialOfferGrantType::AuthorizationCode,
        "https://issuer.example".to_owned(),
    );

    assert!(matches!(
        result,
        Err(error) if error.reason == FlowErrorReason::CredentialOfferResolutionRequired
    ));
    Ok(())
}

#[test]
fn eudi_issuance_resolves_referenced_offer_with_injected_fetcher() -> Result<(), TestError> {
    let fetcher = StaticOfferFetcher {
        offer: Mutex::new(Some(offer()?)),
    };

    let session = start_openid4vci_issuance_from_offer_uri(
        "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffer%2F1",
        Some(&fetcher),
        &issuer_metadata()?,
        CredentialOfferGrantType::AuthorizationCode,
        "https://issuer.example".to_owned(),
    )?;

    assert_eq!(session.credential_configuration_ids(), ["pid".to_owned()]);
    Ok(())
}

#[test]
fn eudi_issuance_builds_pre_authorized_token_request() -> Result<(), TestError> {
    let session = start_pre_authorized_code_issuance(pre_authorized_offer()?)?;
    let session = record_openid4vci_consent(session, &mut ApprovedIssuanceConsentProvider)?;
    let session = bind_openid4vci_wallet_unit_attestation(
        session,
        wallet_unit_attestation()?,
        timestamp(15)?,
    )?;
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
fn eudi_issuance_exchanges_token_through_injected_transport() -> Result<(), TestError> {
    let session = start_pre_authorized_code_issuance(pre_authorized_offer()?)?;
    let session = record_openid4vci_consent(session, &mut ApprovedIssuanceConsentProvider)?;
    let session = bind_openid4vci_wallet_unit_attestation(
        session,
        wallet_unit_attestation()?,
        timestamp(15)?,
    )?;
    let tx_code = transaction_code("123456")?;
    let mut exchanger = AcceptTokenExchanger;

    let (session, handle) = exchange_openid4vci_pre_authorized_token(
        &session,
        Some(&tx_code),
        Some("wallet-client".to_owned()),
        None,
        &mut exchanger,
    )?;

    assert!(matches!(session.state(), IssuanceState::TokenExchanged));
    assert_eq!(handle.id().as_str(), "token-handle-1");
    Ok(())
}

#[test]
fn eudi_issuance_submits_credential_request_through_injected_transport() -> Result<(), TestError> {
    let session = start_authorization_code_issuance(offer()?)?;
    let session = record_openid4vci_consent(session, &mut ApprovedIssuanceConsentProvider)?;
    let session = bind_openid4vci_wallet_unit_attestation(
        session,
        wallet_unit_attestation()?,
        timestamp(20)?,
    )?;
    let session = record_openid4vci_authorized(session)?;
    let (session, token_handle) = bind_authorization_code_token(&session)?;
    let mut requester = AcceptCredentialRequester;

    let session = submit_openid4vci_credential_request(
        &session,
        &token_handle,
        &credential_request()?,
        timestamp(20)?,
        &AcceptProofVerifier,
        &mut requester,
    )?;

    assert!(matches!(session.state(), IssuanceState::CredentialReceived));
    assert!(session.credential_response().is_some());
    Ok(())
}

#[test]
fn eudi_issuance_requires_wua_before_credential_request() -> Result<(), TestError> {
    let session = start_authorization_code_issuance(offer()?)?;
    let session = record_openid4vci_consent(session, &mut ApprovedIssuanceConsentProvider)?;
    let session = record_openid4vci_authorized(session)?;
    let (session, token_handle) = bind_authorization_code_token(&session)?;
    let mut requester = AcceptCredentialRequester;

    let result = submit_openid4vci_credential_request(
        &session,
        &token_handle,
        &credential_request()?,
        timestamp(20)?,
        &AcceptProofVerifier,
        &mut requester,
    );

    assert!(matches!(
        result,
        Err(error) if error.reason == FlowErrorReason::WalletUnitAttestationRequired
    ));
    Ok(())
}

#[test]
fn eudi_issuance_binds_wua_and_reaches_deferred_polling() -> Result<(), TestError> {
    let session = start_authorization_code_issuance(offer()?)?;
    let session = record_openid4vci_consent(session, &mut ApprovedIssuanceConsentProvider)?;
    let session = bind_openid4vci_wallet_unit_attestation(
        session,
        wallet_unit_attestation()?,
        timestamp(20)?,
    )?;
    let session = record_openid4vci_authorized(session)?;
    let attestation = present_openid4vci_wallet_unit_attestation(&session, timestamp(20)?)?;

    assert_eq!(attestation.id().as_str(), "wua-1");

    let (session, token_handle) = bind_authorization_code_token(&session)?;
    let mut requester = DeferredCredentialRequester;
    let session = submit_openid4vci_credential_request(
        &session,
        &token_handle,
        &credential_request()?,
        timestamp(20)?,
        &AcceptProofVerifier,
        &mut requester,
    )?;

    assert!(matches!(session.state(), IssuanceState::Deferred));
    assert!(matches!(
        session.deferred_issuance(),
        Some(status) if status.transaction_id.as_str() == "txn-1"
    ));
    Ok(())
}

#[test]
fn eudi_issuance_polls_deferred_credential_through_injected_transport() -> Result<(), TestError> {
    let session = start_authorization_code_issuance(offer()?)?;
    let session = record_openid4vci_consent(session, &mut ApprovedIssuanceConsentProvider)?;
    let session = bind_openid4vci_wallet_unit_attestation(
        session,
        wallet_unit_attestation()?,
        timestamp(20)?,
    )?;
    let session = record_openid4vci_authorized(session)?;
    let (session, token_handle) = bind_authorization_code_token(&session)?;
    let mut submitter = DeferredCredentialRequester;
    let session = submit_openid4vci_credential_request(
        &session,
        &token_handle,
        &credential_request()?,
        timestamp(20)?,
        &AcceptProofVerifier,
        &mut submitter,
    )?;
    let mut requester = AcceptDeferredCredentialRequester;
    let mut schedule = DeferredPollSchedule::start(&session, timestamp(0)?)?;

    let session = poll_openid4vci_deferred_credential(
        &session,
        &token_handle,
        None,
        &mut schedule,
        timestamp(3_600)?,
        &mut requester,
    )?;

    assert!(matches!(session.state(), IssuanceState::CredentialReceived));
    assert!(session.deferred_issuance().is_none());
    assert!(session.credential_response().is_some());
    Ok(())
}

#[test]
fn deferred_issuance_restores_and_resumes_polling() -> Result<(), TestError> {
    let session = start_authorization_code_issuance(offer()?)?;
    let session = record_openid4vci_consent(session, &mut ApprovedIssuanceConsentProvider)?;
    let session = bind_openid4vci_wallet_unit_attestation(
        session,
        wallet_unit_attestation()?,
        timestamp(20)?,
    )?;
    let session = record_openid4vci_authorized(session)?;
    let (session, _) = bind_authorization_code_token(&session)?;
    let mut submitter = DeferredCredentialRequester;
    let session = submit_openid4vci_credential_request(
        &session,
        &restore_openid4vci_access_token_handle(
            &session,
            session
                .access_token_binding_handle()
                .cloned()
                .ok_or(TestError::Proto)?,
        )?,
        &credential_request()?,
        timestamp(20)?,
        &AcceptProofVerifier,
        &mut submitter,
    )?;

    let checkpoint_key = reallyme_wallet::flows::IssuanceCheckpointKey::new(
        secrecy::SecretBox::new(Box::new([0x4a; 32])),
    )?;
    let tag = checkpoint_key.seal(&session)?;
    let restored = restore_openid4vci_issuance_session(
        IssuanceState::Deferred,
        offer()?,
        &issuer_metadata()?,
        CredentialOfferGrantType::AuthorizationCode,
        "https://issuer.example".to_owned(),
        no_restricted_reuse_methods()?,
        session.credential_request().cloned(),
        session.credential_binding_key_handle_ids().to_vec(),
        session.wallet_unit_attestation().cloned(),
        session.credential_response().cloned(),
        session.deferred_issuance().cloned(),
        session.access_token_binding_handle().cloned(),
        &AcceptProofVerifier,
        Some(reallyme_wallet::flows::IssuanceResumeProof::new(
            &checkpoint_key,
            &tag,
        )),
    )?;
    let wallet_unit_key = session
        .wallet_unit_attestation()
        .ok_or(TestError::Proto)?
        .evidence()
        .key_handle_id
        .clone();
    let reused_key_restore = restore_openid4vci_issuance_session(
        IssuanceState::Deferred,
        offer()?,
        &issuer_metadata()?,
        CredentialOfferGrantType::AuthorizationCode,
        "https://issuer.example".to_owned(),
        no_restricted_reuse_methods()?,
        session.credential_request().cloned(),
        vec![wallet_unit_key],
        session.wallet_unit_attestation().cloned(),
        session.credential_response().cloned(),
        session.deferred_issuance().cloned(),
        session.access_token_binding_handle().cloned(),
        &AcceptProofVerifier,
        Some(reallyme_wallet::flows::IssuanceResumeProof::new(
            &checkpoint_key,
            &tag,
        )),
    );
    assert!(matches!(
        reused_key_restore,
        Err(error) if error.reason == FlowErrorReason::InvalidOpenId4VciState
    ));
    let forged_holder_restore = restore_openid4vci_issuance_session(
        IssuanceState::Deferred,
        offer()?,
        &issuer_metadata()?,
        CredentialOfferGrantType::AuthorizationCode,
        "https://issuer.example".to_owned(),
        no_restricted_reuse_methods()?,
        session.credential_request().cloned(),
        vec![wallet::KeyHandleId::new("forged-holder".to_owned())?],
        session.wallet_unit_attestation().cloned(),
        session.credential_response().cloned(),
        session.deferred_issuance().cloned(),
        session.access_token_binding_handle().cloned(),
        &AcceptProofVerifier,
        Some(reallyme_wallet::flows::IssuanceResumeProof::new(
            &checkpoint_key,
            &tag,
        )),
    );
    assert!(matches!(
        forged_holder_restore,
        Err(error) if error.reason == FlowErrorReason::InvalidOpenId4VciState
    ));
    let mut forged_deferred_status = session
        .deferred_issuance()
        .cloned()
        .ok_or(TestError::Proto)?;
    forged_deferred_status.transaction_id = id("forged-transaction")?;
    let forged_deferred_restore = restore_openid4vci_issuance_session(
        IssuanceState::Deferred,
        offer()?,
        &issuer_metadata()?,
        CredentialOfferGrantType::AuthorizationCode,
        "https://issuer.example".to_owned(),
        no_restricted_reuse_methods()?,
        session.credential_request().cloned(),
        session.credential_binding_key_handle_ids().to_vec(),
        session.wallet_unit_attestation().cloned(),
        session.credential_response().cloned(),
        Some(forged_deferred_status),
        session.access_token_binding_handle().cloned(),
        &AcceptProofVerifier,
        Some(reallyme_wallet::flows::IssuanceResumeProof::new(
            &checkpoint_key,
            &tag,
        )),
    );
    assert!(matches!(
        forged_deferred_restore,
        Err(error) if error.reason == FlowErrorReason::InvalidOpenId4VciState
    ));
    let restored_handle = restore_openid4vci_access_token_handle(
        &restored,
        restored
            .access_token_binding_handle()
            .cloned()
            .ok_or(TestError::Proto)?,
    )?;
    let mut requester = AcceptDeferredCredentialRequester;
    let mut schedule = DeferredPollSchedule::start(&restored, timestamp(0)?)?;
    let completed = poll_openid4vci_deferred_credential(
        &restored,
        &restored_handle,
        None,
        &mut schedule,
        timestamp(3_600)?,
        &mut requester,
    )?;

    assert!(matches!(
        completed.state(),
        IssuanceState::CredentialReceived
    ));
    let empty_stored_restore = restore_openid4vci_issuance_session(
        IssuanceState::CredentialStored {
            credential_ids: Vec::new(),
        },
        offer()?,
        &issuer_metadata()?,
        CredentialOfferGrantType::AuthorizationCode,
        "https://issuer.example".to_owned(),
        no_restricted_reuse_methods()?,
        completed.credential_request().cloned(),
        completed.credential_binding_key_handle_ids().to_vec(),
        completed.wallet_unit_attestation().cloned(),
        completed.credential_response().cloned(),
        completed.deferred_issuance().cloned(),
        completed.access_token_binding_handle().cloned(),
        &AcceptProofVerifier,
        Some(reallyme_wallet::flows::IssuanceResumeProof::new(
            &checkpoint_key,
            &tag,
        )),
    );
    assert!(matches!(
        empty_stored_restore,
        Err(error) if error.reason == FlowErrorReason::InvalidOpenId4VciState
    ));
    Ok(())
}

#[derive(Debug, thiserror::Error)]
enum TestError {
    #[error("flow")]
    Flow(#[from] FlowError),
    #[error("reallyme_openid4vci_wallet")]
    Wallet(#[from] reallyme_openid4vci_wallet::WalletError),
    #[error("openid4vci")]
    OpenId4Vci(#[from] openid4vci_types::OpenId4VciError),
    #[error("serde")]
    Serde,
    #[error("wallet_types")]
    WalletTypes(#[from] wallet::WalletTypesError),
    #[error("attestation")]
    Attestation(#[from] reallyme_wallet::attestation::AttestationError),
    #[error("proto")]
    Proto,
}

#[path = "issuance_flow/restore_checkpoint.rs"]
mod restore_checkpoint;
