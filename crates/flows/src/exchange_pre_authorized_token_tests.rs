// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use openid4vci_types::{CredentialOffer, TxCode, TxCodeInputMode};
use reallyme_openid4vci_wallet::TransactionCode;
use reallyme_openid_oauth::AttestationClientAuthentication;
use reallyme_wallet_attestation::{
    verify_wallet_unit_attestation, AttestationResult, UnverifiedWalletUnitAttestation,
    WalletUnitAttestation, WalletUnitAttestationVerifier,
};
use reallyme_wallet_keystore::KeyAttestationEvidence;
use reallyme_wallet_types::UnixTimestamp;
use secrecy::SecretString;
use serde_json::Value;

use crate::test_support::start_pre_authorized_code_issuance;

use crate::{
    bind_openid4vci_authorization_code_token, bind_openid4vci_wallet_unit_attestation,
    exchange_openid4vci_pre_authorized_token, record_openid4vci_consent, FlowError,
    FlowErrorReason, IssuanceState, OpenId4VciAccessTokenHandle, OpenId4VciTokenExchanger,
};

struct AcceptExchanger {
    calls: u8,
    last_grant_type: Option<Value>,
    received_attestation_headers: bool,
}

impl OpenId4VciTokenExchanger for AcceptExchanger {
    fn exchange_pre_authorized_token(
        &mut self,
        request: &reallyme_openid4vci_wallet::PreAuthorizedTokenRequest,
        attestation_client_authentication: Option<&AttestationClientAuthentication>,
    ) -> Result<OpenId4VciAccessTokenHandle, FlowError> {
        self.calls = self.calls.saturating_add(1);
        let serialized = serde_json::to_value(request)
            .map_err(|_| FlowError::new(FlowErrorReason::OpenId4VciIssuerTransportRejected))?;
        self.last_grant_type = Some(serialized["grant_type"].clone());
        self.received_attestation_headers = attestation_client_authentication.is_some();
        if serialized.get("client_attestation").is_some()
            || serialized.get("client_attestation_pop").is_some()
        {
            return Err(FlowError::new(
                FlowErrorReason::OpenId4VciIssuerTransportRejected,
            ));
        }

        let id = reallyme_wallet_types::NonEmptyIdentifier::new("token-handle-1".to_owned())
            .map_err(|_| FlowError::new(FlowErrorReason::OpenId4VciIssuerTransportRejected))?;
        Ok(OpenId4VciAccessTokenHandle::from_transport(id))
    }
}

struct RejectExchanger;

impl OpenId4VciTokenExchanger for RejectExchanger {
    fn exchange_pre_authorized_token(
        &mut self,
        _request: &reallyme_openid4vci_wallet::PreAuthorizedTokenRequest,
        _attestation_client_authentication: Option<&AttestationClientAuthentication>,
    ) -> Result<OpenId4VciAccessTokenHandle, FlowError> {
        Err(FlowError::new(
            FlowErrorReason::OpenId4VciIssuerTransportRejected,
        ))
    }
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
    let issued_at = UnixTimestamp::from_seconds(10)?;
    let unverified = UnverifiedWalletUnitAttestation::new(
        reallyme_wallet_types::NonEmptyIdentifier::new("wua-1".to_owned())?,
        KeyAttestationEvidence {
            key_handle_id: reallyme_wallet_types::KeyHandleId::new("key-1".to_owned())?,
            evidence: vec![1, 2, 3],
            issued_at,
            challenge: [7; 32],
        },
        UnixTimestamp::from_seconds(30)?,
        vec![9, 8, 7],
    )?;
    Ok(verify_wallet_unit_attestation(
        unverified,
        &AcceptAttestationVerifier,
        issued_at,
    )?)
}

#[test]
fn exchange_advances_state_after_transport_accepts() -> Result<(), TestError> {
    let session = start_pre_authorized_code_issuance(pre_authorized_offer()?)?;
    let session = record_openid4vci_consent(
        session,
        &mut crate::test_support::ApprovedIssuanceConsentProvider,
    )?;
    let session = bind_openid4vci_wallet_unit_attestation(
        session,
        attestation()?,
        reallyme_wallet_types::UnixTimestamp::from_seconds(15)?,
    )?;
    let tx_code = transaction_code("123456")?;
    let mut exchanger = AcceptExchanger {
        calls: 0,
        last_grant_type: None,
        received_attestation_headers: false,
    };
    let authentication = AttestationClientAuthentication::new(
        "attestation.payload.signature".to_owned(),
        "proof.payload.signature".to_owned(),
    )
    .map_err(|_| {
        TestError::Flow(FlowError::new(
            FlowErrorReason::OpenId4VciIssuerTransportRejected,
        ))
    })?;

    let (session, handle) = exchange_openid4vci_pre_authorized_token(
        &session,
        Some(&tx_code),
        Some("wallet-client".to_owned()),
        Some(authentication),
        &mut exchanger,
    )?;

    assert!(matches!(session.state, IssuanceState::TokenExchanged));
    assert_eq!(handle.id().as_str(), "token-handle-1");
    assert_eq!(exchanger.calls, 1);
    assert!(exchanger.received_attestation_headers);
    assert_eq!(
        exchanger.last_grant_type,
        Some(Value::String(
            "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_owned()
        ))
    );
    Ok(())
}

#[test]
fn exchange_leaves_borrowed_state_unchanged_when_transport_rejects() -> Result<(), TestError> {
    let session = start_pre_authorized_code_issuance(pre_authorized_offer()?)?;
    let session = record_openid4vci_consent(
        session,
        &mut crate::test_support::ApprovedIssuanceConsentProvider,
    )?;
    let session = bind_openid4vci_wallet_unit_attestation(
        session,
        attestation()?,
        reallyme_wallet_types::UnixTimestamp::from_seconds(15)?,
    )?;
    let tx_code = transaction_code("123456")?;
    let mut exchanger = RejectExchanger;

    let result = exchange_openid4vci_pre_authorized_token(
        &session,
        Some(&tx_code),
        None,
        None,
        &mut exchanger,
    );

    assert!(matches!(
        result,
        Err(error) if error.reason == FlowErrorReason::OpenId4VciIssuerTransportRejected
    ));
    assert!(matches!(session.state, IssuanceState::ConsentCaptured));
    Ok(())
}

#[test]
fn authorization_code_token_rejects_pre_authorized_offer() -> Result<(), TestError> {
    let session = start_pre_authorized_code_issuance(pre_authorized_offer()?)?;
    let session = record_openid4vci_consent(
        session,
        &mut crate::test_support::ApprovedIssuanceConsentProvider,
    )?;
    let handle = OpenId4VciAccessTokenHandle::from_transport(
        reallyme_wallet_types::NonEmptyIdentifier::new("token-handle-1".to_owned())?,
    );

    let result = bind_openid4vci_authorization_code_token(&session, handle);

    assert!(matches!(
        result,
        Err(error) if error.reason == FlowErrorReason::InvalidOpenId4VciState
    ));
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
    #[error("types")]
    Types(#[from] reallyme_wallet_types::WalletTypesError),
    #[error("attestation")]
    Attestation(#[from] reallyme_wallet_attestation::AttestationError),
}
