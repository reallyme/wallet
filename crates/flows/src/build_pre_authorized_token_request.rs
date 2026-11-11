// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Builds OpenID4VCI pre-authorized token requests.

use openid4vci_types::{TxCode, TxCodeInputMode};
use reallyme_openid4vci_wallet::{
    CredentialOfferGrantType, PreAuthorizedTokenRequest, TransactionCode,
};

use crate::issue::OpenId4VciIssuanceSession;
use crate::{FlowError, FlowErrorReason, FlowResult, IssuanceState};

/// Build the holder token request for an OpenID4VCI pre-authorized-code offer.
///
/// The returned DTO is secret-bearing and should be sent directly by the HTTP
/// adapter. Wallet-core deliberately does not copy it into the resumable
/// session snapshot; only the state transition is persisted after the token
/// endpoint succeeds.
pub fn build_openid4vci_pre_authorized_token_request(
    session: &OpenId4VciIssuanceSession,
    transaction_code: Option<&TransactionCode>,
    client_id: Option<String>,
) -> FlowResult<PreAuthorizedTokenRequest> {
    match session.state {
        IssuanceState::ConsentCaptured | IssuanceState::Authorized => {
            if session.grant_type != CredentialOfferGrantType::PreAuthorizedCode {
                return Err(FlowError::new(
                    FlowErrorReason::PreAuthorizedCodeGrantRequired,
                ));
            }
            validate_transaction_code_for_offer(
                session.transaction_code.as_ref(),
                transaction_code,
            )?;
            if session.wallet_unit_attestation.is_none() {
                return Err(FlowError::new(
                    FlowErrorReason::WalletUnitAttestationRequired,
                ));
            }
            PreAuthorizedTokenRequest::new(session.issuance.as_ref(), transaction_code, client_id)
                .map_err(|_| FlowError::new(FlowErrorReason::InvalidOpenId4VciState))
        }
        IssuanceState::OfferReceived
        | IssuanceState::TokenExchanged
        | IssuanceState::Deferred
        | IssuanceState::CredentialReceived
        | IssuanceState::CredentialStored { .. } => {
            Err(FlowError::new(FlowErrorReason::InvalidTransition))
        }
    }
}

fn validate_transaction_code_for_offer(
    metadata: Option<&TxCode>,
    transaction_code: Option<&TransactionCode>,
) -> FlowResult<()> {
    match (metadata, transaction_code) {
        (Some(metadata), Some(transaction_code)) => {
            validate_transaction_code_metadata(metadata, transaction_code)
        }
        (Some(_), None) => Err(FlowError::new(FlowErrorReason::TransactionCodeRequired)),
        (None, Some(_)) => Err(FlowError::new(FlowErrorReason::TransactionCodeUnexpected)),
        (None, None) => Ok(()),
    }
}

fn validate_transaction_code_metadata(
    metadata: &TxCode,
    transaction_code: &TransactionCode,
) -> FlowResult<()> {
    let value = transaction_code.expose_secret();

    // OpenID4VCI defines `numeric` as the default when `input_mode` is absent.
    if !matches!(metadata.input_mode, Some(TxCodeInputMode::Text))
        && !value.chars().all(|character| character.is_ascii_digit())
    {
        return Err(FlowError::new(
            FlowErrorReason::TransactionCodeInvalidForOffer,
        ));
    }

    if let Some(expected_length) = metadata.length {
        let actual_length = u64::try_from(value.chars().count())
            .map_err(|_| FlowError::new(FlowErrorReason::TransactionCodeInvalidForOffer))?;
        if actual_length != expected_length {
            return Err(FlowError::new(
                FlowErrorReason::TransactionCodeInvalidForOffer,
            ));
        }
    }

    Ok(())
}
