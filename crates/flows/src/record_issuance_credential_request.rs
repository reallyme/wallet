// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Records a credential request after validated issuer token exchange.

use reallyme_wallet_types::UnixTimestamp;

use crate::credential_request_proof::CredentialRequestProofVerifier;
use crate::issue::{validate_issuance_attestation, OpenId4VciIssuanceSession};
use crate::prepare_credential_request::PreparedOpenId4VciCredentialRequest;
use crate::validate_credential_request::validate_proof_binding;
use crate::{FlowError, FlowErrorReason, FlowResult, IssuanceState};

/// Record the holder-built credential request after token exchange.
///
/// Persist the returned session before submitting the request so a retry after
/// a restart resumes with this exact request; see
/// `submit_recorded_openid4vci_credential_request`.
pub fn record_openid4vci_credential_request(
    mut session: OpenId4VciIssuanceSession,
    credential_request: &PreparedOpenId4VciCredentialRequest,
    now: UnixTimestamp,
    proof_verifier: &dyn CredentialRequestProofVerifier,
) -> FlowResult<OpenId4VciIssuanceSession> {
    match session.state {
        IssuanceState::TokenExchanged => {
            if session.credential_request.is_some() {
                return Err(FlowError::new(FlowErrorReason::InvalidTransition));
            }
            if session.issuer_metadata.as_ref() != credential_request.issuer_metadata.as_ref() {
                return Err(FlowError::new(FlowErrorReason::InvalidOpenId4VciState));
            }
            let Some(attestation) = session.wallet_unit_attestation.as_ref() else {
                return Err(FlowError::new(
                    FlowErrorReason::WalletUnitAttestationRequired,
                ));
            };
            validate_issuance_attestation(attestation, now)?;
            credential_request
                .canonical_request
                .validate()
                .map_err(|_| FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
            let Some(configuration_id) = credential_request
                .canonical_request
                .credential_configuration_id
                .as_ref()
            else {
                return Err(FlowError::new(FlowErrorReason::InvalidOpenId4VciState));
            };
            if !session
                .credential_configuration_ids
                .iter()
                .any(|offered| offered == configuration_id)
            {
                return Err(FlowError::new(FlowErrorReason::InvalidOpenId4VciState));
            }
            if let Some(nonce) = credential_request.issuer_nonce_binding.as_ref() {
                crate::bind_openid4vci_issuer_nonce(&mut session, nonce.clone(), now)?;
            }
            let binding = proof_verifier
                .verify_credential_request_proof(&credential_request.canonical_request)?;
            validate_proof_binding(
                &session,
                &credential_request.canonical_request,
                &binding,
                now,
            )?;
            session.credential_binding_key_handle_ids = binding
                .proofs
                .iter()
                .map(|proof| proof.holder_key_handle_id.clone())
                .collect();
            session.credential_request = Some(credential_request.canonical_request.clone());
            // Each recorded request gets its own dispatch guard, so a request
            // recorded later with a fresh nonce or proof can still be sent.
            session.credential_submission_started =
                std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            Ok(session)
        }
        IssuanceState::OfferReceived
        | IssuanceState::ConsentCaptured
        | IssuanceState::Authorized
        | IssuanceState::Deferred
        | IssuanceState::CredentialReceived
        | IssuanceState::CredentialStored { .. } => {
            Err(FlowError::new(FlowErrorReason::InvalidTransition))
        }
    }
}
