// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Submits OpenID4VCI credential requests through injected transport.

use openid4vci_types::CredentialResponse;
use reallyme_openid4vci_wallet::WalletCredentialRequest;
use reallyme_wallet_types::UnixTimestamp;
use std::sync::atomic::Ordering;

use crate::credential_request_proof::CredentialRequestProofVerifier;
use crate::exchange_pre_authorized_token::OpenId4VciAccessTokenHandle;
use crate::issue::OpenId4VciIssuanceSession;
use crate::prepare_credential_request::PreparedOpenId4VciCredentialRequest;
use crate::record_issuance_credential_request::record_openid4vci_credential_request;
use crate::{
    record_openid4vci_credential_response, FlowError, FlowErrorReason, FlowResult, IssuanceState,
};

/// Injected OpenID4VCI credential endpoint transport.
pub trait OpenId4VciCredentialRequester {
    /// Durably reserve the final wire request before sending it to the issuer.
    ///
    /// The transport owns the token and final HTTP representation, including
    /// any randomized request encryption. Atomically retain those exact body
    /// bytes under the stable issuance attempt before the first send. A
    /// previously reserved attempt requires reconciliation after restart.
    ///
    /// Return `OpenId4VciIssuerTransportRejected` only when the issuer
    /// answered with an error response, such as `invalid_nonce` or
    /// `invalid_proof`. Every other failure is treated as an uncertain
    /// delivery that must be reconciled.
    fn submit_credential_request(
        &mut self,
        token_handle: &OpenId4VciAccessTokenHandle,
        request: &WalletCredentialRequest,
    ) -> FlowResult<CredentialResponse>;
}

/// Validate, submit, and record an OpenID4VCI credential endpoint response.
///
/// The input session and prepared request are borrowed. If the issuer refuses
/// the request, the caller's token-exchanged session is unchanged and a new
/// request with a fresh nonce or proof can be recorded from it. Any other
/// failure is reported as `CredentialSubmissionUncertain`: the request may
/// have reached the issuer, so the flow does not resend it, and the outcome
/// must be reconciled. This one-call form does not return the recorded
/// session; use `record_openid4vci_credential_request` and
/// `submit_recorded_openid4vci_credential_request` when an uncertain outcome
/// must later be reconciled with
/// `OpenId4VciIssuanceSession::record_reconciled_credential_response`.
pub fn submit_openid4vci_credential_request(
    session: &OpenId4VciIssuanceSession,
    token_handle: &OpenId4VciAccessTokenHandle,
    credential_request: &PreparedOpenId4VciCredentialRequest,
    now: UnixTimestamp,
    proof_verifier: &dyn CredentialRequestProofVerifier,
    requester: &mut dyn OpenId4VciCredentialRequester,
) -> FlowResult<OpenId4VciIssuanceSession> {
    token_handle.validate_for_session(session)?;
    let requested_session = record_openid4vci_credential_request(
        session.clone(),
        credential_request,
        now,
        proof_verifier,
    )?;
    submit_recorded_openid4vci_credential_request(
        &requested_session,
        token_handle,
        credential_request,
        now,
        proof_verifier,
        requester,
    )
}

/// Submit a credential request that is already recorded in `requested_session`.
///
/// The session must hold exactly this prepared request and no response. A
/// request rebuilt with different proofs does not match the recorded request.
/// Within one process, clones of the recorded session share a guard that
/// allows one dispatch. A session restored after a restart starts with a new
/// guard, so a second dispatch is safe only because the transport's durable
/// reservation refuses to send a reserved attempt again and reports its
/// outcome instead.
/// `now` must be a fresh trusted time observation at dispatch. Revalidate the
/// retained attestation, nonce and authenticated proof before reserving I/O.
pub fn submit_recorded_openid4vci_credential_request(
    requested_session: &OpenId4VciIssuanceSession,
    token_handle: &OpenId4VciAccessTokenHandle,
    credential_request: &PreparedOpenId4VciCredentialRequest,
    now: UnixTimestamp,
    proof_verifier: &dyn CredentialRequestProofVerifier,
    requester: &mut dyn OpenId4VciCredentialRequester,
) -> FlowResult<OpenId4VciIssuanceSession> {
    token_handle.validate_for_session(requested_session)?;
    if requested_session.state != IssuanceState::TokenExchanged
        || requested_session.credential_response.is_some()
        || requested_session.credential_request.as_ref()
            != Some(&credential_request.canonical_request)
        || requested_session.issuer_metadata.as_ref() != credential_request.issuer_metadata.as_ref()
    {
        return Err(FlowError::new(FlowErrorReason::InvalidOpenId4VciState));
    }
    let uncertain = || FlowError::new(FlowErrorReason::CredentialSubmissionUncertain);
    // An earlier send remains uncertain even after its proof expires. Time
    // validation must never turn a spent request into a safely retryable one.
    if requested_session
        .credential_submission_started
        .load(Ordering::Acquire)
    {
        return Err(uncertain());
    }
    let attestation = requested_session
        .wallet_unit_attestation
        .as_ref()
        .ok_or_else(|| FlowError::new(FlowErrorReason::WalletUnitAttestationRequired))?;
    crate::issue::validate_issuance_attestation(attestation, now)?;
    let binding =
        proof_verifier.verify_credential_request_proof(&credential_request.canonical_request)?;
    crate::validate_credential_request::validate_proof_binding(
        requested_session,
        &credential_request.canonical_request,
        &binding,
        now,
    )?;
    if requested_session
        .credential_submission_started
        .swap(true, Ordering::AcqRel)
    {
        return Err(uncertain());
    }
    let credential_response = requester
        .submit_credential_request(token_handle, &credential_request.transport_request)
        .map_err(|error| match error.reason {
            // The issuer answered and refused this request; it is spent, and
            // the caller records a new one rather than reconciling.
            FlowErrorReason::OpenId4VciIssuerTransportRejected => error,
            _ => uncertain(),
        })?;

    record_openid4vci_credential_response(requested_session.clone(), credential_response)
        .map_err(|_| uncertain())
}

impl OpenId4VciIssuanceSession {
    /// Record the issuer's response obtained while reconciling an uncertain
    /// submission of exactly `credential_request`.
    ///
    /// Reconciliation recovers the outcome of the one dispatched request, for
    /// example from the transport's durable reservation; it never sends a new
    /// request. `self` must be the session that recorded this request, which
    /// the two-phase `record_openid4vci_credential_request` and
    /// `submit_recorded_openid4vci_credential_request` API returns before
    /// dispatch.
    pub fn record_reconciled_credential_response(
        &self,
        credential_request: &PreparedOpenId4VciCredentialRequest,
        credential_response: CredentialResponse,
    ) -> FlowResult<Self> {
        if self.state != IssuanceState::TokenExchanged
            || self.credential_response.is_some()
            || self.credential_request.as_ref() != Some(&credential_request.canonical_request)
            || self.issuer_metadata.as_ref() != credential_request.issuer_metadata.as_ref()
        {
            return Err(FlowError::new(FlowErrorReason::InvalidOpenId4VciState));
        }
        record_openid4vci_credential_response(self.clone(), credential_response)
    }
}

#[cfg(test)]
#[path = "submit_credential_request_tests.rs"]
mod tests;
