// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Restore persisted OpenID4VCI sessions through stage-specific invariants.

use openid4vci_profiles::{validate_etsi_credential_request_proofs, ReuseMethodSet};
use openid4vci_types::{CredentialOffer, CredentialRequest, CredentialResponse, IssuerMetadata};
use reallyme_openid4vci_wallet::{
    CredentialOfferGrantType, SignedMetadataSignerTrustPurpose, VerifiedSignedIssuerMetadata,
};
use reallyme_wallet_attestation::WalletUnitAttestation;
use reallyme_wallet_types::{KeyHandleId, NonEmptyIdentifier, OpenId4VciIssuerMetadataProfile};

use crate::credential_request_proof::CredentialRequestProofVerifier;
use crate::issue::{
    deferred_status, validate_credential_count, DeferredIssuanceStatus, OpenId4VciIssuanceSession,
};
use crate::validate_credential_request::proof_shape_matches_binding;
use crate::{FlowError, FlowErrorReason, FlowResult, IssuanceResumeProof, IssuanceState};

/// Restore a persisted issuance session after validating every stage invariant.
///
/// Every stage beyond the initial offer requires a checkpoint authenticated by
/// the owning Wallet Unit. A state label, attestation, or token handle alone
/// cannot establish approval for the original issuance interaction.
#[allow(clippy::too_many_arguments)]
pub fn restore_openid4vci_issuance_session(
    state: IssuanceState,
    offer: CredentialOffer,
    issuer_metadata: &IssuerMetadata,
    grant_type: CredentialOfferGrantType,
    authorization_server: String,
    supported_reuse_methods: ReuseMethodSet,
    credential_request: Option<CredentialRequest>,
    credential_binding_key_handle_ids: Vec<KeyHandleId>,
    wallet_unit_attestation: Option<WalletUnitAttestation>,
    credential_response: Option<CredentialResponse>,
    deferred_issuance: Option<DeferredIssuanceStatus>,
    access_token_binding_handle: Option<NonEmptyIdentifier>,
    proof_verifier: &dyn CredentialRequestProofVerifier,
    checkpoint: Option<IssuanceResumeProof<'_>>,
) -> FlowResult<OpenId4VciIssuanceSession> {
    restore_openid4vci_issuance_session_with_profile(
        state,
        offer,
        issuer_metadata,
        OpenId4VciIssuerMetadataProfile::OpenId4Vci,
        grant_type,
        authorization_server,
        supported_reuse_methods,
        credential_request,
        credential_binding_key_handle_ids,
        wallet_unit_attestation,
        credential_response,
        deferred_issuance,
        access_token_binding_handle,
        proof_verifier,
        checkpoint,
        None,
    )
}

/// Restore an ETSI-profiled session using freshly authenticated signed metadata.
///
/// Pass the retained `issuer_nonce_binding` when the issuer metadata names a
/// Nonce Endpoint and a credential request was recorded; without it such a
/// session cannot be restored.
///
/// Every stage beyond the initial offer requires an authenticated checkpoint.
#[allow(clippy::too_many_arguments)]
pub fn restore_openid4vci_issuance_session_with_verified_metadata_profile(
    state: IssuanceState,
    offer: CredentialOffer,
    verified_issuer_metadata: &VerifiedSignedIssuerMetadata,
    issuer_metadata_profile: OpenId4VciIssuerMetadataProfile,
    grant_type: CredentialOfferGrantType,
    authorization_server: String,
    supported_reuse_methods: ReuseMethodSet,
    credential_request: Option<CredentialRequest>,
    credential_binding_key_handle_ids: Vec<KeyHandleId>,
    wallet_unit_attestation: Option<WalletUnitAttestation>,
    credential_response: Option<CredentialResponse>,
    deferred_issuance: Option<DeferredIssuanceStatus>,
    access_token_binding_handle: Option<NonEmptyIdentifier>,
    proof_verifier: &dyn CredentialRequestProofVerifier,
    checkpoint: Option<IssuanceResumeProof<'_>>,
    issuer_nonce_binding: Option<reallyme_wallet_types::IssuerNonceBinding>,
) -> FlowResult<OpenId4VciIssuanceSession> {
    if issuer_metadata_profile == OpenId4VciIssuerMetadataProfile::OpenId4Vci {
        return Err(FlowError::new(
            FlowErrorReason::InvalidIssuerMetadataProfile,
        ));
    }
    if verified_issuer_metadata
        .trust_evidence()
        .signer_trust_purpose()
        != SignedMetadataSignerTrustPurpose::WalletRelyingPartyAccessCertificate
    {
        return Err(FlowError::new(
            FlowErrorReason::InvalidIssuerMetadataProfile,
        ));
    }
    restore_openid4vci_issuance_session_with_profile(
        state,
        offer,
        verified_issuer_metadata.metadata(),
        issuer_metadata_profile,
        grant_type,
        authorization_server,
        supported_reuse_methods,
        credential_request,
        credential_binding_key_handle_ids,
        wallet_unit_attestation,
        credential_response,
        deferred_issuance,
        access_token_binding_handle,
        proof_verifier,
        checkpoint,
        issuer_nonce_binding,
    )
}

#[allow(clippy::too_many_arguments)]
fn restore_openid4vci_issuance_session_with_profile(
    state: IssuanceState,
    offer: CredentialOffer,
    issuer_metadata: &IssuerMetadata,
    issuer_metadata_profile: OpenId4VciIssuerMetadataProfile,
    grant_type: CredentialOfferGrantType,
    authorization_server: String,
    supported_reuse_methods: ReuseMethodSet,
    credential_request: Option<CredentialRequest>,
    credential_binding_key_handle_ids: Vec<KeyHandleId>,
    wallet_unit_attestation: Option<WalletUnitAttestation>,
    credential_response: Option<CredentialResponse>,
    deferred_issuance: Option<DeferredIssuanceStatus>,
    access_token_binding_handle: Option<NonEmptyIdentifier>,
    proof_verifier: &dyn CredentialRequestProofVerifier,
    checkpoint: Option<IssuanceResumeProof<'_>>,
    issuer_nonce_binding: Option<reallyme_wallet_types::IssuerNonceBinding>,
) -> FlowResult<OpenId4VciIssuanceSession> {
    offer
        .validate()
        .map_err(|_| FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
    if let Some(request) = credential_request.as_ref() {
        request
            .validate()
            .map_err(|_| FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
    }
    if let Some(response) = credential_response.as_ref() {
        response
            .validate()
            .map_err(|_| FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
    }

    let binding_count_matches_request = match credential_request.as_ref() {
        Some(request) => request.proofs.as_ref().is_some_and(|proofs| {
            proof_shape_matches_binding(proofs, credential_binding_key_handle_ids.len())
        }),
        None => credential_binding_key_handle_ids.is_empty(),
    };
    let unique_binding_count = credential_binding_key_handle_ids
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    if !binding_count_matches_request
        || unique_binding_count != credential_binding_key_handle_ids.len()
        || wallet_unit_attestation.as_ref().is_some_and(|attestation| {
            credential_binding_key_handle_ids
                .iter()
                .any(|holder_key| holder_key == &attestation.evidence().key_handle_id)
        })
    {
        return Err(FlowError::new(FlowErrorReason::InvalidOpenId4VciState));
    }

    let no_request_or_response = credential_request.is_none()
        && credential_response.is_none()
        && deferred_issuance.is_none()
        && access_token_binding_handle.is_none();
    let valid = match &state {
        IssuanceState::OfferReceived => no_request_or_response && wallet_unit_attestation.is_none(),
        IssuanceState::ConsentCaptured | IssuanceState::Authorized => no_request_or_response,
        IssuanceState::TokenExchanged => {
            // A pre-authorized token request already carries the Wallet Unit
            // Attestation. An authorization-code token is bound first and the
            // attestation follows before the credential request, so it may be
            // absent until a request is recorded.
            let attestation_present = wallet_unit_attestation.is_some();
            credential_response.is_none()
                && deferred_issuance.is_none()
                && access_token_binding_handle.is_some()
                && match grant_type {
                    CredentialOfferGrantType::PreAuthorizedCode => attestation_present,
                    CredentialOfferGrantType::AuthorizationCode => {
                        attestation_present || credential_request.is_none()
                    }
                }
        }
        IssuanceState::Deferred => {
            credential_request.is_some()
                && credential_response.is_some()
                && deferred_issuance.is_some()
                && access_token_binding_handle.is_some()
                && wallet_unit_attestation.is_some()
        }
        IssuanceState::CredentialReceived | IssuanceState::CredentialStored { .. } => {
            credential_request.is_some()
                && credential_response.is_some()
                && deferred_issuance.is_none()
                && access_token_binding_handle.is_some()
                && wallet_unit_attestation.is_some()
        }
    };
    if !valid {
        return Err(FlowError::new(FlowErrorReason::InvalidOpenId4VciState));
    }

    let mut session = crate::issue::start_openid4vci_issuance_with_profile(
        offer,
        issuer_metadata,
        issuer_metadata_profile,
        grant_type,
        authorization_server,
        supported_reuse_methods,
    )?;
    session.state = state;
    session.issuer_nonce_binding = issuer_nonce_binding;
    session.credential_request = credential_request;
    session.credential_binding_key_handle_ids = credential_binding_key_handle_ids;
    session.wallet_unit_attestation = wallet_unit_attestation;
    session.credential_response = credential_response;
    session.deferred_issuance = deferred_issuance;
    session.access_token_binding_handle = access_token_binding_handle;
    if session.state != IssuanceState::OfferReceived || checkpoint.is_some() {
        checkpoint
            .ok_or_else(|| FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?
            .verify(&session)?;
    }

    match &session.state {
        IssuanceState::Deferred => {
            let response = session
                .credential_response
                .as_ref()
                .ok_or_else(|| FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
            let response_status = deferred_status(response)?;
            if response_status != session.deferred_issuance {
                return Err(FlowError::new(FlowErrorReason::InvalidOpenId4VciState));
            }
        }
        IssuanceState::CredentialReceived | IssuanceState::CredentialStored { .. } => {
            let response = session
                .credential_response
                .as_ref()
                .ok_or_else(|| FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
            if deferred_status(response)?.is_some() {
                return Err(FlowError::new(FlowErrorReason::InvalidOpenId4VciState));
            }
            validate_credential_count(&session, response)?;
            if let IssuanceState::CredentialStored { credential_ids } = &session.state {
                let expected_count = response.credentials.as_ref().map_or(0, Vec::len);
                if !valid_stored_ids(credential_ids, expected_count) {
                    return Err(FlowError::new(FlowErrorReason::InvalidOpenId4VciState));
                }
            }
        }
        IssuanceState::OfferReceived
        | IssuanceState::ConsentCaptured
        | IssuanceState::Authorized
        | IssuanceState::TokenExchanged => {}
    }
    if let Some(request) = session.credential_request.as_ref() {
        let Some(configuration_id) = request.credential_configuration_id.as_ref() else {
            return Err(FlowError::new(FlowErrorReason::InvalidOpenId4VciState));
        };
        if !session
            .credential_configuration_ids
            .iter()
            .any(|offered| offered == configuration_id)
        {
            return Err(FlowError::new(FlowErrorReason::InvalidOpenId4VciState));
        }
        if session.issuer_metadata_profile != OpenId4VciIssuerMetadataProfile::OpenId4Vci {
            let configuration = session
                .issuer_metadata
                .credential_configurations_supported
                .get(configuration_id)
                .ok_or_else(|| FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
            validate_etsi_credential_request_proofs(
                request.proofs.as_ref(),
                configuration.supports_proofs(),
            )
            .map_err(|_| FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
        }
        let binding = proof_verifier.verify_credential_request_proof(request)?;
        crate::bind_issuer_nonce::validate_nonce_binding(&session, &binding, None)?;
        let attested_key = session
            .wallet_unit_attestation
            .as_ref()
            .map(|attestation| &attestation.evidence().key_handle_id)
            .ok_or_else(|| FlowError::new(FlowErrorReason::WalletUnitAttestationRequired))?;
        if &binding.wallet_unit_key_handle_id != attested_key
            || binding.proofs.len() != session.credential_binding_key_handle_ids.len()
            || binding
                .proofs
                .iter()
                .zip(&session.credential_binding_key_handle_ids)
                .any(|(proof, stored_key)| {
                    proof.audience != session.credential_issuer
                        || &proof.holder_key_handle_id != stored_key
                        || &proof.holder_key_handle_id == attested_key
                })
        {
            return Err(FlowError::new(FlowErrorReason::InvalidOpenId4VciState));
        }
    }
    Ok(session)
}

fn valid_stored_ids(
    credential_ids: &[reallyme_wallet_types::CredentialRecordId],
    expected_count: usize,
) -> bool {
    credential_ids.len() == expected_count
        && !credential_ids.is_empty()
        && credential_ids
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == expected_count
}

#[cfg(test)]
#[path = "restore_issuance_tests.rs"]
mod tests;

/// Restore a generic issuance session with its retained authenticated nonce binding.
/// The owning proof verifier must authenticate nonce claims from the exact JWTs.
///
/// Every stage beyond the initial offer requires an authenticated checkpoint.
#[allow(clippy::too_many_arguments)]
pub fn restore_openid4vci_issuance_session_with_nonce_binding(
    state: IssuanceState,
    offer: CredentialOffer,
    issuer_metadata: &IssuerMetadata,
    grant_type: CredentialOfferGrantType,
    authorization_server: String,
    supported_reuse_methods: ReuseMethodSet,
    credential_request: Option<CredentialRequest>,
    credential_binding_key_handle_ids: Vec<KeyHandleId>,
    wallet_unit_attestation: Option<WalletUnitAttestation>,
    credential_response: Option<CredentialResponse>,
    deferred_issuance: Option<DeferredIssuanceStatus>,
    access_token_binding_handle: Option<NonEmptyIdentifier>,
    proof_verifier: &dyn CredentialRequestProofVerifier,
    checkpoint: Option<IssuanceResumeProof<'_>>,
    issuer_nonce_binding: Option<reallyme_wallet_types::IssuerNonceBinding>,
) -> FlowResult<OpenId4VciIssuanceSession> {
    restore_openid4vci_issuance_session_with_profile(
        state,
        offer,
        issuer_metadata,
        OpenId4VciIssuerMetadataProfile::OpenId4Vci,
        grant_type,
        authorization_server,
        supported_reuse_methods,
        credential_request,
        credential_binding_key_handle_ids,
        wallet_unit_attestation,
        credential_response,
        deferred_issuance,
        access_token_binding_handle,
        proof_verifier,
        checkpoint,
        issuer_nonce_binding,
    )
}
