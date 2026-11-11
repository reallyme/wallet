// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Holder-side OpenID4VCI issuance sequencing.

mod offer_uri;
mod session;

pub use offer_uri::{
    start_openid4vci_issuance_from_offer_uri,
    start_openid4vci_issuance_from_offer_uri_with_reuse_capabilities,
    start_openid4vci_issuance_from_offer_uri_with_verified_metadata_profile,
};
pub use session::{
    DeferredIssuanceStatus, IssuanceConsentDecision, IssuanceConsentProvider,
    IssuanceConsentRequest, OpenId4VciIssuanceSession,
};

use openid4vci_profiles::{
    parse_credential_reuse_policy, ReuseMethodSet, SelectedCredentialReusePolicy,
};
use openid4vci_types::{CredentialOffer, CredentialResponse, IssuerMetadata};
use reallyme_etsi_eaa_conformance::{validate_issuer_information, IssuerInformationEntry};
use reallyme_openid4vci_wallet::{
    CredentialOfferGrantType, SignedMetadataSignerTrustPurpose, ValidatedIssuance,
    VerifiedSignedIssuerMetadata,
};
use reallyme_wallet_attestation::{validate_wallet_unit_attestation, WalletUnitAttestation};
use reallyme_wallet_types::{
    CredentialReuseMethod, CredentialReusePolicySelection, NonEmptyIdentifier,
    OpenId4VciIssuerMetadataProfile, UnixTimestamp,
};

use crate::{capture_issuance_consent, FlowError, FlowErrorReason, FlowResult, IssuanceState};

const MAX_DEFERRED_INTERVAL_SECONDS: u64 = 86_400;

/// Start a holder-side OpenID4VCI issuance flow from a validated offer.
pub fn start_openid4vci_issuance(
    offer: CredentialOffer,
    issuer_metadata: &IssuerMetadata,
    grant_type: CredentialOfferGrantType,
    authorization_server: String,
) -> FlowResult<OpenId4VciIssuanceSession> {
    let supported = ReuseMethodSet::new(0)
        .map_err(|_| FlowError::new(FlowErrorReason::InvalidCredentialReusePolicy))?;
    start_openid4vci_issuance_with_reuse_capabilities(
        offer,
        issuer_metadata,
        grant_type,
        authorization_server,
        supported,
    )
}

/// Start issuance with explicit wallet credential-reuse capabilities.
///
/// The generic entry point advertises no restricted reuse methods and therefore
/// fails closed when an issuer requires one. EUDI composers must call this
/// function with only the methods whose lifecycle rules they actually enforce.
pub fn start_openid4vci_issuance_with_reuse_capabilities(
    offer: CredentialOffer,
    issuer_metadata: &IssuerMetadata,
    grant_type: CredentialOfferGrantType,
    authorization_server: String,
    supported_reuse_methods: ReuseMethodSet,
) -> FlowResult<OpenId4VciIssuanceSession> {
    start_openid4vci_issuance_with_profile(
        offer,
        issuer_metadata,
        OpenId4VciIssuerMetadataProfile::OpenId4Vci,
        grant_type,
        authorization_server,
        supported_reuse_methods,
    )
}

/// Start an ETSI-profiled issuance from authenticated signed issuer metadata.
///
/// Accepting [`VerifiedSignedIssuerMetadata`] at this boundary prevents a
/// caller from applying registrar data obtained from an unsigned or
/// downgraded metadata response. Generic OpenID4VCI remains available through
/// [`start_openid4vci_issuance_with_reuse_capabilities`].
pub fn start_openid4vci_issuance_with_verified_metadata_profile(
    offer: CredentialOffer,
    verified_issuer_metadata: &VerifiedSignedIssuerMetadata,
    issuer_metadata_profile: OpenId4VciIssuerMetadataProfile,
    grant_type: CredentialOfferGrantType,
    authorization_server: String,
    supported_reuse_methods: ReuseMethodSet,
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
    start_openid4vci_issuance_with_profile(
        offer,
        verified_issuer_metadata.metadata(),
        issuer_metadata_profile,
        grant_type,
        authorization_server,
        supported_reuse_methods,
    )
}

pub(crate) fn start_openid4vci_issuance_with_profile(
    offer: CredentialOffer,
    issuer_metadata: &IssuerMetadata,
    issuer_metadata_profile: OpenId4VciIssuerMetadataProfile,
    grant_type: CredentialOfferGrantType,
    authorization_server: String,
    supported_reuse_methods: ReuseMethodSet,
) -> FlowResult<OpenId4VciIssuanceSession> {
    offer
        .validate()
        .map_err(|_| FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
    validate_issuer_metadata_profile(issuer_metadata, issuer_metadata_profile)?;
    let credential_issuer = offer.credential_issuer.clone();
    let credential_configuration_ids = offer.credential_configuration_ids.clone();
    let credential_reuse_policies = select_credential_reuse_policies(
        &credential_configuration_ids,
        issuer_metadata,
        supported_reuse_methods,
    )?;
    let transaction_code = offer
        .grants
        .as_ref()
        .and_then(|grants| grants.pre_authorized_code.as_ref())
        .and_then(|grant| grant.tx_code.clone());
    let authorization_code_issuer_state = offer
        .grants
        .as_ref()
        .and_then(|grants| grants.authorization_code.as_ref())
        .and_then(|grant| grant.issuer_state.clone());
    let offer_digest = crate::seal_issuance_checkpoint::offer_digest(&offer)?;
    let issuance = ValidatedIssuance::new(offer, issuer_metadata, grant_type, authorization_server)
        .map_err(|_| FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;

    Ok(OpenId4VciIssuanceSession {
        offer_digest,
        credential_submission_started: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
            false,
        )),
        issuer_nonce_binding: None,
        state: IssuanceState::OfferReceived,
        issuance: std::sync::Arc::new(issuance),
        issuer_metadata: std::sync::Arc::new(issuer_metadata.clone()),
        grant_type,
        credential_issuer,
        credential_configuration_ids,
        credential_reuse_policies,
        issuer_metadata_profile,
        transaction_code,
        authorization_code_issuer_state,
        credential_request: None,
        credential_binding_key_handle_ids: Vec::new(),
        wallet_unit_attestation: None,
        credential_response: None,
        deferred_issuance: None,
        access_token_binding_handle: None,
    })
}

fn validate_issuer_metadata_profile(
    issuer_metadata: &IssuerMetadata,
    profile: OpenId4VciIssuerMetadataProfile,
) -> FlowResult<()> {
    if profile == OpenId4VciIssuerMetadataProfile::OpenId4Vci {
        return Ok(());
    }
    let issuer_information = issuer_metadata
        .issuer_info
        .as_deref()
        .ok_or_else(|| FlowError::new(FlowErrorReason::InvalidIssuerMetadataProfile))?;
    let entries = issuer_information
        .iter()
        .map(|entry| IssuerInformationEntry {
            format: entry.format.as_str(),
            data: &entry.data,
        })
        .collect::<Vec<_>>();
    let summary = validate_issuer_information(&entries)
        .map_err(|_| FlowError::new(FlowErrorReason::InvalidIssuerMetadataProfile))?;
    if profile == OpenId4VciIssuerMetadataProfile::EuEtsiTs119472Part3
        && !summary.registration_certificate_present()
    {
        return Err(FlowError::new(
            FlowErrorReason::InvalidIssuerMetadataProfile,
        ));
    }
    Ok(())
}

fn select_credential_reuse_policies(
    credential_configuration_ids: &[String],
    issuer_metadata: &IssuerMetadata,
    supported_reuse_methods: ReuseMethodSet,
) -> FlowResult<Vec<CredentialReusePolicySelection>> {
    credential_configuration_ids
        .iter()
        .map(|configuration_id| {
            let configuration = issuer_metadata
                .credential_configurations_supported
                .get(configuration_id)
                .ok_or_else(|| FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
            let policy = parse_credential_reuse_policy(configuration.credential_metadata.as_ref())
                .map_err(|_| FlowError::new(FlowErrorReason::InvalidCredentialReusePolicy))?;
            let selected = policy
                .select_first_supported_policy(supported_reuse_methods)
                .ok_or_else(|| FlowError::new(FlowErrorReason::UnsupportedCredentialReusePolicy))?;
            build_credential_reuse_selection(configuration_id, selected)
        })
        .collect()
}

fn build_credential_reuse_selection(
    configuration_id: &str,
    selected: SelectedCredentialReusePolicy,
) -> FlowResult<CredentialReusePolicySelection> {
    let credential_configuration_id = NonEmptyIdentifier::new(configuration_id.to_owned())
        .map_err(|_| FlowError::new(FlowErrorReason::InvalidCredentialReusePolicy))?;
    let (method, batch_size, reissue_trigger_unused, lifetime_left) = match selected {
        SelectedCredentialReusePolicy::Unrestricted => {
            (CredentialReuseMethod::Unrestricted, None, None, None)
        }
        SelectedCredentialReusePolicy::ArfAnnexIi {
            method,
            batch_size,
            reissue_trigger_unused,
            reissue_trigger_lifetime_left_seconds,
        } => {
            let method = match method {
                openid4vci_profiles::ReuseMethod::OnceOnly => CredentialReuseMethod::OnceOnly,
                openid4vci_profiles::ReuseMethod::LimitedTime => CredentialReuseMethod::LimitedTime,
                openid4vci_profiles::ReuseMethod::RotatingBatch => {
                    CredentialReuseMethod::RotatingBatch
                }
                openid4vci_profiles::ReuseMethod::PerRelyingParty => {
                    CredentialReuseMethod::PerRelyingParty
                }
            };
            (
                method,
                batch_size,
                reissue_trigger_unused,
                reissue_trigger_lifetime_left_seconds,
            )
        }
    };
    CredentialReusePolicySelection::new(
        credential_configuration_id,
        method,
        batch_size,
        reissue_trigger_unused,
        lifetime_left,
    )
    .map_err(|_| FlowError::new(FlowErrorReason::InvalidCredentialReusePolicy))
}

/// Record explicit user consent before authorization/token work is performed by adapters.
pub fn record_openid4vci_consent(
    mut session: OpenId4VciIssuanceSession,
    provider: &mut dyn IssuanceConsentProvider,
) -> FlowResult<OpenId4VciIssuanceSession> {
    if session.state != IssuanceState::OfferReceived {
        return Err(FlowError::new(FlowErrorReason::InvalidTransition));
    }
    let request = IssuanceConsentRequest {
        credential_issuer: &session.credential_issuer,
        credential_configuration_ids: &session.credential_configuration_ids,
        grant_type: session.grant_type,
    };
    if provider.capture_issuance_consent(request)? != IssuanceConsentDecision::Approved {
        return Err(FlowError::new(FlowErrorReason::InvalidTransition));
    }
    session.state = capture_issuance_consent(session.state)?;
    Ok(session)
}

/// Record completion of the authorization step.
pub fn record_openid4vci_authorized(
    mut session: OpenId4VciIssuanceSession,
) -> FlowResult<OpenId4VciIssuanceSession> {
    match session.state {
        IssuanceState::ConsentCaptured => {
            session.state = IssuanceState::Authorized;
            Ok(session)
        }
        IssuanceState::OfferReceived
        | IssuanceState::Authorized
        | IssuanceState::TokenExchanged
        | IssuanceState::Deferred
        | IssuanceState::CredentialReceived
        | IssuanceState::CredentialStored { .. } => {
            Err(FlowError::new(FlowErrorReason::InvalidTransition))
        }
    }
}

/// Bind a validated wallet unit attestation after user consent and before credential request work.
pub fn bind_openid4vci_wallet_unit_attestation(
    mut session: OpenId4VciIssuanceSession,
    wallet_unit_attestation: WalletUnitAttestation,
    now: UnixTimestamp,
) -> FlowResult<OpenId4VciIssuanceSession> {
    match session.state {
        IssuanceState::ConsentCaptured
        | IssuanceState::Authorized
        | IssuanceState::TokenExchanged => {
            // A recorded request already binds its proof to the prior attestation.
            // Rebinding here would let restored sessions change that identity.
            if session.credential_request.is_some() {
                return Err(FlowError::new(FlowErrorReason::InvalidTransition));
            }
            // After token exchange an attestation already bound may have been
            // presented to the issuer; replacing it would let the session
            // certify a different Wallet Unit than the one the issuer saw.
            if session.state == IssuanceState::TokenExchanged
                && session.wallet_unit_attestation.is_some()
            {
                return Err(FlowError::new(FlowErrorReason::InvalidTransition));
            }
            validate_issuance_attestation(&wallet_unit_attestation, now)?;
            session.wallet_unit_attestation = Some(wallet_unit_attestation);
            Ok(session)
        }
        IssuanceState::OfferReceived
        | IssuanceState::Deferred
        | IssuanceState::CredentialReceived
        | IssuanceState::CredentialStored { .. } => {
            Err(FlowError::new(FlowErrorReason::InvalidTransition))
        }
    }
}

/// Return the attestation that adapters must present to the issuer.
pub fn present_openid4vci_wallet_unit_attestation(
    session: &OpenId4VciIssuanceSession,
    now: UnixTimestamp,
) -> FlowResult<&WalletUnitAttestation> {
    match session.state {
        IssuanceState::Authorized | IssuanceState::TokenExchanged | IssuanceState::Deferred => {
            let Some(attestation) = session.wallet_unit_attestation.as_ref() else {
                return Err(FlowError::new(
                    FlowErrorReason::WalletUnitAttestationRequired,
                ));
            };
            validate_issuance_attestation(attestation, now)?;
            Ok(attestation)
        }
        IssuanceState::OfferReceived
        | IssuanceState::ConsentCaptured
        | IssuanceState::CredentialReceived
        | IssuanceState::CredentialStored { .. } => {
            Err(FlowError::new(FlowErrorReason::InvalidTransition))
        }
    }
}

/// Record an immediate or deferred credential response from the issuer.
pub(crate) fn record_openid4vci_credential_response(
    mut session: OpenId4VciIssuanceSession,
    credential_response: CredentialResponse,
) -> FlowResult<OpenId4VciIssuanceSession> {
    match session.state {
        IssuanceState::TokenExchanged => {
            credential_response
                .validate()
                .map_err(|_| FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
            session.deferred_issuance = deferred_status(&credential_response)?;
            if session.deferred_issuance.is_some() {
                session.state = IssuanceState::Deferred;
            } else {
                validate_credential_count(&session, &credential_response)?;
                session.state = IssuanceState::CredentialReceived;
            }
            session.credential_response = Some(credential_response);
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

/// Record one Deferred Credential Endpoint response.
///
/// A successful poll can either complete issuance or return another pending
/// `transaction_id` and `interval`. Preserving the latter in wallet state is
/// required so the host can wait again and issue the next request with the
/// issuer's latest transaction coordinates.
pub(crate) fn record_openid4vci_deferred_credential_response(
    mut session: OpenId4VciIssuanceSession,
    credential_response: CredentialResponse,
) -> FlowResult<OpenId4VciIssuanceSession> {
    match session.state {
        IssuanceState::Deferred => {
            credential_response
                .validate()
                .map_err(|_| FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
            let next_deferred = deferred_status(&credential_response)?;
            if let (Some(previous), Some(next)) =
                (session.deferred_issuance.as_ref(), next_deferred.as_ref())
            {
                if previous.transaction_id != next.transaction_id {
                    return Err(FlowError::new(FlowErrorReason::InvalidOpenId4VciState));
                }
            }
            if next_deferred.is_none() {
                validate_credential_count(&session, &credential_response)?;
                session.state = IssuanceState::CredentialReceived;
            }
            session.deferred_issuance = next_deferred;
            session.credential_response = Some(credential_response);
            Ok(session)
        }
        IssuanceState::OfferReceived
        | IssuanceState::ConsentCaptured
        | IssuanceState::Authorized
        | IssuanceState::TokenExchanged
        | IssuanceState::CredentialReceived
        | IssuanceState::CredentialStored { .. } => {
            Err(FlowError::new(FlowErrorReason::InvalidTransition))
        }
    }
}

pub(crate) fn validate_issuance_attestation(
    wallet_unit_attestation: &WalletUnitAttestation,
    now: UnixTimestamp,
) -> FlowResult<()> {
    validate_wallet_unit_attestation(wallet_unit_attestation, now)
        .map_err(|_| FlowError::new(FlowErrorReason::InvalidWalletUnitAttestation))
}

pub(crate) fn deferred_status(
    response: &CredentialResponse,
) -> FlowResult<Option<DeferredIssuanceStatus>> {
    match (&response.transaction_id, response.interval) {
        (Some(_), Some(interval_seconds)) if interval_seconds > MAX_DEFERRED_INTERVAL_SECONDS => {
            Err(FlowError::new(FlowErrorReason::InvalidOpenId4VciState))
        }
        (Some(transaction_id), Some(interval_seconds)) => Ok(Some(DeferredIssuanceStatus {
            transaction_id: NonEmptyIdentifier::new(transaction_id.clone())
                .map_err(|_| FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?,
            interval_seconds,
        })),
        (None, None) => Ok(None),
        (Some(_), None) | (None, Some(_)) => {
            Err(FlowError::new(FlowErrorReason::InvalidOpenId4VciState))
        }
    }
}

pub(crate) fn validate_credential_count(
    session: &OpenId4VciIssuanceSession,
    response: &CredentialResponse,
) -> FlowResult<()> {
    let response_count = response.credentials.as_ref().map_or(0, Vec::len);
    // A single key-attestation JWT can authorize several holder keys. The
    // verified key set, not the transport proof count, defines batch size.
    let expected_count = session.credential_binding_key_handle_ids.len();
    if response_count != expected_count {
        return Err(FlowError::new(FlowErrorReason::InvalidCredentialReceipt));
    }
    Ok(())
}

#[cfg(test)]
#[path = "issue_tests.rs"]
mod tests;
